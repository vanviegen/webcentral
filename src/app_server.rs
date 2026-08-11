//! A managed server: one command with its own lifecycle, port and idle timeout. A
//! project can declare several, and each starts on demand the first time a request is routed to
//! it, independently of the others. File watching belongs to the project, which stops the servers
//! when their files change.
//!
//! State machine, driven by `lifecycle_task`:
//!
//! * **Stopped** - nothing running; a waiting request triggers a start
//! * **Starting** - processes spawned, waiting for the port to answer
//! * **Running** - serving; watching for a stop trigger (file change, idle, process exit, shutdown)
//! * **Failed** - startup failed; waiting requests get a 502, and a later file change retries

use crate::config::{ServerConfig, DEFAULT_BASE_IMAGE};
use crate::logger::Logger;
use crate::owner::Owner;
use crate::project::StreamBody;
use crate::server::SHARED_EXECUTOR;
use crate::streams::AnyConnector;
use anyhow::Result;
use include_exclude_watcher::Matcher;
use hyper_util::client::legacy::Client;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::{mpsc, watch, Mutex, Notify};
use tokio::time::sleep;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    Stopped,
    Starting,
    Running,
    Failed,
}

/// How an attempt to start ended: serving, given up on, or thrown away because the files moved
/// under it.
enum Startup {
    Ready,
    Failed,
    Aborted,
}

#[derive(Debug, Clone, Copy)]
pub enum StopReason {
    FileChange,
    Inactivity,
    ProcessExit,
    Shutdown,
}

/// Connection info for the current run; replaced on every restart, since each start gets a fresh
/// port to avoid TIME_WAIT conflicts.
#[derive(Debug)]
pub struct AppConnection {
    pub port: u16,
    pub http_client: Client<AnyConnector, StreamBody>,
    pub connector: AnyConnector,
}

/// How many images may be pulled or built at the same time, across every project. Enough to keep
/// a slow registry from serialising everything, few enough that a restart is not a thundering
/// herd.
fn image_work() -> &'static tokio::sync::Semaphore {
    static LIMIT: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    LIMIT.get_or_init(|| tokio::sync::Semaphore::new(4))
}

/// What a service needs settled before it can be started, and only needs settling once.
#[derive(Debug, Clone)]
struct Prepared {
    image: String,
    /// What to pass to `--user`, if anything.
    user_arg: Option<String>,
    /// The ids the container really runs as, which the host-side ownership mapping derives from.
    run_uid: u32,
    run_gid: u32,
    /// Paths the image declares with `VOLUME` that nothing else already covers, to be given a
    /// directory on the host. Settled with the image, since that is what declares them.
    volumes: Vec<String>,
}

#[derive(Debug)]
pub struct AppServer {
    pub config: ServerConfig,
    pub logger: Arc<Logger>,
    /// Which changed files make this server stale.
    reload: Matcher,
    /// Everything that can be settled before a request arrives, per service in this group.
    /// Preparation starts as soon as the service is declared, so a request that comes later
    /// usually finds it done - and one that arrives mid-build waits on this same lock rather than
    /// starting a second one.
    prepared: Mutex<std::collections::HashMap<String, Prepared>>,
    dir: PathBuf,
    /// Whose project this is: podman runs as them, so what a container writes is already theirs.
    owner: Arc<Owner>,
    connection: Mutex<Option<AppConnection>>,
    state_tx: watch::Sender<AppState>,
    state_rx: watch::Receiver<AppState>,
    stop_tx: mpsc::Sender<StopReason>,
    /// Flipped once the lifecycle task has ended, so a shutdown can wait for the containers to
    /// really be gone rather than only for the request to stop them to be sent.
    finished_tx: watch::Sender<bool>,
    finished_rx: watch::Receiver<bool>,
    pending_requests: AtomicU64,
    active_upgrades: AtomicU64,
    total_requests: AtomicU64,
    last_activity: Mutex<Instant>,
    state_changed: Notify,
}

impl AppServer {
    pub fn new(
        config: ServerConfig,
        dir: &Path,
        owner: Arc<Owner>,
        logger: Arc<Logger>,
    ) -> Arc<AppServer> {
        let (state_tx, state_rx) = watch::channel(AppState::Stopped);
        let (stop_tx, stop_rx) = mpsc::channel(8);
        let (finished_tx, finished_rx) = watch::channel(false);

        let server = Arc::new(AppServer {
            reload: Matcher::new(&config.reload_include, &config.reload_exclude),
            prepared: Mutex::new(std::collections::HashMap::new()),
            config,
            logger,
            dir: dir.to_path_buf(),
            owner,
            connection: Mutex::new(None),
            state_tx,
            state_rx,
            stop_tx,
            finished_tx,
            finished_rx,
            pending_requests: 0.into(),
            active_upgrades: 0.into(),
            total_requests: 0.into(),
            last_activity: Mutex::new(Instant::now()),
            state_changed: Notify::new(),
        });

        let running = server.clone();
        tokio::spawn(async move {
            running.lifecycle_task(stop_rx).await;
        });

        // Get the images ready now rather than when the first request is waiting on them. The
        // parent goes first: a sidecar without a `base` of its own builds on the parent's image.
        let preparing = server.clone();
        tokio::spawn(async move {
            let parent = match preparing.ensure_prepared(&preparing.config, None).await {
                Ok(prepared) => prepared.image,
                Err(e) => {
                    preparing.log(&format!("Could not prepare {}: {}", preparing.config.name, e));
                    return;
                }
            };
            for sidecar in &preparing.config.sidecars {
                if let Err(e) = preparing.ensure_prepared(sidecar, Some(&parent)).await {
                    preparing.log(&format!("Could not prepare {}: {}", sidecar.name, e));
                }
            }
        });

        server
    }

    /// Log lines are tagged per server, so a project with several of them stays readable.
    fn log_tag(&self) -> String {
        if self.config.name == "default" {
            "server".to_string()
        } else {
            format!("server:{}", self.config.name)
        }
    }

    fn log(&self, message: &str) {
        self.logger.write(&self.log_tag(), message);
    }

    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Whether a change to `path` (relative to the project directory) concerns this server.
    pub fn wants(&self, path: &str) -> bool {
        self.reload.matches(path)
    }

    pub fn state(&self) -> AppState {
        *self.state_rx.borrow()
    }

    pub fn port(&self) -> Option<u16> {
        self.connection.try_lock().ok().and_then(|c| c.as_ref().map(|c| c.port))
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    pub fn pending_requests(&self) -> u64 {
        self.pending_requests.load(Ordering::Relaxed)
    }

    pub fn active_upgrades(&self) -> u64 {
        self.active_upgrades.load(Ordering::Relaxed)
    }

    pub fn idle_seconds(&self) -> Option<u64> {
        self.last_activity.try_lock().ok().map(|t| t.elapsed().as_secs())
    }

    pub async fn touch(&self) {
        *self.last_activity.lock().await = Instant::now();
    }

    pub fn track_upgrade(&self) {
        self.active_upgrades.fetch_add(1, Ordering::SeqCst);
    }

    pub fn untrack_upgrade(&self) {
        self.active_upgrades.fetch_sub(1, Ordering::SeqCst);
        self.state_changed.notify_one();
    }

    fn track_request(&self) {
        self.pending_requests.fetch_add(1, Ordering::SeqCst);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.state_changed.notify_one();
    }

    pub fn untrack_request(&self) {
        self.pending_requests.fetch_sub(1, Ordering::SeqCst);
        self.state_changed.notify_one();
    }

    /// Wait until the server is serving, starting it if needed. On success the caller MUST call
    /// `untrack_request` when done.
    ///
    /// No timeout here on purpose: the lifecycle always resolves to Running or Failed (it gives up
    /// after `startup_time`), so a slow start is left to finish and the client's own timeout
    /// applies instead of us forcing a premature error.
    pub async fn wait_until_ready(&self) -> Result<()> {
        self.track_request();
        self.touch().await;

        let mut rx = self.state_rx.clone();
        let state = match rx.wait_for(|&s| s == AppState::Running || s == AppState::Failed).await {
            Ok(state) => *state,
            Err(_) => {
                self.untrack_request();
                anyhow::bail!("Server state channel closed");
            }
        };
        if state == AppState::Failed {
            self.untrack_request();
            anyhow::bail!("502 server '{}' failed to start", self.config.name);
        }
        Ok(())
    }

    pub async fn http_client(&self) -> Result<Client<AnyConnector, StreamBody>> {
        match self.connection.lock().await.as_ref() {
            Some(connection) => Ok(connection.http_client.clone()),
            None => anyhow::bail!("502 server '{}' not started", self.config.name),
        }
    }

    pub async fn connector(&self) -> Result<AnyConnector> {
        match self.connection.lock().await.as_ref() {
            Some(connection) => Ok(connection.connector.clone()),
            None => anyhow::bail!("502 server '{}' not started", self.config.name),
        }
    }

    pub fn request_stop(&self, reason: StopReason) {
        let _ = self.stop_tx.try_send(reason);
    }

    /// Stop for a file change, and say so *now* rather than when the lifecycle task gets round to
    /// it. The stop travels through a channel, so between a change being noticed and the task
    /// acting on it there is a window in which the state still reads Running - and a request
    /// arriving in it would be served by the very process that is about to be replaced, which is
    /// exactly what someone who just edited a file will not expect. Marking it Stopped here makes
    /// that request wait for the restart instead.
    pub fn request_restart(&self) {
        let _ = self.state_tx.send(AppState::Stopped);
        self.request_stop(StopReason::FileChange);
    }

    pub fn shutdown(&self) {
        self.request_stop(StopReason::Shutdown);
    }

    /// Wait until the lifecycle task has ended, which is when its containers are actually stopped.
    /// Returns at once for a server that already finished.
    pub async fn wait_finished(&self) {
        let mut rx = self.finished_rx.clone();
        let _ = rx.wait_for(|&done| done).await;
    }

    // --- Lifecycle ---

    async fn lifecycle_task(self: Arc<Self>, stop_rx: mpsc::Receiver<StopReason>) {
        self.clone().lifecycle_loop(stop_rx).await;
        // Every exit from the loop above has already stopped whatever was running.
        let _ = self.finished_tx.send(true);
    }

    async fn lifecycle_loop(self: Arc<Self>, mut stop_rx: mpsc::Receiver<StopReason>) {
        let idle_timeout = (self.config.shutdown_time > 0)
            .then(|| Duration::from_secs(self.config.shutdown_time));

        loop {
            match self.state() {
                AppState::Stopped => {
                    // Wait for a request to ask for us.
                    loop {
                        if self.pending_requests.load(Ordering::SeqCst) > 0 {
                            break;
                        }
                        tokio::select! {
                            reason = stop_rx.recv() => match reason {
                                Some(StopReason::Shutdown) | None => {
                                    return;
                                }
                                Some(StopReason::FileChange) => {
                                    // The project is being rebuilt; this instance is orphaned.
                                    return;
                                }
                                _ => {}
                            },
                            _ = self.state_changed.notified() => {}
                            _ = sleep(Duration::from_millis(100)) => {}
                        }
                    }
                    let _ = self.state_tx.send(AppState::Starting);
                }

                AppState::Starting => {
                    self.log("Starting");
                    let mut children = match self.spawn_processes().await {
                        Ok(children) => children,
                        Err(e) => {
                            self.log(&format!("Failed to spawn: {}; giving up", e));
                            let _ = self.state_tx.send(AppState::Failed);
                            continue;
                        }
                    };

                    let deadline =
                        tokio::time::Instant::now() + Duration::from_secs(self.config.startup_time);
                    let outcome = loop {
                        tokio::select! {
                            reason = stop_rx.recv() => {
                                self.kill_processes(&mut children).await;
                                match reason {
                                    Some(StopReason::Shutdown) | None => {
                                        self.log("Shutdown during startup");
                                        return;
                                    }
                                    // Not a failure and not the end of this server: the files it
                                    // was starting from are stale, so go back to Stopped and let
                                    // the next request start it from the new ones. Returning here
                                    // ended the lifecycle task, which left the service unable to
                                    // start ever again - and a change landing during startup is
                                    // ordinary, since a deploy writes the files that triggered
                                    // the project to load in the first place.
                                    Some(StopReason::FileChange) => break Startup::Aborted,
                                    _ => break Startup::Failed,
                                }
                            }
                            status = async { children.first_mut().unwrap().wait().await } => {
                                self.log(&format!("Process exited during startup: {:?}", status));
                                break Startup::Failed;
                            }
                            ready = self.probe_port() => {
                                if ready {
                                    break Startup::Ready;
                                } else if tokio::time::Instant::now() >= deadline {
                                    self.log(&format!(
                                        "Port did not become ready within {}s",
                                        self.config.startup_time));
                                    break Startup::Failed;
                                }
                                sleep(Duration::from_millis(50)).await;
                            }
                        }
                    };

                    match outcome {
                        Startup::Ready => {}
                        Startup::Aborted => {
                            self.log("File change during startup; starting again on the next request");
                            let _ = self.state_tx.send(AppState::Stopped);
                            continue;
                        }
                        Startup::Failed => {
                            self.log("Startup failed; terminating and giving up");
                            self.kill_processes(&mut children).await;
                            let _ = self.state_tx.send(AppState::Failed);
                            continue;
                        }
                    }

                    let port = self.port().unwrap_or(0);
                    self.log(&format!("Ready on port {}", port));
                    let _ = self.state_tx.send(AppState::Running);

                    match self.run_until_stop(children, &mut stop_rx, idle_timeout).await {
                        StopReason::Shutdown => {
                            self.log("Stopped (shutdown)");
                            return;
                        }
                        StopReason::FileChange => {
                            // Restart on the next request, with whatever the files now say.
                            self.forget_prepared_if_copying().await;
                            self.log("Stopped (file change)");
                        }
                        StopReason::Inactivity => self.log("Stopped (inactivity)"),
                        StopReason::ProcessExit => self.log("Stopped (process exit)"),
                    }
                }

                AppState::Running => {
                    // run_until_stop owns Running; recover rather than panicking, which would kill
                    // the lifecycle task and wedge the server.
                    self.log("Unexpected Running state in lifecycle; resetting to Stopped");
                    let _ = self.state_tx.send(AppState::Stopped);
                }

                AppState::Failed => {
                    // Stay Failed until the project is rebuilt: pending requests have already been
                    // answered with a 502, and a rebuild happens on the next request.
                    match stop_rx.recv().await {
                        Some(StopReason::FileChange) => {
                            self.forget_prepared_if_copying().await;
                            self.log("Retrying after file change");
                            let _ = self.state_tx.send(AppState::Stopped);
                        }
                        Some(StopReason::Shutdown) | None => {
                            return;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Forget what was prepared, so the next start derives the image afresh. Only needed when the
    /// image is built from project files - `copy`, or a Dockerfile of the project's own: anything
    /// else it is built from comes from `webcentral.conf`, and a change to that replaces the whole
    /// project anyway.
    async fn forget_prepared_if_copying(&self) {
        let from_project = |config: &ServerConfig| {
            !config.copy.is_empty() || config.dockerfile.is_some()
        };
        if from_project(&self.config) || self.config.sidecars.iter().any(from_project) {
            self.prepared.lock().await.clear();
        }
    }

    /// Single port probe with a 2s timeout. Returns true once the port answers like a web server.
    ///
    /// Addressed as `127.0.0.1` rather than `localhost`: podman publishes on IPv4 only, while
    /// `localhost` resolves to `::1` first on a dual-stack host.
    async fn probe_port(&self) -> bool {
        let Some(port) = self.port() else { return false };
        let addr = format!("127.0.0.1:{}", port);

        let probe = tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream = TcpStream::connect(&addr).await?;
            stream.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n").await?;
            let mut buf = [0u8; 32];
            let n = stream.read(&mut buf).await?;
            Ok::<_, std::io::Error>((n, buf))
        })
        .await;

        matches!(probe, Ok(Ok((n, buf))) if n >= 12 && buf.starts_with(b"HTTP/1.") && buf[9] != b'5')
    }

    async fn run_until_stop(
        self: &Arc<Self>,
        mut children: Vec<tokio::process::Child>,
        stop_rx: &mut mpsc::Receiver<StopReason>,
        idle_timeout: Option<Duration>,
    ) -> StopReason {
        loop {
            let idle_deadline = match idle_timeout {
                Some(timeout) => {
                    let last = *self.last_activity.lock().await;
                    // An active upgrade holds the server open however stale `last_activity` is,
                    // so arm the full timeout then - an already-expired deadline would make this
                    // select spin for as long as the socket stays open.
                    let since = if self.active_upgrades.load(Ordering::SeqCst) > 0 {
                        Duration::ZERO
                    } else {
                        last.elapsed()
                    };
                    Some(tokio::time::Instant::now() + timeout.saturating_sub(since))
                }
                None => None,
            };

            tokio::select! {
                reason = stop_rx.recv() => {
                    let reason = reason.unwrap_or(StopReason::Shutdown);
                    // Transition first, so new requests wait for the restart instead of racing it.
                    let _ = self.state_tx.send(AppState::Stopped);
                    self.kill_processes(&mut children).await;
                    return reason;
                }

                result = async {
                    match children.first_mut() {
                        Some(main) => main.wait().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Ok(status) = result {
                        self.log(&format!("Main process exited: {}", status));
                    }
                    let _ = self.state_tx.send(AppState::Stopped);
                    self.kill_processes(&mut children).await;
                    return StopReason::ProcessExit;
                }

                _ = async {
                    match idle_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    if let Some(timeout) = idle_timeout {
                        let last = *self.last_activity.lock().await;
                        // Upgraded connections (WebSockets) are idle by this measure but very much
                        // alive, so they hold the server open.
                        if last.elapsed() >= timeout
                            && self.active_upgrades.load(Ordering::SeqCst) == 0
                        {
                            self.log("Stopping due to inactivity");
                            let _ = self.state_tx.send(AppState::Stopped);
                            self.kill_processes(&mut children).await;
                            return StopReason::Inactivity;
                        }
                    }
                }
            }
        }
    }

    async fn kill_processes(&self, children: &mut Vec<tokio::process::Child>) {
        // Signalling the `podman run` client is not enough: it forwards the signal and then waits
        // for the container's own stop timeout, which outlasts our grace period - so we would
        // SIGKILL the client and leave the container running. Stopping the containers by name
        // first is what actually ends them, and what keeps them from being leaked.
        // Spawned so the stops run concurrently - a future made here and awaited in the loop
        // below would run them one after another, 2s of grace each.
        let stops: Vec<_> = self
            .container_names()
            .into_iter()
            .map(|name| {
                // Built here, run there: the command carries the owner's identity with it.
                let mut stop = self.owner.podman();
                stop.args(["stop", "--time", "2", &name])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                tokio::spawn(async move { let _ = stop.status().await; })
            })
            .collect();
        for stop in stops {
            let _ = stop.await;
        }

        for child in children.iter() {
            if let Some(pid) = child.id() {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;
                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
            }
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        for child in children.iter_mut() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            tokio::select! {
                _ = child.wait() => {}
                _ = sleep(remaining) => {
                    // start_kill() (sync) actually sends SIGKILL; Child::kill() is async and a
                    // no-op if its future is dropped unawaited.
                    let _ = child.start_kill();
                    // Bound the reap: an unkillable (D-state) process must not freeze the lifecycle.
                    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
                }
            }
        }
        children.clear();
    }

    // --- Spawning ---

    async fn spawn_processes(&self) -> Result<Vec<tokio::process::Child>> {
        let port = get_free_port()?;
        let addr = format!("127.0.0.1:{}", port);
        let connector = AnyConnector::FixedTcp(addr);
        let http_client = Client::builder(SHARED_EXECUTOR.clone()).build(connector.clone());
        *self.connection.lock().await = Some(AppConnection { port, http_client, connector });

        let mut children = Vec::new();

        // A service and its sidecars share a network, so they can address each other by name and
        // a sidecar needs no published port at all. Only the service itself is published, and only
        // on loopback, because webcentral is the only thing on the host that talks to it.
        let networked = !self.config.sidecars.is_empty();
        if networked {
            self.ensure_network().await?;
        }

        // The parent's preparation settles the image its sidecars may inherit. Cached, so this is
        // instant whenever the declaration-time preparation already ran.
        let prepared = self.ensure_prepared(&self.config, None).await?;

        for sidecar in &self.config.sidecars {
            let mut process =
                match self.prepare_and_build_command(sidecar, Some(&prepared.image), None).await {
                    Ok(process) => process,
                    Err(e) => {
                        self.log(&format!("Failed to build sidecar {}: {}", sidecar.name, e));
                        continue;
                    }
                };
            match process.spawn() {
                Ok(mut child) => {
                    self.log(&format!(
                        "Started sidecar {}, reachable as {}:{}",
                        sidecar.name,
                        internal_host(&sidecar.name),
                        sidecar.port
                    ));
                    self.stream_output(&mut child, &format!("{}-", sidecar.name));
                    children.push(child);
                }
                Err(e) => self.log(&format!("Failed to start sidecar {}: {}", sidecar.name, e)),
            }
        }

        let mut process = self.build_command(&self.config, &prepared, Some(port)).await?;
        self.log(&format!("Running: {}", describe(&process)));

        let mut child = process.spawn()?;
        self.stream_output(&mut child, "");
        // The main process must stay first: the lifecycle watches it to notice the server exiting.
        children.insert(0, child);

        Ok(children)
    }

    /// The network a service and its sidecars share. Created on demand and then left alone: a
    /// podman network is a config file and a bridge, and removing it on every stop would race with
    /// the next start recreating it.
    fn network_name(&self) -> String {
        format!("webcentral-{:x}", self.dir_hash("network"))
    }

    async fn ensure_network(&self) -> Result<()> {
        let name = self.network_name();
        let exists = self.owner.podman()
            .args(["network", "exists", &name])
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        if exists {
            return Ok(());
        }
        let out = self.owner.podman()
            .args(["network", "create", &name])
            .output()
            .await?;
        // A concurrent start may have won the race, which is not a failure.
        if !out.status.success() && !String::from_utf8_lossy(&out.stderr).contains("already exists") {
            anyhow::bail!("could not create network {}: {}", name, String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }

    /// `build_command` for a sidecar, which owns its preparation but may inherit `parent_image`.
    async fn prepare_and_build_command(
        &self,
        config: &ServerConfig,
        parent_image: Option<&str>,
        publish: Option<u16>,
    ) -> Result<Command> {
        let prepared = self.ensure_prepared(config, parent_image).await?;
        self.build_command(config, &prepared, publish).await
    }

    /// Build the command for a server or sidecar.
    /// `publish` is the host port to expose this container on, for the one member webcentral
    /// itself connects to. Sidecars are reached over the shared network instead.
    async fn build_command(
        &self,
        config: &ServerConfig,
        prepared: &Prepared,
        publish: Option<u16>,
    ) -> Result<Command> {
        let mut process = self.build_podman_command(config, prepared, publish).await?;
        process.current_dir(&self.dir);
        process.stdout(std::process::Stdio::piped());
        process.stderr(std::process::Stdio::piped());
        Ok(process)
    }

    fn stream_output(&self, child: &mut tokio::process::Child, prefix: &str) {
        if let Some(stdout) = child.stdout.take() {
            let logger = self.logger.clone();
            let tag = format!("{}stdout", prefix);
            tokio::spawn(async move {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    logger.write(&tag, &line);
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            let logger = self.logger.clone();
            let tag = format!("{}stderr", prefix);
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    logger.write(&tag, &line);
                }
            });
        }
    }

    // --- Podman ---

    /// Every container this server runs: itself and its sidecars. Derived rather
    /// than remembered, so a leftover from a previous run answers to the same name.
    fn container_names(&self) -> Vec<String> {
        let mut names = vec![self.config.name.clone()];
        names.extend(self.config.sidecars.iter().map(|sidecar| sidecar.name.clone()));
        names.iter().map(|name| format!("webcentral-{:x}", self.dir_hash(name))).collect()
    }

    /// A stable identifier for one server's image and container. Several servers - and their
    /// sidecars - share a project directory, so the name has to distinguish them too.
    fn dir_hash(&self, name: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.dir.hash(&mut hasher);
        self.config.name.hash(&mut hasher);
        name.hash(&mut hasher);
        hasher.finish()
    }

    /// Hand the container its environment through podman's *own* environment rather than its
    /// command line.
    ///
    /// `podman run -e NAME`, with no value, takes the value from the environment of the client
    /// process. That matters because `podman run` stays alive for as long as the container does
    /// and `/proc/<pid>/cmdline` is world-readable, so a value written as `-e NAME=value` can be
    /// read with `ps` by every user on the machine - which on a multi-user webcentral means one
    /// project's secrets are legible to another project's owner. `/proc/<pid>/environ` is 0400
    /// instead, so only the process owner and root can read it, and nothing is written to disk.
    fn add_env_args(&self, cmd: &mut Command, env: &[(String, String)]) {
        for (key, value) in env {
            if PODMAN_READS_ENV.contains(&key.as_str()) {
                // Handing these over the client's environment would change how podman itself
                // behaves - rootless podman finds its storage through HOME. They are paths and
                // locales rather than secrets, so the command line is where they go.
                cmd.args(["-e", &format!("{}={}", key, value)]);
            } else {
                cmd.env(key, value);
                cmd.args(["-e", key]);
            }
        }
    }

    /// Create a directory for the container to write in, owned by the project owner - which is
    /// where the container's writes land on every supported path, since `add_userns_args` maps
    /// whatever user the container runs as onto the owner. Directories that already exist are left
    /// alone. Chown failure only means webcentral runs as neither root nor the owner, the same
    /// unsupported case `add_userns_args` warns about - so a warning, not an error.
    fn create_dir_for_container(&self, path: &Path) -> Result<()> {
        if path.exists() {
            return Ok(());
        }
        fs::create_dir_all(path)?;
        if crate::owner::ownership(path) != (self.owner.uid, self.owner.gid) {
            if let Err(e) =
                std::os::unix::fs::chown(path, Some(self.owner.uid), Some(self.owner.gid))
            {
                self.logger.write("podman", &format!(
                    "Could not give {} to {}:{} ({}); the container may not be able to write there.",
                    path.display(), self.owner.uid, self.owner.gid, e));
            }
        }
        Ok(())
    }

    /// The uid/gid a container started from `image` actually runs as. This needs podman's help:
    /// `USER` may name a user that only exists inside the image, and an image declaring no user at
    /// all runs as root. Cached per image+user, as it costs a container round trip.
    async fn container_user_ids(&self, image: &str, user_arg: Option<&str>) -> Option<(u32, u32)> {
        use std::collections::HashMap;
        use std::sync::{Mutex, OnceLock};
        static CACHE: OnceLock<Mutex<HashMap<String, (u32, u32)>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

        let key = format!("{}\0{}", image, user_arg.unwrap_or(""));
        if let Some(ids) = cache.lock().unwrap().get(&key) {
            return Some(*ids);
        }

        // Asking `id` inside the container resolves names and an absent USER uniformly, and pulls
        // the image if it isn't local yet - which `run` would do moments later anyway.
        let mut probe = self.owner.podman();
        probe.args(["run", "--rm", "--entrypoint", "/bin/sh"]);
        if let Some(user) = user_arg {
            probe.args(["--user", user]);
        }
        probe.args([image, "-c", "id -u; id -g"]);

        let ids = match probe.output().await {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut fields = stdout.split_whitespace();
                match (
                    fields.next().and_then(|v| v.parse().ok()),
                    fields.next().and_then(|v| v.parse().ok()),
                ) {
                    (Some(uid), Some(gid)) => Some((uid, gid)),
                    _ => None,
                }
            }
            _ => None,
        };

        // Images without a shell (distroless and friends) can't be probed, so fall back to the
        // declared USER. Only a numeric uid:gid pair is usable - anything else would need the
        // image's passwd to resolve.
        let ids = match (ids, user_arg) {
            (None, None) => {
                let out = self.owner.podman()
                    .args(["image", "inspect", "--format", "{{.Config.User}}", image])
                    .output()
                    .await;
                match out {
                    Ok(out) if out.status.success() => {
                        let declared = String::from_utf8_lossy(&out.stdout).trim().to_string();
                        if declared.is_empty() || declared == "root" {
                            Some((0, 0))
                        } else {
                            parse_numeric_user(&declared)
                        }
                    }
                    _ => None,
                }
            }
            (ids, _) => ids,
        };

        if let Some(ids) = ids {
            cache.lock().unwrap().insert(key, ids);
        }
        ids
    }

    /// Build (or reuse) an image derived from the configured base, optionally with `uid:gid` added
    /// as a real user that the image then runs as.
    async fn build_image(&self, config: &ServerConfig, base: &str) -> Result<String> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut dockerfile = format!("FROM {}\n", base);

        if !config.packages.is_empty() {
            let packages = config.packages.join(" ");
            dockerfile.push_str(&format!(
                "RUN if command -v apk > /dev/null ; then apk add --update --no-cache {} ; \
                elif command -v apt-get > /dev/null ; then apt-get update && apt-get install --no-install-recommends --yes {} ; \
                elif command -v dnf > /dev/null ; then dnf install -y {} ; \
                elif command -v yum > /dev/null ; then yum install -y {} ; \
                else echo 'No supported package manager found' && exit 1 ; fi\n",
                packages, packages, packages, packages
            ));
        }

        // Copied before the build commands and into a directory of their own: `/app` is where
        // the project gets mounted at *run* time, so anything put there would be shadowed the
        // moment the container starts.
        if !config.copy.is_empty() {
            for path in &config.copy {
                dockerfile.push_str(&format!("COPY {} /webcentral-build/{}\n", path, path));
            }
            dockerfile.push_str("WORKDIR /webcentral-build\n");
        }

        for command in &config.build {
            dockerfile.push_str(&format!("RUN {}\n", command));
        }

        // Leave the working directory as the image had it; `-w` sets the runtime one when the
        // project directory is mounted, but an unmounted service should still start where its
        // image expects to.
        if !config.copy.is_empty() {
            dockerfile.push_str(&format!(
                "WORKDIR {}\n",
                config.app_dir.as_deref().unwrap_or("/")
            ));
        }

        // Tag by what goes into the image rather than by project directory alone, so an unchanged
        // configuration can skip the build entirely. Even a fully cached build costs about a
        // second, and servers are started on demand while a request is waiting. The base image's
        // local ID is part of the hash, so a pulled base update triggers one (cached) rebuild. A
        // base that isn't local yet hashes as empty and self-corrects once the first build pulls it.
        let base_id = self.owner.podman()
            .args(["image", "inspect", "--format", "{{.Id}}", base])
            .output()
            .await
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .unwrap_or_default();
        // A copied file is part of what the image *is*, so its contents belong in the tag -
        // otherwise an edited requirements.txt would go on reusing the image built from the old
        // one. Reading them here also re-checks containment now that symlinks can be resolved:
        // the parser rejects `..` and absolute paths, but not a link pointing out of the project.
        let mut copied = Vec::new();
        if !config.copy.is_empty() {
            let base = self.dir.canonicalize()?;
            for path in &config.copy {
                let real = base.join(path).canonicalize().map_err(|e| {
                    anyhow::anyhow!("copy {}: {}", path, e)
                })?;
                if !real.starts_with(&base) {
                    anyhow::bail!(
                        "copy {} leads outside the project directory (via a symlink)",
                        path
                    );
                }
                copied.push(fs::read(&real)?);
            }
        }

        let mut hasher = DefaultHasher::new();
        dockerfile.hash(&mut hasher);
        base_id.hash(&mut hasher);
        copied.hash(&mut hasher);
        let repo = format!("webcentral-{:x}", self.dir_hash(&config.name));
        let image_name = format!("{}:{:x}", repo, hasher.finish());

        let exists = self.owner.podman()
            .args(["image", "inspect", &image_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        if exists {
            return Ok(image_name);
        }

        let dockerfile_path = self
            .dir
            .join("_webcentral_data")
            .join(format!("Dockerfile.{}", config.name));
        fs::create_dir_all(dockerfile_path.parent().unwrap())?;
        fs::write(&dockerfile_path, &dockerfile)?;

        let output = self.owner.podman()
            .args(["build", "-t", &image_name, "-f"])
            .arg(&dockerfile_path)
            .arg(&self.dir)
            .output()
            .await?;

        if !output.status.success() {
            self.log_build_output(&output);
            anyhow::bail!("Image build failed");
        }

        // Remove this server's images for older configs. They are named tags, which
        // `podman image prune` never touches, so they would otherwise pile up forever.
        if let Ok(out) = self.owner.podman()
            .args(["images", &repo, "--format", "{{.Tag}}"])
            .output()
            .await
        {
            for tag in String::from_utf8_lossy(&out.stdout).split_whitespace() {
                let stale = format!("{}:{}", repo, tag);
                if stale != image_name {
                    let _ = self.owner.podman()
                        .args(["rmi", &stale])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .await;
                }
            }
        }

        Ok(image_name)
    }

    /// Build the project's own Dockerfile, with the project directory as the build context.
    ///
    /// Nothing of ours goes into it: the file says what the image is. Podman confines the context
    /// to that directory - `COPY ../x` is refused, and a symlink out of it resolves *inside* it
    /// and so finds nothing - which is what makes it safe to build somebody else's Dockerfile on a
    /// shared host. The build runs as the project's owner like everything else, so what its `RUN`
    /// steps can reach is what that person can reach.
    ///
    /// The tag is fixed and the build is run every time the image is prepared: podman's layer
    /// cache makes that cheap when nothing changed, and it is the only way to notice that
    /// something did without hashing the whole project.
    async fn build_from_dockerfile(&self, config: &ServerConfig, dockerfile: &str) -> Result<String> {
        let base = self.dir.canonicalize()?;
        let path = base.join(dockerfile).canonicalize().map_err(|e| {
            anyhow::anyhow!("dockerfile {}: {}", dockerfile, e)
        })?;
        if !path.starts_with(&base) {
            anyhow::bail!("dockerfile {} leads outside the project directory", dockerfile);
        }

        let image = format!("webcentral-{:x}:dockerfile", self.dir_hash(&config.name));
        self.log(&format!("Building {} from {}", image, dockerfile));
        let output = self
            .owner
            .podman()
            .args(["build", "-t", &image, "-f"])
            .arg(&path)
            .arg(&base)
            .output()
            .await?;
        if !output.status.success() {
            self.log_build_output(&output);
            anyhow::bail!("building {} failed", dockerfile);
        }
        Ok(image)
    }

    /// Everything a failed build said. The reason usually comes from the command that failed -
    /// a package manager that could not reach its mirror, a compiler error - which podman writes
    /// to stdout, while stderr carries only its own summary of which step failed. Logging just
    /// the summary leaves the log saying that a step failed and never why.
    fn log_build_output(&self, output: &std::process::Output) {
        for stream in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(stream);
            if !text.trim().is_empty() {
                self.logger.write("podman", text.trim_end());
            }
        }
    }

    /// Home directory for the baked-in user. It lives in the project directory when that is
    /// mounted, so it persists; otherwise there is nowhere to put it that outlives the container.
    fn container_home(&self, config: &ServerConfig) -> String {
        match &config.app_dir {
            Some(app_dir) => format!("{}/_webcentral_data/home", app_dir),
            None => "/tmp".to_string(),
        }
    }

    /// Which user the container runs as *inside*.
    ///
    /// Podman is already the project's owner, and rootless podman maps container root onto the
    /// invoking user - so a container that runs as root writes as the owner with no help from us.
    /// That is why `project` resolves to root rather than to the owner's own id. Anything else the
    /// image or the configuration asks for is a different id inside, which only lands on the owner
    /// if podman is told to map it: `keep-id` does that, and is skipped for root, where it would
    /// be a no-op that some podman/kernel combinations refuse anyway (containers/podman#27785).
    fn add_userns_args(&self, cmd: &mut Command, run_uid: u32, run_gid: u32) {
        if run_uid == 0 && run_gid == 0 {
            return;
        }
        if !self.owner.runs_rootless() {
            // A root-owned project on a root webcentral: podman is root's own, where there is no
            // `keep-id` to map with and a container's uid is already a host uid. Everything this
            // container writes as that id therefore belongs to it rather than to the owner.
            self.log(&format!(
                "This project belongs to root, so podman runs as root, where a container asking \
                 to be {}:{} simply is that user on the host - what it writes will not belong to \
                 root. Give the project to an ordinary user to keep that guarantee.",
                run_uid, run_gid
            ));
            return;
        }
        let (euid, egid) = (nix::unistd::geteuid().as_raw(), nix::unistd::getegid().as_raw());
        if (run_uid, run_gid) == (euid, egid) {
            // The plain form works on any podman version, unlike the uid=/gid= form below.
            cmd.args(["--userns", "keep-id"]);
        } else {
            // Map the owner to whatever the container runs as (needs podman >= 4.3).
            cmd.args(["--userns", &format!("keep-id:uid={},gid={}", run_uid, run_gid)]);
        }
    }

    /// Get a service's image and the user it will run as, doing the work once. Concurrent callers
    /// wait for whoever got there first; a failure is not remembered, so the next attempt retries.
    async fn ensure_prepared(&self, config: &ServerConfig, parent_image: Option<&str>) -> Result<Prepared> {
        let mut cache = self.prepared.lock().await;
        if let Some(prepared) = cache.get(&config.name) {
            return Ok(prepared.clone());
        }

        let image = self.prepare_image(config, parent_image).await?;

        // `user` only decides who the container runs as *inside*; the owner's writes land as
        // theirs either way. `project` is container root, which is how rootless podman represents
        // the user it runs as. `known` skips asking podman when the configuration already tells
        // us, and must always agree with what podman would report.
        let (user_arg, known): (Option<String>, Option<(u32, u32)>) = match config.user.as_str() {
            "project" => (Some("0:0".to_string()), Some((0, 0))),
            "image" => (None, None),
            spec => (Some(spec.to_string()), parse_numeric_user(spec)),
        };
        let (run_uid, run_gid) = match known {
            Some(ids) => ids,
            None => match self.container_user_ids(&image, user_arg.as_deref()).await {
                Some(ids) => ids,
                None => {
                    self.logger.write("podman", &format!(
                        "Could not determine which user image {} runs as; assuming root. If that's \
                         wrong, files the container writes may not end up owned by the project \
                         owner, and it may not be able to write in its mounts.",
                        image));
                    (0, 0)
                }
            },
        };

        let volumes = self.volumes_to_persist(config, &image).await;
        let prepared = Prepared { image, user_arg, run_uid, run_gid, volumes };
        cache.insert(config.name.clone(), prepared.clone());
        Ok(prepared)
    }

    /// Where a `mounts` entry lands inside the container. Relative entries hang off `app_dir`, so
    /// there is nowhere to put one when nothing is mounted - which the parser refuses anyway.
    fn container_mount_path(config: &ServerConfig, mount: &str) -> Option<String> {
        match (&config.app_dir, mount.starts_with('/')) {
            (_, true) => Some(mount.to_string()),
            (Some(app_dir), false) => Some(format!("{}/{}", app_dir, mount)),
            (None, false) => None,
        }
    }

    /// Whether `path` is `covered_by` or sits inside it.
    fn is_within(path: &str, covered_by: &str) -> bool {
        path == covered_by || path.starts_with(&format!("{}/", covered_by.trim_end_matches('/')))
    }

    /// What the image asks to have persisted, minus whatever the configuration already persists.
    ///
    /// An image that declares `VOLUME /data` persists nothing by itself: podman gives the
    /// container an anonymous volume and `--rm` takes it away with the container, so a stock
    /// database image would lose everything it wrote on the first restart - and only on the first
    /// restart, which is the worst moment to find out. Webcentral gives each one a directory
    /// beside the mounts the configuration asked for instead. Saying so in the file with `mounts`
    /// still wins; this is only about the case where nobody said anything.
    async fn volumes_to_persist(&self, config: &ServerConfig, image: &str) -> Vec<String> {
        let mut covered: Vec<String> = config
            .mounts
            .iter()
            .filter_map(|mount| Self::container_mount_path(config, mount))
            .collect();
        // The project directory is already a host directory, so anything under it persists.
        if let Some(app_dir) = &config.app_dir {
            covered.push(app_dir.clone());
        }

        let mut persist = Vec::new();
        for volume in self.image_volumes(image).await {
            if covered.iter().any(|c| Self::is_within(&volume, c)) {
                continue;
            }
            self.log(&format!(
                "Image {} declares VOLUME {}, which podman would discard when the container \
                 stops; keeping it in _webcentral_data/mounts instead. Say 'mounts = {}' to place \
                 it yourself.",
                image, volume, volume
            ));
            self.seed_from_image(image, &volume).await;
            persist.push(volume);
        }
        persist
    }

    /// Where a path inside the container is kept on the host.
    fn host_mount_path(&self, container_path: &str) -> PathBuf {
        self.dir.join("_webcentral_data/mounts").join(container_path.trim_start_matches('/'))
    }

    /// Give a directory webcentral is about to bind-mount whatever the image ships at that path.
    ///
    /// Podman does this when it creates a volume of its own, but never for a bind mount: the host
    /// directory simply covers what was there. An image that seeds a declared volume with
    /// configuration, a schema or a first-run database would come up looking as though it had lost
    /// all of it - so the contents are copied out once, while the directory is still empty.
    /// Anything that goes wrong here leaves an empty directory, which is what podman's own
    /// behaviour would have given us anyway.
    async fn seed_from_image(&self, image: &str, container_path: &str) {
        let host_path = self.host_mount_path(container_path);
        if self.create_dir_for_container(&host_path).is_err() {
            return;
        }
        let empty = fs::read_dir(&host_path).map(|mut d| d.next().is_none()).unwrap_or(false);
        if !empty {
            return;
        }

        // Mounted somewhere else, so that the image's own contents at `container_path` are still
        // visible to copy from.
        const SCRATCH: &str = "/webcentral-seed";
        let mut copy = self.owner.podman();
        copy.args(["run", "--rm", "--entrypoint", "/bin/sh"]);
        copy.args(["-v", &format!("{}:{}", host_path.display(), SCRATCH)]);
        copy.args([
            image,
            "-c",
            &format!("cp -a {}/. {}/ 2>/dev/null || true", container_path, SCRATCH),
        ]);
        match copy.output().await {
            Ok(out) if out.status.success() => {
                if fs::read_dir(&host_path).map(|mut d| d.next().is_some()).unwrap_or(false) {
                    self.log(&format!("Copied what {} ships in {} into it", image, container_path));
                }
            }
            // An image with no shell cannot be copied out of this way. It is also an image that
            // could not have had anything but an empty directory there to begin with, unless it
            // was built FROM one that had a shell - so this is worth a line, not a failure.
            _ => self.log(&format!(
                "Could not read what {} ships in {}; starting it empty",
                image, container_path
            )),
        }
    }

    /// The `VOLUME` paths an image declares, sorted so the same image always reports them in the
    /// same order. An image that declares none, or that cannot be inspected, has none.
    async fn image_volumes(&self, image: &str) -> Vec<String> {
        let mut inspect = self.owner.podman();
        inspect.args(["image", "inspect", "--format", "{{json .Config.Volumes}}", image]);
        let output = match inspect.output().await {
            Ok(out) if out.status.success() => out.stdout,
            _ => return Vec::new(),
        };
        let parsed: Option<std::collections::BTreeMap<String, serde_json::Value>> =
            serde_json::from_slice(&output).unwrap_or_default();
        parsed.map(|map| map.into_keys().collect()).unwrap_or_default()
    }

    /// The image for one service, whether it needs a build of its own or just its base pulled.
    /// The base defaults to the parent's prepared image for a sidecar - so a nested service runs
    /// another command in the same environment, or layers `packages` on top of it - and to
    /// `alpine` for a top-level service.
    async fn prepare_image(&self, config: &ServerConfig, parent_image: Option<&str>) -> Result<String> {
        // Every project prepares its images as soon as it is read, and every project is read at
        // startup - so without a cap, starting webcentral on a host with sixty projects would ask
        // podman to pull or build sixty images at once, and a registry or a disk would be the
        // thing that decided how that went. The work still happens, just a few at a time.
        let _permit = image_work().acquire().await;

        let base = match (&config.base, parent_image) {
            (Some(base), _) => base.clone(),
            (None, Some(parent)) => parent.to_string(),
            (None, None) => DEFAULT_BASE_IMAGE.to_string(),
        };
        if let Some(dockerfile) = &config.dockerfile {
            return self.build_from_dockerfile(config, dockerfile).await;
        }
        if config.packages.is_empty() && config.build.is_empty() {
            // Nothing to add, so the base image is the image - but it still has to be here.
            let present = self.owner.podman()
                .args(["image", "exists", &base])
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);
            if !present {
                self.log(&format!("Pulling {}", base));
                let out = self.owner.podman()
                    .args(["pull", &base])
                    .output()
                    .await?;
                if !out.status.success() {
                    anyhow::bail!(
                        "could not pull {}: {}",
                        base,
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
            }
            return Ok(base);
        }
        self.build_image(config, &base).await
    }

    async fn build_podman_command(
        &self,
        config: &ServerConfig,
        prepared: &Prepared,
        publish: Option<u16>,
    ) -> Result<Command> {
        let container_name = format!("webcentral-{:x}", self.dir_hash(&config.name));
        let Prepared { image, user_arg, run_uid, run_gid, .. } = prepared.clone();

        // A container that outlived its webcentral (killed rather than shut down) keeps holding
        // the name, and `run` then fails with a name conflict on every subsequent attempt -
        // wedging the service for good. The name is derived from the project directory and service
        // name, so anything still answering to it is a leftover of ours. `--time 2`: without it a
        // still-running leftover gets podman's default 10s SIGTERM grace, all of it spent in this
        // start's critical path while a request waits.
        let _ = self.owner.podman()
            .args(["rm", "--force", "--time", "2", &container_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;

        let mut cmd = self.owner.podman();
        cmd.args(["run", "--rm", "--name", &container_name]);

        self.add_userns_args(&mut cmd, run_uid, run_gid);

        // Published on loopback only: webcentral is the sole thing on the host that talks to it,
        // and podman publishes IPv4 only, so `localhost` would resolve to `::1` and fail.
        if let Some(host_port) = publish {
            cmd.args(["-p", &format!("127.0.0.1:{}:{}", host_port, config.port)]);
        }
        if !self.config.sidecars.is_empty() {
            cmd.args(["--network", &self.network_name()]);
            cmd.args(["--network-alias", &internal_host(&config.name)]);
        }

        if let Some(user) = &user_arg {
            cmd.args(["--user", user]);
        }

        if let Some(app_dir) = &config.app_dir {
            cmd.args(["-v", &format!("{}:{}", self.dir.display(), app_dir)]);
            cmd.args(["-w", app_dir]);
        }

        // A persistent home for `project` containers, whether the owner is baked in (rootful,
        // where the passwd entry also points here) or is container root (rootless). Set the
        // environment variable explicitly rather than trusting podman to resolve it from passwd.
        let mut env: Vec<(String, String)> = Vec::new();
        if config.user == "project" {
            if config.app_dir.is_some() {
                self.create_dir_for_container(&self.dir.join("_webcentral_data/home"))?;
            }
            env.push(("HOME".to_string(), self.container_home(config)));
        }

        // Additional mounts. These live on the host but are written by the container; owner
        // ownership is exactly where the container's writes land through the userns mapping.
        let configured = config.mounts.iter().filter_map(|mount| {
            // A relative entry with nothing to hang off is refused at parse time; skipping keeps a
            // stray one from mounting at garbage.
            Self::container_mount_path(config, mount)
        });
        for container_path in configured.chain(prepared.volumes.iter().cloned()) {
            let host_path = self.host_mount_path(&container_path);
            self.create_dir_for_container(&host_path)?;
            cmd.args(["-v", &format!("{}:{}", host_path.display(), container_path)]);
        }

        // Each container is told its own port and nothing about the others: a group member is
        // reached at the `<name>.internal` name podman's DNS answers on their shared network, and
        // a port written where it is needed rather than announced everywhere.
        env.push(("PORT".to_string(), config.port.to_string()));
        env.extend(config.env.iter().cloned());
        self.add_env_args(&mut cmd, &env);

        cmd.arg(&image);

        if !config.command.is_empty() {
            cmd.args(["/bin/sh", "-c", &config.command]);
        }

        Ok(cmd)
    }
}

/// Variables podman itself reads from its environment, which therefore cannot be used to carry a
/// value to the container - setting them would reconfigure podman instead.
const PODMAN_READS_ENV: &[&str] = &[
    "HOME",
    "PATH",
    "TMPDIR",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "CONTAINERS_CONF",
    "CONTAINERS_STORAGE_CONF",
    "CONTAINERS_REGISTRIES_CONF",
    "STORAGE_DRIVER",
    "STORAGE_OPTS",
];

/// The command as a single line, with any environment *value* still on it hidden - the ones that
/// get there are paths rather than secrets, but this line goes to a log file.
fn describe(command: &Command) -> String {
    let command = command.as_std();
    let mut parts = vec![command.get_program().to_string_lossy().into_owned()];
    let mut is_env_value = false;
    for arg in command.get_args() {
        let arg = arg.to_string_lossy();
        if is_env_value {
            parts.push(match arg.split_once('=') {
                Some((key, _)) => format!("{}=***", key),
                None => arg.to_string(),
            });
        } else {
            parts.push(arg.to_string());
        }
        is_env_value = arg == "-e";
    }
    parts.join(" ")
}

/// The name a group member answers to on their shared network.
fn internal_host(name: &str) -> String {
    format!("{}.internal", name)
}

fn get_free_port() -> Result<u16> {
    use std::os::unix::io::AsRawFd;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    // Allow immediate port reuse - without this, ~5% failure rate in tests
    unsafe {
        libc::setsockopt(
            listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &1i32 as *const _ as _,
            std::mem::size_of::<i32>() as _,
        );
    }
    Ok(listener.local_addr()?.port())
}

/// Parse a numeric `uid:gid` pair. Anything else - including a bare uid, whose gid would depend on
/// the image's /etc/passwd - returns None.
fn parse_numeric_user(spec: &str) -> Option<(u32, u32)> {
    let (uid, gid) = spec.split_once(':')?;
    Some((uid.parse().ok()?, gid.parse().ok()?))
}

