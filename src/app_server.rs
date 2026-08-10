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

/// What a service needs settled before it can be started, and only needs settling once.
#[derive(Debug, Clone)]
struct Prepared {
    image: String,
    /// What to pass to `--user`, if anything.
    user_arg: Option<String>,
    /// The ids the container really runs as, which the host-side ownership mapping derives from.
    run_uid: u32,
    run_gid: u32,
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
    uid: u32,
    gid: u32,
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
        uid: u32,
        gid: u32,
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
            uid,
            gid,
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
                    let ready = loop {
                        tokio::select! {
                            reason = stop_rx.recv() => {
                                self.kill_processes(&mut children).await;
                                match reason {
                                    Some(StopReason::Shutdown) => {
                                        self.log("Shutdown during startup");
                                        return;
                                    }
                                    Some(StopReason::FileChange) => {
                                        self.log("File change during startup");
                                        return;
                                    }
                                    _ => break false,
                                }
                            }
                            status = async { children.first_mut().unwrap().wait().await } => {
                                self.log(&format!("Process exited during startup: {:?}", status));
                                break false;
                            }
                            ready = self.probe_port() => {
                                if ready {
                                    break true;
                                } else if tokio::time::Instant::now() >= deadline {
                                    self.log(&format!(
                                        "Port did not become ready within {}s",
                                        self.config.startup_time));
                                    break false;
                                }
                                sleep(Duration::from_millis(50)).await;
                            }
                        }
                    };

                    if !ready {
                        self.log("Startup failed; terminating and giving up");
                        self.kill_processes(&mut children).await;
                        let _ = self.state_tx.send(AppState::Failed);
                        continue;
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

    /// Forget what was prepared, so the next start derives the image afresh. Only needed when a
    /// service copies project files into its image: everything else the image is built from comes
    /// from `webcentral.conf`, and a change to that replaces the whole project anyway.
    async fn forget_prepared_if_copying(&self) {
        let copies = !self.config.copy.is_empty()
            || self.config.sidecars.iter().any(|sidecar| !sidecar.copy.is_empty());
        if copies {
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
                tokio::spawn(async move {
                    let _ = Command::new(get_podman_path())
                        .args(["stop", "--time", "2", &name])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .await;
                })
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
        let exists = Command::new(get_podman_path())
            .args(["network", "exists", &name])
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        if exists {
            return Ok(());
        }
        let out = Command::new(get_podman_path())
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
        if get_ownership(path) != (self.uid, self.gid) {
            if let Err(e) = std::os::unix::fs::chown(path, Some(self.uid), Some(self.gid)) {
                self.logger.write("podman", &format!(
                    "Could not give {} to {}:{} ({}); the container may not be able to write there.",
                    path.display(), self.uid, self.gid, e));
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
        let mut probe = Command::new(get_podman_path());
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
                let out = Command::new(get_podman_path())
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
    async fn build_image(
        &self,
        config: &ServerConfig,
        build_user: Option<(u32, u32)>,
        base: &str,
    ) -> Result<String> {
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
            dockerfile.push_str(&format!("WORKDIR {}\n", config.app_dir));
        }

        // Added last, so the build itself still runs as root. Appending to passwd/group only when
        // the ids are absent keeps this additive: unlike bind-mounting the host's passwd over the
        // image's at runtime, it can't break users the image defines for itself. A real entry
        // matters because a uid without one has no name and no home, which trips up git, npm and
        // anything else calling getpwuid().
        if let Some((uid, gid)) = build_user {
            dockerfile.push_str(&format!(
                "RUN grep -q \"^[^:]*:[^:]*:{gid}:\" /etc/group || echo \"webcentral:x:{gid}:\" >> /etc/group ; \
                grep -q \"^[^:]*:[^:]*:{uid}:\" /etc/passwd || echo \"webcentral:x:{uid}:{gid}::{home}:/bin/sh\" >> /etc/passwd\n\
                USER {uid}:{gid}\n",
                uid = uid, gid = gid, home = self.container_home(config)
            ));
        }

        // Tag by what goes into the image rather than by project directory alone, so an unchanged
        // configuration can skip the build entirely. Even a fully cached build costs about a
        // second, and servers are started on demand while a request is waiting. The base image's
        // local ID is part of the hash, so a pulled base update triggers one (cached) rebuild. A
        // base that isn't local yet hashes as empty and self-corrects once the first build pulls it.
        let base_id = Command::new(get_podman_path())
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

        let exists = Command::new(get_podman_path())
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

        let output = Command::new(get_podman_path())
            .args(["build", "-t", &image_name, "-f"])
            .arg(&dockerfile_path)
            .arg(&self.dir)
            .output()
            .await?;

        if !output.status.success() {
            self.logger.write("podman", &String::from_utf8_lossy(&output.stderr));
            anyhow::bail!("Image build failed");
        }

        // Remove this server's images for older configs. They are named tags, which
        // `podman image prune` never touches, so they would otherwise pile up forever.
        if let Ok(out) = Command::new(get_podman_path())
            .args(["images", &repo, "--format", "{{.Tag}}"])
            .output()
            .await
        {
            for tag in String::from_utf8_lossy(&out.stdout).split_whitespace() {
                let stale = format!("{}:{}", repo, tag);
                if stale != image_name {
                    let _ = Command::new(get_podman_path())
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

    /// Home directory for the baked-in user. It lives in the project directory when that is
    /// mounted, so it persists; otherwise there is nowhere to put it that outlives the container.
    fn container_home(&self, config: &ServerConfig) -> String {
        if config.mount_app_dir {
            format!("{}/_webcentral_data/home", config.app_dir)
        } else {
            "/tmp".to_string()
        }
    }

    /// The one place uid policy lives: whatever user the container runs as inside, everything it
    /// writes into the project directory or `mounts` must land on the host owned by the project
    /// owner. Rootful podman maps host ids straight through, so when the container user differs
    /// from the owner, an identity mapping with the two swapped puts the container's writes on the
    /// owner - and shows it the owner's files as its own. A non-root webcentral means rootless
    /// podman, where the only host user a container can write as is webcentral's own: that's the
    /// owner precisely when the project is ours, and unsupported otherwise. Container root already
    /// is us under rootless podman (`user = project` resolves to it for that reason), so only an
    /// explicitly requested other uid needs keep-id - which fails at start, loudly rather than by
    /// leaking ownership, on setups where custom rootless mappings are broken (podman#27785).
    fn add_userns_args(&self, cmd: &mut Command, run_uid: u32, run_gid: u32) {
        let euid = nix::unistd::geteuid().as_raw();
        if euid == 0 {
            if (run_uid, run_gid) != (self.uid, self.gid) {
                cmd.args(swap_map_args("--uidmap", run_uid, self.uid));
                cmd.args(swap_map_args("--gidmap", run_gid, self.gid));
            }
        } else if self.uid != euid {
            self.logger.write("podman", &format!(
                "This project is owned by uid {} but webcentral runs as uid {}; a non-root \
                 webcentral can only keep container-written files owned by its own user. Files \
                 this container writes may end up owned by a meaningless subuid.",
                self.uid, euid));
        } else if run_uid == 0 {
            // Rootless podman maps container root to us all by itself.
        } else if (run_uid, run_gid) == (euid, nix::unistd::getegid().as_raw()) {
            // The plain form works on any podman version, unlike the uid=/gid= form below.
            cmd.args(["--userns", "keep-id"]);
        } else {
            // Map us to whatever the container runs as (needs podman >= 4.3).
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

        // `user` only decides who the container runs as *inside* - host-side, add_userns_args
        // makes its writes land owned by the project owner regardless. Under a root webcentral,
        // `project` bakes the owner into the image as a real user and lets the image declare it.
        // Under a non-root webcentral (rootless podman) the owner is container root - that is how
        // rootless podman represents the invoking user - so there is nothing to bake and nothing
        // to map. `known` skips asking podman when the config already tells us, and must always
        // agree with what podman would report.
        let rootful = nix::unistd::geteuid().is_root();
        let (user_arg, known): (Option<String>, Option<(u32, u32)>) = match config.user.as_str() {
            "project" if rootful => (None, Some((self.uid, self.gid))),
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

        let prepared = Prepared { image, user_arg, run_uid, run_gid };
        cache.insert(config.name.clone(), prepared.clone());
        Ok(prepared)
    }

    /// The image for one service, whether it needs a build of its own or just its base pulled.
    /// The base defaults to the parent's prepared image for a sidecar - so a nested service runs
    /// another command in the same environment, or layers `packages` on top of it - and to
    /// `alpine` for a top-level service.
    async fn prepare_image(&self, config: &ServerConfig, parent_image: Option<&str>) -> Result<String> {
        let base = match (&config.base, parent_image) {
            (Some(base), _) => base.clone(),
            (None, Some(parent)) => parent.to_string(),
            (None, None) => DEFAULT_BASE_IMAGE.to_string(),
        };
        let build_user = self.build_user(config);
        if build_user.is_none() && config.packages.is_empty() && config.build.is_empty() {
            // Nothing to add, so the base image is the image - but it still has to be here.
            let present = Command::new(get_podman_path())
                .args(["image", "exists", &base])
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);
            if !present {
                self.log(&format!("Pulling {}", base));
                let out = Command::new(get_podman_path())
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
        self.build_image(config, build_user, &base).await
    }

    /// Whether the project owner has to be baked into the image as a real user.
    fn build_user(&self, config: &ServerConfig) -> Option<(u32, u32)> {
        match config.user.as_str() {
            "project" if nix::unistd::geteuid().is_root() => Some((self.uid, self.gid)),
            _ => None,
        }
    }

    async fn build_podman_command(
        &self,
        config: &ServerConfig,
        prepared: &Prepared,
        publish: Option<u16>,
    ) -> Result<Command> {
        let container_name = format!("webcentral-{:x}", self.dir_hash(&config.name));
        let Prepared { image, user_arg, run_uid, run_gid } = prepared.clone();

        // A container that outlived its webcentral (killed rather than shut down) keeps holding
        // the name, and `run` then fails with a name conflict on every subsequent attempt -
        // wedging the service for good. The name is derived from the project directory and service
        // name, so anything still answering to it is a leftover of ours. `--time 2`: without it a
        // still-running leftover gets podman's default 10s SIGTERM grace, all of it spent in this
        // start's critical path while a request waits.
        let _ = Command::new(get_podman_path())
            .args(["rm", "--force", "--time", "2", &container_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;

        let mut cmd = Command::new(get_podman_path());
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

        if config.mount_app_dir {
            cmd.args(["-v", &format!("{}:{}", self.dir.display(), config.app_dir)]);
            cmd.args(["-w", &config.app_dir]);
        }

        // A persistent home for `project` containers, whether the owner is baked in (rootful,
        // where the passwd entry also points here) or is container root (rootless). Set the
        // environment variable explicitly rather than trusting podman to resolve it from passwd.
        let mut env: Vec<(String, String)> = Vec::new();
        if config.user == "project" {
            if config.mount_app_dir {
                self.create_dir_for_container(&self.dir.join("_webcentral_data/home"))?;
            }
            env.push(("HOME".to_string(), self.container_home(config)));
        }

        // Additional mounts. These live on the host but are written by the container; owner
        // ownership is exactly where the container's writes land through the userns mapping.
        for mount in &config.mounts {
            let container_path = if mount.starts_with('/') {
                mount.clone()
            } else {
                format!("{}/{}", config.app_dir, mount)
            };
            let host_path = self
                .dir
                .join("_webcentral_data/mounts")
                .join(container_path.trim_start_matches('/'));
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

pub fn get_ownership(path: &Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).ok().map(|m| (m.uid(), m.gid())).unwrap_or((0, 0))
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

/// Returns the podman installation to use, checking PATH on first call.
fn get_podman_path() -> &'static str {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::OnceLock;
    static PODMAN_PATH: OnceLock<String> = OnceLock::new();

    PODMAN_PATH.get_or_init(|| {
        let path_var = std::env::var("PATH").unwrap_or_default();
        for dir in path_var.split(':') {
            let full_path = PathBuf::from(dir).join("podman");
            if let Ok(meta) = fs::metadata(&full_path) {
                if meta.is_file() && (meta.permissions().mode() & 0o111) != 0 {
                    return full_path.to_string_lossy().to_string();
                }
            }
        }
        println!("Warning: podman not found in PATH");
        "podman".to_string()
    })
}

/// Parse a numeric `uid:gid` pair. Anything else - including a bare uid, whose gid would depend on
/// the image's /etc/passwd - returns None.
fn parse_numeric_user(spec: &str) -> Option<(u32, u32)> {
    let (uid, gid) = spec.split_once(':')?;
    Some((uid.parse().ok()?, gid.parse().ok()?))
}

/// Podman `--uidmap`/`--gidmap` arguments for an identity mapping over 0..max(65536, ids+1) with
/// `container_id` and `host_id` swapped (a mapping must be a bijection, so the displaced id has to
/// land somewhere). Under rootful podman host ids map directly, so this makes everything the
/// container writes as `container_id` land on the host as `host_id` and vice versa, while every
/// other id stays put, keeping the rest of the image's ownership intact. Equal ids degenerate to a
/// plain identity map.
fn swap_map_args(flag: &str, container_id: u32, host_id: u32) -> Vec<String> {
    let (lo, hi) = (container_id.min(host_id), container_id.max(host_id));
    let top = 65536.max(hi.saturating_add(1));
    let mut args = Vec::new();
    let mut push = |from: u32, to: u32, amount: u32| {
        if amount > 0 {
            args.push(flag.to_string());
            args.push(format!("{}:{}:{}", from, to, amount));
        }
    };
    push(0, 0, lo);
    push(lo, hi, 1);
    push(lo + 1, lo + 1, hi.saturating_sub(lo + 1));
    if hi != lo {
        push(hi, lo, 1);
    }
    push(hi.saturating_add(1), hi.saturating_add(1), top.saturating_sub(hi.saturating_add(1)));
    args
}
