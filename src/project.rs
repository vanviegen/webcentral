//! A project: one domain directory, its declared servers, and the routing script run for every
//! request.
//!
//! The project itself has no lifecycle state any more - that lives per server in `AppServer`.
//! What the project owns is the configuration, the shared logger, and the single file watcher its
//! servers share: a change to the config replaces the project wholesale, any other watched change
//! stops the servers so they restart from the new files on the next request.

use crate::app_server::{get_ownership, AppServer, AppState, StopReason};
use crate::config::ProjectConfig;
use crate::dashboard::ServerStatus;
use crate::logger::Logger;
use crate::script::{self, Terminal};
use crate::server::SHARED_EXECUTOR;
use crate::streams::AnyConnector;
use anyhow::Result;
use bytes::Bytes;
use http::{HeaderValue, Request, Response};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use std::error::Error as StdError;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::Service;

/// Streaming response body type used throughout the proxy.
pub type StreamBody = BoxBody<Bytes, anyhow::Error>;

pub fn empty_body() -> StreamBody {
    BoxBody::new(Full::new(Bytes::new()).map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e)))
}

pub fn body_from<T: Into<Bytes>>(data: T) -> StreamBody {
    BoxBody::new(Full::new(data.into()).map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e)))
}

lazy_static::lazy_static! {
    static ref DEFAULT_HTTP_CLIENT: Client<AnyConnector, StreamBody> =
        Client::builder(SHARED_EXECUTOR.clone())
            .retry_canceled_requests(false)
            .build(AnyConnector::Http(HttpConnector::new()));
    static ref DEFAULT_CONNECTOR: AnyConnector = AnyConnector::Http(HttpConnector::new());
}

#[derive(Debug)]
pub struct Project {
    pub config: Arc<ProjectConfig>,
    pub logger: Arc<Logger>,
    pub domain: String,
    dir: PathBuf,
    servers: Vec<Arc<AppServer>>,
    /// Clients for `forward`/`proxy` targets, built on first use and reused after that.
    targets: dashmap::DashMap<String, (AnyConnector, Client<AnyConnector, StreamBody>)>,
    total_requests: AtomicU64,
    /// The project files' mtimes from just before the configuration was read, so an event that
    /// merely reports the write this project was built from can be told from a real change.
    project_file_mtimes: Vec<(PathBuf, Option<std::time::SystemTime>)>,
    /// The configuration's constants plus `$domain`, copied into every request.
    vars: script::Vars,
    /// Whether `admin_dashboard` may be served: only for projects owned by the user webcentral
    /// runs as, since that page shows every user's domains.
    admin_allowed: bool,
    changes: tokio::sync::mpsc::UnboundedSender<PathBuf>,
}

impl Project {
    pub fn new(dir: &Path, domain: String, prune_logs: i64) -> Result<Arc<Project>> {
        // Snapshotted *before* the configuration is read: a write landing during the read makes
        // the later event differ from the snapshot, which errs towards one redundant reload
        // rather than a missed one.
        let project_file_mtimes = crate::config::PROJECT_FILES
            .iter()
            .map(|f| {
                let path = dir.join(f);
                let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
                (path, mtime)
            })
            .collect();
        let config = ProjectConfig::load(dir)?;
        let (uid, gid) = get_ownership(dir);

        let log_dir = dir.join("_webcentral_data/log");
        let logger = Arc::new(Logger::new(log_dir, uid, gid, prune_logs)?);

        logger.write("supervisor", &config.summary());
        for problem in config.errors.iter().chain(config.warnings.iter()) {
            logger.write("supervisor", problem);
        }

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        // Servers never watch files themselves; changes are dispatched to them below.
        let servers = config
            .servers
            .iter()
            .map(|server| {
                AppServer::new(server.clone(), dir, uid, gid, logger.clone())
            })
            .collect();

        // The project's own domain, as opposed to `$host` - which is whatever the client asked for.
        let mut vars = config.vars.clone();
        vars.set("domain", &domain);

        let project = Arc::new(Project {
            domain,
            dir: dir.to_path_buf(),
            config: Arc::new(config),
            logger: logger.clone(),
            servers,
            targets: dashmap::DashMap::new(),
            total_requests: 0.into(),
            project_file_mtimes,
            vars,
            admin_allowed: uid == nix::unistd::geteuid().as_raw(),
            changes: tx,
        });

        // Changes arrive from the one process-wide watcher and are debounced here, per project.
        let weak = Arc::downgrade(&project);
        tokio::spawn(async move { apply_file_changes(weak, rx).await });

        Ok(project)
    }

    fn server(&self, name: &str) -> Option<&Arc<AppServer>> {
        self.servers.iter().find(|s| s.name() == name)
    }

    /// Queue a changed file, given relative to the project directory. The one process-wide
    /// watcher calls this; what the change means is worked out once the dust settles.
    pub fn file_changed(&self, relative: PathBuf) {
        let _ = self.changes.send(relative);
    }

    /// Tear the project down so the next request rebuilds it from the changed configuration.
    /// Returns whether it did; an event this project already reflects is not acted on.
    fn reload(&self, changed: &Path) -> bool {
        // A change this project already read is not a reason to throw it away. Files are watched
        // from before any project exists, so an event for the write that *created* this project's
        // configuration can easily arrive just after it was loaded. The test is whether the mtime
        // *differs* from the loaded snapshot, not whether it is newer: deploy tools like
        // `rsync -a` preserve mtimes, so a change may well look older than this project.
        let current = std::fs::metadata(changed).and_then(|m| m.modified()).ok();
        if let Some((_, recorded)) = self.project_file_mtimes.iter().find(|(p, _)| p == changed) {
            if *recorded == current {
                return false;
            }
        }

        // Deregister before tearing down: the teardown is asynchronous, and until it happens this
        // project would keep serving with the old configuration.
        crate::server::deregister_project_by_dir(&self.dir);
        let name = changed.file_name().unwrap_or(changed.as_os_str());
        self.logger.write(
            "supervisor",
            &format!(
                "Stopping due to file changes: {} (reloading configuration)",
                Path::new(name).display()
            ),
        );
        self.shutdown();
        true
    }

    /// Stop every server and wait for them to be gone. Signalling alone is not enough at
    /// shutdown: the process would exit before the lifecycle tasks ran, leaving the containers
    /// running with nothing left to stop them.
    pub async fn stop(self: Arc<Self>) {
        for server in &self.servers {
            server.request_stop(StopReason::Shutdown);
        }
        for server in &self.servers {
            server.wait_finished().await;
        }
    }

    /// Fully tear down: stop the servers and abort every watcher. Called when the domain is
    /// removed or re-registered, so a replaced project doesn't leave zombie watchers behind.
    pub fn shutdown(&self) {
        for server in &self.servers {
            server.shutdown();
        }
    }

    // --- Status, for the dashboard ---

    pub fn get_type_name(&self) -> String {
        self.config.summary()
    }

    pub fn get_total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    pub fn get_server_status(&self) -> Vec<ServerStatus> {
        self.servers
            .iter()
            .map(|server| ServerStatus {
                name: server.name().to_string(),
                kind: server
                    .config
                    .base
                    .clone()
                    .unwrap_or_else(|| crate::config::DEFAULT_BASE_IMAGE.to_string()),
                state: match server.state() {
                    AppState::Stopped => "Stopped",
                    AppState::Starting => "Starting",
                    AppState::Running => "Running",
                    AppState::Failed => "Failed",
                }
                .to_string(),
                port: server.port(),
                total_requests: server.total_requests(),
                pending_requests: server.pending_requests(),
                active_upgrades: server.active_upgrades(),
                idle_seconds: server.idle_seconds(),
            })
            .collect()
    }

    // --- Request handling ---

    /// HTTP/1.1 and HTTP/2, where a request may ask to be upgraded (WebSockets).
    pub async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Result<Response<StreamBody>> {
        let mut req = stream_request(req);

        if is_upgrade_request(&req) {
            self.log_request(&req);
            let outcome = self.script_pass(&mut req, self.vars.clone()).await?;
            let response = match outcome.terminal {
                Terminal::Response(response) => response,
                Terminal::ServeApp(name) => {
                    let Some(server) = self.server(&name) else {
                        anyhow::bail!("502 no server named '{}'", name);
                    };
                    server.wait_until_ready().await?;
                    let connector = server.connector().await?;
                    let result = self.clone().upgrade(connector, req, Some(server.clone())).await;
                    server.untrack_request();
                    result?
                }
                Terminal::Forward(target) => {
                    let connector = forward_connector(&target);
                    self.clone().upgrade(connector, req, None).await?
                }
                Terminal::Proxy(target) => {
                    let req = rewrite_for_proxy(req, &target)?;
                    self.clone().upgrade(DEFAULT_CONNECTOR.clone(), req, None).await?
                }
            };
            return Ok(decorate(response, outcome.headers));
        }

        self.serve_chain(req).await
    }

    /// HTTP/3, which has no upgrade mechanism.
    pub async fn handle_inner<B>(self: Arc<Self>, req: Request<B>) -> Result<Response<StreamBody>>
    where
        B: http_body::Body<Data = Bytes> + Send + Sync + 'static,
        B::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        self.serve_chain(stream_request(req)).await
    }

    /// Run the script and perform what it decided, following internal redirects: an upstream
    /// response naming a path in `X-Accel-Redirect` is discarded and the request re-routed there,
    /// so an application can authenticate or account a request and leave the actual delivery to
    /// the script - typically a static file. The next pass sees `$redirected_from` and
    /// `$redirected_by`, and the redirected request is a plain GET: the upstream consumed the
    /// original, body and all, and this pass only delivers something else in its place (which is
    /// also what keeps redirects compatible with request streaming). The redirecting response's
    /// remaining headers carry over onto the final response, so the application still controls
    /// things like Content-Type and Content-Disposition.
    async fn serve_chain(self: Arc<Self>, mut req: Request<StreamBody>) -> Result<Response<StreamBody>> {
        self.log_request(&req);
        let mut vars = self.vars.clone();
        let mut headers = Vec::new();
        let mut carried: Vec<(http::HeaderName, HeaderValue)> = Vec::new();

        loop {
            let outcome = self.script_pass(&mut req, vars.clone()).await?;
            headers.extend(outcome.headers);

            // What could issue a redirect this pass, and what the next pass needs of a request
            // that `dispatch` is about to consume.
            let upstream = match &outcome.terminal {
                Terminal::ServeApp(name) => Some(name.clone()),
                Terminal::Forward(target) | Terminal::Proxy(target) => Some(target.clone()),
                Terminal::Response(_) => None,
            };
            let orig_uri = req.uri().clone();
            let orig_headers = req.headers().clone();

            let mut response = self.clone().dispatch(outcome.terminal, req).await?;

            let target = upstream.as_ref().and_then(|_| {
                response.headers().get("X-Accel-Redirect")?.to_str().ok().map(str::to_string)
            });
            let Some(target) = target else {
                for (name, value) in carried {
                    response.headers_mut().insert(name, value);
                }
                return Ok(decorate(response, headers));
            };
            if !target.starts_with('/') {
                anyhow::bail!("502 X-Accel-Redirect '{}' is not an absolute path", target);
            }
            if !carried.is_empty() {
                anyhow::bail!("502 X-Accel-Redirect chained more than once (to '{}')", target);
            }

            // Everything else the redirecting response said is carried onto the final response -
            // minus the marker itself and the framing of the body we are replacing.
            let mut kept = std::mem::take(response.headers_mut());
            for name in ["x-accel-redirect", "content-length", "transfer-encoding", "connection", "date"] {
                kept.remove(name);
            }
            let mut last_name = None;
            for (name, value) in kept {
                let name = name.or(last_name.take()).expect("first header entry carries its name");
                carried.push((name.clone(), value));
                last_name = Some(name);
            }

            vars.set("redirected_from", orig_uri.path());
            vars.set("redirected_by", upstream.unwrap_or_default());

            let mut parts = orig_uri.into_parts();
            parts.path_and_query = Some(target.parse().map_err(|e| {
                anyhow::anyhow!("502 X-Accel-Redirect to '{}' is not a valid path: {}", target, e)
            })?);
            let mut redirected = Request::builder()
                .method(http::Method::GET)
                .uri(http::Uri::from_parts(parts)?)
                .body(empty_body())?;
            *redirected.headers_mut() = orig_headers;
            for name in [http::header::CONTENT_LENGTH, http::header::CONTENT_TYPE, http::header::TRANSFER_ENCODING] {
                redirected.headers_mut().remove(name);
            }
            req = redirected;
        }
    }

    async fn script_pass(
        &self,
        req: &mut Request<StreamBody>,
        vars: script::Vars,
    ) -> Result<script::Outcome> {
        let env = script::Env {
            dir: &self.dir,
            logger: &self.logger,
            domain: &self.domain,
            admin_allowed: self.admin_allowed,
        };
        script::run(&self.config.script, env, vars, req).await
    }

    /// Perform whatever the script decided, for a request that is not being upgraded.
    async fn dispatch(self: Arc<Self>, terminal: Terminal, req: Request<StreamBody>) -> Result<Response<StreamBody>> {
        match terminal {
            Terminal::Response(response) => Ok(response),
            Terminal::ServeApp(name) => {
                let Some(server) = self.server(&name) else {
                    anyhow::bail!("502 no server named '{}'", name);
                };
                server.wait_until_ready().await?;
                let client = server.http_client().await?;
                let result = self.send(client, req, Some(server.clone())).await;
                server.untrack_request();
                result
            }
            Terminal::Forward(target) => {
                let (_, client) = self.target(&target, || forward_connector(&target));
                self.send(client, req, None).await
            }
            Terminal::Proxy(target) => {
                let req = rewrite_for_proxy(req, &target)?;
                self.send(DEFAULT_HTTP_CLIENT.clone(), req, None).await
            }
        }
    }

    fn log_request<B>(&self, req: &Request<B>) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        if self.config.log_requests {
            let addr = req
                .headers()
                .get("X-Forwarded-For")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("-");
            self.logger
                .write("request", &format!("{} {} {}", addr, req.method(), req.uri().path()));
        }
    }

    /// Build (once) and reuse a connector/client pair for a `forward` target. Proxying goes
    /// through the shared client instead, which pools per upstream host by itself.
    fn target(
        &self,
        key: &str,
        connector: impl FnOnce() -> AnyConnector,
    ) -> (AnyConnector, Client<AnyConnector, StreamBody>) {
        if let Some(existing) = self.targets.get(key) {
            return existing.clone();
        }
        let connector = connector();
        let client = Client::builder(SHARED_EXECUTOR.clone())
            .retry_canceled_requests(false)
            .build(connector.clone());
        let pair = (connector, client);
        self.targets.insert(key.to_string(), pair.clone());
        pair
    }

    async fn send(
        &self,
        client: Client<AnyConnector, StreamBody>,
        req: Request<StreamBody>,
        server: Option<Arc<AppServer>>,
    ) -> Result<Response<StreamBody>> {
        let (mut parts, body) = req.into_parts();

        // Upstream connections are always HTTP/1.1, so the HTTP/2 and HTTP/3 pseudo-headers have
        // to go: they are not valid there and upstream servers reject them.
        parts.version = http::Version::HTTP_11;
        for pseudo in [":authority", ":method", ":path", ":scheme", ":status", ":protocol"] {
            parts.headers.remove(pseudo);
        }

        // The body is streamed through, not collected: an upload costs one chunk of memory, and
        // the trade is that a request whose body was already partly sent can never be retried on
        // a stale pooled connection - such failures 502 (and restart the service) instead.
        let req = Request::from_parts(parts, body);

        let response = match client.request(req).await {
            Ok(response) => response,
            Err(e) => {
                // Anything the client reports is a failure to talk to the upstream, so it is a bad
                // gateway rather than webcentral breaking - and a reason to stop the service, so
                // the next request rebuilds it. Not just on a refused connection: a service that
                // dies while a pooled connection is open fails as a closed connection instead, and
                // treating only the former as fatal left it wedged. ProcessExit (not Shutdown) so
                // the lifecycle restarts it rather than exiting for good.
                if let Some(server) = &server {
                    server.request_stop(StopReason::ProcessExit);
                }
                let source = StdError::source(&e).map(|s| s.to_string()).unwrap_or_default();
                anyhow::bail!("502 upstream request failed: {} {}", e, source);
            }
        };

        // Stream the upstream body through as-is. When the client disconnects the response is
        // dropped, which drops the body, which closes the upstream connection.
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(parts, BoxBody::new(body.map_err(|e| anyhow::anyhow!("{}", e)))))
    }

    /// Bridge a protocol upgrade (WebSocket and friends) to the backend, which needs raw byte
    /// piping rather than the HTTP client.
    async fn upgrade(
        self: Arc<Self>,
        mut connector: AnyConnector,
        req: Request<StreamBody>,
        server: Option<Arc<AppServer>>,
    ) -> Result<Response<StreamBody>> {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let headers = req.headers().clone();
        let logger = self.logger.clone();

        let upgrade_fut = hyper::upgrade::on(req);

        let io = connector
            .call(uri.clone())
            .await
            .map_err(|e| anyhow::anyhow!("Connector error: {}", e))?;
        let mut backend = io.into_tokio();

        let mut buf = Vec::new();
        use std::io::Write;
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string();
        write!(&mut buf, "{} {} HTTP/1.1\r\n", method, path).unwrap();
        for (name, value) in &headers {
            write!(&mut buf, "{}: ", name).unwrap();
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        buf.extend_from_slice(b"\r\n");

        backend
            .write_all(&buf)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send upgrade request to backend: {}", e))?;

        let mut response_buf = [0u8; 4096];
        let mut bytes_read = 0;
        let header_end = loop {
            let n = backend
                .read(&mut response_buf[bytes_read..])
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read backend response: {}", e))?;
            if n == 0 {
                anyhow::bail!("Backend closed connection during handshake");
            }
            bytes_read += n;
            if let Some(index) = response_buf[..bytes_read].windows(4).position(|w| w == b"\r\n\r\n") {
                break index + 4;
            }
            if bytes_read == response_buf.len() {
                anyhow::bail!("Response headers too long");
            }
        };

        let response_str = String::from_utf8_lossy(&response_buf[..header_end]);
        let mut lines = response_str.lines();
        let status_line = lines.next().ok_or_else(|| anyhow::anyhow!("Empty backend response"))?;
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| anyhow::anyhow!("Invalid status line: {}", status_line))?;

        let mut builder = Response::builder().status(status_code);
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some(index) = line.find(':') {
                let (name, value) = line.split_at(index);
                builder = builder.header(name.trim(), value[1..].trim());
            }
        }

        // Tracked only from here on: every failure path above returns without ever reaching the
        // task below, and an increment nothing decrements would hold the server open forever. The
        // handshake itself is covered by the caller's pending-request count instead.
        if let Some(server) = &server {
            server.track_upgrade();
        }
        tokio::spawn(async move {
            let result = match upgrade_fut.await {
                Ok(upgraded) => {
                    let mut upgraded = TokioIo::new(upgraded);
                    if header_end < bytes_read {
                        if let Err(e) = upgraded.write_all(&response_buf[header_end..bytes_read]).await {
                            logger.write("error", &format!("Failed to write excess data to client: {}", e));
                            return;
                        }
                    }
                    tokio::io::copy_bidirectional(&mut upgraded, &mut backend).await.map(|_| ())
                }
                Err(e) => {
                    logger.write("error", &format!("Client upgrade failed: {}", e));
                    Err(std::io::Error::other(e))
                }
            };

            if let Err(e) = result {
                // Benign closures: the peer went away, possibly without a TLS close_notify.
                if !matches!(
                    e.kind(),
                    std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::UnexpectedEof
                ) {
                    logger.write("error", &format!("WebSocket error: {}", e));
                }
            }

            if let Some(server) = server {
                server.touch().await;
                server.untrack_upgrade();
            }
        });

        Ok(builder.body(empty_body())?)
    }
}

/// Box any request body into the one streaming body type used throughout, so requests stay one
/// concrete type - and stream to the upstream rather than being collected first.
fn stream_request<B>(req: Request<B>) -> Request<StreamBody>
where
    B: http_body::Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    req.map(|body| BoxBody::new(BodyExt::map_err(body, |e| anyhow::anyhow!("{}", e.into()))))
}

/// Apply the headers the script gathered (`set_header`) to the response.
fn decorate(
    mut response: Response<StreamBody>,
    headers: Vec<(http::HeaderName, HeaderValue)>,
) -> Response<StreamBody> {
    for (name, value) in headers {
        response.headers_mut().insert(name, value);
    }
    response
}

/// Collect a project's file changes until they stop arriving, then act on the batch as a whole.
///
/// Batching matters for more than log noise: a change to one of the files that *define* the
/// project anywhere in the batch has to win, or a `git pull` touching both a source file and the
/// configuration would restart the servers and go on serving the old rules.
///
/// Holds only a weak reference, so the project is still dropped when its domain goes away; the
/// task then ends on the next event, or when the sender goes with it.
async fn apply_file_changes(
    project: std::sync::Weak<Project>,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<PathBuf>,
) {
    const QUIET: std::time::Duration = std::time::Duration::from_millis(100);

    while let Some(first) = rx.recv().await {
        let mut paths = vec![first];
        while let Ok(Some(path)) = tokio::time::timeout(QUIET, rx.recv()).await {
            paths.push(path);
        }
        let Some(project) = project.upgrade() else { return };

        // Ending the task only when the project was actually torn down matters: the batch may
        // hold nothing but the (ignored) event for the write this project was built from, and a
        // project must not lose its debouncer over that.
        if let Some(path) = paths.iter().find(|path| is_project_file(&project, path)) {
            if project.reload(&project.dir.join(path)) {
                return;
            }
        }

        // Each server decides for itself whether the change was any of its business.
        for server in &project.servers {
            let Some(path) = paths.iter().find(|p| server.wants(&p.to_string_lossy())) else {
                continue;
            };
            // Marked stale before the line is logged, so that anything reacting to the log -
            // a person hitting reload, a test - cannot slip a request in ahead of the restart.
            server.request_restart();
            project.logger.write(
                &format!("server:{}", server.name()),
                &format!("Stopping due to file changes: {}", path.display()),
            );
        }
    }
}

/// Whether a path names one of the files that define a project: the ones it actually read (its
/// configuration, whatever was auto-detected, any `env_file`), plus the project files at its root
/// whether or not they exist yet - creating a `Procfile` has to be noticed too.
fn is_project_file(project: &Project, relative: &Path) -> bool {
    if project.config.config_files.iter().any(|f| Path::new(f) == relative) {
        return true;
    }
    let mut parts = relative.components();
    let first = parts.next();
    parts.next().is_none()
        && first.is_some_and(|c| {
            crate::config::PROJECT_FILES.iter().any(|f| c.as_os_str() == *f)
        })
}

fn is_upgrade_request<B>(req: &Request<B>) -> bool {
    req.headers()
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("upgrade"))
        .unwrap_or(false)
}

/// A `forward` target: a bare number is a port on this host, a path is a unix socket, anything
/// else an address. Forwarding leaves the Host header alone - that is what makes it a *forward*.
fn forward_connector(target: &str) -> AnyConnector {
    if target.starts_with('/') {
        AnyConnector::FixedUnix(target.to_string())
    } else if target.chars().all(|c| c.is_ascii_digit()) {
        AnyConnector::FixedTcp(format!("127.0.0.1:{}", target))
    } else if target.contains(':') {
        AnyConnector::FixedTcp(target.to_string())
    } else {
        AnyConnector::FixedTcp(format!("{}:80", target))
    }
}

/// Point a request at an absolute `proxy` target: the request path is appended to it, the Host
/// header becomes the upstream's, and the original travels on in X-Forwarded-Host.
fn rewrite_for_proxy<B>(req: Request<B>, target: &str) -> Result<Request<B>> {
    let (mut parts, body) = req.into_parts();
    let base = target.trim_end_matches('/');
    let path = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let uri: http::Uri = format!("{}{}", base, path).parse()?;

    let original_host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    parts.headers.insert("X-Forwarded-Host", HeaderValue::from_str(&original_host)?);
    if let Some(authority) = uri.authority() {
        parts.headers.insert(http::header::HOST, HeaderValue::from_str(authority.as_str())?);
    }
    parts.uri = uri;
    Ok(Request::from_parts(parts, body))
}
