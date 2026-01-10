use include_exclude_watcher as file_watcher;
use crate::logger::Logger;
use crate::project_config::{DockerConfig, ProjectConfig, ProjectType};
use crate::server::SHARED_EXECUTOR;
use crate::streams::AnyConnector;
use tower::Service;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::Engine;

use anyhow::Result;
use bytes::Bytes;
use http::HeaderValue;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use std::error::Error as StdError;
use hyper::{body::Incoming, Request, Response};

/// Streaming response body type used throughout the proxy.
/// Wraps BoxBody to allow streaming responses from upstream to clients.
pub type StreamBody = BoxBody<Bytes, anyhow::Error>;

/// Create an empty StreamBody (for redirects, upgrade responses, etc.)
pub fn empty_body() -> StreamBody {
    BoxBody::new(Full::new(Bytes::new()).map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e)))
}

/// Create a StreamBody from any data that can be converted to Bytes
pub fn body_from<T: Into<Bytes>>(data: T) -> StreamBody {
    BoxBody::new(Full::new(data.into()).map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e)))
}
use hyper_util::client::legacy::connect::{HttpConnector};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioIo},
};
use nix::unistd::Uid;
use regex::Regex;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::{mpsc, Mutex, Notify, watch};
use tokio::time::sleep;
use std::sync::atomic::{AtomicU64, Ordering};

/// Application lifecycle state for Application-type projects
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    Stopped,   // No process running, will start on demand
    Starting,  // Process spawning, waiting for port
    Running,   // Process running and accepting requests
    Failed,    // Startup failed twice, project should be deregistered
}

/// Reasons for stopping the application
#[derive(Debug, Clone, Copy)]
pub enum StopReason {
    FileChange,
    Inactivity,
    ProcessExit,
    Shutdown,  // Server shutdown
}

/// Result of authentication check
enum AuthResult {
    Passed,                     // Auth passed (via cookie)
    PassedSetCookie(String),    // Auth passed via basic auth, set cookie for username
    Failed(Response<StreamBody>), // Auth failed, return this response
}

lazy_static::lazy_static! {
     static ref DEFAULT_HTTP_CLIENT: Client<AnyConnector, Full<Bytes>> = Client::builder(SHARED_EXECUTOR.clone()).build(AnyConnector::Http(HttpConnector::new()));
     static ref DEFAULT_CONNECTOR: AnyConnector = AnyConnector::Http(HttpConnector::new());
}


// --- Project ---

/// Connection info for Application projects - updated on each restart with new port
#[derive(Debug)]
struct AppConnection {
    port: u16,
    http_client: Client<AnyConnector, Full<Bytes>>,
    connector: AnyConnector,
}

#[derive(Debug)]
pub struct Project {
    pub config: Arc<ProjectConfig>,
    pub logger: Arc<Logger>,
    pub domain: String,
    dir: PathBuf,
    uid: u32,
    gid: u32,
    use_firejail: bool,
    // For non-Application projects: static connection info
    // For Application projects: None (uses app_connection instead)
    static_http_client: Option<Client<AnyConnector, Full<Bytes>>>,
    static_connector: Option<AnyConnector>,
    // For Application projects: connection info updated on each restart
    app_connection: Mutex<Option<AppConnection>>,
    // Application state (only meaningful for Application type projects)
    state_tx: watch::Sender<AppState>,
    state_rx: watch::Receiver<AppState>,
    stop_tx: mpsc::Sender<StopReason>,  // Send to request stop
    pending_requests: AtomicU64,        // Requests currently being handled (for startup trigger)
    active_upgrades: AtomicU64,         // Active WebSocket/upgraded connections
    total_requests: AtomicU64,          // Total requests served
    last_activity: Mutex<Instant>,
    watcher_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    state_changed: Notify,              // Notified when pending_requests changes
}

impl Project {
    pub fn new(
        dir: &Path,
        domain: String,
        use_firejail: bool,
        prune_logs: i64,
    ) -> Result<Arc<Project>> {
        // Load configuration
        let config = ProjectConfig::load(dir)?;
        let (uid, gid) = get_ownership(dir);

        // Create logger
        let log_dir = dir.join("_webcentral_data/log");
        let logger = Arc::new(Logger::new(log_dir, uid, gid, prune_logs)?);

        // Create connector based on project type
        // For Application types, connector is created dynamically on each start
        let is_application = matches!(config.project_type, ProjectType::Application { .. });
        let (static_connector, static_http_client) = if is_application {
            logger.write("supervisor", "Application server (port assigned on start)");
            (None, None)
        } else {
            let (connector, descr) = match &config.project_type {
                ProjectType::Redirect { target } => {
                    (None, format!("Redirect to {}", target))
                }
                ProjectType::Proxy { target } => {
                    (None, format!("Proxy to {}", target))
                }
                ProjectType::TcpForward { address } => {
                    (Some(AnyConnector::FixedTcp(address.clone())), format!("Forward to port {}", address))
                }
                ProjectType::UnixForward { socket_path } => {
                    (Some(AnyConnector::FixedUnix(socket_path.clone())), format!("Forward to unix socket {}", socket_path))
                }
                ProjectType::Static => {
                    (None, "Static file server".to_string())
                }
                ProjectType::Dashboard => {
                    (None, "Dashboard".to_string())
                }
                ProjectType::Application { .. } => unreachable!(),
            };
            logger.write("supervisor", &descr);

            if let Some(c) = connector {
                (Some(c.clone()), Some(Client::builder(SHARED_EXECUTOR.clone()).build(c)))
            } else {
                (Some(DEFAULT_CONNECTOR.clone()), Some(DEFAULT_HTTP_CLIENT.clone()))
            }
        };

        // Log configuration errors
        for err in &config.config_errors {
            logger.write("supervisor", err);
        }

        let (state_tx, state_rx) = watch::channel(AppState::Stopped);
        let (stop_tx, stop_rx) = mpsc::channel(8);
        
        let project = Arc::new(Project {
            domain: domain.clone(),
            dir: dir.to_path_buf(),
            config: Arc::new(config.clone()),
            logger,
            uid,
            gid,
            use_firejail,
            static_http_client,
            static_connector,
            app_connection: Mutex::new(None),
            state_tx,
            state_rx,
            stop_tx,
            pending_requests: 0.into(),
            active_upgrades: 0.into(),
            total_requests: 0.into(),
            last_activity: Mutex::new(Instant::now()),
            watcher_task: Mutex::new(None),
            state_changed: Notify::new(),
        });

        // Start file watcher
        let proj = project.clone();
        let proj_for_watcher = project.clone();
        let watcher_handle = tokio::spawn(async move {
            if let Err(e) = proj.clone().watch_files().await {
                let _ = proj.logger.write("supervisor", &format!("File watcher error: {}", e));
            }
        });
        
        // Store the watcher handle (spawn a task to do it since we're not async)
        tokio::spawn(async move {
            *proj_for_watcher.watcher_task.lock().await = Some(watcher_handle);
        });

        // Start lifecycle task for Application type projects
        if let ProjectType::Application { .. } = project.config.project_type {
            let proj = project.clone();
            tokio::spawn(async move {
                proj.lifecycle_task(stop_rx).await;
            });
        } else {
            // For non-Application types, just listen for FileChange to deregister
            let proj = project.clone();
            tokio::spawn(async move {
                proj.stop_listener(stop_rx).await;
            });
        }

        Ok(project)
    }

    /// Simple stop listener for non-Application projects.
    /// Deregisters on FileChange so a new project is created with fresh config.
    async fn stop_listener(self: Arc<Self>, mut stop_rx: mpsc::Receiver<StopReason>) {
        while let Some(reason) = stop_rx.recv().await {
            match reason {
                StopReason::FileChange => {
                    crate::server::deregister_project(&self.domain, &self);
                    self.stop_watcher();
                    return;
                }
                StopReason::Shutdown => {
                    self.stop_watcher();
                    return;
                }
                _ => {}
            }
        }
    }

    /// RAII guard to track pending requests - decrements count on drop
    fn track_request(&self) {
        self.pending_requests.fetch_add(1, Ordering::SeqCst);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.state_changed.notify_one();
    }

    fn untrack_request(&self) {
        self.pending_requests.fetch_sub(1, Ordering::SeqCst);
        self.state_changed.notify_one();
    }

    pub async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Result<Response<StreamBody>> {
        // Check for WebSocket upgrade before generic handling (requires Incoming body)
        if is_upgrade_request(&req) {
            // Log upgrade requests (handle_inner does logging for non-upgrades)
            *self.last_activity.lock().await = Instant::now();
            if self.config.log_requests {
                let _ = self.logger.write("request", &format!("{} {}", req.method(), req.uri().path()));
            }

            // Check auth if configured (no cookie setting for upgrades)
            if !self.config.auth.is_empty() {
                match self.check_auth(&req) {
                    AuthResult::Failed(response) => return Ok(response),
                    _ => {} // Passed or PassedSetCookie - both mean auth ok
                }
            }

            // Upgrades only work for forward/proxy/application types
            match &self.config.project_type {
                ProjectType::Application { .. } => {
                    self.wait_for_app_ready().await?;
                    let result = self.clone().proxy_upgrade(req).await;
                    self.untrack_request();
                    return result;
                }
                ProjectType::Proxy { .. } | ProjectType::TcpForward { .. } | 
                ProjectType::UnixForward { .. } => {
                    return self.clone().proxy_upgrade(req).await;
                }
                _ => {} // Fall through to normal handling
            }
        }

        self.handle_inner(req).await
    }

    /// Internal handler that works with any body type (no upgrade support).
    /// Used by HTTP/3 which doesn't support WebSocket upgrades.
    pub async fn handle_inner<B>(self: Arc<Self>, req: Request<B>) -> Result<Response<StreamBody>>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        // Update activity timestamp
        *self.last_activity.lock().await = Instant::now();

        if self.config.log_requests {
            let _ = self.logger.write("request", &format!("{} {}", req.method(), req.uri().path()));
        }

        // Track if we need to set auth cookie on successful response
        let mut set_auth_cookie: Option<String> = None;

        // Check auth if configured
        if !self.config.auth.is_empty() {
            // Handle /webcentral/logout - clear cookie and redirect to /
            if req.uri().path() == "/webcentral/logout" {
                return Ok(Response::builder()
                    .status(302)
                    .header("Location", "/")
                    .header("Set-Cookie", "webcentral_auth=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
                    .body(empty_body())?);
            }

            match self.check_auth(&req) {
                AuthResult::Failed(response) => return Ok(response),
                AuthResult::PassedSetCookie(username) => set_auth_cookie = Some(username),
                AuthResult::Passed => {}
            }
        }

        // Apply URL rewrites
        let (_path, redirect) = self.apply_rewrites(req.uri().path());

        if !redirect.is_empty() {
            return Ok(Response::builder()
                .status(301)
                .header("Location", redirect)
                .body(empty_body())?);
        }

        // Determine handler based on configuration
        // Clone self upfront since some handlers take ownership
        let self_clone = self.clone();
        let mut response = match &self.config.project_type {
            ProjectType::Redirect { target } => self.handle_redirect(&req, target).await,
            ProjectType::Proxy { target } => self_clone.proxy_request(req, target).await,
            ProjectType::TcpForward { .. } => self.forward_request(req).await,
            ProjectType::UnixForward { .. } => self.forward_request(req).await,
            ProjectType::Application { .. } => self_clone.handle_application(req).await,
            ProjectType::Static => self.handle_static(&req).await,
            ProjectType::Dashboard => self.handle_dashboard(&req).await,
        }?;

        // Add auth cookie if authentication just succeeded via basic auth
        if let Some(username) = set_auth_cookie {
            let password_hash = self.config.auth.get(&username).unwrap();
            let cookie = format!("webcentral_auth={}:{}; Path=/; HttpOnly; SameSite=Strict; Max-Age=315360000", username, password_hash);
            response.headers_mut().insert(
                http::header::SET_COOKIE,
                HeaderValue::from_str(&cookie).unwrap()
            );
        }

        Ok(response)
    }

    fn apply_rewrites(&self, path: &str) -> (String, String) {
        for (pattern, target) in &self.config.rewrites {
            if let Ok(re) = Regex::new(&format!("^{}$", pattern)) {
                if re.is_match(path) {
                    let result = re.replace(path, target).to_string();
                    if result.starts_with("http://")
                        || result.starts_with("https://")
                        || result.starts_with("webcentral://")
                    {
                        return (path.to_string(), result);
                    }
                    return (result, String::new());
                }
            }
        }
        (path.to_string(), String::new())
    }

    /// Check authentication. Returns Some(response) if auth failed/logout, None if auth passed.
    /// When basic auth succeeds, the returned None indicates the handler should set an auth cookie.
    fn check_auth<B>(&self, req: &Request<B>) -> AuthResult {
        // Check for valid auth cookie first
        if let Some(cookie_header) = req.headers().get(http::header::COOKIE) {
            if let Ok(cookies) = cookie_header.to_str() {
                for cookie in cookies.split(';') {
                    let cookie = cookie.trim();
                    if let Some(value) = cookie.strip_prefix("webcentral_auth=") {
                        // Cookie format: username:password_hash
                        if let Some((username, cookie_hash)) = value.split_once(':') {
                            if let Some(password_hash) = self.config.auth.get(username) {
                                if cookie_hash == password_hash {
                                    return AuthResult::Passed;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // No valid cookie, check for basic auth header
        let Some(auth_header) = req.headers().get(http::header::AUTHORIZATION) else {
            return AuthResult::Failed(self.auth_required_response());
        };
        let Some(auth_str) = auth_header.to_str().ok() else {
            return AuthResult::Failed(self.auth_required_response());
        };
        
        if !auth_str.starts_with("Basic ") {
            return AuthResult::Failed(self.auth_required_response());
        }
        
        let encoded = &auth_str[6..];
        let Some(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded).ok() else {
            return AuthResult::Failed(self.auth_required_response());
        };
        let Some(credentials) = String::from_utf8(decoded).ok() else {
            return AuthResult::Failed(self.auth_required_response());
        };
        
        let Some((username, password)) = credentials.split_once(':') else {
            return AuthResult::Failed(self.auth_required_response());
        };
        
        // Look up password hash for username
        let Some(password_hash) = self.config.auth.get(username) else {
            return AuthResult::Failed(self.auth_required_response());
        };
        
        // Verify password using argon2
        let Ok(parsed_hash) = PasswordHash::new(password_hash) else {
            return AuthResult::Failed(self.auth_required_response());
        };
        if Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok() {
            // Auth passed via basic auth - signal that cookie should be set
            AuthResult::PassedSetCookie(username.to_string())
        } else {
            AuthResult::Failed(self.auth_required_response())
        }
    }

    /// Generate a 401 Unauthorized response with WWW-Authenticate header
    fn auth_required_response(&self) -> Response<StreamBody> {
        Response::builder()
            .status(401)
            .header("WWW-Authenticate", "Basic realm=\"Authentication Required\"")
            .body(body_from("Unauthorized"))
            .unwrap()
    }

    async fn handle_redirect<B>(&self, req: &Request<B>, target: &str) -> Result<Response<StreamBody>> {
        Ok(Response::builder()
            .status(301)
            .header("Location", &format!("{}{}", target, req.uri().path()))
            .body(empty_body())?)
    }

    async fn handle_static<B>(&self, req: &Request<B>) -> Result<Response<StreamBody>> {
        let public_dir = self.dir.join("public");
        if !public_dir.exists() {
            return Ok(Response::builder()
                .status(404)
                .body(body_from("Not Found"))?);
        }

        // Simple static file serving
        let mut path = req.uri().path().trim_start_matches('/').to_string();

        // If path is empty or ends with /, append index.html
        if path.is_empty() || path.ends_with('/') {
            path.push_str("index.html");
        }

        let file_path = public_dir.join(&path);

        if file_path.starts_with(&public_dir) && file_path.exists() && file_path.is_file() {
            let content = tokio::fs::read(&file_path).await?;
            let mime = mime_guess::from_path(&file_path)
                .first_or_octet_stream()
                .to_string();
            Ok(Response::builder()
                .status(200)
                .header("Content-Type", mime)
                .body(body_from(content))?)
        } else {
            Ok(Response::builder()
                .status(404)
                .body(body_from("Not Found"))?)
        }
    }

    async fn handle_dashboard<B>(&self, _req: &Request<B>) -> Result<Response<StreamBody>> {
        let domains = crate::server::get_domain_status();
        let server_info = crate::server::get_server_info();
        
        // Format uptime nicely
        let uptime_secs = server_info.uptime_seconds;
        let uptime_str = if uptime_secs < 60 {
            format!("{}s", uptime_secs)
        } else if uptime_secs < 3600 {
            format!("{}m {}s", uptime_secs / 60, uptime_secs % 60)
        } else if uptime_secs < 86400 {
            format!("{}h {}m", uptime_secs / 3600, (uptime_secs % 3600) / 60)
        } else {
            format!("{}d {}h", uptime_secs / 86400, (uptime_secs % 86400) / 3600)
        };
        
        let mut html = format!(r#"<!DOCTYPE html>
<html>
<head>
<title>Webcentral Dashboard</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2em; background: #f5f5f5; }}
h1 {{ color: #333; }}
h2 {{ color: #555; margin-top: 2em; }}
table {{ border-collapse: collapse; width: 100%; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 1em; }}
th, td {{ border: 1px solid #ddd; padding: 0.75em 1em; text-align: left; }}
th {{ background: #f8f8f8; }}
tr:hover {{ background: #f5f5f5; }}
.status-running {{ color: #2a2; }}
.status-stopped {{ color: #888; }}
.status-starting {{ color: #f90; }}
.status-failed {{ color: #c22; }}
.status-active {{ color: #2a2; }}
.cert-valid {{ color: #2a2; }}
.cert-error {{ color: #c22; }}
.cert-acquiring {{ color: #f90; }}
.server-info {{ display: flex; gap: 2em; margin-bottom: 2em; flex-wrap: wrap; }}
.info-card {{ background: white; padding: 1em 1.5em; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.info-card h3 {{ margin: 0 0 0.5em 0; color: #666; font-size: 0.9em; }}
.info-card .value {{ font-size: 1.5em; color: #333; }}
.num {{ text-align: right; }}
.dir {{ font-size: 0.85em; color: #666; max-width: 300px; overflow: hidden; text-overflow: ellipsis; }}
</style>
</head>
<body>
<h1>Webcentral Dashboard</h1>

<div class="server-info">
<div class="info-card"><h3>Uptime</h3><div class="value">{}</div></div>
<div class="info-card"><h3>Domains</h3><div class="value">{}</div></div>
</div>

<h2>Projects</h2>
<table>
<tr><th>Domain</th><th>Type</th><th>Status</th><th>TLS</th><th>Requests</th><th>Pending</th><th>Idle</th><th>Directory</th></tr>
"#, uptime_str, server_info.domain_count);

        for d in domains {
            let status_class = match d.status.as_str() {
                "Running" => "status-running",
                "Stopped" => "status-stopped",
                "Starting" => "status-starting",
                "Failed" => "status-failed",
                "Active" => "status-active",
                _ => "",
            };
            let idle_str = if d.active_upgrades > 0 {
                format!("{} websocket{}", d.active_upgrades, if d.active_upgrades == 1 { "" } else { "s" })
            } else {
                d.idle_seconds.map(|s| {
                    if s < 60 { format!("{}s", s) }
                    else if s < 3600 { format!("{}m", s / 60) }
                    else { format!("{}h", s / 3600) }
                }).unwrap_or_else(|| "-".to_string())
            };
            
            let (cert_class, cert_str) = match d.cert_status.as_deref() {
                Some(s) if s.starts_with("Valid") => ("cert-valid", s),
                Some(s) if s.starts_with("Error") => ("cert-error", s),
                Some(s) if s == "Expired" => ("cert-error", s),
                Some(s) => ("cert-acquiring", s),
                None => ("", "-"),
            };
            
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td class=\"{}\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"dir\" title=\"{}\">{}</td></tr>\n",
                d.domain, d.project_type, status_class, d.status, cert_class, cert_str, d.total_requests, d.pending_requests, idle_str, d.directory, d.directory
            ));
        }

        html.push_str("</table>\n</body>\n</html>");

        Ok(Response::builder()
            .status(200)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(body_from(html))?)
    }

    async fn proxy_request<B>(
        self: Arc<Self>,
        req: Request<B>,
        target: &str,
    ) -> Result<Response<StreamBody>>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (parts, body) = req.into_parts();
        let uri_str = format!("{}{}", target, parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));

        let mut new_parts = parts.clone();
        let new_uri: http::Uri = uri_str.parse()?;
        new_parts.uri = new_uri.clone();

        let original_host = parts
            .headers
            .get("host")
            .or_else(|| parts.headers.get(":authority"))
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        // Set X-Forwarded headers to preserve original request info
        new_parts.headers.insert("X-Forwarded-Host", HeaderValue::from_str(original_host)?);
        new_parts.headers.insert("X-Forwarded-Proto", HeaderValue::from_str(parts.uri.scheme_str().unwrap_or("https"))?);

        // Rewrite Host header to match the backend (extracted from target URI)
        if let Some(authority) = new_uri.authority() {
            new_parts.headers.insert("host", HeaderValue::from_str(authority.as_str())?);
        }

        let proxy_req = Request::from_parts(new_parts, body);
        self.forward_request(proxy_req).await
    }

    async fn forward_request<B>(
        self: &Arc<Self>,
        req: Request<B>,
    ) -> Result<Response<StreamBody>>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        // Note: WebSocket upgrades are handled separately in handle_upgrade
        // because they require the hyper::body::Incoming type specifically.

        // Buffer the request body (we must send the full request to upstream)
        let (mut parts, body) = req.into_parts();
        
        // Upstream connections are always HTTP/1.1
        parts.version = http::Version::HTTP_11;
        
        // Remove HTTP/2 and HTTP/3 pseudo-headers (they start with ':')
        // These are not valid in HTTP/1.1 and will cause upstream errors
        parts.headers.remove(":authority");
        parts.headers.remove(":method");
        parts.headers.remove(":path");
        parts.headers.remove(":scheme");
        parts.headers.remove(":status");
        parts.headers.remove(":protocol");
        
        let body_bytes = BodyExt::collect(body).await.map_err(|e| anyhow::anyhow!("{}", e.into()))?.to_bytes();
        let req = Request::from_parts(parts, Full::new(body_bytes));

        // Get the http_client from the appropriate source
        let http_client = if let Some(client) = &self.static_http_client {
            client.clone()
        } else {
            let conn = self.app_connection.lock().await;
            match conn.as_ref() {
                Some(c) => c.http_client.clone(),
                None => anyhow::bail!("502 application not started"),
            }
        };

        let resp = match http_client.request(req).await {
            Ok(resp) => resp,
            Err(e) => {
                if e.is_connect() {
                    // Upstream refused connection - stop the project and return specific error
                    self.clone().stop();
                    let source = StdError::source(&e).map(|s| s.to_string()).unwrap_or_default();
                    anyhow::bail!("502 upstream connect failed: {}", source);
                }
                return Err(e.into());
            }
        };

        // Return the upstream response body as-is for streaming.
        // When the client disconnects, the response is dropped, which drops the body,
        // which closes the connection to the upstream server.
        let (parts, body) = resp.into_parts();
        Ok(Response::from_parts(parts, BoxBody::new(body.map_err(|e| anyhow::anyhow!("{}", e)))))
    }

    async fn handle_application<B>(self: Arc<Self>, req: Request<B>) -> Result<Response<StreamBody>>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.wait_for_app_ready().await?;
        let result = self.forward_request(req).await;
        self.untrack_request();
        result
    }

    /// Wait for application to be ready, tracking the request.
    /// On success, caller MUST call untrack_request() when done.
    async fn wait_for_app_ready(&self) -> Result<()> {
        self.track_request();
        
        let state = {
            let mut rx = self.state_rx.clone();
            let wait_result = tokio::time::timeout(
                Duration::from_secs(30),
                rx.wait_for(|&s| s == AppState::Running || s == AppState::Failed)
            ).await;

            match wait_result {
                Ok(Ok(s)) => *s,
                Ok(Err(_)) => {
                    self.untrack_request();
                    anyhow::bail!("Application state channel closed");
                }
                Err(_) => {
                    self.untrack_request();
                    anyhow::bail!("Application startup timeout");
                }
            }
        };

        if state == AppState::Failed {
            self.untrack_request();
            anyhow::bail!("502 application failed to start");
        }

        Ok(())
    }

    /// Spawns the application process and workers. Returns handles to await for process exit.
    /// Allocates a new port and stores connection info in app_connection.
    /// Does NOT wait for port readiness - caller should do that.
    async fn spawn_processes(&self) -> Result<Vec<tokio::process::Child>> {
        // Allocate a new port for this startup cycle
        let port = get_free_port()?;
        let addr = format!("localhost:{}", port);
        let connector = AnyConnector::FixedTcp(addr.clone());
        let http_client = Client::builder(SHARED_EXECUTOR.clone()).build(connector.clone());
        
        // Store the new connection info
        *self.app_connection.lock().await = Some(AppConnection {
            port,
            http_client,
            connector,
        });

        self.logger.write("supervisor", &format!("Starting on port {}", port));

        let (command, docker, workers) = match &self.config.project_type {
            ProjectType::Application {
                command,
                docker,
                workers,
                ..
            } => (command.clone(), docker.clone(), workers.clone()),
            _ => unreachable!("spawn_processes called for non-Application project"),
        };

        let mut process = if let Some(docker_config) = &docker {
            self.build_docker_command(port, docker_config, &command)
                .await?
        } else {
            self.build_shell_command(&command)?
        };

        // Set environment
        process.env("PORT", port.to_string());
        for (key, val) in &self.config.environment {
            process.env(key, val);
        }

        // Set working directory
        process.current_dir(&self.dir);

        // Capture stdout/stderr
        process.stdout(std::process::Stdio::piped());
        process.stderr(std::process::Stdio::piped());

        self.logger.write("supervisor", &format!("Starting application: {:?}", process));

        let mut child = process.spawn()?;
        let mut children = Vec::new();

        // Stream stdout to log
        if let Some(stdout) = child.stdout.take() {
            let logger = self.logger.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    logger.write("stdout", &line);
                }
            });
        }

        // Stream stderr to log
        if let Some(stderr) = child.stderr.take() {
            let logger = self.logger.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    logger.write("stderr", &line);
                }
            });
        }

        children.push(child);

        // Spawn workers
        if !workers.is_empty() {
            self.logger.write("supervisor", &format!("Starting {} worker(s)", workers.len()));
        }

        for (name, cmd) in &workers {
            let mut process = match self.build_shell_command(cmd) {
                Ok(p) => p,
                Err(e) => {
                    self.logger.write("supervisor", &format!("Failed to build worker {}: {}", name, e));
                    continue;
                }
            };

            process.env("PORT", port.to_string());
            for (key, val) in &self.config.environment {
                process.env(key, val);
            }
            process.current_dir(&self.dir);
            process.stdout(std::process::Stdio::piped());
            process.stderr(std::process::Stdio::piped());

            match process.spawn() {
                Ok(mut worker_child) => {
                    let logger = self.logger.clone();
                    let label = format!("worker-{}", name);
                    if let Some(stdout) = worker_child.stdout.take() {
                        let logger = logger.clone();
                        let label = label.clone();
                        tokio::spawn(async move {
                            let reader = BufReader::new(stdout);
                            let mut lines = reader.lines();
                            while let Ok(Some(line)) = lines.next_line().await {
                                logger.write(&label, &line);
                            }
                        });
                    }
                    if let Some(stderr) = worker_child.stderr.take() {
                        let logger = logger.clone();
                        let label = label.clone();
                        tokio::spawn(async move {
                            let reader = BufReader::new(stderr);
                            let mut lines = reader.lines();
                            while let Ok(Some(line)) = lines.next_line().await {
                                logger.write(&label, &line);
                            }
                        });
                    }
                    children.push(worker_child);
                }
                Err(e) => {
                    self.logger.write("supervisor", &format!("Failed to start worker {}: {}", name, e));
                }
            }
        }

        Ok(children)
    }

    /// Main lifecycle state machine for Application projects.
    /// Manages: Stopped -> Starting -> Running -> (stop trigger) -> Stopped cycle
    /// On startup failure (twice), transitions to Failed and deregisters.
    async fn lifecycle_task(self: Arc<Self>, mut stop_rx: mpsc::Receiver<StopReason>) {
        let timeout_duration = if self.config.reload.timeout > 0 {
            Some(Duration::from_secs(self.config.reload.timeout as u64))
        } else {
            None
        };
        let mut retry_count = 0;

        loop {
            let state = *self.state_rx.borrow();
            
            match state {
                AppState::Stopped => {
                    // Wait for a pending request to trigger startup
                    loop {
                        if self.pending_requests.load(Ordering::SeqCst) > 0 {
                            break;
                        }
                        // Check for shutdown signal while waiting
                        // Use a timeout to periodically re-check pending_requests
                        // in case we missed a notification
                        tokio::select! {
                            reason = stop_rx.recv() => {
                                if let Some(StopReason::Shutdown) = reason {
                                    self.logger.write("supervisor", "Shutdown requested");
                                    return;
                                }
                                // Other stop reasons in Stopped state - ignore
                            }
                            _ = self.state_changed.notified() => {
                                // Got notification, loop back to check pending_requests
                            }
                            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                                // Periodic check in case notification was missed
                            }
                        }
                    }
                    
                    let _ = self.state_tx.send(AppState::Starting);
                }
                
                AppState::Starting => {
                    self.logger.write("supervisor", "Starting application");
                    
                    // Spawn processes
                    let mut children = match self.spawn_processes().await {
                        Ok(c) => c,
                        Err(e) => {
                            self.logger.write("supervisor", &format!("Failed to spawn: {}", e));
                            retry_count += 1;
                            if retry_count >= 2 {
                                self.logger.write("supervisor", "Startup failed twice, giving up");
                                let _ = self.state_tx.send(AppState::Failed);
                            } else {
                                self.logger.write("supervisor", "Will retry once");
                                // Brief delay before retry
                                sleep(Duration::from_millis(500)).await;
                            }
                            continue;
                        }
                    };

                    // Wait for port to be ready, but also listen for stop signals and process exit
                    let port_ready = self.wait_for_port_ready(&mut stop_rx, &mut children).await;
                    
                    if !port_ready {
                        self.kill_processes(children).await;
                        retry_count += 1;
                        if retry_count >= 2 {
                            self.logger.write("supervisor", "Startup failed twice, giving up");
                            let _ = self.state_tx.send(AppState::Failed);
                        } else {
                            self.logger.write("supervisor", "Will retry once");
                            sleep(Duration::from_millis(500)).await;
                        }
                        continue;
                    }

                    // Get port from app_connection for logging
                    let port = {
                        let conn = self.app_connection.lock().await;
                        conn.as_ref().map(|c| c.port).unwrap_or(0)
                    };
                    self.logger.write("supervisor", &format!("Ready on port {}", port));
                    retry_count = 0;
                    let _ = self.state_tx.send(AppState::Running);
                    
                    // Run until stop trigger or process exit
                    let stop_reason = self.run_until_stop(children, &mut stop_rx, timeout_duration).await;
                    
                    match stop_reason {
                        StopReason::Shutdown => {
                            self.logger.write("supervisor", "Stopped app (shutdown)");
                            return;
                        }
                        StopReason::FileChange => {
                            // Config may have changed. Already deregistered in run_until_stop.
                            self.logger.write("supervisor", "Stopped app (file change)");
                            self.stop_watcher();
                            return;
                        }
                        StopReason::Inactivity => {
                            self.logger.write("supervisor", "Stopped app (inactivity)");
                            // Loop continues, will restart on next request
                        }
                        StopReason::ProcessExit => {
                            self.logger.write("supervisor", "Stopped app (process exit)");
                            // Loop continues, will restart on next request
                        }
                    }
                    // State is already Stopped (set by run_until_stop before killing processes)
                }
                
                AppState::Running => {
                    // Should not reach here - run_until_stop handles Running state
                    unreachable!("lifecycle_task in Running state outside run_until_stop");
                }
                
                AppState::Failed => {
                    // Deregister from server and exit
                    self.logger.write("supervisor", "Deregistering failed project");
                    crate::server::deregister_project(&self.domain, &self);
                    self.stop_watcher();
                    return;
                }
            }
        }
    }

    /// Wait for port to become ready, returns false if stop signal received, timeout, or process exits
    async fn wait_for_port_ready(&self, stop_rx: &mut mpsc::Receiver<StopReason>, children: &mut [tokio::process::Child]) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let port = {
            let conn = self.app_connection.lock().await;
            match conn.as_ref() {
                Some(c) => c.port,
                None => return false, // No connection info = startup failed
            }
        };
        let addr = format!("localhost:{}", port);

        loop {
            // Check for stop signal (non-blocking)
            match stop_rx.try_recv() {
                Ok(StopReason::Shutdown) => return false,
                Ok(_) => return false, // Any stop during startup = abort
                Err(_) => {}
            }

            // Check if main process has exited
            if let Some(main) = children.first_mut() {
                match main.try_wait() {
                    Ok(Some(status)) => {
                        self.logger.write("supervisor", &format!("Application failed to start listening on port {} (process exited: {})", port, status));
                        return false;
                    }
                    Ok(None) => {} // Still running
                    Err(e) => {
                        self.logger.write("supervisor", &format!("Error checking process status: {}", e));
                        return false;
                    }
                }
            }

            if tokio::time::Instant::now() >= deadline {
                return false;
            }

            // Try to connect
            if let Ok(mut stream) = TcpStream::connect(&addr).await {
                if stream.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n").await.is_ok() {
                    let mut buf = [0u8; 32];
                    if let Ok(n) = stream.read(&mut buf).await {
                        if n >= 12 && buf.starts_with(b"HTTP/1.") && buf[9] != b'5' {
                            return true;
                        }
                    }
                }
            }

            sleep(Duration::from_millis(50)).await;
        }
    }

    /// Run until a stop trigger occurs. Returns the stop reason.
    async fn run_until_stop(
        self: &Arc<Self>,
        mut children: Vec<tokio::process::Child>,
        stop_rx: &mut mpsc::Receiver<StopReason>,
        timeout_duration: Option<Duration>,
    ) -> StopReason {
        loop {
            // Calculate inactivity deadline
            let inactivity_deadline = if let Some(timeout) = timeout_duration {
                let last = *self.last_activity.lock().await;
                Some(tokio::time::Instant::now() + timeout.saturating_sub(last.elapsed()))
            } else {
                None
            };

            tokio::select! {
                // Stop signal received
                reason = stop_rx.recv() => {
                    let reason = reason.unwrap_or(StopReason::Shutdown);
                    
                    // For FileChange, deregister immediately so new requests create fresh project
                    if let StopReason::FileChange = reason {
                        crate::server::deregister_project(&self.domain, &self);
                    }
                    
                    // Immediately transition to Stopped so new requests wait for restart
                    let _ = self.state_tx.send(AppState::Stopped);
                    self.kill_processes_by_ref(&mut children).await;
                    return reason;
                }
                
                // Check for main process exit (first child is the main process)
                result = async {
                    if let Some(main) = children.first_mut() {
                        main.wait().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    if let Ok(status) = result {
                        self.logger.write("supervisor", &format!("Main process exited: {}", status));
                    }
                    // Immediately transition to Stopped so new requests wait for restart
                    let _ = self.state_tx.send(AppState::Stopped);
                    self.kill_processes_by_ref(&mut children).await;
                    return StopReason::ProcessExit;
                }
                
                // Inactivity timeout
                _ = async {
                    if let Some(deadline) = inactivity_deadline {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    // Check if actually inactive (activity might have happened)
                    if let Some(timeout) = timeout_duration {
                        let last = *self.last_activity.lock().await;
                        if last.elapsed() >= timeout {
                            // Only stop if no active upgraded connections (WebSockets)
                            if self.active_upgrades.load(Ordering::SeqCst) == 0 {
                                self.logger.write("supervisor", "Stopping due to inactivity");
                                // Immediately transition to Stopped so new requests wait for restart
                                let _ = self.state_tx.send(AppState::Stopped);
                                self.kill_processes_by_ref(&mut children).await;
                                return StopReason::Inactivity;
                            }
                        }
                    }
                    // Activity happened or active upgrades exist, loop again
                }
            }
        }
    }

    /// Kill all processes gracefully (SIGTERM then SIGKILL after 5s)
    async fn kill_processes(&self, mut children: Vec<tokio::process::Child>) {
        self.kill_processes_by_ref(&mut children).await;
    }

    async fn kill_processes_by_ref(&self, children: &mut Vec<tokio::process::Child>) {
        // Send SIGTERM to all
        for child in children.iter() {
            if let Some(pid) = child.id() {
                #[cfg(unix)]
                {
                    use nix::sys::signal::{kill, Signal};
                    use nix::unistd::Pid;
                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                }
            }
        }

        // Wait up to 5s for graceful exit
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        for child in children.iter_mut() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            tokio::select! {
                _ = child.wait() => {}
                _ = sleep(remaining) => {
                    let _ = child.kill();
                    let _ = child.wait().await;
                }
            }
        }
        children.clear();
    }

    /// Request stop - sends to the lifecycle task
    pub fn request_stop(&self, reason: StopReason) {
        let _ = self.stop_tx.try_send(reason);
    }

    fn build_shell_command(&self, command: &str) -> Result<Command> {
        let has_docker = matches!(
            self.config.project_type,
            ProjectType::Application {
                docker: Some(_),
                ..
            }
        );

        let mut cmd = if self.use_firejail && !has_docker {
            let home = get_user_home(self.uid);
            let mut c = Command::new("firejail");
            c.args(&[
                "--quiet",
                "--noprofile",
                "--private-tmp",
                "--private-dev",
                &format!("--private={}", home),
                &format!("--whitelist={}", self.dir.display()),
                "--read-only=/",
                &format!("--read-write={}", self.dir.display()),
                "--",
                "/bin/sh",
                "-c",
                &command,
            ]);
            c
        } else {
            let mut c = Command::new("/bin/sh");
            c.args(&["-c", &command]);
            c
        };

        // Set user if running as root
        #[cfg(target_os = "linux")]
        if nix::unistd::geteuid().is_root() && !self.use_firejail {
            cmd.uid(self.uid);
            cmd.gid(self.gid);
        }

        Ok(cmd)
    }

    async fn build_docker_command(
        &self,
        port: u16,
        dc: &DockerConfig,
        command: &str,
    ) -> Result<Command> {
        // Generate container name using a hash of the directory path
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.dir.hash(&mut hasher);
        let hash = hasher.finish();
        let container_name = format!("webcentral-{:x}", hash);

        let image_name = if dc.packages.is_empty() && dc.commands.is_empty() {
            // Just use the base image
            dc.base.clone()
        } else {
            // Create our own Dockerfile, as we need some RUN commands
            let image_name = format!("{}:latest", container_name);

            // Build Dockerfile
            let mut dockerfile = format!("FROM {}\n", dc.base);

            for cmd in &dc.commands {
                dockerfile.push_str(&format!("RUN {}\n", cmd));
            }

            // Write Dockerfile
            let dockerfile_path = self.dir.join("_webcentral_data/Dockerfile");
            fs::create_dir_all(dockerfile_path.parent().unwrap())?;
            fs::write(&dockerfile_path, dockerfile)?;

            // Build image
            let output = Command::new(get_docker_path())
                .args(&["build", "-t", &image_name, "-f"])
                .arg(&dockerfile_path)
                .arg(&self.dir)
                .output()
                .await?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                self.logger.write("docker", &stderr);
                anyhow::bail!("Docker build failed");
            }
            image_name
        };

        // Prepare run command
        let mut cmd = Command::new(get_docker_path());
        cmd.args(&["run", "--rm", "--name", &container_name]);

        // Port mapping
        cmd.args(&["-p", &format!("{}:{}", port, dc.http_port)]);

        // App directory mount
        if dc.mount_app_dir {
            cmd.args(&["-v", &format!("{}:{}", self.dir.display(), dc.app_dir)]);
            cmd.args(&["-w", &dc.app_dir]);
        }

        // Additional mounts
        for mount in &dc.mounts {
            let container_path = if mount.starts_with('/') {
                mount.clone()
            } else {
                format!("{}/{}", dc.app_dir, mount)
            };
            let host_path = self.dir
                .join("_webcentral_data/mounts")
                .join(&container_path.trim_start_matches('/'));
            fs::create_dir_all(&host_path)?;
            cmd.args(&["-v", &format!("{}:{}", host_path.display(), container_path)]);
        }

        // Environment variables
        cmd.args(&["-e", &format!("PORT={}", dc.http_port)]);
        for (key, val) in &self.config.environment {
            cmd.args(&["-e", &format!("{}={}", key, val)]);
        }

        cmd.arg(&image_name);

        if !command.is_empty() {
            cmd.args(&["/bin/sh", "-c", command]);
        }

        Ok(cmd)
    }

    async fn watch_files(self: Arc<Self>) -> Result<()> {
        let proj = self.clone();

        // Watch files with callback
        file_watcher::Watcher::new()
            .set_base_dir(&self.dir)
            .add_includes(&self.config.reload.include)
            .add_excludes(&self.config.reload.exclude)
            .run_debounced(100, move |path| {
                proj.logger.write("supervisor", &format!("Stopping due to file changes: {}", path.display()));
                proj.request_stop(StopReason::FileChange);
            })
            .await?;

        Ok(())
    }

    fn stop_watcher(&self) {
        // Abort the file watcher task
        if let Ok(mut guard) = self.watcher_task.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }

    /// Stop this project (for server shutdown)
    pub fn stop(self: Arc<Self>) {
        self.request_stop(StopReason::Shutdown);
    }

    /// Get the project type name for dashboard display
    pub fn get_type_name(&self) -> String {
        match &self.config.project_type {
            ProjectType::Application { docker: Some(_), .. } => "Docker",
            ProjectType::Application { .. } => "Application",
            ProjectType::Static => "Static",
            ProjectType::Redirect { .. } => "Redirect",
            ProjectType::Proxy { .. } => "Proxy",
            ProjectType::TcpForward { .. } => "TCP Forward",
            ProjectType::UnixForward { .. } => "Unix Forward",
            ProjectType::Dashboard => "Dashboard",
        }.to_string()
    }

    /// Get the current status for dashboard display
    pub fn get_status(&self) -> String {
        match &self.config.project_type {
            ProjectType::Application { .. } => {
                match *self.state_rx.borrow() {
                    AppState::Stopped => "Stopped".to_string(),
                    AppState::Starting => "Starting".to_string(),
                    AppState::Running => {
                        // Try to get port from app_connection without blocking
                        if let Ok(conn) = self.app_connection.try_lock() {
                            if let Some(c) = conn.as_ref() {
                                return format!("Running (port {})", c.port);
                            }
                        }
                        "Running".to_string()
                    }
                    AppState::Failed => "Failed".to_string(),
                }
            }
            _ => "Active".to_string()
        }
    }

    /// Get pending request count
    pub fn get_pending_requests(&self) -> u64 {
        self.pending_requests.load(Ordering::Relaxed)
    }

    /// Get total request count
    pub fn get_total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Get active upgraded (WebSocket) connections
    pub fn get_active_upgrades(&self) -> u64 {
        self.active_upgrades.load(Ordering::Relaxed)
    }

    /// Get seconds since last activity (returns None if lock unavailable)
    pub fn get_idle_seconds(&self) -> Option<u64> {
        self.last_activity.try_lock().ok().map(|guard| guard.elapsed().as_secs())
    }

    async fn proxy_upgrade(
        self: Arc<Self>,
        req: Request<Incoming>,
    ) -> Result<Response<StreamBody>> {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let headers = req.headers().clone();
        let logger = self.logger.clone();
        
        // Track this as an active upgrade to prevent inactivity timeout
        self.active_upgrades.fetch_add(1, Ordering::SeqCst);
        let project = self.clone();

        // Get the upgrade future before we return a response
        let upgrade_fut = hyper::upgrade::on(req);

        // Get the connector from the appropriate source
        let mut connector = if let Some(c) = &self.static_connector {
            c.clone()
        } else {
            let conn = self.app_connection.lock().await;
            match conn.as_ref() {
                Some(c) => c.connector.clone(),
                None => anyhow::bail!("502 application not started"),
            }
        };

        // Connect to backend
        let io = connector.call(uri.clone()).await.map_err(|e| anyhow::anyhow!("Connector error: {}", e))?;
        let mut backend = io.into_tokio();

        // Build and send the upgrade request to backend
        let mut buf = Vec::new();
        use std::io::Write;

        let path = uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .to_string();
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

        // Read response headers from backend
        let mut response_buf = [0u8; 4096];
        let mut bytes_read = 0;

        let header_end = loop {
            let n = backend
                .read(&mut response_buf[bytes_read..])
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read backend response: {}", e))?;

            if n == 0 {
                return Err(anyhow::anyhow!(
                    "Backend closed connection during handshake"
                ));
            }

            bytes_read += n;
            let window = &response_buf[..bytes_read];
            if let Some(idx) = window.windows(4).position(|w| w == b"\r\n\r\n") {
                break idx + 4;
            }
            if bytes_read == response_buf.len() {
                return Err(anyhow::anyhow!("Response headers too long"));
            }
        };

        let response_str = String::from_utf8_lossy(&response_buf[..header_end]);

        // Parse backend response to extract status and headers
        let mut response_lines = response_str.lines();
        let status_line = response_lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("Empty backend response"))?;

        // Extract status code from "HTTP/1.1 101 Switching Protocols"
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| anyhow::anyhow!("Invalid status line: {}", status_line))?;

        // Build response with backend's headers
        let mut response_builder = Response::builder().status(status_code);

        for line in response_lines {
            if line.is_empty() {
                break;
            }
            if let Some(colon_idx) = line.find(':') {
                let (name, value) = line.split_at(colon_idx);
                let value = value[1..].trim();
                response_builder = response_builder.header(name.trim(), value);
            }
        }

        // Spawn task to pipe data bidirectionally after upgrade completes
        tokio::task::spawn(async move {
            let result = match upgrade_fut.await {
                Ok(upgraded) => {
                    let mut upgraded = TokioIo::new(upgraded);

                    // Write any excess data from the response to the client
                    if header_end < bytes_read {
                        if let Err(e) = upgraded
                            .write_all(&response_buf[header_end..bytes_read])
                            .await
                        {
                            logger.write("error", &format!("Failed to write excess data to client: {}", e));
                            return;
                        }
                    }

                    // Pipe data bidirectionally
                    tokio::io::copy_bidirectional(&mut upgraded, &mut backend).await.map(|_| ())
                }
                Err(e) => {
                    logger.write("error", &format!("Client upgrade failed: {}", e));
                    Err(std::io::Error::new(std::io::ErrorKind::Other, e))
                }
            };

            if let Err(e) = result {
                if e.kind() != std::io::ErrorKind::NotConnected && e.kind() != std::io::ErrorKind::ConnectionReset {
                    logger.write("error", &format!("WebSocket error: {}", e));
                }
            }

            // Connection closed, update activity and decrement upgrade count
            *project.last_activity.lock().await = Instant::now();
            project.active_upgrades.fetch_sub(1, Ordering::SeqCst);
            project.state_changed.notify_one();
        });

        Ok(response_builder.body(empty_body())?)
    }
}

// Helper function to detect WebSocket upgrade requests
fn is_upgrade_request<B>(req: &Request<B>) -> bool {
    req.headers()
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("upgrade"))
        .unwrap_or(false)
}

fn get_free_port() -> Result<u16> {
    use std::os::unix::io::AsRawFd;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    // Allow immediate port reuse - without this, ~5% failure rate in tests
    unsafe {
        libc::setsockopt(listener.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR,
            &1i32 as *const _ as _, std::mem::size_of::<i32>() as _);
    }
    Ok(listener.local_addr()?.port())
}

fn get_ownership(path: &Path) -> (u32, u32) {
    fs::metadata(path)
        .ok()
        .map(|m| (m.uid(), m.gid()))
        .unwrap_or((0, 0))
}

fn get_user_home(uid: u32) -> String {
    nix::unistd::User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.dir.to_string_lossy().to_string())
        .unwrap_or_else(|| "/tmp".to_string())
}

/// Returns the path to podman or docker, checking PATH on first call.
/// Prefers podman if available, falls back to docker, warns if neither found.
fn get_docker_path() -> &'static str {
    use std::sync::OnceLock;
    use std::os::unix::fs::PermissionsExt;
    static DOCKER_PATH: OnceLock<String> = OnceLock::new();

    DOCKER_PATH.get_or_init(|| {
        let path_var = std::env::var("PATH").unwrap_or_default();
        // Check for podman first (preferred), then docker
        for cmd in &["podman", "docker"] {
            for dir in path_var.split(':') {
                let full_path = PathBuf::from(dir).join(cmd);
                if let Ok(meta) = fs::metadata(&full_path) {
                    if meta.is_file() && (meta.permissions().mode() & 0o111) != 0 {
                        return full_path.to_string_lossy().to_string();
                    }
                }
            }
        }
        // Neither found, warn and fall back to "docker"
        println!("Warning: neither podman nor docker found in PATH, using 'docker'");
        "docker".to_string()
    })
}
