use crate::acme::CertManager;
use crate::project::{self, Project, StreamBody, empty_body, body_from};
use anyhow::Result;
#[cfg(feature = "http3")]
use bytes::Bytes;
use dashmap::DashMap;

#[cfg(feature = "http3")]
use h3_quinn::quinn::crypto::rustls::QuicServerConfig;
use http::HeaderValue;
#[cfg(feature = "http3")]
use http_body_util::BodyExt;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use lazy_static::lazy_static;
use regex::Regex;
use rustls::ServerConfig;
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, Write};
#[cfg(feature = "http3")]
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

lazy_static! {
    pub static ref SHARED_EXECUTOR: TokioExecutor = TokioExecutor::new();
}

// Domain information stored in the global DOMAINS map
struct DomainInfo {
    directory: String,
    project: Option<Arc<Project>>,
    cert_task: Option<tokio::task::JoinHandle<()>>,
}

impl DomainInfo {
    fn new(directory: String, cert_task: Option<tokio::task::JoinHandle<()>>) -> Self {
        Self {
            directory,
            project: None,
            cert_task,
        }
    }
}

impl Drop for DomainInfo {
    fn drop(&mut self) {
        if let Some(cert_task) = self.cert_task.take() {
            cert_task.abort();
        }
        // Tear down the project so its file watcher and lifecycle task don't keep running
        // after the domain is removed or re-registered (otherwise they become zombies that
        // log spurious "Stopping due to file changes" and never get cleaned up).
        if let Some(project) = self.project.take() {
            project.shutdown();
        }
    }
}

lazy_static::lazy_static! {
    static ref DOMAINS: DashMap<String, DomainInfo> = DashMap::new();
    static ref VALID_DOMAIN: Regex = Regex::new(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$").unwrap();
    static ref SERVER_START_TIME: std::time::Instant = std::time::Instant::now();
    static ref CERT_STATUS: DashMap<String, String> = DashMap::new();
    /// Proves to ourselves that a `SELF_CHECK_PATH` response came from this very process.
    static ref SELF_CHECK_TOKEN: String = format!("{:032x}", rand::random::<u128>());
}

/// What `redirect_http` means for a project that doesn't say, filled in by `Server::new`. The
/// dashboard shows what a request actually does rather than the word "unset", and the default is
/// a webcentral-wide flag rather than anything the project owner can change.
static REDIRECT_HTTP_DEFAULT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Path serving `SELF_CHECK_TOKEN`, used to verify a domain resolves to this server (see
/// `Server::points_at_us`).
const SELF_CHECK_PATH: &str = "/.well-known/webcentral-self-check";

/// Streaming body adapter for HTTP/3 - wraps h3 RecvStream as an http_body::Body.
#[cfg(feature = "http3")]
struct H3RecvBody<S: h3::quic::RecvStream> {
    // SyncWrapper only hands out `&mut`, which is what makes this body `Sync` - required by the
    // boxed streaming body every request is converted into - without the h3 stream being so.
    stream: sync_wrapper::SyncWrapper<h3::server::RequestStream<S, Bytes>>,
}

#[cfg(feature = "http3")]
impl<S: h3::quic::RecvStream> http_body::Body for H3RecvBody<S> {
    type Data = Bytes;
    type Error = anyhow::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        use bytes::Buf;
        use std::future::Future;
        
        let fut = self.stream.get_mut().recv_data();
        tokio::pin!(fut);
        
        match fut.poll(cx) {
            std::task::Poll::Ready(Ok(Some(mut buf))) => {
                std::task::Poll::Ready(Some(Ok(http_body::Frame::data(buf.copy_to_bytes(buf.remaining())))))
            }
            std::task::Poll::Ready(Ok(None)) => std::task::Poll::Ready(None),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Some(Err(anyhow::anyhow!("H3 recv error: {}", e))))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// The www-prefixed variant of a bare domain, or the bare variant of a www-prefixed one.
fn alt_domain(domain: &str) -> String {
    domain
        .strip_prefix("www.")
        .map(str::to_owned)
        .unwrap_or_else(|| format!("www.{}", domain))
}

/// Hand a changed file to the project whose directory holds it. Nothing happens for a directory
/// no project has been built for yet - the next request reads the new configuration anyway.
fn file_changed(changed: &std::path::Path) {
    // Paths come back relative to the watcher's base directory, which is the filesystem root, so
    // they arrive without their leading separator.
    let changed = std::path::Path::new("/").join(changed);

    let found = DOMAINS.iter().find_map(|entry| {
        let relative = changed.strip_prefix(&entry.directory).ok()?;
        Some((entry.project.clone()?, relative.to_path_buf()))
    });
    if let Some((project, relative)) = found {
        project.file_changed(relative);
    }
}

/// Forget the project registered for `dir`, whatever domain it is under.
/// The running server, for the few things that have to reach it from outside a request: a project
/// asking to be read again after its configuration changed. A `Weak`, so that dropping the server
/// in a test or on shutdown does not keep it alive.
static SERVER: std::sync::OnceLock<std::sync::Weak<Server>> = std::sync::OnceLock::new();

/// Remember the server, so a project can ask to be read again from outside a request.
pub fn register(server: &Arc<Server>) {
    let _ = SERVER.set(Arc::downgrade(server));
}

/// How long a project directory that *appears* is left alone before its configuration is read
/// unasked. It usually appears because a deploy is in progress, and reading it while its files are
/// still landing would answer requests from half of it - so it is given a moment to stop moving.
/// A request arriving first reads it itself, which makes this a no-op for anything busy.
///
/// A directory that was already there when webcentral started is not landing anywhere, so it is
/// read at once instead: everything is in place before the first request, and a restart has no
/// window in which projects exist but nothing is known about them.
const SETTLE: std::time::Duration = std::time::Duration::from_secs(2);

/// Read a project's configuration without waiting for somebody to make a request first, so its
/// problems reach its log while whoever wrote them is still looking, and the dashboard can show a
/// project nobody has visited. Reading starts no containers - a service is started by a request -
/// though it does prepare their images, which `image_work` keeps to a few at a time.
///
/// Errors are already reported by `Project::new` into the project's own log; there is nothing
/// useful to do with them here.
pub fn load_project(domain: &str, after: std::time::Duration) {
    let Some(server) = SERVER.get().and_then(|weak| weak.upgrade()) else { return };
    let domain = domain.to_string();
    tokio::spawn(async move {
        if !after.is_zero() {
            tokio::time::sleep(after).await;
            // Read by a request in the meantime, which is the common case for a busy domain.
            if DOMAINS.get(&domain).is_some_and(|info| info.project.is_some()) {
                return;
            }
        }
        let _ = server.get_project_for_domain(&domain).await;
    });
}

/// Read it again after the configuration that built it changed. The old one is torn down first -
/// its containers are stopped by `Project::shutdown` before this is called - so the new one finds
/// no container of its own still running.
pub fn reload_project_by_dir(dir: &std::path::Path) {
    let dir = dir.to_string_lossy().to_string();
    let domain = DOMAINS.iter().find(|entry| entry.directory == dir).map(|e| e.key().clone());
    if let Some(domain) = domain {
        // Settled, because the change that triggered this is usually one of many still arriving.
        load_project(&domain, SETTLE);
    }
}

pub fn deregister_project_by_dir(dir: &std::path::Path) {
    let dir = dir.to_string_lossy();
    let domain = DOMAINS.iter().find(|entry| entry.directory == dir).map(|e| e.key().clone());
    if let Some(domain) = domain {
        if let Some(mut info) = DOMAINS.get_mut(&domain) {
            info.project = None;
        }
    }
}

// Stop all running projects (called during shutdown)
pub async fn stop_all_projects() {
    // Collected first: holding DashMap iteration guards across an await would deadlock anything
    // that touches the map while we wait.
    let projects: Vec<_> = DOMAINS.iter().filter_map(|entry| entry.project.clone()).collect();
    // Concurrently, since each one spends a couple of seconds waiting for podman.
    let stopping: Vec<_> =
        projects.into_iter().map(|project| tokio::spawn(project.stop())).collect();
    for handle in stopping {
        let _ = handle.await;
    }
}

/// Get status info for all domains (for dashboard display)
pub fn get_domain_status() -> Vec<DomainStatus> {
    let mut result: Vec<DomainStatus> = DOMAINS.iter().map(|entry| {
        let domain = entry.key().clone();
        let directory = entry.directory.clone();
        let cert_status = CERT_STATUS.get(&domain).map(|s| s.clone());
        match &entry.project {
            Some(project) => DomainStatus {
                // The set of files that reload the project includes the ones it would be defined
                // by if they appeared - naming those would read as a claim that they are there.
                config_files: project
                    .config
                    .config_files
                    .iter()
                    .filter(|file| PathBuf::from(&directory).join(file).exists())
                    .cloned()
                    .collect(),
                domain,
                directory,
                loaded: true,
                services: project.get_service_status(),
                total_requests: project.get_total_requests(),
                cert_status,
                script: project.get_script(),
                source_name: project.config.source_name.clone(),
                settings: project_settings(&project.config),
                read_headers: project.config.read_headers.clone(),
                owner: project.owner_name(),
                problems: project
                    .config
                    .errors
                    .iter()
                    .chain(project.config.warnings.iter())
                    .cloned()
                    .collect(),
            },
            // Deregistered, and not yet rebuilt: the next request to it makes a new one.
            None => DomainStatus {
                domain,
                directory,
                loaded: false,
                services: Vec::new(),
                total_requests: 0,
                cert_status,
                script: Vec::new(),
                source_name: String::new(),
                config_files: Vec::new(),
                settings: Vec::new(),
                read_headers: Vec::new(),
                owner: String::new(),
                problems: Vec::new(),
            },
        }
    }).collect();
    result.sort_by(|a, b| a.domain.cmp(&b.domain));
    result
}

/// The project-wide settings as they actually behave: what the `settings` block said, or what
/// webcentral falls back to when it said nothing.
fn project_settings(config: &crate::config::ProjectConfig) -> Vec<crate::dashboard::Setting> {
    let redirect_http = config
        .redirect_http
        .unwrap_or_else(|| REDIRECT_HTTP_DEFAULT.load(std::sync::atomic::Ordering::Relaxed));
    vec![
        crate::dashboard::Setting {
            name: "redirect_http",
            value: if redirect_http { "to https" } else { "off" }.to_string(),
            explicit: config.redirect_http.is_some(),
        },
        crate::dashboard::Setting {
            name: "redirect_https",
            value: if config.redirect_https == Some(true) { "to http" } else { "off" }.to_string(),
            explicit: config.redirect_https.is_some(),
        },
    ]
}

pub use crate::dashboard::DomainStatus;

/// Server-wide status info
pub struct ServerInfo {
    pub uptime_seconds: u64,
    pub domain_count: usize,
}

/// Get basic server-wide info (thread-safe, no config needed)
pub fn get_server_info() -> ServerInfo {
    ServerInfo {
        uptime_seconds: SERVER_START_TIME.elapsed().as_secs(),
        domain_count: DOMAINS.len(),
    }
}

pub struct Server {
    config: crate::GlobalConfig,
    cert_manager: Option<Arc<CertManager>>,
    bindings: HashSet<String>,
    write_bindings_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Server {
    pub async fn new(config: crate::GlobalConfig) -> Result<Self> {
        // Initialize SERVER_START_TIME, as otherwise it will initialize when we first open the dashoard
        let _ = *SERVER_START_TIME;
        REDIRECT_HTTP_DEFAULT
            .store(config.redirect_http(), std::sync::atomic::Ordering::Relaxed);

        // Create certificate manager if HTTPS is enabled
        let cert_manager = if config.https > 0 {
            let email = config.email.clone().expect("Email required for HTTPS");
            Some(Arc::new(CertManager::new(
                PathBuf::from(&config.data_dir),
                email,
                config.acme_url.clone(),
            )))
        } else {
            None
        };

        let bindings = Self::load_bindings(&config.data_dir);

        Ok(Server {
            config,
            cert_manager,
            bindings,
            write_bindings_task: Mutex::new(None),
        })
    }

    // Read bindings.list file containing authorized project directories
    fn load_bindings(data_dir: &str) -> HashSet<String> {
        let mut bindings = HashSet::new();
        let bindings_path = PathBuf::from(data_dir).join("bindings.list");
        
        if let Ok(file) =  fs::File::open(&bindings_path) {
            let reader = std::io::BufReader::new(file);
            
            for line in reader.lines() {
                if let Ok(path) = line {
                    let path = path.trim();
                    if !path.is_empty() {
                        bindings.insert(path.to_string());
                    }
                }
            }
            println!(
                "Loaded {} authorized bindings from {}",
                bindings.len(),
                bindings_path.display()
            );
        }
        bindings
    }

    // Write current DOMAINS mapping to bindings.list
    fn write_bindings(&self) -> Result<()> {
        let bindings_path = PathBuf::from(&self.config.data_dir).join("bindings.list");

        // Ensure data directory exists
        fs::create_dir_all(&self.config.data_dir)?;

        // Collect all unique directories from DOMAINS
        let mut directories = HashSet::new();
        for entry in DOMAINS.iter() {
            directories.insert(entry.directory.clone());
        }

        // Convert to sorted vector for deterministic output
        let mut sorted_dirs: Vec<_> = directories.into_iter().collect();
        sorted_dirs.sort();

        // Write to file
        let mut file = fs::File::create(&bindings_path)?;
        for dir in sorted_dirs {
            writeln!(file, "{}", dir)?;
        }

        println!(
            "Wrote {} bindings to {}",
            DOMAINS.len(),
            bindings_path.display()
        );
        Ok(())
    }

    // Schedule write_bindings to run 500ms after the last call (debounced)
    fn schedule_write_bindings(self: &Arc<Self>) {
        let server = self.clone();
        tokio::spawn(async move {
            let mut guard = server.write_bindings_task.lock().await;
            // Abort any pending write task
            if let Some(task) = guard.take() {
                task.abort();
            }
            // Spawn new delayed task
            let server_clone = server.clone();
            *guard = Some(tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if let Err(e) = server_clone.write_bindings() {
                    eprintln!("Failed to write bindings: {}", e);
                }
            }));
        });
    }

    pub async fn start(self: Arc<Self>) -> Result<()> {
        // Bind listeners early so we fail fast if ports are in use
        let http_listener = if self.config.http > 0 {
            let addr = format!("0.0.0.0:{}", self.config.http);
            Some(TcpListener::bind(&addr).await.map_err(|e| {
                anyhow::anyhow!("Failed to bind HTTP server on port {}: {}", self.config.http, e)
            })?)
        } else {
            None
        };

        let https_listener = if self.config.https > 0 {
            let addr = format!("0.0.0.0:{}", self.config.https);
            Some(TcpListener::bind(&addr).await.map_err(|e| {
                anyhow::anyhow!("Failed to bind HTTPS server on port {}: {}", self.config.https, e)
            })?)
        } else {
            None
        };

        // Start directory watcher to maintain DOMAINS
        let server = self.clone();
        tokio::spawn(async move {
            if let Err(e) = include_exclude_watcher::Watcher::new()
                .set_base_dir("/")
                .add_include(format!("{}/*.*", server.config.projects))
                .return_absolute(true)
                .match_files(true)
                .watch_update(false)
                .watch_initial(true)
                .run(move |event, path| {
                    // A directory that was already there is read at once; one that just appeared
                    // is probably still being written to.
                    let settle = match event {
                        include_exclude_watcher::WatchEvent::Initial => std::time::Duration::ZERO,
                        _ => SETTLE,
                    };
                    server.process_project_directory(&path, settle);
                })
                .await {
                eprintln!("Directory watcher error: {}", e);
            }
        });

        // One file watcher for every project at once. An inotify *instance* is a scarce
        // per-user resource (fs.inotify.max_user_instances is 128 by default) while the *watches*
        // it holds are not (hundreds of thousands), so one watcher for the whole tree costs the
        // same in watches as one per project and nothing in instances. Which project - and which
        // of its servers - an event concerns is then worked out in `Project`, against the same
        // patterns this watcher was given.
        let server = self.clone();
        tokio::spawn(async move {
            let projects = &server.config.projects;
            // Pruning has to be expressed relative to each project directory, which is what the
            // per-project patterns mean; anchored ones stay at the project root.
            let excludes: Vec<String> = crate::config::DEFAULT_EXCLUDES
                .iter()
                .map(|pattern| match pattern.strip_prefix('/') {
                    Some(anchored) => format!("{}/*.*/{}", projects, anchored),
                    None => format!("{}/*.*/**/{}", projects, pattern),
                })
                .collect();

            if let Err(e) = include_exclude_watcher::Watcher::new()
                .set_base_dir("/")
                .add_include(format!("{}/*.*/**/*", projects))
                .add_excludes(&excludes)
                .return_absolute(true)
                .match_dirs(false)
                .run(move |_event, path| file_changed(&path))
                .await
            {
                eprintln!("File watcher error: {}", e);
            }
        });

        // Start HTTP server
        if let Some(listener) = http_listener {
            println!("HTTP server listening on port {}", self.config.http);
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.run_http_server(listener).await {
                    eprintln!("HTTP server error: {}", e);
                }
            });
        }

        // Start HTTPS server
        if let Some(listener) = https_listener {
            println!("HTTPS server listening on port {}", self.config.https);
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.run_https_server(listener).await {
                    eprintln!("HTTPS server error: {}", e);
                }
            });

            // Start HTTP/3 server (QUIC) on same port - UDP vs TCP
            #[cfg(feature = "http3")]
            if self.config.http3 {
                let server = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = server.run_http3_server().await {
                        eprintln!("HTTP/3 server error: {}", e);
                    }
                });
            }
        }

        Ok(())
    }

    async fn run_http_server(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    handle_accept_error("HTTP", e).await;
                    continue;
                }
            };
            let server = self.clone();

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                if let Err(e) = auto::Builder::new(SHARED_EXECUTOR.clone())
                    .serve_connection_with_upgrades(
                        io,
                        service_fn(move |req| {
                            let server = server.clone();
                            async move { server.handle_http(req, addr).await }
                        }),
                    )
                    .await
                {
                    eprintln!("HTTP connection error from {}: {}", addr, e);
                }
            });
        }
    }

    async fn run_https_server(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        // Create TLS config with SNI resolver
        let cert_manager = self
            .cert_manager
            .as_ref()
            .expect("Certificate manager required for HTTPS");
        let cert_manager_clone = cert_manager.clone();

        let mut tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver {
                cert_manager: cert_manager_clone,
                redirect_www: self.config.redirect_www,
            }));
        
        // ALPN protocols for HTTP/2 and HTTP/1.1 negotiation
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // Disable session tickets and early data - they become invalid after server restart,
        // causing browsers to send encrypted data the server can't decrypt (appears as corrupt TLS).
        tls_config.send_tls13_tickets = 0;

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    handle_accept_error("HTTPS", e).await;
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let server = self.clone();

            tokio::spawn(async move {
                // Perform TLS handshake
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        // Only log if it's not a "no certificate" error (unconfigured domain)
                        let err_str = e.to_string();
                        if !err_str.contains("no server certificate chain resolved") {
                            eprintln!("TLS handshake error from {}: {}", addr, e);
                        }
                        return;
                    }
                };

                // The name the client asked for, which is all the context a failed connection
                // has: a connection-level error means no request was parsed
                let sni = tls_stream.get_ref().1.server_name().unwrap_or("no SNI").to_string();

                let io = TokioIo::new(tls_stream);
                if let Err(e) = auto::Builder::new(SHARED_EXECUTOR.clone())
                    .serve_connection_with_upgrades(
                        io,
                        service_fn(move |req| {
                            let server = server.clone();
                            async move { server.handle_https(req, addr).await }
                        }),
                    )
                    .await
                {
                    eprintln!("HTTPS connection error from {} for {}: {}", addr, sni, e);
                }
            });
        }
    }

    #[cfg(feature = "http3")]
    async fn run_http3_server(self: Arc<Self>) -> Result<()> {
        let cert_manager = self
            .cert_manager
            .as_ref()
            .expect("Certificate manager required for HTTP/3");

        // Build TLS config for QUIC - same as HTTPS but with h3 ALPN
        let mut tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver {
                cert_manager: cert_manager.clone(),
                redirect_www: self.config.redirect_www,
            }));
        tls_config.alpn_protocols = vec![b"h3".to_vec()];
        // Disable session tickets and early data for QUIC - they become invalid after server restart.
        tls_config.send_tls13_tickets = 0;

        let quic_config = QuicServerConfig::try_from(tls_config)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC server config: {}", e))?;

        let server_config = h3_quinn::quinn::ServerConfig::with_crypto(Arc::new(quic_config));
        let addr: SocketAddr = format!("0.0.0.0:{}", self.config.https).parse()?;

        let endpoint = h3_quinn::quinn::Endpoint::server(server_config, addr)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC endpoint: {}", e))?;

        println!("HTTP/3 server listening on port {} (UDP)", self.config.https);

        while let Some(incoming) = endpoint.accept().await {
            let server = self.clone();
            let peer = incoming.remote_address();
            tokio::spawn(async move {
                if let Err(e) = server.handle_http3_connection(incoming).await {
                    let err_str = e.to_string();
                    // Don't log "no certificate" errors (unconfigured domain) or idle timeouts
                    if !err_str.contains("no server certificate") && !err_str.contains("Timeout") {
                        eprintln!("HTTP/3 connection error from {}: {}", peer, e);
                    }
                }
            });
        }

        Ok(())
    }

    #[cfg(feature = "http3")]
    async fn handle_http3_connection(
        self: Arc<Self>,
        incoming: h3_quinn::quinn::Incoming,
    ) -> Result<()> {
        let addr = incoming.remote_address();
        let conn = incoming.accept()?.await?;
        let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;

        loop {
            match h3_conn.accept().await {
                Ok(Some(resolver)) => {
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_http3_request(resolver, addr).await {
                            eprintln!("HTTP/3 request error: {}", e);
                        }
                    });
                }
                Ok(None) => break, // Connection closed gracefully
                Err(e) => {
                    return Err(anyhow::anyhow!("HTTP/3 accept error: {}", e));
                }
            }
        }

        Ok(())
    }

    #[cfg(feature = "http3")]
    async fn handle_http3_request<C>(
        &self,
        resolver: h3::server::RequestResolver<C, Bytes>,
        addr: SocketAddr,
    ) -> Result<()>
    where
        C: h3::quic::Connection<Bytes>,
        C::BidiStream: h3::quic::BidiStream<Bytes>,
        <C::BidiStream as h3::quic::BidiStream<Bytes>>::RecvStream: Send + 'static,
    {
        let (req, stream) = resolver.resolve_request().await?;

        // Split stream into send/recv halves for concurrent request/response streaming
        let (mut send_stream, recv_stream) = stream.split();

        // Extract domain from headers before consuming request
        let (mut parts, _) = req.into_parts();
        let domain = match self.extract_domain_from_parts(&parts) {
            Some(d) => d,
            None => {
                let resp = http::Response::builder().status(StatusCode::BAD_REQUEST).body(()).unwrap();
                send_stream.send_response(resp).await?;
                send_stream.send_data(Bytes::from("Bad Request")).await?;
                return Ok(send_stream.finish().await?);
            }
        };

        // Get project
        let project = match self.get_project_for_domain(&domain).await {
            Ok(p) => p,
            Err(_) => {
                let resp = http::Response::builder().status(StatusCode::NOT_FOUND).body(()).unwrap();
                send_stream.send_response(resp).await?;
                send_stream.send_data(Bytes::from("Not Found")).await?;
                return Ok(send_stream.finish().await?);
            }
        };

        // Wrap recv stream as streaming body
        let body = H3RecvBody { stream: sync_wrapper::SyncWrapper::new(recv_stream) };

        // Add forwarding headers (for the likely case this connection will be proxied)
        if let Ok(forwarded_for) = HeaderValue::from_str(&addr.ip().to_string()) {
            parts.headers.insert("X-Forwarded-For", forwarded_for);
        }
        parts.headers.insert("X-Forwarded-Proto", HeaderValue::from_static("https"));
 
        let req = Request::from_parts(parts, body);

        // Handle request with streaming body - HTTP/3 doesn't support upgrades
        let logger = project.logger.clone();
        let domain = project.domain.clone();
        let response = project.clone().handle_inner(req).await;

        match response {
            Ok(resp) => {
                // Send response headers
                let (resp_parts, mut body) = resp.into_parts();
                let mut builder = http::Response::builder().status(resp_parts.status);
                for (name, value) in resp_parts.headers.iter() {
                    // Skip connection-specific headers forbidden in HTTP/3
                    let name_lower = name.as_str().to_lowercase();
                    if name_lower == "transfer-encoding" 
                        || name_lower == "connection"
                        || name_lower == "keep-alive"
                        || name_lower == "upgrade"
                        || name_lower == "proxy-connection"
                    {
                        continue;
                    }
                    builder = builder.header(name, value);
                }
                // HTTP/3 is always over TLS, so add HSTS
                let hsts = if self.should_redirect_to_https(&project) { "max-age=31536000; includeSubDomains" } else { "max-age=0" };
                builder = builder.header("Strict-Transport-Security", hsts);
                send_stream.send_response(builder.body(()).unwrap()).await?;
                
                // Stream response body
                while let Some(chunk) = body.frame().await {
                    match chunk {
                        Ok(frame) => {
                            if let Some(data) = frame.data_ref() {
                                send_stream.send_data(data.clone()).await?;
                            }
                        }
                        Err(e) => {
                            eprintln!("HTTP/3 body stream error: {}", e);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                let msg = e.to_string();
                eprintln!("HTTP/3 request error for {}: {}", domain, msg);
                logger.write("error", &msg);
                let status = if msg.starts_with("502 ") {
                    StatusCode::BAD_GATEWAY
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                };
                // HTTP/3 is always over TLS, so add HSTS
                let resp = http::Response::builder()
                    .status(status)
                    .header("Strict-Transport-Security", if self.should_redirect_to_https(&project) { "max-age=31536000; includeSubDomains" } else { "max-age=0" })
                    .body(()).unwrap();
                send_stream.send_response(resp).await?;
                send_stream.send_data(Bytes::from(status.canonical_reason().unwrap_or("Error"))).await?;
            }
        }

        Ok(send_stream.finish().await?)
    }

    #[cfg(feature = "http3")]
    fn extract_domain_from_parts(&self, parts: &http::request::Parts) -> Option<String> {
        // h3 puts :authority in the URI, fall back to headers
        let host = parts.uri.host()
            .map(|h| h.to_string())
            .or_else(|| parts.headers.get("host").and_then(|h| h.to_str().ok()).map(|s| s.to_string()))
            .or_else(|| parts.headers.get(":authority").and_then(|h| h.to_str().ok()).map(|s| s.to_string()))?;
        let host = host.split(':').next().unwrap_or(&host).to_lowercase();
        if !VALID_DOMAIN.is_match(&host) { return None; }
        Some(host)
    }

    async fn handle_http(
        &self,
        req: Request<hyper::body::Incoming>,
        addr: std::net::SocketAddr,
    ) -> Result<Response<StreamBody>, hyper::Error> {
        let path = req.uri().path();
        if path == SELF_CHECK_PATH {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(body_from(SELF_CHECK_TOKEN.clone()))
                .unwrap());
        }

        // Handle ACME HTTP-01 challenges
        if path.starts_with("/.well-known/acme-challenge/") {
            let token = &path[28..]; // Skip "/.well-known/acme-challenge/"
            if let Some(cert_manager) = &self.cert_manager {
                if let Some(key_auth) = cert_manager.get_challenge(token).await {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/plain")
                        .body(body_from(key_auth))
                        .unwrap());
                }
            }
            eprintln!("ACME challenge not found for token {} (domain: {})", token,
                req.headers().get("host").and_then(|h| h.to_str().ok()).unwrap_or("unknown"));
            return Ok(Self::make_error(
                StatusCode::NOT_FOUND,
                "Challenge not found",
            ));
        }

        self.route_request(req, addr, false).await
    }

    async fn handle_https(
        &self,
        req: Request<hyper::body::Incoming>,
        addr: std::net::SocketAddr,
    ) -> Result<Response<StreamBody>, hyper::Error> {
        self.route_request(req, addr, true).await
    }

    fn make_redirect(&self, scheme: &str, project: &Project, req: &Request<hyper::body::Incoming>) -> Response<StreamBody> {
        let port_suffix = match scheme {
            "http" if self.config.http != 80 => format!(":{}", self.config.http),
            "https" if self.config.https != 443 => format!(":{}", self.config.https),
            _ => String::new(),
        };
        let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let url = format!("{}://{}{}{}", scheme, &project.domain, port_suffix, path);
        Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header("Location", url)
            .body(empty_body())
            .unwrap()
    }

    fn make_error(status: StatusCode, message: &str) -> Response<StreamBody> {
        Response::builder()
            .status(status)
            .body(body_from(message.to_owned()))
            .unwrap()
    }

    async fn route_request(
        &self,
        mut req: Request<hyper::body::Incoming>,
        addr: std::net::SocketAddr,
        from_https: bool,
    ) -> Result<Response<StreamBody>, hyper::Error> {
        if let Some(host) = req.headers().get("host").and_then(|h| h.to_str().ok()) {
            let scheme = if from_https { "https" } else { "http" };
            let path_and_query = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
            let uri_string = format!("{}://{}{}", scheme, host, path_and_query);
            if let Ok(uri) = uri_string.parse() {
                *req.uri_mut() = uri;
            }
        }

        let domain = if let Some(d) = self.extract_domain(&req) {
            d
        } else {
            return Ok(Self::make_error(
                StatusCode::BAD_REQUEST,
                "Bad Request: Missing Host header",
            ));
        };

        let project = match self.get_project_for_domain(&domain).await {
            Ok(p) => p,
            Err(_) => {
                // Check for www redirect
                if self.config.redirect_www {
                    if let Ok(project) = self.get_project_for_domain(&alt_domain(&domain)).await {
                        let scheme = if from_https { "https" } else { "http" };
                        return Ok(self.make_redirect(scheme, &project, &req));
                    }
                }
                return Ok(Self::make_error(StatusCode::NOT_FOUND, "Not Found"));
            }
        };

        // Check for HTTP/HTTPS redirect based on project config first, then server config
        if from_https {
            // HTTPS request - check if we should redirect to HTTP
            if project.config.redirect_https == Some(true) {
                return Ok(self.make_redirect("http", &project, &req));
            }
        } else {
            // HTTP request - check if we should redirect to HTTPS
            
            if self.should_redirect_to_https(&project) {
                return Ok(self.make_redirect("https", &project, &req));
            }
        }

        // Handle request with project - response body is streamed directly to client
        let logger = project.logger.clone();

        // Add forwarding headers (for the likely case this connection will be proxied)
        if let Ok(forwarded_for) = HeaderValue::from_str(&addr.ip().to_string()) {
            req.headers_mut().insert("X-Forwarded-For", forwarded_for);
        }
        req.headers_mut().insert("X-Forwarded-Proto", HeaderValue::from_static(if from_https { "https" } else { "http" }));

        let result = match project.clone().handle(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                let msg = e.to_string();
                logger.write("error", &msg);
                if msg.starts_with("502 ") {
                    Ok(Self::make_error(StatusCode::BAD_GATEWAY, "Bad Gateway"))
                } else {
                    Ok(Self::make_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"))
                }
            }
        };

        // Add HSTS and Alt-Svc headers for HTTPS responses
        if from_https {
            if let Ok(mut resp) = result {
                let hsts = if self.should_redirect_to_https(&project) { "max-age=31536000; includeSubDomains" } else { "max-age=0" };
                resp.headers_mut().insert("Strict-Transport-Security", hsts.parse().unwrap());
                if self.config.http3 {
                    let alt_svc = format!("h3=\":{}\"; ma=86400", self.config.https);
                    resp.headers_mut().insert("Alt-Svc", alt_svc.parse().unwrap());
                }
                return Ok(resp);
            }
        }

        result
    }

    fn extract_domain(&self, req: &Request<hyper::body::Incoming>) -> Option<String> {
        let host = req.uri().host()?.to_lowercase();

        // Validate domain format
        if !VALID_DOMAIN.is_match(&host) {
            return None;
        }

        Some(host)
    }

    fn should_redirect_to_https(&self, project: &Project) -> bool {
        if self.config.https == 0 {
            return false;
        }
        project.config.redirect_http.unwrap_or_else(|| self.config.redirect_http())
    }

    async fn get_project_for_domain(&self, domain: &str) -> Result<Arc<Project>> {
        // First do an immutable lookup
        let domain_info = DOMAINS
            .get(domain)
            .ok_or_else(|| anyhow::anyhow!("Domain not found: {}", domain))?;
        if let Some(project) = domain_info.project.as_ref() {
            return Ok(project.clone());
        }
        drop(domain_info); // Drop immutable lock

        // Now get a mutable lock on the domain_info, to prevent race conditions
        let mut domain_info = DOMAINS
            .get_mut(domain)
            .ok_or_else(|| anyhow::anyhow!("Domain not found: {}", domain))?;
        if let Some(project) = domain_info.project.as_ref() {
            // Was project was created in the mean time.
            return Ok(project.clone());
        }

        // Create or recreate project
        let project = project::Project::new(
            &PathBuf::from(&domain_info.directory),
            domain.to_string(),
            self.config.prune_logs,
        )?;

        // Store in domain info
        domain_info.project = Some(project.clone());

        Ok(project)
    }

    // Process a directory path, validating domain and setting up project + certificate
    fn process_project_directory(
        self: &Arc<Self>,
        path: &std::path::Path,
        settle: std::time::Duration,
    ) {
        let Some(domain_name) = path.file_name().and_then(|n| n.to_str()) else {
            return ; // Shouldn't happen?
        };
        if !VALID_DOMAIN.is_match(domain_name) {
            return; // It doesn't look like a domain name
        }
        let domain = domain_name.to_lowercase();

        let directory = path.to_string_lossy().to_string();

        if !path.is_dir() {
            // Path is gone (or no longer a directory; is_dir follows symlinks). Handle deletion,
            // but only if the registered project is the one for this directory - otherwise a
            // stale delete event could tear down a project that was since re-registered elsewhere.
            if let Some(existing) = DOMAINS.get(&domain) {
                if existing.directory == directory {
                    drop(existing);
                    println!("Domain {} removed ({:?})", domain, directory);
                    DOMAINS.remove(&domain); // Dropping the DomainInfo shuts down its project
                    CERT_STATUS.remove(&domain);
                    self.schedule_write_bindings();
                }
            }
            return;
        }
        
        // Check if domain exists and if transfer is allowed
        if let Some(existing) = DOMAINS.get(&domain) {
            let existing_dir_gone = !std::path::Path::new(&existing.directory).exists();
            let authorized = self.bindings.contains(&directory);
            if !existing_dir_gone && !authorized {
                println!(
                    "Rejecting domain override attempt for {} from unauthorized directory {}",
                    domain, directory
                );
                return;
            }
            println!(
                "Overriding domain {} from {} to {}{}",
                domain,
                existing.directory,
                directory,
                if authorized {
                    " (authorized)"
                } else {
                    " (directory gone)"
                }
            );
        }

        // Start certificate management task if HTTPS is enabled
        let cert_task = self.cert_manager.is_some().then(|| {
            let server = self.clone();
            let domain = domain.clone();
            tokio::spawn(async move { server.manage_certificate(domain).await })
        });

        println!("Domain {} added ({:?})", &domain, directory);
        DOMAINS.insert(domain.clone(), DomainInfo::new(directory, cert_task));
        self.schedule_write_bindings();
        load_project(&domain, settle);
    }

    /// Whether `domain` resolves to this very process on port 80, verified by fetching a path
    /// only we can answer with a token that is new for every run. `Err` describes why it doesn't.
    ///
    /// This is the same round trip the ACME server makes for an HTTP-01 challenge, so it tells us
    /// up front whether an order including this name could succeed - without bothering Let's
    /// Encrypt (and burning its rate limits) for names that aren't pointed here.
    async fn points_at_us(&self, domain: &str) -> Result<(), String> {
        let request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", SELF_CHECK_PATH, domain);
        let response = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = tokio::net::TcpStream::connect((domain, 80)).await?;
            stream.write_all(request.as_bytes()).await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            Ok::<_, std::io::Error>(response)
        }).await;

        match response {
            // `contains` rather than an exact body match, so an intermediary that reformats or
            // pads the response doesn't fail a check the ACME server would pass
            Ok(Ok(response)) if String::from_utf8_lossy(&response).contains(SELF_CHECK_TOKEN.as_str()) => Ok(()),
            Ok(Ok(_)) => Err("it is served by a different web server".to_string()),
            Ok(Err(e)) => Err(format!("port 80 is unreachable: {}", e)),
            Err(_) => Err("port 80 did not respond within 10s".to_string()),
        }
    }

    async fn manage_certificate(&self, domain: String) {
        let cert_manager = self.cert_manager.as_ref().unwrap();
        const RENEW_BEFORE: i32 = 7 * 24 * 60 * 60;
        let mut backoff_time = 15 * 60; // 15m, growing to 16h on repeated acquisition failures

        let alt = self.config.redirect_www.then(|| alt_domain(&domain));
        // What we last successfully ordered, so that a name the CA leaves out of the certificate
        // can't make us re-order it on every cycle
        let mut ordered: Option<Vec<String>> = None;

        loop {
            // Names that don't reach us can only fail the HTTP-01 challenge, taking the whole
            // order (and Let's Encrypt rate limits) down with them. Usually only one of a
            // www/non-www pair is pointed here, so the counterpart is included only when it is.
            // Re-checked on every cycle, including while the certificate is still valid, so a
            // domain that stops pointing here is reported long before its renewal fails.
            let domain_check = self.points_at_us(&domain).await;
            let alt_check = match &alt {
                Some(alt) => Some((alt, self.points_at_us(alt).await)),
                None => None,
            };

            let mut names = vec![domain.clone()];
            // Kept short: appended to whatever single line the cycle ends up logging
            let alt_note = match &alt_check {
                Some((alt, Ok(()))) => {
                    names.push(alt.to_string());
                    format!(", with {}", alt)
                }
                Some((alt, Err(reason))) => format!(", without {} ({})", alt, reason),
                None => String::new(),
            };

            if let Err(reason) = &domain_check {
                eprintln!("ERROR: no certificate for {}{}: it does not point at this server, as {}. \
                    Check its DNS record, and that this server is reachable on port 80", domain, alt_note, reason);
                CERT_STATUS.insert(domain.clone(), "Not pointed here".to_string());
                tokio::time::sleep(to_jittered_duration(60 * 60)).await;
                continue;
            }

            // Sleep until renewal time if the certificate is still valid for long enough and
            // already covers every name we want on it
            let renewal_reason = match cert_manager.get_certificate_info(&domain) {
                Err(_) => "none stored yet".to_string(),
                Ok((expiration, covered)) => match expiration.duration_since(std::time::SystemTime::now()) {
                    Err(_) => {
                        CERT_STATUS.insert(domain.clone(), "Expired".to_string());
                        "expired".to_string()
                    }
                    Ok(remaining) => {
                        let days = remaining.as_secs() / 86400;
                        let complete = names.iter().all(|name| covered.contains(name))
                            || ordered.as_ref() == Some(&names);
                        match remaining.checked_sub(to_jittered_duration(RENEW_BEFORE)) {
                            Some(sleep_time) if complete => {
                                CERT_STATUS.insert(domain.clone(), format!("Valid ({}d)", days));
                                println!("Certificate for {}{} is valid for {}d", domain, alt_note, days);
                                tokio::time::sleep(sleep_time).await;
                                continue;
                            }
                            Some(_) => "names changed".to_string(),
                            None => {
                                CERT_STATUS.insert(domain.clone(), format!("Renewing ({}d left)", days));
                                format!("{}d left", days)
                            }
                        }
                    }
                },
            };

            // No line on success: the next cycle logs the new certificate as valid
            println!("Requesting certificate for {}{} ({})", domain, alt_note, renewal_reason);
            CERT_STATUS.insert(domain.clone(), "Acquiring".to_string());
            match cert_manager.acquire_certificate(&names).await {
                Ok(()) => {
                    ordered = Some(names);
                    backoff_time = 15 * 60;
                }
                Err(e) => {
                    // Add +/- 10% jitter
                    let sleep_time = to_jittered_duration(backoff_time);
                    if backoff_time < 12*60*60 { // 15m, 1h, 4h, 16h
                        backoff_time *= 4;
                    }
                    CERT_STATUS.insert(domain.clone(), format!("Error (retry {}m)", sleep_time.as_secs() / 60));
                    eprintln!("Failed to acquire certificate for {}: {:?} (retrying in {}s)", names.join(" and "), e, sleep_time.as_secs());
                    tokio::time::sleep(sleep_time).await;
                }
            }
        }
    }

    pub async fn stop(&self) {
        // Shutdown logic
        println!("Stopping server...");
    }
}

// SNI certificate resolver for rustls
#[derive(Debug)]
struct CertResolver {
    cert_manager: Arc<CertManager>,
    redirect_www: bool,
}

impl rustls::server::ResolvesServerCert for CertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let server_name = client_hello.server_name()?;
        let domain: &str = server_name.as_ref();

        // Load certificate for the requested domain. A www/non-www counterpart shares the
        // registered domain's certificate, which is stored under that domain's name.
        let certificate = self.cert_manager.get_certificate(domain).or_else(|e| {
            if self.redirect_www { self.cert_manager.get_certificate(&alt_domain(domain)) } else { Err(e) }
        });
        let (certs, key) = match certificate {
            Ok(cert) => cert,
            Err(_) => {
                eprintln!("HTTPS request for {} but no certificate is available yet", domain);
                return None;
            }
        };

        let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).ok()?;

        Some(Arc::new(rustls::sign::CertifiedKey::new(
            certs,
            signing_key,
        )))
    }
}

/// Handle an error from `TcpListener::accept()` without leaving the accept loop.
///
/// An accept error is never fatal to the listening socket, but returning from the accept loop
/// would drop the `TcpListener` and stop listening for the rest of the process lifetime - while
/// the process itself stays alive, so systemd's `Restart=always` never kicks in and the port
/// silently disappears until someone restarts it manually.
///
/// Per-connection errors (ECONNABORTED, and the Linux "pending network error" family that
/// accept(2) says to treat like EAGAIN) are retried immediately. Resource exhaustion is retried
/// after a delay: the pending connection stays in the accept queue and keeps the listener
/// readable, so retrying immediately would spin a core at 100% without making progress.
async fn handle_accept_error(proto: &str, e: std::io::Error) {
    let exhausted = matches!(
        e.raw_os_error(),
        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOBUFS) | Some(libc::ENOMEM)
    );
    eprintln!(
        "{} accept error: {}{}",
        proto,
        e,
        if exhausted { " (retrying in 500ms)" } else { " (retrying)" }
    );
    if exhausted {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

fn to_jittered_duration(seconds: i32) -> std::time::Duration {
    use rand::Rng;
    std::time::Duration::from_secs(
        ((seconds as f64 * rand::rng().random_range(0.9..=1.1)).max(0.0)).round() as u64,
    )
}
