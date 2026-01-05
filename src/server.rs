use crate::acme::CertManager;
use crate::project::{self, Project, StreamBody, empty_body, body_from};
use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;

#[cfg(feature = "http3")]
use h3_quinn::quinn::crypto::rustls::QuicServerConfig;
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
    }
}

lazy_static::lazy_static! {
    static ref DOMAINS: DashMap<String, DomainInfo> = DashMap::new();
    static ref VALID_DOMAIN: Regex = Regex::new(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$").unwrap();
    static ref SERVER_START_TIME: std::time::Instant = std::time::Instant::now();
    static ref CERT_STATUS: DashMap<String, String> = DashMap::new();
}

/// Streaming body adapter for HTTP/3 - wraps h3 RecvStream as an http_body::Body.
#[cfg(feature = "http3")]
struct H3RecvBody<S: h3::quic::RecvStream> {
    stream: h3::server::RequestStream<S, Bytes>,
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
        
        let fut = self.stream.recv_data();
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

/// Deregister a project (only if it's still the current one for the domain).
/// Called when a project enters Failed state or on file change.
pub fn deregister_project(domain: &str, project: &Arc<project::Project>) {
    if let Some(mut domain_info) = DOMAINS.get_mut(domain) {
        if let Some(ref current) = domain_info.project {
            if Arc::ptr_eq(current, project) {
                domain_info.project = None;
            }
        }
    }
}

// Stop all running projects (called during shutdown)
pub fn stop_all_projects() {
    for entry in DOMAINS.iter() {
        if let Some(project) = entry.project.clone() {
            project.stop();
        }
    }
}

/// Get status info for all domains (for dashboard display)
pub fn get_domain_status() -> Vec<DomainStatus> {
    let mut result: Vec<DomainStatus> = DOMAINS.iter().map(|entry| {
        let domain = entry.key().clone();
        let directory = entry.directory.clone();
        let cert_status = CERT_STATUS.get(&domain).map(|s| s.clone());
        if let Some(project) = &entry.project {
            DomainStatus {
                domain,
                directory,
                project_type: project.get_type_name(),
                status: project.get_status(),
                pending_requests: project.get_pending_requests(),
                total_requests: project.get_total_requests(),
                idle_seconds: project.get_idle_seconds(),
                cert_status,
            }
        } else {
            DomainStatus {
                domain,
                directory,
                project_type: "Unknown".to_string(),
                status: "Not loaded".to_string(),
                pending_requests: 0,
                total_requests: 0,
                idle_seconds: None,
                cert_status,
            }
        }
    }).collect();
    result.sort_by(|a, b| a.domain.cmp(&b.domain));
    result
}

/// Status info for a single domain
pub struct DomainStatus {
    pub domain: String,
    pub directory: String,
    pub project_type: String,
    pub status: String,
    pub pending_requests: u64,
    pub total_requests: u64,
    pub idle_seconds: Option<u64>,
    pub cert_status: Option<String>,
}

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
            use include_exclude_watcher as file_watcher;

            if let Err(e) = file_watcher::Watcher::new()
                .set_base_dir("/")
                .add_include(format!("{}/*.*", server.config.projects))
                .return_absolute(true)
                .match_files(false)
                .watch_update(false)
                .watch_initial(true)
                .run(move |_event, path| {
                    server.process_project_directory(&path);
                })
                .await {
                eprintln!("Directory watcher error: {}", e);
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
            let (stream, _) = listener.accept().await?;
            let server = self.clone();

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                if let Err(e) = auto::Builder::new(SHARED_EXECUTOR.clone())
                    .serve_connection_with_upgrades(
                        io,
                        service_fn(move |req| {
                            let server = server.clone();
                            async move { server.handle_http(req).await }
                        }),
                    )
                    .await
                {
                    eprintln!("HTTP connection error: {}", e);
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
            }));
        
        // ALPN protocols for HTTP/2 and HTTP/1.1 negotiation
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // Disable session tickets and early data - they become invalid after server restart,
        // causing browsers to send encrypted data the server can't decrypt (appears as corrupt TLS).
        tls_config.send_tls13_tickets = 0;

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        loop {
            let (stream, _addr) = listener.accept().await?;
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
                            eprintln!("TLS handshake error: {}", e);
                        }
                        return;
                    }
                };

                let io = TokioIo::new(tls_stream);
                if let Err(e) = auto::Builder::new(SHARED_EXECUTOR.clone())
                    .serve_connection_with_upgrades(
                        io,
                        service_fn(move |req| {
                            let server = server.clone();
                            async move { server.handle_https(req).await }
                        }),
                    )
                    .await
                {
                    eprintln!("HTTPS connection error: {}", e);
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
            tokio::spawn(async move {
                if let Err(e) = server.handle_http3_connection(incoming).await {
                    let err_str = e.to_string();
                    // Don't log "no certificate" errors (unconfigured domain) or idle timeouts
                    if !err_str.contains("no server certificate") && !err_str.contains("Timeout") {
                        eprintln!("HTTP/3 connection error: {}", e);
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
        let conn = incoming.accept()?.await?;
        let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;

        loop {
            match h3_conn.accept().await {
                Ok(Some(resolver)) => {
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_http3_request(resolver).await {
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
        let (parts, _) = req.into_parts();
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
        let body = H3RecvBody { stream: recv_stream };
        let req = Request::from_parts(parts, body);

        // Handle request with streaming body - HTTP/3 doesn't support upgrades
        let logger = project.logger.clone();
        let domain = project.domain.clone();
        let response = project.handle_inner(req).await;

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
                builder = builder.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
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
                    .header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
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
    ) -> Result<Response<StreamBody>, hyper::Error> {
        // Handle ACME HTTP-01 challenges
        let path = req.uri().path();
        if path.starts_with("/.well-known/acme-challenge/") {
            if let Some(cert_manager) = &self.cert_manager {
                let token = &path[28..]; // Skip "/.well-known/acme-challenge/"
                if let Some(key_auth) = cert_manager.get_challenge(token).await {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/plain")
                        .body(body_from(key_auth))
                        .unwrap());
                }
            }
            return Ok(Self::make_error(
                StatusCode::NOT_FOUND,
                "Challenge not found",
            ));
        }

        self.route_request(req, false).await
    }

    async fn handle_https(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<StreamBody>, hyper::Error> {
        self.route_request(req, true).await
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
                    let alt_domain = domain.strip_prefix("www.")
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("www.{}", domain));

                    if let Ok(project) = self.get_project_for_domain(&alt_domain).await {
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
            let should_redirect = if let Some(redirect_http) = project.config.redirect_http {
                // Project config takes precedence
                redirect_http && self.config.https > 0
            } else {
                // Fall back to server config
                self.config.redirect_http() && self.config.https > 0
            };

            if should_redirect {
                return Ok(self.make_redirect("https", &project, &req));
            }
        }

        // Handle request with project - response body is streamed directly to client
        let logger = project.logger.clone();
        let result = match project.handle(req).await {
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
                resp.headers_mut().insert("Strict-Transport-Security", "max-age=31536000; includeSubDomains".parse().unwrap());
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
            self.config.firejail,
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
    ) {
        if !path.is_dir() {
            return; // It's a file
        }
        let Some(domain_name) = path.file_name().and_then(|n| n.to_str()) else {
            return ; // Shouldn't happen?
        };
        if !VALID_DOMAIN.is_match(domain_name) {
            return; // It doesn't look like a domain name
        }
        let domain = domain_name.to_lowercase();

        if !path.exists() {
            // Handle deletion
            if DOMAINS.contains_key(&domain) {
                println!("Domain {} removed ({:?})", domain, path.to_string_lossy());
                DOMAINS.remove(&domain);
                self.schedule_write_bindings();
            }
            return;
        }
        
        let directory = path.to_string_lossy().to_string();
        
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
        let cert_task = if self.cert_manager.is_some() {
            let server = self.clone();
            let domain = domain.clone();
            Some(tokio::spawn(async move {
                server.manage_certificate(domain).await;
            }))
        } else {
            None
        };

        println!("Domain {} added ({:?})", &domain, directory);
        DOMAINS.insert(domain, DomainInfo::new(directory, cert_task));
        self.schedule_write_bindings();
    }

    async fn manage_certificate(&self, domain: String) {
        let cert_manager = self.cert_manager.as_ref().unwrap();
        
        loop {
            // 1. Check certificate status
            let now = std::time::SystemTime::now();
            
            // Determine if we need to acquire a certificate
            // If we have a valid certificate, we will sleep and continue the loop
            // If we need to acquire, we will break out of this match and proceed to acquisition
            match cert_manager.get_certificate_expiration(&domain) {
                Ok(expiration) => {
                    if let Ok(duration_until_expiry) = expiration.duration_since(now) {
                        // Renew if expires in < 8 days
                        if duration_until_expiry < std::time::Duration::from_secs(8 * 24 * 60 * 60) {
                            let days = duration_until_expiry.as_secs() / 86400;
                            CERT_STATUS.insert(domain.clone(), format!("Renewing ({}d left)", days));
                            println!("Certificate for {} expires in {:?}, renewing...", domain, duration_until_expiry);
                            // Acquire!
                        } else {
                            // Valid certificate, sleep until renewal time (expiration - 7 days)
                            let days = duration_until_expiry.as_secs() / 86400;
                            CERT_STATUS.insert(domain.clone(), format!("Valid ({}d)", days));
                            let sleep_time = duration_until_expiry - to_jittered_duration(7 * 24 * 60 * 60);
                            println!("Certificate for {} is valid. Sleeping for {}s", domain, sleep_time.as_secs());
                            tokio::time::sleep(sleep_time).await;
                            continue; // Do not acquire
                        }
                    } else {
                        // Already expired - acquire!
                        CERT_STATUS.insert(domain.clone(), "Expired".to_string());
                        println!("Certificate for {} has expired", domain);
                    }
                }
                Err(_) => {
                    // No certificate or invalid - acquire!
                    CERT_STATUS.insert(domain.clone(), "Acquiring".to_string());
                }
            };

            let mut backoff_time = 15 * 60; // 15 minutes
            loop {
                CERT_STATUS.insert(domain.clone(), "Acquiring".to_string());
                match cert_manager.acquire_certificate(&domain).await {
                    Ok(_) => {
                        CERT_STATUS.insert(domain.clone(), "Valid".to_string());
                        println!("Successfully acquired certificate for {}", domain);
                        break; // Go back to outer loop to check expiration and sleep
                    }
                    Err(e) => {
                        // Add +/- 10% jitter
                        let sleep_time = to_jittered_duration(backoff_time);
                        if backoff_time < 12*60*60 { // 15m, 1h, 4h, 16h
                            backoff_time *= 4;
                        }
                        CERT_STATUS.insert(domain.clone(), format!("Error (retry {}m)", sleep_time.as_secs() / 60));
                        eprintln!("Failed to acquire certificate for {}: {} (retrying in {}s)", domain, e, sleep_time.as_secs());
                        tokio::time::sleep(sleep_time).await;
                    }
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
}

impl rustls::server::ResolvesServerCert for CertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let server_name = client_hello.server_name()?;
        let domain: &str = server_name.as_ref();

        // Load certificate for the requested domain
        let (certs, key) = match self.cert_manager.get_certificate(domain) {
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

fn to_jittered_duration(seconds: i32) -> std::time::Duration {
    use rand::Rng;
    std::time::Duration::from_secs(
        ((seconds as f64 * rand::rng().random_range(0.9..=1.1)).max(0.0)).round() as u64,
    )
}
