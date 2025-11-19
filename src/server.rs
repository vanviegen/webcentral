use crate::acme::CertManager;
use crate::project;
use anyhow::Result;
use dashmap::DashMap;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::Full;
use bytes::Bytes;
use notify::{Watcher, RecursiveMode};
use regex::Regex;
use rustls::ServerConfig;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;

pub struct Server {
    config: crate::Config,
    bindings: Arc<DashMap<String, String>>,
    bindings_file: PathBuf,
    last_scan: Arc<RwLock<Instant>>,
    cert_requests: Arc<DashMap<String, ()>>,
    #[allow(dead_code)]
    approved_hosts: Arc<DashMap<String, ()>>,
    cert_manager: Option<Arc<CertManager>>,
}

impl Server {
    pub async fn new(config: crate::Config) -> Result<Self> {
        project::set_projects_pattern(config.projects.clone());

        let bindings_file = config.bindings_file();
        let bindings = Arc::new(DashMap::new());

        // Load bindings cache
        if let Ok(data) = fs::read_to_string(&bindings_file) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&data) {
                for (k, v) in map {
                    bindings.insert(k, v);
                }
            }
        }

        // Create certificate manager if HTTPS is enabled
        let cert_manager = if config.https > 0 {
            let email = config.email.clone().expect("Email required for HTTPS");
            Some(Arc::new(CertManager::new(
                PathBuf::from(&config.config),
                email,
                config.acme_url.clone(),
            )))
        } else {
            None
        };

        Ok(Server {
            config,
            bindings,
            bindings_file,
            last_scan: Arc::new(RwLock::new(Instant::now() - Duration::from_secs(1000))),
            cert_requests: Arc::new(DashMap::new()),
            approved_hosts: Arc::new(DashMap::new()),
            cert_manager,
        })
    }

    pub async fn start(self: Arc<Self>) -> Result<()> {
        // Start HTTP server
        if self.config.http > 0 {
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.run_http_server().await {
                    eprintln!("HTTP server error: {}", e);
                }
            });
            println!("HTTP server listening on port {}", self.config.http);
        }

        // Start HTTPS server
        if self.config.https > 0 {
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.run_https_server().await {
                    eprintln!("HTTPS server error: {}", e);
                }
            });
            println!("HTTPS server listening on port {}", self.config.https);

            // Watch for new project directories
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.watch_project_directories().await {
                    eprintln!("Directory watcher error: {}", e);
                }
            });

            // Acquire certificates for existing domains
            let server = self.clone();
            tokio::spawn(async move {
                server.ensure_all_certificates().await;
            });
        }

        Ok(())
    }

    async fn run_http_server(self: Arc<Self>) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.http);
        let listener = TcpListener::bind(&addr).await?;

        loop {
            let (stream, _) = listener.accept().await?;
            let server = self.clone();

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                if let Err(e) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, service_fn(move |req| {
                        let server = server.clone();
                        async move { server.handle_http(req).await }
                    }))
                    .await
                {
                    eprintln!("HTTP connection error: {}", e);
                }
            });
        }
    }

    async fn run_https_server(self: Arc<Self>) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.https);
        let listener = TcpListener::bind(&addr).await?;

        // Create TLS config with SNI resolver
        let cert_manager = self.cert_manager.as_ref()
            .expect("Certificate manager required for HTTPS");
        let cert_manager_clone = cert_manager.clone();

        let tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver {
                cert_manager: cert_manager_clone,
            }));

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        loop {
            let (stream, _) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let server = self.clone();

            tokio::spawn(async move {
                // Perform TLS handshake
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("TLS handshake error: {}", e);
                        return;
                    }
                };

                let io = TokioIo::new(tls_stream);
                if let Err(e) = http1::Builder::new()
                    .serve_connection(io, service_fn(move |req| {
                        let server = server.clone();
                        async move { server.handle_https(req).await }
                    }))
                    .await
                {
                    eprintln!("HTTPS connection error: {}", e);
                }
            });
        }
    }

    async fn handle_http(&self, req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        // Handle ACME HTTP-01 challenges
        let path = req.uri().path();
        if path.starts_with("/.well-known/acme-challenge/") {
            if let Some(cert_manager) = &self.cert_manager {
                let token = &path[28..]; // Skip "/.well-known/acme-challenge/"
                if let Some(key_auth) = cert_manager.get_challenge(token).await {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/plain")
                        .body(Full::new(Bytes::from(key_auth)))
                        .unwrap());
                }
            }
            return Ok(Self::error_response(StatusCode::NOT_FOUND, "Challenge not found"));
        }

        self.route_request(req, false).await
    }

    async fn handle_https(&self, req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        self.route_request(req, true).await
    }

    fn redirect_to(url: String) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header("Location", url)
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .body(Full::new(Bytes::from(message.to_string())))
            .unwrap()
    }

    async fn route_request(&self, req: Request<hyper::body::Incoming>, from_https: bool)
        -> Result<Response<Full<Bytes>>, hyper::Error> {

        let domain = match self.extract_domain(&req) {
            Some(d) => d,
            None => {
                return Ok(Self::error_response(StatusCode::BAD_REQUEST, 
                    "Bad Request: Missing Host header"));
            }
        };

        let project_dir = match self.get_project_dir(&domain).await {
            Ok(dir) => dir,
            Err(_) => {
                // Check for www redirect
                if self.config.redirect_www {
                    let alt_domain = if let Some(stripped) = domain.strip_prefix("www.") {
                        stripped.to_string()
                    } else {
                        format!("www.{}", domain)
                    };

                    if self.get_project_dir(&alt_domain).await.is_ok() {
                        let proto = if from_https { "https" } else { "http" };
                        let redirect_url = format!("{}://{}{}", proto, domain,
                        req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));
                        return Ok(Self::redirect_to(redirect_url));
                    }
                }
                return Ok(Self::error_response(StatusCode::NOT_FOUND, "Not Found"));
            }
        };

        // Get or create project first to access its config
        let project = match project::get_project(&PathBuf::from(project_dir), self.config.firejail, self.config.prune_logs).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to get project: {}", e);
                return Ok(Self::error_response(StatusCode::INTERNAL_SERVER_ERROR, 
                    "Internal Server Error"));
            }
        };

        // Check for HTTP/HTTPS redirect based on project config first, then server config
        if from_https {
            // HTTPS request - check if we should redirect to HTTP
            if project.config.redirect_https == Some(true) {
                let redirect_url = format!("http://{}{}",
                    req.headers().get("host").and_then(|h| h.to_str().ok()).unwrap_or(&domain),
                    req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));
                return Ok(Self::redirect_to(redirect_url));
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
                let redirect_url = format!("https://{}{}",
                    req.headers().get("host").and_then(|h| h.to_str().ok()).unwrap_or(&domain),
                    req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));
                return Ok(Self::redirect_to(redirect_url));
            }
        }

        // Handle request with project
        match project.handle(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                eprintln!("Project handle error: {}", e);
                Ok(Self::error_response(StatusCode::INTERNAL_SERVER_ERROR, 
                    "Internal Server Error"))
            }
        }
    }

    fn extract_domain(&self, req: &Request<hyper::body::Incoming>) -> Option<String> {
        let host = req.headers().get("host")?.to_str().ok()?;

        // Strip port
        let host = host.split(':').next().unwrap_or(host);

        // Convert to lowercase
        let host = host.to_lowercase();

        // Validate domain format
        let valid_domain = Regex::new(r"^[a-zA-Z0-9.-]+$").unwrap();
        if !valid_domain.is_match(&host) {
            return None;
        }

        Some(host)
    }

    async fn get_project_dir(&self, domain: &str) -> Result<String> {
        // Check cache first
        {
            let last_scan = *self.last_scan.read().await;
            if last_scan.elapsed() < Duration::from_secs(10) {
                if let Some(dir) = self.bindings.get(domain) {
                    // Verify directory still exists
                    if Path::new(dir.value()).exists() {
                        return Ok(dir.value().clone());
                    }
                    // Directory no longer exists, will rescan
                    drop(dir);
                    self.bindings.remove(domain);
                }
            }
        }

        // Scan for project directory
        let mut last_scan = self.last_scan.write().await;

        // Double-check after acquiring write lock
        if last_scan.elapsed() < Duration::from_secs(10) {
            if let Some(dir) = self.bindings.get(domain) {
                if Path::new(dir.value()).exists() {
                    return Ok(dir.value().clone());
                }
                drop(dir);
                self.bindings.remove(domain);
            }
        }

        // Scan directories
        let dir = self.scan_for_project(domain).await?;
        self.bindings.insert(domain.to_string(), dir.clone());
        *last_scan = Instant::now();

        self.save_bindings();

        Ok(dir)
    }

    async fn scan_for_project(&self, domain: &str) -> Result<String> {
        for entry in glob::glob(&self.config.projects)? {
            let base_path = entry?;
            let project_path = base_path.join(domain);

            if project_path.exists() && project_path.is_dir() {
                return Ok(project_path.to_string_lossy().to_string());
            }
        }

        anyhow::bail!("Project not found for domain: {}", domain)
    }

    fn save_bindings(&self) {
        let map: HashMap<String, String> = self.bindings.iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        if let Ok(data) = serde_json::to_string_pretty(&map) {
            let _ = fs::create_dir_all(self.bindings_file.parent().unwrap());
            let _ = fs::write(&self.bindings_file, data);
        }
    }

    async fn watch_project_directories(self: Arc<Self>) -> Result<()> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);

        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        })?;

        // Find all project base directories and watch them
        for entry in glob::glob(&self.config.projects)? {
            let base_path = entry?;
            watcher.watch(&base_path, RecursiveMode::NonRecursive)?;
            println!("Watching for new projects in {}", base_path.display());
        }

        while let Some(event) = rx.recv().await {
            if event.kind.is_create() {
                for path in event.paths {
                    if path.is_dir() {
                        if let Some(domain) = path.file_name().and_then(|n| n.to_str()) {
                            let valid_domain = Regex::new(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$").unwrap();
                            if valid_domain.is_match(domain) {
                                println!("New project directory detected: {}", domain);
                                // Acquire certificate in background
                                let domain = domain.to_string();
                                let server = self.clone();
                                tokio::spawn(async move {
                                    server.acquire_certificate_for_domain(&domain).await;
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn acquire_certificate_for_domain(&self, domain: &str) {
        // Check if already being requested
        if self.cert_requests.contains_key(domain) {
            return;
        }

        let cert_manager = match &self.cert_manager {
            Some(cm) => cm,
            None => return,
        };

        // Check if certificate already exists
        if cert_manager.has_certificate(domain) {
            return;
        }

        self.cert_requests.insert(domain.to_string(), ());

        // Acquire certificate using ACME
        match cert_manager.acquire_certificate(domain).await {
            Ok(_) => {},
            Err(e) => {
                eprintln!("Failed to acquire certificate for {}: {}", domain, e);
            }
        }

        self.cert_requests.remove(domain);
    }

    async fn ensure_all_certificates(&self) {
        // Scan for all project directories
        let mut domains = Vec::new();

        for entry in glob::glob(&self.config.projects).unwrap() {
            if let Ok(base_path) = entry {
                if let Ok(entries) = fs::read_dir(base_path) {
                    for entry in entries.flatten() {
                        if entry.path().is_dir() {
                            if let Some(domain) = entry.file_name().to_str() {
                                let valid_domain = Regex::new(r"^[a-zA-Z0-9.-]+$").unwrap();
                                if valid_domain.is_match(domain) {
                                    domains.push(domain.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        println!("Acquiring certificates for {} domains...", domains.len());

        for domain in domains {
            self.acquire_certificate_for_domain(&domain).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        println!("Certificate acquisition complete");
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
    fn resolve(&self, client_hello: rustls::server::ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let server_name = client_hello.server_name()?;
        let domain: &str = server_name.as_ref();

        // Load certificate for the requested domain
        let (certs, key) = self.cert_manager.get_certificate(domain).ok()?;

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .ok()?;

        Some(Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key)))
    }
}
