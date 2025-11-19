use crate::acme::CertManager;
use crate::project::{self, Project};
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
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpListener;
use tokio::sync::{RwLock, Notify};
use tokio_rustls::TlsAcceptor;

// Domain information stored in the global DOMAINS map
struct DomainInfo {
    directory: String,
    project: RwLock<Option<Arc<Project>>>,
    // Notify when certificate becomes ready
    cert_ready: Arc<Notify>,
    // Track if certificate acquisition is in progress
    cert_acquiring: AtomicBool,
}

impl DomainInfo {
    fn new(directory: String) -> Self {
        Self {
            directory,
            project: RwLock::new(None),
            cert_ready: Arc::new(Notify::new()),
            cert_acquiring: AtomicBool::new(false),
        }
    }
}

lazy_static::lazy_static! {
    static ref DOMAINS: DashMap<String, DomainInfo> = DashMap::new();
    static ref VALID_DOMAIN: Regex = Regex::new(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$").unwrap();
}

// Called by Project when it shuts down to remove itself from DOMAINS
pub async fn discard_project(domain: &str) {
    if let Some(domain_info) = DOMAINS.get_mut(domain) {
        *domain_info.project.write().await = None;
    }
}

// Stop all running projects (called during shutdown)
pub async fn stop_all_projects() {
    for entry in DOMAINS.iter() {
        if let Some(project) = entry.project.read().await.as_ref() {
            project.stop().await;
        }
    }
}

pub struct Server {
    config: crate::GlobalConfig,
    cert_manager: Option<Arc<CertManager>>,
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

        Ok(Server {
            config,
            cert_manager,
        })
    }

    // Read bindings.list file containing authorized project directories
    fn read_bindings(data_dir: &str) -> Result<HashSet<String>> {
        let bindings_path = PathBuf::from(data_dir).join("bindings.list");
        let mut bindings = HashSet::new();
        
        if bindings_path.exists() {
            let file = fs::File::open(&bindings_path)?;
            let reader = std::io::BufReader::new(file);
            
            for line in reader.lines() {
                if let Ok(path) = line {
                    let path = path.trim();
                    if !path.is_empty() {
                        bindings.insert(path.to_string());
                    }
                }
            }
            println!("Loaded {} authorized bindings from {}", bindings.len(), bindings_path.display());
        }
        
        Ok(bindings)
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
        
        println!("Wrote {} bindings to {}", DOMAINS.len(), bindings_path.display());
        Ok(())
    }

    pub async fn start(self: Arc<Self>) -> Result<()> {
        // Do initial scan to populate DOMAINS
        let server = self.clone();
        server.scan_all_project_directories().await;

        // Start directory watcher to maintain DOMAINS
        let server = self.clone();
        tokio::spawn(async move {
            if let Err(e) = server.watch_project_directories().await {
                eprintln!("Directory watcher error: {}", e);
            }
        });

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
                    .serve_connection(io, service_fn(move |req| {
                        let server = server.clone();
                        async move { server.handle_http(req).await }
                    }))
                    .with_upgrades()
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
                    .with_upgrades()
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

        let project = match self.get_project_for_domain(&domain).await {
            Ok(p) => p,
            Err(_) => {
                // Check for www redirect
                if self.config.redirect_www {
                    let alt_domain = if let Some(stripped) = domain.strip_prefix("www.") {
                        stripped.to_string()
                    } else {
                        format!("www.{}", domain)
                    };

                    if let Ok(_) = self.get_project_for_domain(&alt_domain).await {
                        let proto = if from_https { "https" } else { "http" };
                        let redirect_url = format!("{}://{}{}", proto, alt_domain,
                        req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));
                        return Ok(Self::redirect_to(redirect_url));
                    }
                }
                return Ok(Self::error_response(StatusCode::NOT_FOUND, "Not Found"));
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

    async fn get_project_for_domain(&self, domain: &str) -> Result<Arc<Project>> {
        // Look up domain in DOMAINS map
        let domain_info = DOMAINS.get(domain)
            .ok_or_else(|| anyhow::anyhow!("Domain not found: {}", domain))?;

        // Check if project already exists
        {
            let project_guard = domain_info.project.read().await;
            if let Some(project) = project_guard.as_ref() {
                return Ok(project.clone());
            }
        }

        // Create or recreate project
        let project = project::create_project(
            &PathBuf::from(&domain_info.directory),
            domain.to_string(),
            self.config.firejail,
            self.config.prune_logs
        ).await?;

        // Store in domain info
        {
            let mut project_guard = domain_info.project.write().await;
            *project_guard = Some(project.clone());
        }

        Ok(project)
    }

    async fn add_domain(&self, domain: String, directory: String, bindings: Option<&HashSet<String>>) {
        if let Some(existing) = DOMAINS.get(&domain) {
            // Domain exists - check if transfer is allowed
            let existing_dir_gone = !std::path::Path::new(&existing.directory).exists();
            let authorized = bindings.map_or(false, |b| b.contains(&directory));
            if !existing_dir_gone && !authorized {
                println!("Rejecting domain override attempt for {} from unauthorized directory {}", domain, directory);
                return
            }
            println!("Overriding domain {} from {} to {}{}", domain, existing.directory, directory, if authorized { " (authorized)" } else { " (directory gone)" });
        }
        DOMAINS.insert(domain, DomainInfo::new(directory));
    }

    // Process a directory path, validating domain and setting up project + certificate
    async fn process_project_directory(self: &Arc<Self>, path: &std::path::Path, bindings: Option<&HashSet<String>>) {
        if !path.is_dir() {
            return;
        }
        
        if let Some(domain) = path.file_name().and_then(|n| n.to_str()) {
            if VALID_DOMAIN.is_match(domain) {
                let directory = path.to_string_lossy().to_string();
                let domain = domain.to_lowercase();
                self.add_domain(domain.clone(), directory, bindings).await;

                // Start certificate acquisition in background if HTTPS enabled
                if self.cert_manager.is_some() {
                    let server = self.clone();
                    let domain = domain.clone();
                    tokio::spawn(async move {
                        server.acquire_certificate_for_domain(&domain).await;
                    });
                }
            }
        }
    }

    async fn scan_all_project_directories(self: Arc<Self>) {
        // Read authorized bindings from previous run
        let bindings = Self::read_bindings(&self.config.data_dir).unwrap_or_else(|_e| {
            HashSet::new()
        });

        for entry in glob::glob(&self.config.projects).unwrap() {
            if let Ok(base_path) = entry {
                if let Ok(entries) = fs::read_dir(base_path) {
                    for entry in entries.flatten() {
                        self.process_project_directory(&entry.path(), Some(&bindings)).await;
                    }
                }
            }
        }
        
        // Write current bindings to file
        if let Err(e) = self.write_bindings() {
            eprintln!("Failed to write bindings: {}", e);
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
            let mut changed = false;
            
            match event.kind {
                notify::EventKind::Create(_) => {
                    for path in event.paths {
                        println!("New project directory detected: {}", path.display());
                        self.process_project_directory(&path, None).await;
                        changed = true;
                    }
                },
                notify::EventKind::Remove(_) => {
                    for path in event.paths {
                        if let Some(domain) = path.file_name().and_then(|n| n.to_str()) {
                            if VALID_DOMAIN.is_match(domain) {
                                let domain = domain.to_lowercase();
                                println!("Project directory removed: {}", domain);
                                
                                // Remove from DOMAINS
                                DOMAINS.remove(&domain);
                                changed = true;
                                
                                // Note: Certificate removal from ACME client would go here
                                // For now, we just keep the certificate files
                            }
                        }
                    }
                },
                _ => {}
            }
            
            // Write bindings after any changes
            if changed {
                if let Err(e) = self.write_bindings() {
                    eprintln!("Failed to write bindings: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn acquire_certificate_for_domain(&self, domain: &str) {
        // Check if already being acquired using compare-and-swap
        let domain_info = match DOMAINS.get(domain) {
            Some(info) => info,
            None => return,
        };
        
        // Try to set cert_acquiring from false to true atomically
        if domain_info.cert_acquiring.compare_exchange(
            false, 
            true, 
            Ordering::SeqCst, 
            Ordering::SeqCst
        ).is_err() {
            // Already being acquired
            return;
        }

        let cert_manager = match &self.cert_manager {
            Some(cm) => cm,
            None => {
                domain_info.cert_acquiring.store(false, Ordering::SeqCst);
                return;
            }
        };

        // Check if certificate already exists
        if cert_manager.has_certificate(domain) {
            // Notify any waiters
            domain_info.cert_ready.notify_waiters();
            domain_info.cert_acquiring.store(false, Ordering::SeqCst);
            return;
        }

        // Acquire certificate using ACME
        match cert_manager.acquire_certificate(domain).await {
            Ok(_) => {
                // Notify any waiters that certificate is ready
                domain_info.cert_ready.notify_waiters();
            },
            Err(e) => {
                eprintln!("Failed to acquire certificate for {}: {}", domain, e);
            }
        }

        // Mark as no longer acquiring
        domain_info.cert_acquiring.store(false, Ordering::SeqCst);
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

        // Check if domain exists in DOMAINS
        if let Some(domain_info) = DOMAINS.get(domain) {
            // Check if certificate is currently being acquired
            if domain_info.cert_acquiring.load(Ordering::SeqCst) {
                eprintln!("Certificate for {} is still being acquired, connection will be closed", domain);
                return None;
            }
        }

        // Load certificate for the requested domain
        let (certs, key) = self.cert_manager.get_certificate(domain).ok()?;

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .ok()?;

        Some(Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key)))
    }
}
