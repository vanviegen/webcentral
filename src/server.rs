use crate::acme::CertManager;
use crate::project::{self, Project};
use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::Full;

use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use notify::{RecursiveMode, Watcher};
use regex::Regex;
use rustls::ServerConfig;
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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
}

// Called by Project when it shuts down to remove itself from DOMAINS
pub async fn discard_project(domain: &str) {
    if let Some(mut domain_info) = DOMAINS.get_mut(domain) {
        domain_info.project = None;
    }
}

// Stop all running projects (called during shutdown)
pub async fn stop_all_projects() {
    for entry in DOMAINS.iter() {
        if let Some(project) = entry.project.as_ref() {
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
            println!(
                "Loaded {} authorized bindings from {}",
                bindings.len(),
                bindings_path.display()
            );
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

        println!(
            "Wrote {} bindings to {}",
            DOMAINS.len(),
            bindings_path.display()
        );
        Ok(())
    }

    pub async fn start(self: Arc<Self>) -> Result<()> {
        // Start directory watcher to maintain DOMAINS
        let server = self.clone();
        tokio::spawn(async move {
            if let Err(e) = server.watch_project_directories().await {
                eprintln!("Directory watcher error: {}", e);
            }
        });

        // Do initial scan to populate DOMAINS
        let server = self.clone();
        server.scan_all_project_directories().await;

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
                if let Err(e) = auto::Builder::new(TokioExecutor::new())
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

    async fn run_https_server(self: Arc<Self>) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.https);
        let listener = TcpListener::bind(&addr).await?;

        // Create TLS config with SNI resolver
        let cert_manager = self
            .cert_manager
            .as_ref()
            .expect("Certificate manager required for HTTPS");
        let cert_manager_clone = cert_manager.clone();

        let tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver {
                cert_manager: cert_manager_clone,
            }));

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
                if let Err(e) = auto::Builder::new(TokioExecutor::new())
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

    async fn handle_http(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
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
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        self.route_request(req, true).await
    }

    fn make_redirect(&self, scheme: &str, project: &Project, req: &Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
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
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    fn make_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .body(Full::new(Bytes::from(message.to_string())))
            .unwrap()
    }

    async fn route_request(
        &self,
        mut req: Request<hyper::body::Incoming>,
        from_https: bool,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
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
                    let alt_domain = if let Some(stripped) = domain.strip_prefix("www.") {
                        stripped.to_string()
                    } else {
                        format!("www.{}", domain)
                    };

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

        // Handle request with project
        match project.handle(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                println!("Error for {}: {}", project.domain, e);
                project.logger.write("handler", e.to_string().as_str());
                Ok(Self::make_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"))
            }
        }
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
        // Look up domain in DOMAINS map
        let domain_info = DOMAINS
            .get(domain)
            .ok_or_else(|| anyhow::anyhow!("Domain not found: {}", domain))?;

        // Check if project already exists
        if let Some(project) = domain_info.project.as_ref() {
            return Ok(project.clone());
        }
        
        // Need to drop the ref to get mutable access
        drop(domain_info);

        // Create or recreate project
        let project = project::create_project(
            &PathBuf::from(&DOMAINS.get(domain).unwrap().directory),
            domain.to_string(),
            self.config.firejail,
            self.config.prune_logs,
        )
        .await?;

        // Store in domain info
        if let Some(mut domain_info) = DOMAINS.get_mut(domain) {
            domain_info.project = Some(project.clone());
        }

        Ok(project)
    }

    // Process a directory path, validating domain and setting up project + certificate
    async fn process_project_directory(
        self: &Arc<Self>,
        path: &std::path::Path,
        bindings: Option<&HashSet<String>>,
    ) {
        if !path.is_dir() {
            return; // It's a file
        }
        let Some(domain_name) = path.file_name().and_then(|n| n.to_str()) else {
            return; // Shouldn't happen?
        };
        if !VALID_DOMAIN.is_match(domain_name) {
            return; // It doesn't look like a domain name
        }
        
        let directory = path.to_string_lossy().to_string();
        let domain = domain_name.to_lowercase();
        
        // Check if domain exists and if transfer is allowed
        if let Some(existing) = DOMAINS.get(&domain) {
            let existing_dir_gone = !std::path::Path::new(&existing.directory).exists();
            let authorized = bindings.map_or(false, |b| b.contains(&directory));
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

        DOMAINS.insert(domain, DomainInfo::new(directory, cert_task));
    }

    async fn scan_all_project_directories(self: Arc<Self>) {
        // Read authorized bindings from previous run
        let bindings =
            Self::read_bindings(&self.config.data_dir).unwrap_or_else(|_e| HashSet::new());

        for entry in glob::glob(&self.config.projects).unwrap() {
            if let Ok(base_path) = entry {
                if let Ok(entries) = fs::read_dir(base_path) {
                    for entry in entries.flatten() {
                        self.process_project_directory(&entry.path(), Some(&bindings))
                            .await;
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

        let mut watcher =
            notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
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
                }
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
                }
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
                            println!("Certificate for {} expires in {:?}, renewing...", domain, duration_until_expiry);
                            // Acquire!
                        } else {
                            // Valid certificate, sleep until renewal time (expiration - 7 days)
                            let sleep_time = duration_until_expiry - to_jittered_duration(7 * 24 * 60 * 60);
                            println!("Certificate for {} is valid. Sleeping for {}s", domain, sleep_time.as_secs());
                            tokio::time::sleep(sleep_time).await;
                            continue; // Do not acquire
                        }
                    } else {
                        // Already expired - acquire!
                        println!("Certificate for {} has expired", domain);
                    }
                }
                Err(_) => {
                    // No certificate or invalid - acquire!
                }
            };

            let mut backoff_time = 15 * 60; // 15 minutes
            loop {
                match cert_manager.acquire_certificate(&domain).await {
                    Ok(_) => {
                        println!("Successfully acquired certificate for {}", domain);
                        break; // Go back to outer loop to check expiration and sleep
                    }
                    Err(e) => {
                        // Add +/- 10% jitter
                        let sleep_time = to_jittered_duration(backoff_time);
                        if backoff_time < 12*60*60 { // 15m, 1h, 4h, 16h
                            backoff_time *= 4;
                        }
                        
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

        // Check if domain exists in DOMAINS
        if !DOMAINS.contains_key(domain) {
            // Domain not configured
            eprintln!("Unconfigured domain: {}", domain);
            return None;
        }

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
