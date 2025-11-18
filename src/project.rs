use crate::config::{DockerConfig, ProjectConfig};
use crate::logger::Logger;
use anyhow::{Context, Result};
use dashmap::DashMap;
use hyper::{body::Incoming, Request, Response};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use http_body_util::{BodyExt, Full};
use bytes::Bytes;
use nix::unistd::Uid;
use notify::{Watcher, RecursiveMode, Event as NotifyEvent};
use regex::Regex;
use std::fs;
use std::future::Future;
use std::net::TcpStream;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{Mutex, RwLock};
use tokio::time::sleep;

static PROJECTS: once_cell::sync::Lazy<DashMap<String, Arc<Project>>> =
    once_cell::sync::Lazy::new(|| DashMap::new());

static PROJECTS_PATTERN: RwLock<Option<String>> = RwLock::const_new(None);

pub fn set_projects_pattern(pattern: String) {
    tokio::spawn(async move {
        *PROJECTS_PATTERN.write().await = Some(pattern);
    });
}

pub async fn get_project(dir: &Path, use_firejail: bool, prune_logs: i64) -> Result<Arc<Project>> {
    let dir_str = dir.to_string_lossy().to_string();

    if let Some(project) = PROJECTS.get(&dir_str) {
        return Ok(project.clone());
    }

    // Load configuration
    let config = ProjectConfig::load(dir)?;
    let (uid, gid) = get_ownership(dir);

    // Create logger
    let log_dir = dir.join("_webcentral_data/log");
    let logger = Arc::new(Logger::new(log_dir, uid, gid, prune_logs)?);

    // Log project type
    if !config.redirect.is_empty() {
        logger.write("", &format!("starting redirect to {}", config.redirect))?;
    } else if !config.proxy.is_empty() {
        logger.write("", &format!("starting proxy for {}", config.proxy))?;
    } else if !config.socket_path.is_empty() {
        logger.write("", &format!("starting forward to socket {}", config.socket_path))?;
    } else if config.port > 0 {
        logger.write("", &format!("starting forward to http://{}:{}", config.host, config.port))?;
    } else if config.command.is_empty() && config.docker.is_none() {
        logger.write("", "starting static file server")?;
    }

    // Log configuration errors
    for err in &config.config_errors {
        logger.write("", err)?;
    }

    let project = Arc::new(Project {
        dir: dir_str.clone(),
        config: Arc::new(config),
        logger: logger.clone(),
        uid,
        gid,
        use_firejail,
        state: Arc::new(Mutex::new(ProjectState::Stopped)),
        last_activity: Arc::new(Mutex::new(Instant::now())),
    });

    PROJECTS.insert(dir_str, project.clone());

    // Start file watcher
    let proj = project.clone();
    tokio::spawn(async move {
        if let Err(e) = proj.watch_files().await {
            let _ = proj.logger.write("", &format!("File watcher error: {}", e));
        }
    });

    // Start inactivity timer if configured
    if project.config.reload.timeout > 0 {
        let proj = project.clone();
        tokio::spawn(async move {
            proj.inactivity_timer().await;
        });
    }

    Ok(project)
}

pub async fn stop_all_projects() {
    for entry in PROJECTS.iter() {
        entry.value().stop().await;
    }
}

#[derive(Debug)]
enum ProjectState {
    Stopped,
    Starting { port: u16, #[allow(dead_code)] start_time: Instant },
    Running { port: u16, process: tokio::process::Child, workers: Vec<tokio::process::Child> },
}

pub struct Project {
    dir: String,
    config: Arc<ProjectConfig>,
    logger: Arc<Logger>,
    uid: u32,
    gid: u32,
    use_firejail: bool,
    state: Arc<Mutex<ProjectState>>,
    last_activity: Arc<Mutex<Instant>>,
}

impl Project {
    fn needs_process_management(&self) -> bool {
        !self.config.command.is_empty() || self.config.docker.is_some()
    }

    pub fn handle<'a>(&'a self, req: Request<Incoming>) -> Pin<Box<dyn Future<Output = Result<Response<Full<Bytes>>>> + Send + 'a>> {
        Box::pin(async move { self.handle_impl(req).await })
    }

    async fn handle_impl(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        eprintln!("project.handle_impl: start");
        *self.last_activity.lock().await = Instant::now();

        if self.config.log_requests {
            let _ = self.logger.write("", &format!("{} {}", req.method(), req.uri().path()));
        }

        eprintln!("project.handle_impl: applying rewrites");
        // Apply URL rewrites
        let (_path, redirect) = self.apply_rewrites(req.uri().path());

        if !redirect.is_empty() {
            // Handle webcentral:// URLs
            if redirect.starts_with("webcentral://") {
                return self.handle_webcentral_redirect(&redirect, req).await;
            }
            return Ok(Response::builder()
                .status(301)
                .header("Location", redirect)
                .body(Full::new(Bytes::new()))?);
        }

        // Determine handler based on configuration
        eprintln!("project.handle_impl: determining handler");
        let result = if !self.config.redirect.is_empty() {
            eprintln!("project.handle_impl: redirect");
            self.handle_redirect().await
        } else if !self.config.proxy.is_empty() {
            eprintln!("project.handle_impl: proxy_remote");
            self.handle_proxy_remote(req).await
        } else if !self.config.socket_path.is_empty() || self.config.port > 0 {
            eprintln!("project.handle_impl: forward");
            self.handle_forward(req).await
        } else if self.needs_process_management() {
            eprintln!("project.handle_impl: application");
            self.handle_application(req).await
        } else {
            eprintln!("project.handle_impl: static");
            self.handle_static(req).await
        };
        eprintln!("project.handle_impl: handler returned");
        result
    }

    fn apply_rewrites(&self, path: &str) -> (String, String) {
        for (pattern, target) in &self.config.rewrites {
            if let Ok(re) = Regex::new(&format!("^{}$", pattern)) {
                if re.is_match(path) {
                    let result = re.replace(path, target).to_string();
                    if result.starts_with("http://") || result.starts_with("https://") || result.starts_with("webcentral://") {
                        return (path.to_string(), result);
                    }
                    return (result, String::new());
                }
            }
        }
        (path.to_string(), String::new())
    }

    async fn handle_webcentral_redirect(&self, redirect: &str, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        let target_name = redirect.strip_prefix("webcentral://").unwrap();
        let parts: Vec<&str> = target_name.splitn(2, '/').collect();
        let project_name = parts[0];
        let _target_path = if parts.len() == 2 { format!("/{}", parts[1]) } else { "/".to_string() };

        // Find target project directory
        let target_dir = find_project_by_name(project_name).await?;
        let target_project = get_project(&target_dir, self.use_firejail, self.logger.prune_days).await?;

        // Forward request to target project
        target_project.handle(req).await
    }

    async fn handle_redirect(&self) -> Result<Response<Full<Bytes>>> {
        Ok(Response::builder()
            .status(301)
            .header("Location", &self.config.redirect)
            .body(Full::new(Bytes::new()))?)
    }

    async fn handle_static(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        let public_dir = PathBuf::from(&self.dir).join("public");
        if !public_dir.exists() {
            return Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::from("Not Found")))?);
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
            Ok(Response::builder()
                .status(200)
                .body(Full::new(Bytes::from(content)))?)
        } else {
            Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::from("Not Found")))?)
        }
    }

    async fn handle_forward(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        // For forwards (static port/socket), just proxy directly
        let target = if !self.config.socket_path.is_empty() {
            format!("unix://{}", self.config.socket_path)
        } else {
            format!("http://{}:{}", self.config.host, self.config.port)
        };

        self.proxy_request(req, &target).await
    }

    async fn handle_proxy_remote(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        // Simplified proxy without retry logic
        // (Retry would require request cloning which is complex with streaming bodies)
        self.proxy_request(req, &self.config.proxy).await
    }

    async fn proxy_request(&self, req: Request<Incoming>, target: &str) -> Result<Response<Full<Bytes>>> {
        // Parse target URL
        let target_uri: hyper::Uri = target.parse()?;

        // Build the full URI for the proxied request
        let path_and_query = req.uri().path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let uri_str = format!("{}{}", target, path_and_query);
        let uri: hyper::Uri = uri_str.parse()?;

        // Collect the incoming body first
        let (parts, body) = req.into_parts();
        let body_bytes = body.collect().await?.to_bytes();

        // Create HTTP client
        let client = Client::builder(TokioExecutor::new()).build_http();

        // Build proxied request with collected body
        let mut proxy_req = hyper::Request::builder()
            .method(&parts.method)
            .uri(uri)
            .version(hyper::Version::HTTP_11);

        // Copy headers, skipping connection-related headers
        for (name, value) in &parts.headers {
            let name_str = name.as_str().to_lowercase();
            if name_str != "host" && name_str != "connection" &&
               name_str != "transfer-encoding" && name_str != "content-length" {
                proxy_req = proxy_req.header(name, value);
            }
        }

        // Set proper Host header
        if let Some(host) = target_uri.host() {
            let host_value = if let Some(port) = target_uri.port_u16() {
                format!("{}:{}", host, port)
            } else {
                host.to_string()
            };
            proxy_req = proxy_req.header("Host", host_value);
        }

        // Add X-Forwarded headers
        let proto = if parts.uri.scheme_str() == Some("https") { "https" } else { "http" };
        let original_host = parts.headers.get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        proxy_req = proxy_req
            .header("X-Forwarded-Host", original_host)
            .header("X-Forwarded-Proto", proto);

        // Set Content-Length if we have a body
        if !body_bytes.is_empty() {
            proxy_req = proxy_req.header("Content-Length", body_bytes.len());
        }

        let proxy_req = proxy_req.body(Full::new(body_bytes))?;

        // Send request
        let resp = client.request(proxy_req).await?;

        // Convert response
        let (resp_parts, resp_body) = resp.into_parts();
        let resp_bytes = resp_body.collect().await?.to_bytes();

        let mut response = Response::builder()
            .status(resp_parts.status)
            .version(resp_parts.version);

        // Copy response headers
        for (name, value) in resp_parts.headers {
            if let Some(name) = name {
                response = response.header(name, value);
            }
        }

        Ok(response.body(Full::new(resp_bytes))?)
    }

    async fn handle_application(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        eprintln!("handle_application: ensuring app started");
        // Ensure application is started
        self.ensure_started().await?;

        eprintln!("handle_application: getting port");
        // Get current port
        let port = {
            let state = self.state.lock().await;
            match *state {
                ProjectState::Running { port, .. } => port,
                ProjectState::Starting { port, .. } => port,
                _ => return Ok(Response::builder().status(503).body(Full::new(Bytes::from("Service Unavailable")))?),
            }
        };

        eprintln!("handle_application: port={}, proxying", port);
        // Proxy to application
        let target = format!("http://localhost:{}", port);
        let result = self.proxy_request(req, &target).await;
        eprintln!("handle_application: proxy_request returned");
        result
    }

    async fn ensure_started(&self) -> Result<()> {
        let mut state = self.state.lock().await;

        match *state {
            ProjectState::Running { .. } => return Ok(()),
            ProjectState::Starting { .. } => {
                // Wait for startup to complete (with timeout)
                drop(state);
                for _ in 0..300 {  // 30 second timeout
                    sleep(Duration::from_millis(100)).await;
                    let s = self.state.lock().await;
                    match *s {
                        ProjectState::Running { .. } => return Ok(()),
                        ProjectState::Stopped => anyhow::bail!("Application failed to start"),
                        _ => continue,
                    }
                }
                anyhow::bail!("Application startup timeout");
            }
            ProjectState::Stopped => {
                // Start the application
                let port = get_free_port()?;
                self.logger.write("", &format!("starting on port {}", port))?;

                *state = ProjectState::Starting {
                    port,
                    start_time: Instant::now(),
                };
                drop(state);

                // Start process in background
                let proj = Arc::new(self.clone());
                tokio::spawn(async move {
                    if let Err(e) = proj.start_process(port).await {
                        let _ = proj.logger.write("", &format!("Failed to start process: {}", e));
                        *proj.state.lock().await = ProjectState::Stopped;
                    }
                });

                // Wait for port to be ready
                for _ in 0..300 {
                    sleep(Duration::from_millis(100)).await;
                    let s = self.state.lock().await;
                    match *s {
                        ProjectState::Running { .. } => return Ok(()),
                        ProjectState::Stopped => anyhow::bail!("Application failed to start"),
                        _ => continue,
                    }
                }

                anyhow::bail!("Application startup timeout");
            }
        }
    }

    async fn start_process(&self, port: u16) -> Result<()> {
        let mut process = if let Some(docker) = &self.config.docker {
            self.build_docker_command(port, docker).await?
        } else {
            self.build_shell_command(&self.config.command)?
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

        self.logger.write("", &format!("starting command: {:?}", process))?;

        let mut child = process.spawn()?;

        // Stream logs
        if let Some(stdout) = child.stdout.take() {
            let logger = self.logger.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = logger.write("out", &line);
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let logger = self.logger.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = logger.write("out", &line);
                }
            });
        }

        // Wait for port to be ready
        let ready = wait_for_port(port, Duration::from_secs(30)).await;

        if !ready {
            child.kill().await?;
            self.logger.write("", "application failed to start listening on port")?;
            *self.state.lock().await = ProjectState::Stopped;
            anyhow::bail!("Port not ready");
        }

        self.logger.write("", &format!("reachable on port {}", port))?;

        // Start workers
        let workers = self.start_workers(port).await;

        *self.state.lock().await = ProjectState::Running { port, process: child, workers };

        // Monitor process exit
        let proj = Arc::new(self.clone());
        tokio::spawn(async move {
            let exit_status = {
                let mut state = proj.state.lock().await;
                if let ProjectState::Running { ref mut process, .. } = *state {
                    process.wait().await
                } else {
                    return;
                }
            };

            match exit_status {
                Ok(status) => {
                    let _ = proj.logger.write("", &format!("process exited: {:?}", status));
                }
                Err(e) => {
                    let _ = proj.logger.write("", &format!("process error: {}", e));
                }
            }

            *proj.state.lock().await = ProjectState::Stopped;
        });

        Ok(())
    }

    async fn start_workers(&self, port: u16) -> Vec<tokio::process::Child> {
        if self.config.workers.is_empty() {
            return vec![];
        }

        self.logger.write("", &format!("starting {} worker(s)", self.config.workers.len())).unwrap();

        let mut workers = vec![];

        for (name, cmd) in &self.config.workers {
            let mut process = match self.build_shell_command(cmd) {
                Ok(p) => p,
                Err(e) => {
                    let _ = self.logger.write("", &format!("failed to build worker {}: {}", name, e));
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
                Ok(mut child) => {
                    // Stream logs
                    let logger = self.logger.clone();
                    let label = format!("worker-{}", name);
                    if let Some(stdout) = child.stdout.take() {
                        let logger = logger.clone();
                        let label = label.clone();
                        tokio::spawn(async move {
                            let reader = BufReader::new(stdout);
                            let mut lines = reader.lines();
                            while let Ok(Some(line)) = lines.next_line().await {
                                let _ = logger.write(&label, &line);
                            }
                        });
                    }
                    if let Some(stderr) = child.stderr.take() {
                        let label = label.clone();
                        tokio::spawn(async move {
                            let reader = BufReader::new(stderr);
                            let mut lines = reader.lines();
                            while let Ok(Some(line)) = lines.next_line().await {
                                let _ = logger.write(&label, &line);
                            }
                        });
                    }

                    workers.push(child);
                }
                Err(e) => {
                    let _ = self.logger.write("", &format!("failed to start worker {}: {}", name, e));
                }
            }
        }

        workers
    }

    fn build_shell_command(&self, command: &str) -> Result<Command> {
        let mut cmd = if self.use_firejail && self.config.docker.is_none() {
            let home = get_user_home(self.uid);
            let mut c = Command::new("firejail");
            c.args(&[
                "--quiet",
                "--noprofile",
                "--private-tmp",
                "--private-dev",
                &format!("--private={}", home),
                &format!("--whitelist={}", self.dir),
                "--read-only=/",
                &format!("--read-write={}", self.dir),
                "--",
                "/bin/sh", "-c", command,
            ]);
            c
        } else {
            let mut c = Command::new("/bin/sh");
            c.args(&["-c", command]);
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

    async fn build_docker_command(&self, port: u16, dc: &DockerConfig) -> Result<Command> {
        // Generate container name
        let hash = md5::compute(self.dir.as_bytes());
        let container_name = format!("webcentral-{:x}", hash);
        let image_name = format!("{}:latest", container_name);

        // Build Dockerfile
        let mut dockerfile = format!("FROM {}\n", dc.base);

        if !dc.packages.is_empty() {
            let packages = dc.packages.join(" ");
            dockerfile.push_str(&format!(
                "RUN if command -v apk > /dev/null ; then apk update && apk add --no-cache {} ; \
                elif command -v apt-get > /dev/null ; then apt-get update && apt-get install --no-install-recommends --yes {} ; \
                elif command -v dnf > /dev/null ; then dnf install -y {} ; \
                elif command -v yum > /dev/null ; then yum install -y {} ; \
                else echo 'No supported package manager found' && exit 1 ; fi\n",
                packages, packages, packages, packages
            ));
        }

        if dc.mount_app_dir {
            dockerfile.push_str(&format!("WORKDIR {}\n", dc.app_dir));
            if !dc.commands.is_empty() {
                dockerfile.push_str("COPY . .\n");
                for cmd in &dc.commands {
                    dockerfile.push_str(&format!("RUN {}\n", cmd));
                }
            }
        }

        dockerfile.push_str(&format!("EXPOSE {}\n", dc.http_port));

        // Write Dockerfile
        let dockerfile_path = PathBuf::from(&self.dir).join("_webcentral_data/Dockerfile");
        fs::create_dir_all(dockerfile_path.parent().unwrap())?;
        fs::write(&dockerfile_path, dockerfile)?;

        // Build image
        let output = Command::new("docker")
            .args(&["build", "-t", &image_name, "-f"])
            .arg(&dockerfile_path)
            .arg(&self.dir)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            self.logger.write("build", &stderr)?;
            anyhow::bail!("Docker build failed");
        }

        // Prepare run command
        let mut cmd = Command::new("docker");
        cmd.args(&["run", "--rm", "--name", &container_name]);

        // Mount /etc/passwd and /etc/group
        cmd.args(&["--mount", "type=bind,src=/etc/passwd,dst=/etc/passwd"]);
        cmd.args(&["--mount", "type=bind,ro,src=/etc/group,dst=/etc/group"]);

        // Port mapping
        cmd.args(&["-p", &format!("{}:{}", port, dc.http_port)]);

        // User and app directory mount
        if dc.mount_app_dir {
            cmd.args(&["--user", &format!("{}:{}", self.uid, self.gid)]);
            cmd.args(&["-v", &format!("{}:{}", self.dir, dc.app_dir)]);
        }

        // Additional mounts
        for mount in &dc.mounts {
            let container_path = if mount.starts_with('/') {
                mount.clone()
            } else {
                format!("{}/{}", dc.app_dir, mount)
            };
            let host_path = PathBuf::from(&self.dir).join("_webcentral_data/mounts").join(&container_path);
            fs::create_dir_all(&host_path)?;
            cmd.args(&["-v", &format!("{}:{}", host_path.display(), container_path)]);
        }

        // Environment variables
        cmd.args(&["-e", &format!("PORT={}", dc.http_port)]);
        for (key, val) in &self.config.environment {
            cmd.args(&["-e", &format!("{}={}", key, val)]);
        }

        cmd.arg(&image_name);

        if !self.config.command.is_empty() {
            cmd.args(&["/bin/sh", "-c", &self.config.command]);
        }

        Ok(cmd)
    }

    async fn watch_files(&self) -> Result<()> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);

        let mut watcher = notify::recommended_watcher(move |res: Result<NotifyEvent, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        })?;

        // Watch directory
        watcher.watch(Path::new(&self.dir), RecursiveMode::Recursive)?;

        while let Some(event) = rx.recv().await {
            if let Some(path) = event.paths.first() {
                let rel_path = path.strip_prefix(&self.dir).unwrap_or(path);

                // Check if should reload
                if self.should_reload_for_file(rel_path) {
                    self.logger.write("", &format!("file changed: {}", rel_path.display()))?;
                    self.reload().await?;
                    break; // Stop watching, will be recreated on reload
                }
            }
        }

        Ok(())
    }

    fn should_reload_for_file(&self, rel_path: &Path) -> bool {
        let path_str = rel_path.to_string_lossy();

        // Default excludes
        let default_excludes = vec![
            "_webcentral_data/**", "node_modules/**", "**/*.log", "**/.*",
            "data/**", "log/**", "logs/**"
        ];

        // Check default excludes
        for pattern in &default_excludes {
            if matches_pattern(&path_str, pattern) {
                return false;
            }
        }

        // Check config excludes
        for pattern in &self.config.reload.exclude {
            if matches_pattern(&path_str, pattern.as_str()) {
                return false;
            }
        }

        // Includes
        let includes = if self.config.reload.include.is_empty() {
            if self.needs_process_management() {
                vec!["**/*"]
            } else {
                vec!["webcentral.ini", "Procfile"]
            }
        } else {
            self.config.reload.include.iter().map(|s| s.as_str()).collect()
        };

        for pattern in &includes {
            if matches_pattern(&path_str, pattern) {
                return true;
            }
        }

        false
    }

    async fn reload(&self) -> Result<()> {
        self.logger.write("", "reloading due to file change")?;
        self.stop().await;

        // Remove from projects map so it will be recreated
        PROJECTS.remove(&self.dir);

        Ok(())
    }

    async fn inactivity_timer(&self) {
        let timeout = Duration::from_secs(self.config.reload.timeout as u64);
        let check_interval = Duration::from_secs((self.config.reload.timeout / 10).max(1) as u64);

        loop {
            sleep(check_interval).await;

            let last = *self.last_activity.lock().await;
            if last.elapsed() > timeout {
                let _ = self.logger.write("", "stopping due to inactivity");
                self.stop().await;
                break;
            }
        }
    }

    pub async fn stop(&self) {
        let mut state = self.state.lock().await;

        match &mut *state {
            ProjectState::Running { process, workers, .. } => {
                // Stop workers
                for worker in workers {
                    let _ = worker.kill().await;
                }

                // Stop main process
                let _ = process.kill().await;

                self.logger.write("", "stopped").unwrap();
            }
            _ => {}
        }

        *state = ProjectState::Stopped;
    }
}

// Make Project cloneable for Arc usage
impl Clone for Project {
    fn clone(&self) -> Self {
        Project {
            dir: self.dir.clone(),
            config: self.config.clone(),
            logger: self.logger.clone(),
            uid: self.uid,
            gid: self.gid,
            use_firejail: self.use_firejail,
            state: self.state.clone(),
            last_activity: self.last_activity.clone(),
        }
    }
}

// Helper functions

fn get_free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
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

async fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        if TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
            return true;
        }
        sleep(Duration::from_millis(200)).await;
    }

    false
}

async fn find_project_by_name(name: &str) -> Result<PathBuf> {
    let pattern = PROJECTS_PATTERN.read().await;
    let pattern = pattern.as_ref().context("Projects pattern not set")?;

    for entry in glob::glob(pattern)? {
        let base_path = entry?;
        let project_path = base_path.join(name);
        if project_path.exists() && project_path.is_dir() {
            return Ok(project_path);
        }
    }

    anyhow::bail!("Project not found: {}", name)
}

fn matches_pattern(path: &str, pattern: &str) -> bool {
    let pattern = pattern.trim_end_matches('/');

    if pattern.contains("**") {
        let parts: Vec<_> = pattern.splitn(2, "**").collect();
        let prefix = parts[0].trim_end_matches('/');
        let suffix = parts.get(1).map(|s| s.trim_start_matches('/')).unwrap_or("");

        if !prefix.is_empty() && !path.starts_with(prefix) {
            return false;
        }

        if !suffix.is_empty() {
            let check_path = if !prefix.is_empty() {
                path.strip_prefix(prefix).unwrap_or(path).trim_start_matches('/')
            } else {
                path
            };

            return check_path == suffix || check_path.ends_with(&format!("/{}", suffix)) ||
                   check_path.contains(&format!("/{}/", suffix));
        }

        return true;
    }

    if pattern.ends_with("/*") {
        let dir = pattern.trim_end_matches("/*");
        return path == dir || (path.starts_with(&format!("{}/", dir)) && !path[dir.len() + 1..].contains('/'));
    }

    if pattern.contains('/') {
        return path == pattern || path.starts_with(&format!("{}/", pattern));
    }

    // Simple pattern matches name anywhere
    path == pattern || path.starts_with(&format!("{}/", pattern)) ||
    path.split('/').any(|part| part == pattern)
}
