use crate::config::{DockerConfig, ProjectConfig, ProjectType};
use crate::logger::Logger;
use anyhow::Result;
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
use tokio::sync::Mutex;
use tokio::time::sleep;


pub async fn create_project(dir: &Path, domain: String, use_firejail: bool, prune_logs: i64) -> Result<Arc<Project>> {
    // Load configuration
    let config = ProjectConfig::load(dir)?;
    let (uid, gid) = get_ownership(dir);

    // Create logger
    let log_dir = dir.join("_webcentral_data/log");
    let logger = Arc::new(Logger::new(log_dir, uid, gid, prune_logs)?);

    // Log project type
    match &config.project_type {
        ProjectType::Redirect { target } => {
            logger.write("", &format!("Redirect to {}", target))?;
        }
        ProjectType::Proxy { target } => {
            logger.write("", &format!("Proxy to {}", target))?;
        }
        ProjectType::Forward { socket_path, host, port } => {
            if !socket_path.is_empty() {
                logger.write("", &format!("Forward to socket {}", socket_path))?;
            } else {
                logger.write("", &format!("Forward to http://{}:{}", host, port))?;
            }
        }
        ProjectType::Application { .. } => {
            // Will log when process starts
        }
        ProjectType::Static => {
            logger.write("", "Static file server")?;
        }
    }

    // Log configuration errors
    for err in &config.config_errors {
        logger.write("config", err)?;
    }

    let project = Arc::new(Project {
        domain: domain.clone(),
        dir: dir.to_string_lossy().to_string(),
        config: Arc::new(config),
        logger: logger.clone(),
        uid,
        gid,
        use_firejail,
        state: Arc::new(Mutex::new(ProjectState::Stopped)),
        last_activity: Arc::new(Mutex::new(Instant::now())),
    });

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

#[derive(Debug)]
enum ProjectState {
    Stopped,
    Starting { port: u16, #[allow(dead_code)] start_time: Instant },
    Running { port: u16, process: tokio::process::Child, workers: Vec<tokio::process::Child> },
}

#[derive(Debug)]
pub struct Project {
    domain: String,
    dir: String,
    pub config: Arc<ProjectConfig>,
    logger: Arc<Logger>,
    uid: u32,
    gid: u32,
    use_firejail: bool,
    state: Arc<Mutex<ProjectState>>,
    last_activity: Arc<Mutex<Instant>>,
}

impl Project {
    fn needs_process_management(&self) -> bool {
        matches!(self.config.project_type, ProjectType::Application { .. })
    }

    pub fn handle<'a>(&'a self, req: Request<Incoming>) -> Pin<Box<dyn Future<Output = Result<Response<Full<Bytes>>>> + Send + 'a>> {
        Box::pin(async move { self.handle_impl(req).await })
    }

    async fn handle_impl(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        *self.last_activity.lock().await = Instant::now();

        if self.config.log_requests {
            let _ = self.logger.write("", &format!("{} {}", req.method(), req.uri().path()));
        }

        // Apply URL rewrites
        let (_path, redirect) = self.apply_rewrites(req.uri().path());

        if !redirect.is_empty() {
            return Ok(Response::builder()
                .status(301)
                .header("Location", redirect)
                .body(Full::new(Bytes::new()))?);
        }

        // Determine handler based on configuration
        match &self.config.project_type {
            ProjectType::Redirect { .. } => {
                self.handle_redirect().await
            }
            ProjectType::Proxy { .. } => {
                self.handle_proxy_remote(req).await
            }
            ProjectType::Forward { .. } => {
                self.handle_forward(req).await
            }
            ProjectType::Application { .. } => {
                self.handle_application(req).await
            }
            ProjectType::Static => {
                self.handle_static(req).await
            }
        }
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

    async fn handle_redirect(&self) -> Result<Response<Full<Bytes>>> {
        let target = match &self.config.project_type {
            ProjectType::Redirect { target } => target,
            _ => unreachable!("handle_redirect called for non-Redirect project"),
        };
        
        Ok(Response::builder()
            .status(301)
            .header("Location", target)
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
        let (socket_path, host, port) = match &self.config.project_type {
            ProjectType::Forward { socket_path, host, port } => (socket_path, host, port),
            _ => unreachable!("handle_forward called for non-Forward project"),
        };
        
        // For forwards (static port/socket), just proxy directly
        let target = if !socket_path.is_empty() {
            format!("unix://{}", socket_path)
        } else {
            format!("http://{}:{}", host, port)
        };

        self.proxy_request(req, &target).await
    }

    async fn handle_proxy_remote(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        let target = match &self.config.project_type {
            ProjectType::Proxy { target } => target,
            _ => unreachable!("handle_proxy_remote called for non-Proxy project"),
        };
        
        // Simplified proxy without retry logic
        // (Retry would require request cloning which is complex with streaming bodies)
        self.proxy_request(req, target).await
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
        // Ensure application is started
        self.ensure_started().await?;

        // Get current port
        let port = {
            let state = self.state.lock().await;
            match *state {
                ProjectState::Running { port, .. } => port,
                ProjectState::Starting { port, .. } => port,
                _ => return Ok(Response::builder().status(503).body(Full::new(Bytes::from("Service Unavailable")))?),
            }
        };

        // Proxy to application
        let target = format!("http://localhost:{}", port);
        self.proxy_request(req, &target).await
    }

    async fn ensure_started(&self) -> Result<()> {
        let mut state = self.state.lock().await;

        match *state {
            ProjectState::Running { .. } => return Ok(()),
            ProjectState::Starting { .. } => {
                // Already starting, just wait
                drop(state);
            }
            ProjectState::Stopped => {
                // Start the application
                let port = get_free_port()?;
                self.logger.write("", &format!("Starting on port {}", port))?;

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
            }
        }

        // Wait for startup to complete (with timeout)
        for _ in 0..300 {  // 30 second timeout
            sleep(Duration::from_millis(100)).await;
            let s = self.state.lock().await;
            match *s {
                ProjectState::Running { .. } => return Ok(()),
                ProjectState::Stopped => anyhow::bail!("Application failed to start"),
                _ => continue,
            }
        }
        
        anyhow::bail!("Application startup timeout")
    }

    async fn start_process(&self, port: u16) -> Result<()> {
        let (command, docker, _workers) = match &self.config.project_type {
            ProjectType::Application { command, docker, workers } => (command, docker, workers),
            _ => unreachable!("start_process called for non-Application project"),
        };
        
        let mut process = if let Some(docker_config) = docker {
            self.build_docker_command(port, docker_config, command).await?
        } else {
            self.build_shell_command(command)?
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

        self.logger.write("", "Starting application")?;

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
            self.logger.write("", "Application failed to start listening on port")?;
            *self.state.lock().await = ProjectState::Stopped;
            anyhow::bail!("Port not ready");
        }

        self.logger.write("", &format!("Ready on port {}", port))?;

        // Start workers
        let workers = self.start_workers(port).await;

        *self.state.lock().await = ProjectState::Running { port, process: child, workers };

        // Monitor process exit in background - extract process ID before spawning
        let child_id = {
            let state = self.state.lock().await;
            if let ProjectState::Running { ref process, .. } = *state {
                process.id()
            } else {
                None
            }
        };

        if let Some(pid) = child_id {
            let logger = self.logger.clone();
            let state_clone = self.state.clone();

            tokio::spawn(async move {
                // Periodically check if process is still running
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;

                    // Check if process still exists
                    #[cfg(unix)]
                    {
                        use nix::sys::signal::{kill};
                        use nix::unistd::Pid;

                        if kill(Pid::from_raw(pid as i32), None).is_err() {
                            // Process no longer exists
                            let _ = logger.write("", "Process exited");
                            *state_clone.lock().await = ProjectState::Stopped;
                            break;
                        }
                    }

                    // Check if we're still in Running state
                    let still_running = {
                        let state = state_clone.lock().await;
                        matches!(*state, ProjectState::Running { .. })
                    };

                    if !still_running {
                        break;
                    }
                }
            });
        }

        Ok(())
    }

    async fn start_workers(&self, port: u16) -> Vec<tokio::process::Child> {
        let workers_map = match &self.config.project_type {
            ProjectType::Application { workers, .. } => workers,
            _ => return vec![],
        };
        
        if workers_map.is_empty() {
            return vec![];
        }

        self.logger.write("", &format!("Starting {} worker(s)", workers_map.len())).unwrap();

        let mut workers = vec![];

        for (name, cmd) in workers_map {
            let mut process = match self.build_shell_command(cmd) {
                Ok(p) => p,
                Err(e) => {
                    let _ = self.logger.write("", &format!("Failed to build worker {}: {}", name, e));
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
                    let _ = self.logger.write("", &format!("Failed to start worker {}: {}", name, e));
                }
            }
        }

        workers
    }

    fn build_shell_command(&self, command: &str) -> Result<Command> {
        let has_docker = matches!(self.config.project_type, ProjectType::Application { docker: Some(_), .. });
        
        let mut cmd = if self.use_firejail && !has_docker {
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
                "/bin/sh", "-c", &command,
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

    async fn build_docker_command(&self, port: u16, dc: &DockerConfig, command: &str) -> Result<Command> {
        // Generate container name using a hash of the directory path
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.dir.hash(&mut hasher);
        let hash = hasher.finish();

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

        if !command.is_empty() {
            cmd.args(&["/bin/sh", "-c", command]);
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

        // Watch directory recursively. Note: notify crate doesn't support exclusion patterns,
        // so we watch everything and filter unwanted paths in should_reload_for_file().
        // This generates events for files in node_modules/, data/, etc. that we then ignore,
        // but the overhead is acceptable and this approach is simpler than selectively watching
        // only certain subdirectories.
        watcher.watch(Path::new(&self.dir), RecursiveMode::Recursive)?;

        while let Some(event) = rx.recv().await {
            if let Some(path) = event.paths.first() {
                let rel_path = path.strip_prefix(&self.dir).unwrap_or(path);

                // Check if should reload
                if self.should_reload_for_file(rel_path) {
                    self.logger.write("", &format!("Stopping due to change in {}", rel_path.display()))?;

                    // Remove from DOMAINS map immediately so new requests create a fresh instance
                    crate::server::discard_project(&self.domain).await;

                    // Stop the old process in background
                    let project_clone = self.clone();
                    tokio::spawn(async move {
                        project_clone.stop().await;
                    });

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

    async fn inactivity_timer(&self) {
        let timeout = Duration::from_secs(self.config.reload.timeout as u64);
        let check_interval = Duration::from_secs((self.config.reload.timeout / 10).max(1) as u64);

        loop {
            sleep(check_interval).await;

            let last = *self.last_activity.lock().await;
            if last.elapsed() > timeout {
                let _ = self.logger.write("", "Stopping due to inactivity");

                // Stop and remove from DOMAINS map so it will be recreated on next request
                let domain = self.domain.clone();
                self.stop().await;
                crate::server::discard_project(&domain).await;
                break;
            }
        }
    }

    pub async fn stop(&self) {
        // Send SIGTERM first, then force kill after delay
        let pids: Vec<u32> = {
            let state = self.state.lock().await;
            match &*state {
                ProjectState::Running { process, workers, .. } => {
                    let mut pids = vec![];
                    if let Some(pid) = process.id() {
                        pids.push(pid);
                    }
                    for worker in workers {
                        if let Some(pid) = worker.id() {
                            pids.push(pid);
                        }
                    }
                    pids
                }
                _ => vec![]
            }
        };

        // Send SIGTERM to all processes
        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            for pid in &pids {
                let _ = kill(Pid::from_raw(*pid as i32), Signal::SIGTERM);
            }
        }

        // Wait for graceful shutdown (but don't block - do it in background)
        let state_clone = self.state.clone();
        let logger_clone = self.logger.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(2500)).await;

            // Force kill if still running
            let mut state = state_clone.lock().await;
            match &mut *state {
                ProjectState::Running { process, workers, .. } => {
                    for worker in workers {
                        let _ = worker.kill().await;
                    }
                    let _ = process.kill().await;
                    let _ = logger_clone.write("", "Stopped");
                    *state = ProjectState::Stopped;
                }
                _ => {
                    *state = ProjectState::Stopped;
                }
            }
        });
    }
}

// Make Project cloneable for Arc usage
impl Clone for Project {
    fn clone(&self) -> Self {
        Project {
            domain: self.domain.clone(),
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

fn matches_pattern(path: &str, pattern: &str) -> bool {
    let pattern = pattern.trim_end_matches('/');

    if pattern.contains("**") {
        let parts: Vec<_> = pattern.splitn(2, "**").collect();
        let prefix = parts[0].trim_end_matches('/');
        let suffix = parts.get(1).map(|s| s.trim_start_matches('/')).unwrap_or("");

        // Check prefix with directory boundary
        if !prefix.is_empty() {
            if path == prefix || path.starts_with(&format!("{}/", prefix)) {
                // Prefix matches
            } else {
                return false;
            }
        }

        if !suffix.is_empty() && suffix != "*" {
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

    // Handle wildcard patterns like *.py, *.txt
    if pattern.starts_with("*.") && !pattern.contains('/') {
        let extension = &pattern[1..]; // includes the dot
        return path.ends_with(extension) ||
               path.split('/').any(|part| part.ends_with(extension));
    }

    if pattern.contains('/') {
        return path == pattern || path.starts_with(&format!("{}/", pattern));
    }

    // Simple pattern matches name anywhere
    path == pattern || path.starts_with(&format!("{}/", pattern)) ||
    path.split('/').any(|part| part == pattern)
}
