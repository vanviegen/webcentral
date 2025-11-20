use crate::logger::Logger;
use crate::project_config::{ConnectionTarget, DockerConfig, ProjectConfig, ProjectType};
use anyhow::Result;
use bytes::Bytes;
use http::{HeaderValue, Uri};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response};
use hyper_util::client::legacy::connect::{HttpConnector, Connection, Connected};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use nix::unistd::Uid;
use notify::{Event as NotifyEvent, RecursiveMode, Watcher};
use regex::Regex;
use std::fs;
use std::net::TcpStream;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tower::Service;

lazy_static::lazy_static! {
     static ref DEFAULT_HTTP_CLIENT: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http(); 
     static ref DEFAULT_CONNECTOR: HttpConnector = HttpConnector::new();
}

pub async fn create_project(
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

    // Create connector
    let mut custom_connector = None;
    let mut port = 0u16;

    // Log project type
    let descr = match &config.project_type {
        ProjectType::Redirect { target } => {
            &format!("Redirect to {}", target)
        }
        ProjectType::Proxy { target } => {
            &format!("Proxy to {}", target)
        }
        ProjectType::TcpForward { address } => {
            custom_connector = Some(FixedTcpHttpConnector::new(address.clone()));
            &format!("Forward to port {}", address)
        }
        ProjectType::UnixForward { socket_path } => {
            custom_connector = Some(FixedUnixHttpConnector::new(socket_path.clone()));
            &format!("Forward to unix socket {}", socket_path)
        }
        ProjectType::Application { .. } => {
            port = get_free_port()?;
            let addr = &format!("127.0.0.1:{}", port);
            custom_connector = Some(FixedTcpHttpConnector::new(addr.clone()));
            &format!("Application server on {}", addr)
        }
        ProjectType::Static => {
            "Static file server"
        }
    };
    logger.write("", descr);

    // Log configuration errors
    for err in &config.config_errors {
        logger.write("config", err);
    }

    let http_client = if let Some(connector) = custom_connector {
        Client::builder(TokioExecutor::new()).build(connector)
    } else {
        DEFAULT_HTTP_CLIENT
    };
    
    let connector = if let Some(connector) = custom_connector {
        connector
    } else {
        DEFAULT_CONNECTOR
    };
    
    let project = Arc::new(Project {
        domain: domain.clone(),
        dir: dir.to_string_lossy().to_string(),
        config: Arc::new(config.clone()),
        logger,
        uid,
        gid,
        use_firejail,
        port: Arc::new(Mutex::new(None)),
        process: Arc::new(Mutex::new(None)),
        workers: Arc::new(Mutex::new(Vec::new())),
        last_activity: Arc::new(Mutex::new(Instant::now())),
        http_client: Client::builder(TokioExecutor::new()).build(connector.clone()),
        connector,
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

    // Start application process if needed
    if let ProjectType::Application { .. } = config.project_type {
        let proj = project.clone();
        tokio::spawn(async move {
            if let Err(e) = proj.start_process(port).await {
                let _ = proj
                    .logger
                    .write("", &format!("Failed to start process: {}", e));
            }
        });
    }

    Ok(project)
}

#[derive(Debug)]
pub struct Project {
    pub config: Arc<ProjectConfig>,
    pub logger: Arc<Logger>,
    pub domain: String,
    dir: String,
    uid: u32,
    gid: u32,
    use_firejail: bool,
    port: Arc<Mutex<Option<u16>>>, // None means the app is still starting
    process: Arc<Mutex<Option<tokio::process::Child>>>,
    workers: Arc<Mutex<Vec<tokio::process::Child>>>,
    last_activity: Arc<Mutex<Instant>>,
    http_client: Client<TODO, Full<Bytes>>,
    connector: TODO,
}

impl Project {
    fn needs_process_management(&self) -> bool {
        matches!(self.config.project_type, ProjectType::Application { .. })
    }

    pub async fn handle(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
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
            ProjectType::Redirect { target } => self.handle_redirect(req, target).await,
            ProjectType::Proxy { target } => self.proxy_request(req, target).await,
            ProjectType::TcpForward { .. } => self.forward_request(req).await,
            ProjectType::UnixForward { .. } => self.forward_request(req).await,
            ProjectType::Application { .. } => self.handle_application(req).await,
            ProjectType::Static => self.handle_static(req).await,
        }
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

    async fn handle_redirect(&self, req: Request<Incoming>, target: &str) -> Result<Response<Full<Bytes>>> {
        Ok(Response::builder()
            .status(301)
            .header("Location", &format!("{}{}", target, req.uri().path()))
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

    async fn proxy_request(
        &self,
        req: Request<Incoming>,
        target: &str,
    ) -> Result<Response<Full<Bytes>>> {

        let (parts, body) = req.into_parts();
        let uri_str = format!("{}{}", target, parts.uri.path_and_query().unwrap());

        let mut new_parts = parts.clone();
        new_parts.uri = uri_str.parse()?;

        let original_host = parts
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        new_parts.headers.insert("X-Forwarded-Host", HeaderValue::from_str(original_host)?);
        new_parts.headers.insert("X-Forwarded-Proto", HeaderValue::from_str(parts.uri.scheme_str().unwrap_or("?"))?);

        let proxy_req = Request::from_parts(new_parts, body);
        self.forward_request(proxy_req).await
    }

    async fn forward_request(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>>
    {
        // Check if this is a WebSocket upgrade request
        if is_upgrade_request(&req) {
            return self.proxy_upgrade(req).await.map_err(|e| anyhow::anyhow!("Error during HTTP upgrade: {}", e));
        }

        let (parts, body) = req.into_parts();
        let body_bytes = body.collect().await?.to_bytes();
        let req = Request::from_parts(parts, Full::new(body_bytes));

        let resp = self.http_client.request(req).await?;

        let (parts, body) = resp.into_parts();
        let body_bytes = body.collect().await?.to_bytes();

        Ok(Response::from_parts(parts, Full::new(body_bytes)))
    }

    async fn handle_application(&self, mut req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        // Wait for port to be available (with timeout)
        let port = self.wait_for_port().await?;
        
        // Rewrite URI to point to localhost:port
        let uri_string = format!("http://127.0.0.1:{}{}", port, req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/"));
        *req.uri_mut() = uri_string.parse()?;

        self.forward_request(req).await
    }

    async fn wait_for_port(&self) -> Result<u16> {
        for _ in 0..300 {
            // 30 second timeout
            if let Some(port) = *self.port.lock().await {
                return Ok(port);
            }
            sleep(Duration::from_millis(100)).await;
        }
        anyhow::bail!("Application startup timeout")
    }

    async fn start_process(&self, port: u16) -> Result<()> {
        self.logger
            .write("", &format!("Starting on port {}", port));

        let (command, docker, _workers) = match &self.config.project_type {
            ProjectType::Application {
                command,
                docker,
                workers,
                ..
            } => (command, docker, workers),
            _ => unreachable!("start_process called for non-Application project"),
        };

        let mut process = if let Some(docker_config) = docker {
            self.build_docker_command(port, docker_config, command)
                .await?
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

        self.logger
            .write("", &format!("Starting application: {:?}", process));

        let mut child = process.spawn()?;

        // Stream logs
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

        // Wait for port to be ready
        let ready = wait_for_port(port, Duration::from_secs(30)).await;

        if !ready {
            child.kill().await?;
            self.logger
                .write("", "Application failed to start listening on port");
            anyhow::bail!("Port not ready");
        }

        self.logger.write("", &format!("Ready on port {}", port));

        // Start workers
        let workers = self.start_workers(port).await;

        // Store process, workers, and port (now that we're ready)
        *self.process.lock().await = Some(child);
        *self.workers.lock().await = workers;
        *self.port.lock().await = Some(port);

        // Monitor process exit in background - extract process ID before spawning
        let child_id = self.process.lock().await.as_ref().and_then(|p| p.id());

        if let Some(pid) = child_id {
            let logger = self.logger.clone();
            let port_clone = self.port.clone();

            tokio::spawn(async move {
                // Periodically check if process is still running
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;

                    // Check if process still exists
                    #[cfg(unix)]
                    {
                        use nix::sys::signal::kill;
                        use nix::unistd::Pid;

                        if kill(Pid::from_raw(pid as i32), None).is_err() {
                            // Process no longer exists
                            logger.write("", "Process exited");
                            *port_clone.lock().await = None;
                            break;
                        }
                    }

                    // Check if we still have a port (project might have been stopped)
                    if port_clone.lock().await.is_none() {
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

        self.logger
            .write("", &format!("Starting {} worker(s)", workers_map.len()));

        let mut workers = vec![];

        for (name, cmd) in workers_map {
            let mut process = match self.build_shell_command(cmd) {
                Ok(p) => p,
                Err(e) => {
                    let _ = self
                        .logger
                        .write("", &format!("Failed to build worker {}: {}", name, e));
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
                                logger.write(&label, &line);
                            }
                        });
                    }
                    if let Some(stderr) = child.stderr.take() {
                        let label = label.clone();
                        tokio::spawn(async move {
                            let reader = BufReader::new(stderr);
                            let mut lines = reader.lines();
                            while let Ok(Some(line)) = lines.next_line().await {
                                logger.write(&label, &line);
                            }
                        });
                    }

                    workers.push(child);
                }
                Err(e) => {
                    let _ = self
                        .logger
                        .write("", &format!("Failed to start worker {}: {}", name, e));
                }
            }
        }

        workers
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
                &format!("--whitelist={}", self.dir),
                "--read-only=/",
                &format!("--read-write={}", self.dir),
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
            self.logger.write("build", &stderr);
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
            let host_path = PathBuf::from(&self.dir)
                .join("_webcentral_data/mounts")
                .join(&container_path);
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

        let mut watcher =
            notify::recommended_watcher(move |res: Result<NotifyEvent, notify::Error>| {
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
            use notify::EventKind;

            // Only process modification, creation, and removal events (ignore Access events)
            if matches!(event.kind, EventKind::Access(_)) {
                continue;
            }

            if let Some(path) = event.paths.first() {
                let rel_path = path.strip_prefix(&self.dir).unwrap_or(path);

                // Skip events for the watched directory itself (empty relative path)
                if rel_path.as_os_str().is_empty() {
                    continue;
                }

                // Check if should reload
                if self.should_reload_for_file(rel_path) {
                    self.logger.write(
                        "",
                        &format!("Stopping due to change in {}", rel_path.display()),
                    );

                    // Remove from DOMAINS map immediately so new requests create a fresh instance
                    crate::server::discard_project(&self.domain).await;

                    // Stop the old process
                    self.stop().await;

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
            "_webcentral_data/**",
            "node_modules/**",
            "**/*.log",
            "**/.*",
            "data/**",
            "log/**",
            "logs/**",
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
            self.config
                .reload
                .include
                .iter()
                .map(|s| s.as_str())
                .collect()
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
            let mut pids = vec![];
            if let Some(process) = self.process.lock().await.as_ref() {
                if let Some(pid) = process.id() {
                    pids.push(pid);
                }
            }
            let workers = self.workers.lock().await;
            for worker in workers.iter() {
                if let Some(pid) = worker.id() {
                    pids.push(pid);
                }
            }
            pids
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
        let process_clone = self.process.clone();
        let workers_clone = self.workers.clone();
        let port_clone = self.port.clone();
        let logger_clone = self.logger.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(2500)).await;

            // Force kill if still running
            if let Some(mut process) = process_clone.lock().await.take() {
                let _ = process.kill().await;
            }
            let mut workers = workers_clone.lock().await;
            for worker in workers.iter_mut() {
                let _ = worker.kill().await;
            }
            workers.clear();
            *port_clone.lock().await = None;
            logger_clone.write("", "Stopped");
        });
    }

    async fn proxy_upgrade(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>> {
        let method = req.method().clone();
        let logger = self.logger.clone();

        // Get the upgrade future before we return a response
        let upgrade_fut = hyper::upgrade::on(req);

        // Connect to backend
        let mut connector = self.connector.clone();
        let io = connector.call(req.uri()).await?;
        let mut backend = io.into_inner();

        // Build and send the upgrade request to backend
        let mut buf = Vec::new();
        use std::io::Write;

        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .to_string();
        write!(&mut buf, "{} {} HTTP/1.1\r\n", method, path).unwrap();
        for (name, value) in req.headers() {
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
            match upgrade_fut.await {
                Ok(upgraded) => {
                    let mut upgraded = TokioIo::new(upgraded);

                    // Write any excess data from the response to the client
                    if header_end < bytes_read {
                        if let Err(e) = upgraded
                            .write_all(&response_buf[header_end..bytes_read])
                            .await
                        {
                            logger.write(
                                "error",
                                &format!("Failed to write excess data to client: {}", e),
                            );
                            return;
                        }
                    }

                    // Pipe data bidirectionally
                    let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut backend).await;
                }
                Err(e) => {
                    logger.write("error", &format!("Client upgrade failed: {}", e));
                }
            }
        });

        Ok(response_builder.body(Full::new(Bytes::new()))?)
    }
}

// Helper function to detect WebSocket upgrade requests
fn is_upgrade_request(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("upgrade"))
        .unwrap_or(false)
}

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
        let suffix = parts
            .get(1)
            .map(|s| s.trim_start_matches('/'))
            .unwrap_or("");

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
                path.strip_prefix(prefix)
                    .unwrap_or(path)
                    .trim_start_matches('/')
            } else {
                path
            };

            return check_path == suffix
                || check_path.ends_with(&format!("/{}", suffix))
                || check_path.contains(&format!("/{}/", suffix));
        }

        return true;
    }

    if pattern.ends_with("/*") {
        let dir = pattern.trim_end_matches("/*");
        return path == dir
            || (path.starts_with(&format!("{}/", dir)) && !path[dir.len() + 1..].contains('/'));
    }

    // Handle wildcard patterns like *.py, *.txt
    if pattern.starts_with("*.") && !pattern.contains('/') {
        let extension = &pattern[1..]; // includes the dot
        return path.ends_with(extension) || path.split('/').any(|part| part.ends_with(extension));
    }

    if pattern.contains('/') {
        return path == pattern || path.starts_with(&format!("{}/", pattern));
    }

    // Simple pattern matches name anywhere
    path == pattern
        || path.starts_with(&format!("{}/", pattern))
        || path.split('/').any(|part| part == pattern)
}

