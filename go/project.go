package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

var (
	projects        = make(map[string]*Project)
	projectsMu      sync.Mutex
	projectsPattern string
)

type Project struct {
	dir          string
	config       *ProjectConfig
	logger       *Logger
	process      *exec.Cmd
	port         int
	proxy        *httputil.ReverseProxy
	watcher      *fsnotify.Watcher
	queue        []QueuedRequest
	started      bool
	stopping     bool
	lastActivity time.Time
	activityMu   sync.Mutex
	queueMu      sync.Mutex
	uid          int
	gid          int
	useFirejail  bool
	cancelWatch  context.CancelFunc
}

type QueuedRequest struct {
	w   http.ResponseWriter
	r   *http.Request
	ctx context.Context
}

func SetProjectsPattern(pattern string) {
	projectsPattern = pattern
}

func GetProject(dir string, useFirejail bool) (*Project, error) {
	projectsMu.Lock()
	defer projectsMu.Unlock()

	if p, ok := projects[dir]; ok {
		return p, nil
	}

	config, err := LoadProjectConfig(dir)
	if err != nil {
		return nil, err
	}

	uid, gid := getOwnership(dir)

	logDir := filepath.Join(dir, "_webcentral_data", "log")
	logger, err := NewLogger(logDir, uid, gid)
	if err != nil {
		return nil, err
	}

	p := &Project{
		dir:          dir,
		config:       config,
		logger:       logger,
		lastActivity: time.Now(),
		uid:          uid,
		gid:          gid,
		useFirejail:  useFirejail,
	}

	projects[dir] = p

	logger.Write("project", fmt.Sprintf("Initialized project: %s", dir))

	// Start file watcher if not a static/redirect/proxy/forward without command
	if p.needsProcessManagement() {
		if err := p.startFileWatcher(); err != nil {
			logger.Write("error", fmt.Sprintf("Failed to start file watcher: %v", err))
		}

		if p.config.Reload.Timeout > 0 {
			go p.checkInactivity()
		}
	}

	return p, nil
}

func StopAllProjects() {
	projectsMu.Lock()
	defer projectsMu.Unlock()

	for _, p := range projects {
		p.Stop()
	}
}

func (p *Project) needsProcessManagement() bool {
	return p.config.Command != "" || p.config.Docker != nil ||
		(p.config.Redirect == "" && p.config.Proxy == "" &&
		 p.config.Port == 0 && p.config.SocketPath == "")
}

func (p *Project) findProjectByName(name string) (string, error) {
	// Expand glob pattern
	matches, err := filepath.Glob(projectsPattern)
	if err != nil {
		return "", err
	}

	for _, basePath := range matches {
		projectPath := filepath.Join(basePath, name)

		// Check if directory exists
		if info, err := os.Stat(projectPath); err == nil && info.IsDir() {
			return projectPath, nil
		}
	}

	return "", fmt.Errorf("project not found: %s", name)
}

func (p *Project) Handle(w http.ResponseWriter, r *http.Request) {
	p.updateActivity()

	if p.config.LogRequests {
		p.logger.Write("request", fmt.Sprintf("%s %s", r.Method, r.URL.Path))
	}

	// Apply URL rewrites
	if newPath, redirectTo := p.applyRewrites(r); redirectTo != "" {
		// Handle webcentral:// URLs
		if strings.HasPrefix(redirectTo, "webcentral://") {
			targetName := strings.TrimPrefix(redirectTo, "webcentral://")
			parts := strings.SplitN(targetName, "/", 2)

			projectName := parts[0]
			targetPath := "/"
			if len(parts) == 2 {
				targetPath = "/" + parts[1]
			}

			// Find the target project directory
			targetDir, err := p.findProjectByName(projectName)
			if err != nil {
				http.Error(w, fmt.Sprintf("Target project not found: %s", projectName), http.StatusNotFound)
				return
			}

			// Get or create the target project
			targetProject, err := GetProject(targetDir, p.useFirejail)
			if err != nil {
				http.Error(w, "Failed to load target project", http.StatusInternalServerError)
				return
			}

			// Update request path and forward to target project
			r.URL.Path = targetPath
			r.RequestURI = targetPath
			targetProject.Handle(w, r)
			return
		}

		http.Redirect(w, r, redirectTo, http.StatusMovedPermanently)
		return
	} else if newPath != r.URL.Path {
		r.URL.Path = newPath
		r.RequestURI = newPath
	}

	// Determine handler based on configuration
	if p.config.Redirect != "" {
		p.handleRedirect(w, r)
	} else if p.config.Proxy != "" {
		p.handleProxyRemote(w, r)
	} else if p.config.SocketPath != "" {
		p.handleForward(w, r)
	} else if p.config.Port > 0 {
		p.handleForward(w, r)
	} else if p.config.Command != "" || p.config.Docker != nil {
		p.handleApplication(w, r)
	} else if _, err := os.Stat(filepath.Join(p.dir, "package.json")); err == nil {
		p.handleApplication(w, r)
	} else {
		p.handleStatic(w, r)
	}
}

func (p *Project) applyRewrites(r *http.Request) (newPath string, redirectTo string) {
	newPath = r.URL.Path

	for pattern, target := range p.config.Rewrites {
		re, err := regexp.Compile("^" + pattern + "$")
		if err != nil {
			continue
		}

		if re.MatchString(r.URL.Path) {
			result := re.ReplaceAllString(r.URL.Path, target)

			// Check if it's a full URL (redirect) or path (rewrite)
			if strings.HasPrefix(result, "http://") || strings.HasPrefix(result, "https://") || strings.HasPrefix(result, "webcentral://") {
				return r.URL.Path, result
			}

			newPath = result
			break
		}
	}

	return newPath, ""
}

func (p *Project) handleRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, p.config.Redirect, http.StatusMovedPermanently)
}

func (p *Project) handleStatic(w http.ResponseWriter, r *http.Request) {
	publicDir := filepath.Join(p.dir, "public")

	if _, err := os.Stat(publicDir); os.IsNotExist(err) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	fs := http.FileServer(http.Dir(publicDir))
	fs.ServeHTTP(w, r)
}

func (p *Project) handleForward(w http.ResponseWriter, r *http.Request) {
	var targetURL *url.URL

	if p.config.SocketPath != "" {
		targetURL = &url.URL{
			Scheme: "http",
			Host:   "unix",
		}
	} else {
		host := p.config.Host
		if host == "" {
			host = "localhost"
		}
		targetURL = &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("%s:%d", host, p.config.Port),
		}
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.Header.Set("X-Forwarded-Host", r.Host)
			req.Header.Set("X-Forwarded-Proto", getProto(r))
		},
	}

	if p.config.SocketPath != "" {
		proxy.Transport = &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", p.config.SocketPath)
			},
		}
	}

	proxy.ServeHTTP(w, r)
}

func (p *Project) handleProxyRemote(w http.ResponseWriter, r *http.Request) {
	targetURL, err := url.Parse(p.config.Proxy)
	if err != nil {
		http.Error(w, "Invalid proxy URL", http.StatusInternalServerError)
		return
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.URL.Path = singleJoiningSlash(targetURL.Path, req.URL.Path)
			if targetURL.RawQuery == "" || req.URL.RawQuery == "" {
				req.URL.RawQuery = targetURL.RawQuery + req.URL.RawQuery
			} else {
				req.URL.RawQuery = targetURL.RawQuery + "&" + req.URL.RawQuery
			}
			req.Header.Set("X-Forwarded-Host", r.Host)
			req.Header.Set("X-Forwarded-Proto", getProto(r))
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.logger.Write("proxy-error", err.Error())
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// Retry logic for GET requests only
	if r.Method == "GET" {
		for i := 0; i < 6; i++ {
			rec := &responseRecorder{ResponseWriter: w}
			proxy.ServeHTTP(rec, r)

			if rec.statusCode < 500 || rec.statusCode >= 600 {
				return
			}

			if i < 5 {
				time.Sleep(500 * time.Millisecond)
			}
		}
	} else {
		proxy.ServeHTTP(w, r)
	}
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (p *Project) handleApplication(w http.ResponseWriter, r *http.Request) {
	if !p.started {
		p.queueMu.Lock()
		if !p.started {
			p.queue = append(p.queue, QueuedRequest{w, r, r.Context()})
			p.queueMu.Unlock()

			go p.startProcess()

			select {
			case <-r.Context().Done():
				return
			case <-time.After(60 * time.Second):
				http.Error(w, "Application startup timeout", http.StatusGatewayTimeout)
				return
			}
		}
		p.queueMu.Unlock()
		return
	}

	if p.proxy != nil {
		p.proxy.ServeHTTP(w, r)
	} else {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}
}

func (p *Project) startProcess() error {
	p.activityMu.Lock()
	if p.started || p.stopping {
		p.activityMu.Unlock()
		return nil
	}
	p.activityMu.Unlock()

	p.logger.Write("start", "Starting application")

	// Allocate a free port
	port, err := getFreePort()
	if err != nil {
		p.logger.Write("error", fmt.Sprintf("Failed to allocate port: %v", err))
		return err
	}
	p.port = port

	// Build and run the command
	var cmd *exec.Cmd

	if p.config.Docker != nil {
		cmd, err = p.buildDockerCommand()
	} else if p.config.Command != "" {
		cmd, err = p.buildCommand()
	} else {
		cmd, err = p.buildCommand()
	}

	if err != nil {
		p.logger.Write("error", fmt.Sprintf("Failed to build command: %v", err))
		return err
	}

	// Set up process environment
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("PORT=%d", p.port))

	for key, val := range p.config.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, val))
	}

	// Set working directory
	cmd.Dir = p.dir

	// Set UID/GID if running as root
	if os.Geteuid() == 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uint32(p.uid),
				Gid: uint32(p.gid),
			},
		}
	}

	// Capture stdout/stderr
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	go p.logOutput(stdout, "stdout")
	go p.logOutput(stderr, "stderr")

	// Start the process
	if err := cmd.Start(); err != nil {
		p.logger.Write("error", fmt.Sprintf("Failed to start process: %v", err))
		return err
	}

	p.process = cmd

	// Wait for the port to become available
	go func() {
		if p.waitForPort(30 * time.Second) {
			p.onStarted()
		} else {
			p.logger.Write("error", "Application failed to start listening on port")
			p.Stop()
		}
	}()

	// Monitor process exit
	go func() {
		cmd.Wait()
		p.logger.Write("exit", fmt.Sprintf("Process exited with status: %v", cmd.ProcessState))
		p.onProcessExit()
	}()

	return nil
}

func (p *Project) buildCommand() (*exec.Cmd, error) {
	command := p.config.Command
	if command == "" {
		command = "npm start"
	}

	// Substitute $PORT
	command = strings.ReplaceAll(command, "$PORT", strconv.Itoa(p.port))

	var cmd *exec.Cmd

	if p.useFirejail && p.config.Docker == nil {
		homeDir := p.dir
		if os.Geteuid() == 0 {
			homeDir = getUserHome(p.uid)
		}

		args := []string{
			"--quiet",
			"--noprofile",
			"--private-tmp",
			"--private-dev",
			fmt.Sprintf("--private=%s", homeDir),
			fmt.Sprintf("--whitelist=%s", p.dir),
			"--read-only=/",
			fmt.Sprintf("--read-write=%s", p.dir),
			"--",
			"/bin/sh", "-c", command,
		}

		cmd = exec.Command("firejail", args...)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}

	return cmd, nil
}

func (p *Project) buildDockerCommand() (*exec.Cmd, error) {
	dc := p.config.Docker

	// Generate a unique container name based on directory
	hash := md5.Sum([]byte(p.dir))
	containerName := "webcentral-" + hex.EncodeToString(hash[:8])

	// Check if we need to build the image
	imageName := containerName + ":latest"

	// Build Dockerfile
	dockerfile := fmt.Sprintf("FROM %s\n", dc.Base)

	if len(dc.Packages) > 0 {
		dockerfile += "RUN apk add --no-cache " + strings.Join(dc.Packages, " ") + "\n"
	}

	if dc.MountAppDir {
		dockerfile += fmt.Sprintf("WORKDIR %s\n", dc.AppDir)
		if len(dc.Commands) > 0 {
			dockerfile += "COPY . .\n"
			for _, cmd := range dc.Commands {
				dockerfile += "RUN " + cmd + "\n"
			}
		}
	}

	dockerfile += fmt.Sprintf("ENV PORT=%d\n", p.port)
	dockerfile += fmt.Sprintf("EXPOSE %d\n", dc.HTTPPort)

	// Write Dockerfile to temp location
	dockerfilePath := filepath.Join(p.dir, "_webcentral_data", "Dockerfile")
	os.MkdirAll(filepath.Dir(dockerfilePath), 0755)
	os.WriteFile(dockerfilePath, []byte(dockerfile), 0644)

	// Build the image
	buildCmd := exec.Command("docker", "build", "-t", imageName, "-f", dockerfilePath, p.dir)
	buildCmd.Dir = p.dir
	if output, err := buildCmd.CombinedOutput(); err != nil {
		p.logger.Write("docker-build", string(output))
		return nil, fmt.Errorf("docker build failed: %v", err)
	}

	// Prepare run arguments
	args := []string{"run", "--rm", "--name", containerName}

	// Port mapping
	args = append(args, "-p", fmt.Sprintf("%d:%d", p.port, dc.HTTPPort))

	// Volume mounts
	if dc.MountAppDir {
		args = append(args, "-v", fmt.Sprintf("%s:%s", p.dir, dc.AppDir))
	}

	for _, mount := range dc.Mounts {
		hostPath := filepath.Join(p.dir, "_webcentral_data", "mounts", mount)
		os.MkdirAll(hostPath, 0755)
		containerPath := filepath.Join(dc.AppDir, mount)
		args = append(args, "-v", fmt.Sprintf("%s:%s", hostPath, containerPath))
	}

	// Home directory mount
	homePath := filepath.Join(p.dir, "_webcentral_data", "home")
	os.MkdirAll(homePath, 0755)
	args = append(args, "-v", fmt.Sprintf("%s:/home", homePath))
	args = append(args, "-e", "HOME=/home")

	// Environment variables
	for key, val := range p.config.Environment {
		args = append(args, "-e", fmt.Sprintf("%s=%s", key, val))
	}

	// User
	if p.uid > 0 {
		args = append(args, "-u", fmt.Sprintf("%d:%d", p.uid, p.gid))
	}

	// Command
	args = append(args, imageName)
	if p.config.Command != "" {
		command := strings.ReplaceAll(p.config.Command, "$PORT", strconv.Itoa(dc.HTTPPort))
		args = append(args, "/bin/sh", "-c", command)
	}

	return exec.Command("docker", args...), nil
}

func (p *Project) logOutput(r io.Reader, source string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		p.logger.Write(source, line)
	}
}

func (p *Project) waitForPort(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", p.port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}

	return false
}

func (p *Project) onStarted() {
	p.logger.Write("ready", fmt.Sprintf("Application listening on port %d", p.port))

	// Create reverse proxy
	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("localhost:%d", p.port),
	}

	p.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Header.Set("X-Forwarded-Host", req.Host)
			proto := getProto(req)
			req.Header.Set("X-Forwarded-Proto", proto)

			// Special handling for WebSocket
			if req.Header.Get("Upgrade") == "websocket" {
				if proto == "https" {
					req.Header.Set("X-Forwarded-Proto", "http")
				}
			}
		},
	}

	p.started = true

	// Process queued requests
	p.queueMu.Lock()
	queue := p.queue
	p.queue = nil
	p.queueMu.Unlock()

	for _, qr := range queue {
		if qr.ctx.Err() == nil {
			p.proxy.ServeHTTP(qr.w, qr.r)
		}
	}
}

func (p *Project) onProcessExit() {
	p.activityMu.Lock()
	p.started = false
	p.proxy = nil
	p.process = nil
	p.activityMu.Unlock()
}

func (p *Project) Stop() {
	p.activityMu.Lock()
	if p.stopping {
		p.activityMu.Unlock()
		return
	}
	p.stopping = true
	p.activityMu.Unlock()

	p.logger.Write("stop", "Stopping project")

	if p.cancelWatch != nil {
		p.cancelWatch()
	}

	if p.watcher != nil {
		p.watcher.Close()
	}

	if p.process != nil {
		p.process.Process.Signal(syscall.SIGTERM)

		done := make(chan bool)
		go func() {
			p.process.Wait()
			done <- true
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			p.process.Process.Kill()
		}
	}

	p.logger.Close()
}

func (p *Project) updateActivity() {
	p.activityMu.Lock()
	p.lastActivity = time.Now()
	p.activityMu.Unlock()
}

func (p *Project) checkInactivity() {
	if p.config.Reload.Timeout == 0 {
		return
	}

	interval := time.Duration(p.config.Reload.Timeout/10) * time.Second
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		p.activityMu.Lock()
		if p.stopping {
			p.activityMu.Unlock()
			return
		}

		if p.started && time.Since(p.lastActivity) > time.Duration(p.config.Reload.Timeout)*time.Second {
			p.activityMu.Unlock()
			p.logger.Write("timeout", "Stopping due to inactivity")
			p.Stop()
			return
		}
		p.activityMu.Unlock()
	}
}

func (p *Project) startFileWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	p.watcher = watcher

	// Add directories to watch
	includes := p.config.Reload.Include
	excludes := append(p.config.Reload.Exclude, "_webcentral_data", "node_modules", "**/*.log", "**/.*", "data", "log", "logs")

	if len(includes) == 0 {
		includes = []string{"**/*"}
	}

	// Always watch webcentral.ini
	iniPath := filepath.Join(p.dir, "webcentral.ini")
	if _, err := os.Stat(iniPath); err == nil {
		watcher.Add(iniPath)
	}

	// Watch directories based on include/exclude patterns
	filepath.Walk(p.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(p.dir, path)

		// Check excludes
		for _, pattern := range excludes {
			if matched, _ := filepath.Match(pattern, relPath); matched {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		if info.IsDir() {
			watcher.Add(path)
		}

		return nil
	})

	// Start watching
	ctx, cancel := context.WithCancel(context.Background())
	p.cancelWatch = cancel

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove) != 0 {
					p.logger.Write("reload", fmt.Sprintf("File changed: %s, restarting", event.Name))
					p.Stop()
					return
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				p.logger.Write("watch-error", err.Error())

			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

func getProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func getFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

func getOwnership(path string) (int, int) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0
	}

	stat := info.Sys().(*syscall.Stat_t)
	return int(stat.Uid), int(stat.Gid)
}

func getUserHome(uid int) string {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return "/tmp"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) >= 6 {
			if u, _ := strconv.Atoi(parts[2]); u == uid {
				return parts[5]
			}
		}
	}

	return "/tmp"
}
