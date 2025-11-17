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

// Event represents all lifecycle events with a single type
type Event struct {
	Type    string // "start", "process_started", "ready", "exit", "file_changed", "timeout", "stop_complete", "shutdown"
	Request *QueuedRequest
	Process *exec.Cmd
	Workers []*exec.Cmd
	Path    string
	Reason  string
}

// projectState holds all mutable state for a project (owned by lifecycle goroutine)
type projectState struct {
	phase        string // "stopped", "starting", "running", "stopping"
	process      *exec.Cmd
	workers      []*exec.Cmd
	port         int
	proxy        *httputil.ReverseProxy
	queue        []QueuedRequest
	lastActivity time.Time
	cancelWatch  context.CancelFunc
	watcher      *fsnotify.Watcher
	cancelTimer  context.CancelFunc
}

// Project represents a single domain/application
type Project struct {
	// Immutable configuration (safe to read from any goroutine)
	dir         string
	config      *ProjectConfig
	logger      *Logger
	uid         int
	gid         int
	useFirejail bool
	pruneLogs   int

	// Lifecycle management (single goroutine owns state)
	eventCh chan *Event
	done    chan struct{}
}

type QueuedRequest struct {
	w    http.ResponseWriter
	r    *http.Request
	ctx  context.Context
	done chan struct{} // Signal when request is complete
}

func SetProjectsPattern(pattern string) {
	projectsPattern = pattern
}

func GetProject(dir string, useFirejail bool, pruneLogs int) (*Project, error) {
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
	logger, err := NewLogger(logDir, uid, gid, pruneLogs)
	if err != nil {
		return nil, err
	}

	p := &Project{
		dir:         dir,
		config:      config,
		logger:      logger,
		uid:         uid,
		gid:         gid,
		useFirejail: useFirejail,
		pruneLogs:   pruneLogs,
		eventCh:     make(chan *Event, 10),
		done:        make(chan struct{}),
	}

	projects[dir] = p

	// Log what type of handler this is
	if p.config.Redirect != "" {
		logger.Write("", fmt.Sprintf("starting redirect to %s", p.config.Redirect))
	} else if p.config.Proxy != "" {
		logger.Write("", fmt.Sprintf("starting proxy for %s", p.config.Proxy))
	} else if p.config.SocketPath != "" {
		logger.Write("", fmt.Sprintf("starting forward to socket %s", p.config.SocketPath))
	} else if p.config.Port > 0 {
		host := p.config.Host
		if host == "" {
			host = "localhost"
		}
		logger.Write("", fmt.Sprintf("starting forward to http://%s:%d", host, p.config.Port))
	} else if p.config.Command == "" && p.config.Docker == nil {
		logger.Write("", "starting static file server")
	}

	// Log configuration errors
	for _, errMsg := range config.ConfigErrors {
		logger.Write("", errMsg)
	}

	// Start lifecycle manager for all projects (even static ones watch for config changes)
	go p.runLifecycle()

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

// runLifecycle is the main lifecycle management goroutine
func (p *Project) runLifecycle() {
	s := &projectState{phase: "stopped", lastActivity: time.Now()}

	// Always start file watcher (all projects watch webcentral.ini, apps watch more)
	if err := p.startFileWatcher(s); err != nil {
		p.logger.Write("", fmt.Sprintf("Failed to start file watcher: %v", err))
	}

	// Inactivity timer for all projects to clean up resources
	if p.config.Reload.Timeout > 0 {
		p.startInactivityTimer(s)
	}

	// Event loop with inline state machine
	for {
		select {
		case e := <-p.eventCh:

			if s.phase == "stopped" {
				if e.Type == "start" {
					s.lastActivity = time.Now()
					if p.needsProcessManagement() {
						if port, err := getFreePort(); err == nil {
							s.phase, s.port = "starting", port
							p.logger.Write("", fmt.Sprintf("starting on port %d", port))
							go p.startProcess(port)
							// Adding to queue happens in 'starting' phase
						} else {
							p.logger.Write("", fmt.Sprintf("failed to allocate port: %v", err))
							http.Error(e.Request.w, "Failed to allocate port", http.StatusServiceUnavailable)
							close(e.Request.done)
						}
					} else {
						s.phase = "running"
					}
				}
			}

			if s.phase == "starting" {
				switch e.Type {
				case "start":
					if e.Request != nil {
						s.queue = append(s.queue, *e.Request)
					}
				case "process_started":
					s.process = e.Process
				case "ready":
					s.phase, s.workers = "running", e.Workers
					s.proxy = p.createProxy(s.port)
					p.logger.Write("", fmt.Sprintf("reachable on port %d", s.port))
					p.serveQueue(s)
				case "exit":
					p.logger.Write("", fmt.Sprintf("process exited during startup: %s", e.Reason))
					p.flushQueue(s.queue, "Application failed to start")
					s.phase, s.queue = "stopped", nil
				case "file_changed":
					p.logger.Write("", fmt.Sprintf("file changed during startup: %s", e.Path))
				}
			}

			if s.phase == "running" {
				switch e.Type {
				case "start":
					s.lastActivity = time.Now()
					if e.Request != nil {
						p.serveRequest(s, *e.Request)
					}
				case "file_changed":
					p.logger.Write("", fmt.Sprintf("stopping due to change for %s", e.Path))
					s.phase = "stopping"
					go p.stopProcess(s)
				case "timeout":
					if time.Since(s.lastActivity) > time.Duration(p.config.Reload.Timeout)*time.Second {
						p.logger.Write("", "stopping due to inactivity")
						s.phase = "stopping"
						go p.stopProcess(s)
					}
				case "exit":
					p.logger.Write("", fmt.Sprintf("process exited unexpectedly: %s", e.Reason))
					s.phase, s.proxy = "stopped", nil
				}
			}

			if s.phase == "stopping" {
				switch e.Type {
				case "start":
					s.queue = append(s.queue, *e.Request)
				case "stop_complete":
					s.phase, s.process, s.workers, s.proxy, s.port = "stopped", nil, nil, nil, 0
					if len(s.queue) > 0 {
						p.logger.Write("", "restarting due to queued requests")
						// Re-inject first request to trigger restart
						p.eventCh <- &Event{Type: "start", Request: &s.queue[0]}
					}
				}
			}
		
		case <-p.done:
			p.cleanup(s)
			return
		}
	}
}

// serveRequest serves a single request using the proxy
func (p *Project) serveRequest(s *projectState, req QueuedRequest) {
	defer close(req.done)

	if req.ctx.Err() != nil {
		return // Request cancelled
	}

	if s.proxy != nil {
		s.proxy.ServeHTTP(req.w, req.r)
	} else {
		http.Error(req.w, "Service Unavailable", http.StatusServiceUnavailable)
	}
}

// Helper functions

func (p *Project) flushQueue(queue []QueuedRequest, errorMsg string) {
	for _, req := range queue {
		if req.ctx.Err() == nil {
			http.Error(req.w, errorMsg, http.StatusServiceUnavailable)
		}
		close(req.done)
	}
}

func (p *Project) serveQueue(s *projectState) {
	queue := s.queue
	s.queue = nil
	for _, req := range queue {
		p.serveRequest(s, req)
	}
}

func (p *Project) createProxy(port int) *httputil.ReverseProxy {
	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("localhost:%d", port),
	}

	return &httputil.ReverseProxy{
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
	// Track activity for inactivity timeout (non-blocking)
	select {
	case p.eventCh <- &Event{Type: "start"}:
	default:
	}

	if p.config.LogRequests {
		p.logger.Write("", fmt.Sprintf("%s %s", r.Method, r.URL.Path))
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
			targetProject, err := GetProject(targetDir, p.useFirejail, p.pruneLogs)
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
			p.logger.Write("", fmt.Sprintf("proxy error: %v", err))
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
	done := make(chan struct{})
	p.eventCh <- &Event{
		Type:    "start",
		Request: &QueuedRequest{w: w, r: r, ctx: r.Context(), done: done},
	}
	<-done // Block until request is served
}

// setupCommand configures a command with environment, dir, uid/gid, and logging
func (p *Project) setupCommand(cmd *exec.Cmd, port int, label string) {
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("PORT=%d", port))
	for key, val := range p.config.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, val))
	}

	cmd.Dir = p.dir

	if os.Geteuid() == 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(p.uid), Gid: uint32(p.gid)},
		}
	}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	go p.logOutput(stdout, label)
	go p.logOutput(stderr, label)
}

func (p *Project) startProcess(port int) {
	var cmd *exec.Cmd
	var err error

	if p.config.Docker != nil {
		cmd, err = p.buildDockerCommand(port)
	} else {
		cmd, err = p.buildCommand(port)
	}

	if err != nil {
		p.logger.Write("", fmt.Sprintf("failed to build command: %v", err))
		p.eventCh <- &Event{Type: "exit", Reason: fmt.Sprintf("build failed: %v", err)}
		return
	}

	p.setupCommand(cmd, port, "out")

	if err := cmd.Start(); err != nil {
		p.logger.Write("", fmt.Sprintf("failed to start process: %v", err))
		p.eventCh <- &Event{Type: "exit", Reason: fmt.Sprintf("start failed: %v", err)}
		return
	}

	// Send process started event
	p.eventCh <- &Event{Type: "process_started", Process: cmd}

	// Monitor process exit
	go func() {
		cmd.Wait()
		reason := "exit code 0"
		if cmd.ProcessState != nil {
			reason = fmt.Sprintf("exit code %d", cmd.ProcessState.ExitCode())
		}
		p.logger.Write("", fmt.Sprintf("process exited: %s", reason))
		p.eventCh <- &Event{Type: "exit", Reason: reason}
	}()

	// Wait for port and start workers
	go func() {
		if p.waitForPort(port, 30*time.Second) {
			workers := p.startWorkers(port)
			p.eventCh <- &Event{Type: "ready", Workers: workers}
		} else {
			p.logger.Write("", "application failed to start listening on port")
			p.eventCh <- &Event{Type: "exit", Reason: "port timeout"}
		}
	}()
}

func (p *Project) startWorkers(port int) []*exec.Cmd {
	if len(p.config.Workers) == 0 {
		return nil
	}

	p.logger.Write("", fmt.Sprintf("starting %d worker(s)", len(p.config.Workers)))

	var workers []*exec.Cmd

	for name, workerCmd := range p.config.Workers {
		// Build worker command
		var cmd *exec.Cmd

		// Substitute $PORT in worker command
		workerCmd = strings.ReplaceAll(workerCmd, "$PORT", strconv.Itoa(port))

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
				"/bin/sh", "-c", workerCmd,
			}

			cmd = exec.Command("firejail", args...)
		} else {
			cmd = exec.Command("/bin/sh", "-c", workerCmd)
		}

		p.setupCommand(cmd, port, fmt.Sprintf("worker-%s", name))

		if err := cmd.Start(); err != nil {
			p.logger.Write("", fmt.Sprintf("failed to start worker %s: %v", name, err))
			continue
		}

		workers = append(workers, cmd)

		// Monitor worker exit
		go func(workerName string, workerCmd *exec.Cmd) {
			workerCmd.Wait()
			p.logger.Write("", fmt.Sprintf("worker %s exited with code %v", workerName, workerCmd.ProcessState))
		}(name, cmd)
	}

	return workers
}

func (p *Project) buildCommand(port int) (*exec.Cmd, error) {
	command := p.config.Command
	if command == "" {
		command = "npm start"
	}

	// Substitute $PORT
	command = strings.ReplaceAll(command, "$PORT", strconv.Itoa(port))

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

func (p *Project) buildDockerCommand(port int) (*exec.Cmd, error) {
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

	dockerfile += fmt.Sprintf("ENV PORT=%d\n", port)
	dockerfile += fmt.Sprintf("EXPOSE %d\n", dc.HTTPPort)

	// Write Dockerfile to temp location
	dockerfilePath := filepath.Join(p.dir, "_webcentral_data", "Dockerfile")
	os.MkdirAll(filepath.Dir(dockerfilePath), 0755)
	os.WriteFile(dockerfilePath, []byte(dockerfile), 0644)

	// Build the image
	buildCmd := exec.Command("docker", "build", "-t", imageName, "-f", dockerfilePath, p.dir)
	buildCmd.Dir = p.dir
	if output, err := buildCmd.CombinedOutput(); err != nil {
		p.logger.Write("build", string(output))
		return nil, fmt.Errorf("docker build failed: %v", err)
	}

	// Prepare run arguments
	args := []string{"run", "--rm", "--name", containerName}

	// Port mapping
	args = append(args, "-p", fmt.Sprintf("%d:%d", port, dc.HTTPPort))

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

func (p *Project) waitForPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}

	return false
}

func (p *Project) stopProcess(s *projectState) {
	hasProcess := false

	// Stop workers
	for i, worker := range s.workers {
		if worker != nil && worker.Process != nil {
			hasProcess = true
			p.logger.Write("", fmt.Sprintf("stopping worker %d", i+1))
			worker.Process.Signal(syscall.SIGTERM)
			time.AfterFunc(2*time.Second, func() { worker.Process.Kill() })
		}
	}

	// Stop main process
	if s.process != nil && s.process.Process != nil {
		hasProcess = true
		s.process.Process.Signal(syscall.SIGTERM)
		time.AfterFunc(2*time.Second, func() { s.process.Process.Kill() })
	}

	// Fast-path for non-apps: signal completion immediately
	if !hasProcess {
		p.eventCh <- &Event{Type: "stop_complete"}
		return
	}

	// Wait a bit then signal completion for apps
	go func() {
		time.Sleep(2500 * time.Millisecond)
		p.eventCh <- &Event{Type: "stop_complete"}
	}()
}

func (p *Project) Stop() {
	select {
	case p.done <- struct{}{}:
	default:
	}
}

func (p *Project) cleanup(s *projectState) {
	if s.cancelWatch != nil {
		s.cancelWatch()
	}
	if s.cancelTimer != nil {
		s.cancelTimer()
	}
	if s.watcher != nil {
		s.watcher.Close()
	}

	// Stop processes if running
	if s.phase == "running" || s.phase == "starting" {
		if s.process != nil && s.process.Process != nil {
			s.process.Process.Kill()
		}
		for _, w := range s.workers {
			if w != nil && w.Process != nil {
				w.Process.Kill()
			}
		}
	}

	p.logger.Close()

	projectsMu.Lock()
	delete(projects, p.dir)
	projectsMu.Unlock()
}

func (p *Project) startFileWatcher(state *projectState) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	state.watcher = watcher

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

	// Only watch other files if this project runs processes
	if p.needsProcessManagement() {
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
	}

	// Start watching
	ctx, cancel := context.WithCancel(context.Background())
	state.cancelWatch = cancel

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove) != 0 {
					p.eventCh <- &Event{Type: "file_changed", Path: event.Name}
					return
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				p.logger.Write("", fmt.Sprintf("file watch error: %v", err))

			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (p *Project) startInactivityTimer(state *projectState) {
	if p.config.Reload.Timeout == 0 {
		return
	}

	interval := time.Duration(p.config.Reload.Timeout/10) * time.Second
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())
	state.cancelTimer = cancel

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				p.eventCh <- &Event{Type: "timeout"}
			case <-ctx.Done():
				return
			}
		}
	}()
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
