package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Server struct {
	config          *Config
	httpServer      *http.Server
	httpsServer     *http.Server
	certManager     *autocert.Manager
	bindings        map[string]string
	bindingsFile    string
	bindingsMu      sync.RWMutex
	lastScan        time.Time
	certRequests    map[string]bool
	certRequestsMu  sync.Mutex
	approvedHosts   map[string]bool
	approvedHostsMu sync.RWMutex
	watcher         *fsnotify.Watcher
}

func NewServer(config *Config) (*Server, error) {
	bindingsFile := config.BindingsFile
	if bindingsFile == "" {
		bindingsFile = filepath.Join(config.ConfigDir, "bindings.json")
	}

	s := &Server{
		config:        config,
		bindings:      make(map[string]string),
		bindingsFile:  bindingsFile,
		certRequests:  make(map[string]bool),
		approvedHosts: make(map[string]bool),
	}

	// Set the global projects pattern for cross-project routing
	SetProjectsPattern(config.Projects)

	// Load bindings cache
	s.loadBindings()

	// Set up ACME/autocert if HTTPS is enabled
	if config.HTTPSPort > 0 {
		certDir := filepath.Join(config.ConfigDir, "acme", "certificates")
		os.MkdirAll(certDir, 0700)

		s.certManager = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(certDir),
			HostPolicy: func(ctx context.Context, host string) error {
				return s.approveHost(ctx, host)
			},
			Email: config.Email,
		}

		if config.ACMEUrl != "https://acme-v02.api.letsencrypt.org/directory" {
			s.certManager.Client = &acme.Client{
				DirectoryURL: config.ACMEUrl,
			}
		}
	}

	return s, nil
}

func (s *Server) Start() error {
	// Proactively acquire certificates for all domains
	if s.certManager != nil {
		go s.ensureAllCertificates()

		// Watch for new project directories
		if err := s.watchProjectDirectories(); err != nil {
			fmt.Printf("Warning: Failed to set up directory watcher: %v\n", err)
		}
	}

	// Start HTTP server
	if s.config.HTTPPort > 0 {
		var handler http.Handler = http.HandlerFunc(s.handleHTTP)

		// Wrap with autocert HTTP handler for ACME challenges
		if s.certManager != nil {
			handler = s.certManager.HTTPHandler(handler)
		}

		s.httpServer = &http.Server{
			Addr:    fmt.Sprintf(":%d", s.config.HTTPPort),
			Handler: handler,
		}

		go func() {
			fmt.Printf("HTTP server listening on port %d\n", s.config.HTTPPort)
			if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
				fmt.Printf("HTTP server error: %v\n", err)
			}
		}()
	}

	// Start HTTPS server
	if s.config.HTTPSPort > 0 {
		tlsConfig := &tls.Config{
			GetCertificate: s.getCertificateWithLogging,
			MinVersion:     tls.VersionTLS12,
		}

		// Enable TLS-ALPN-01 challenge support along with standard protocols
		tlsConfig.NextProtos = []string{
			acme.ALPNProto, // Enable TLS-ALPN-01 challenge
			"h2",           // HTTP/2
			"http/1.1",     // HTTP/1.1
		}

		s.httpsServer = &http.Server{
			Addr:      fmt.Sprintf(":%d", s.config.HTTPSPort),
			Handler:   http.HandlerFunc(s.handleHTTPS),
			TLSConfig: tlsConfig,
		}

		go func() {
			fmt.Printf("HTTPS server listening on port %d\n", s.config.HTTPSPort)
			if err := s.httpsServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				fmt.Printf("HTTPS server error: %v\n", err)
			}
		}()
	}

	return nil
}

func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if s.watcher != nil {
		s.watcher.Close()
	}

	if s.httpServer != nil {
		s.httpServer.Shutdown(ctx)
	}

	if s.httpsServer != nil {
		s.httpsServer.Shutdown(ctx)
	}
}

func (s *Server) watchProjectDirectories() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	s.watcher = watcher

	// Find all project base directories and watch them
	matches, err := filepath.Glob(s.config.Projects)
	if err != nil {
		return err
	}

	for _, basePath := range matches {
		if err := watcher.Add(basePath); err != nil {
			fmt.Printf("Warning: Failed to watch %s: %v\n", basePath, err)
		} else {
			fmt.Printf("Watching for new projects in %s\n", basePath)
		}
	}

	// Start watching in background
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// Only care about directory creation
				if event.Op&fsnotify.Create != 0 {
					// Check if it's a directory
					if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
						domain := filepath.Base(event.Name)

						// Validate domain format
						validDomain := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
						if validDomain.MatchString(domain) {
							fmt.Printf("New project directory detected: %s\n", domain)
							go s.acquireCertificateForDomain(domain)
						}
					}
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Printf("Directory watcher error: %v\n", err)
			}
		}
	}()

	return nil
}

func (s *Server) acquireCertificateForDomain(domain string) {
	// Check if already being requested
	s.certRequestsMu.Lock()
	if s.certRequests[domain] {
		s.certRequestsMu.Unlock()
		return
	}
	s.certRequests[domain] = true
	s.certRequestsMu.Unlock()

	// Use a minimal ClientHello to trigger certificate acquisition
	hello := &tls.ClientHelloInfo{
		ServerName: domain,
	}

	fmt.Printf("Acquiring certificate for new domain: %s\n", domain)
	start := time.Now()
	cert, err := s.certManager.GetCertificate(hello)
	elapsed := time.Since(start)

	s.certRequestsMu.Lock()
	delete(s.certRequests, domain)
	s.certRequestsMu.Unlock()

	if err != nil {
		fmt.Printf("  %s: certificate acquisition failed: %v\n", domain, err)
	} else if cert != nil {
		fmt.Printf("  %s: acquired certificate (took %v)\n", domain, elapsed.Round(time.Millisecond))
	}
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	domain := s.extractDomain(r)
	if domain == "" {
		http.Error(w, "Bad Request: Missing Host header", http.StatusBadRequest)
		return
	}

	projectDir, err := s.getProjectDir(domain)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Load project config to check redirect settings
	projectConfig, err := LoadProjectConfig(projectDir)
	if err == nil {
		// Check for per-project redirect_https setting
		if projectConfig.RedirectHTTPS != nil && *projectConfig.RedirectHTTPS {
			redirectURL := fmt.Sprintf("http://%s%s", r.Host, r.RequestURI)
			http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
			return
		}

		// Check for per-project redirect_http setting
		if projectConfig.RedirectHTTP != nil {
			if *projectConfig.RedirectHTTP && s.config.HTTPSPort > 0 {
				redirectURL := fmt.Sprintf("https://%s%s", r.Host, r.RequestURI)
				http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
				return
			}
		} else if s.config.RedirectHTTP && s.config.HTTPSPort > 0 {
			// Global redirect_http setting
			redirectURL := fmt.Sprintf("https://%s%s", r.Host, r.RequestURI)
			http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
			return
		}
	}

	s.routeRequest(w, r, domain, projectDir)
}

func (s *Server) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	domain := s.extractDomain(r)
	if domain == "" {
		http.Error(w, "Bad Request: Missing Host header", http.StatusBadRequest)
		return
	}

	projectDir, err := s.getProjectDir(domain)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Check for per-project redirect_http setting (HTTPS to HTTP)
	projectConfig, err := LoadProjectConfig(projectDir)
	if err == nil && projectConfig.RedirectHTTPS != nil && *projectConfig.RedirectHTTPS {
		redirectURL := fmt.Sprintf("http://%s%s", r.Host, r.RequestURI)
		http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
		return
	}

	s.routeRequest(w, r, domain, projectDir)
}

func (s *Server) routeRequest(w http.ResponseWriter, r *http.Request, domain, projectDir string) {
	// Check for www redirect
	if s.config.RedirectWWW {
		var targetDomain string

		if strings.HasPrefix(domain, "www.") {
			targetDomain = strings.TrimPrefix(domain, "www.")
			if _, err := s.getProjectDir(targetDomain); err == nil {
				proto := "http"
				if r.TLS != nil {
					proto = "https"
				}
				redirectURL := fmt.Sprintf("%s://%s%s", proto, targetDomain, r.RequestURI)
				http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
				return
			}
		} else {
			targetDomain = "www." + domain
			if _, err := s.getProjectDir(targetDomain); err == nil {
				proto := "http"
				if r.TLS != nil {
					proto = "https"
				}
				redirectURL := fmt.Sprintf("%s://%s%s", proto, targetDomain, r.RequestURI)
				http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
				return
			}
		}
	}

	// Get or create project
	project, err := GetProject(projectDir, s.config.UseFirejail, s.config.PruneLogs)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Handle the request
	project.Handle(w, r)
}

func (s *Server) extractDomain(r *http.Request) string {
	host := r.Host

	// Handle missing Host header
	if host == "" {
		return ""
	}

	// Strip port
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Convert to lowercase
	host = strings.ToLower(host)

	// Validate domain format
	validDomain := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	if !validDomain.MatchString(host) {
		return ""
	}

	return host
}

func (s *Server) getProjectDir(domain string) (string, error) {
	// Check cache first
	s.bindingsMu.RLock()
	if time.Since(s.lastScan) < 10*time.Second {
		if dir, ok := s.bindings[domain]; ok {
			// Verify directory still exists
			if _, err := os.Stat(dir); err == nil {
				s.bindingsMu.RUnlock()
				return dir, nil
			}
			// Directory no longer exists, need to rescan
		}
	}
	s.bindingsMu.RUnlock()

	// Scan for project directory
	s.bindingsMu.Lock()
	defer s.bindingsMu.Unlock()

	// Double-check after acquiring write lock
	if time.Since(s.lastScan) < 10*time.Second {
		if dir, ok := s.bindings[domain]; ok {
			// Verify directory still exists
			if _, err := os.Stat(dir); err == nil {
				return dir, nil
			}
			// Directory no longer exists, remove from cache
			delete(s.bindings, domain)
		}
	}

	// Scan directories
	dir, err := s.scanForProject(domain)
	if err != nil {
		return "", err
	}

	s.bindings[domain] = dir
	s.lastScan = time.Now()
	s.saveBindings()

	return dir, nil
}

func (s *Server) scanForProject(domain string) (string, error) {
	// Expand glob pattern
	matches, err := filepath.Glob(s.config.Projects)
	if err != nil {
		return "", err
	}

	for _, basePath := range matches {
		projectPath := filepath.Join(basePath, domain)

		// Check if directory exists
		if info, err := os.Stat(projectPath); err == nil && info.IsDir() {
			return projectPath, nil
		}
	}

	return "", fmt.Errorf("project not found for domain: %s", domain)
}

func (s *Server) loadBindings() {
	data, err := os.ReadFile(s.bindingsFile)
	if err != nil {
		return
	}

	json.Unmarshal(data, &s.bindings)
}

func (s *Server) saveBindings() {
	data, err := json.MarshalIndent(s.bindings, "", "  ")
	if err != nil {
		return
	}

	os.MkdirAll(filepath.Dir(s.bindingsFile), 0755)
	os.WriteFile(s.bindingsFile, data, 0644)
}

func (s *Server) getCertificateWithLogging(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Just get the certificate - logging happens in ensureAllCertificates
	// This is called on every TLS handshake, usually just reading from cache
	return s.certManager.GetCertificate(hello)
}

func (s *Server) ensureAllCertificates() {
	// Scan for all project directories
	matches, err := filepath.Glob(s.config.Projects)
	if err != nil {
		fmt.Printf("Failed to scan for projects: %v\n", err)
		return
	}

	var domains []string
	for _, basePath := range matches {
		entries, err := os.ReadDir(basePath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			domain := entry.Name()
			// Validate domain format
			validDomain := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
			if !validDomain.MatchString(domain) {
				continue
			}

			domains = append(domains, domain)
		}
	}

	fmt.Printf("Acquiring certificates for %d domains...\n", len(domains))

	// Request certificates for all domains (with rate limiting to avoid Let's Encrypt limits)
	for i, domain := range domains {
		// Check if we're already tracking this request
		s.certRequestsMu.Lock()
		if s.certRequests[domain] {
			s.certRequestsMu.Unlock()
			continue
		}
		s.certRequests[domain] = true
		s.certRequestsMu.Unlock()

		// Use a minimal ClientHello to trigger certificate acquisition
		hello := &tls.ClientHelloInfo{
			ServerName: domain,
		}

		// Time the request to detect if it was cached vs newly acquired
		start := time.Now()
		cert, err := s.certManager.GetCertificate(hello)
		elapsed := time.Since(start)

		s.certRequestsMu.Lock()
		delete(s.certRequests, domain)
		s.certRequestsMu.Unlock()

		if err != nil {
			fmt.Printf("  %s: certificate acquisition failed: %v\n", domain, err)
		} else if cert != nil {
			if elapsed < 100*time.Millisecond {
				// Fast response = cached certificate
				fmt.Printf("  %s: using cached certificate\n", domain)
			} else {
				// Slow response = newly acquired certificate
				fmt.Printf("  %s: acquired new certificate (took %v)\n", domain, elapsed.Round(time.Millisecond))
			}
		}

		// Small delay between requests to serialize them
		// (autocert already handles caching and won't hit Let's Encrypt if cert exists)
		if i < len(domains)-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	fmt.Printf("Certificate acquisition complete\n")
}

func (s *Server) approveHost(ctx context.Context, host string) error {
	// Check if already approved (with read lock first for fast path)
	s.approvedHostsMu.RLock()
	if s.approvedHosts[host] {
		s.approvedHostsMu.RUnlock()
		return nil
	}
	s.approvedHostsMu.RUnlock()

	// Not in cache, validate with write lock
	s.approvedHostsMu.Lock()
	defer s.approvedHostsMu.Unlock()

	// Double-check after acquiring write lock
	if s.approvedHosts[host] {
		return nil
	}

	// Validate that we have a project for this domain
	projectDir, err := s.getProjectDir(host)
	if err != nil {
		fmt.Printf("Certificate request denied for %s: no project found\n", host)
		return fmt.Errorf("no project found for host: %s", host)
	}

	// Cache the approval
	s.approvedHosts[host] = true

	fmt.Printf("Requesting certificate for %s (project: %s)\n", host, projectDir)
	return nil
}
