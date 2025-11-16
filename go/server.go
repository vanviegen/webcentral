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

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Server struct {
	config       *Config
	httpServer   *http.Server
	httpsServer  *http.Server
	certManager  *autocert.Manager
	bindings     map[string]string
	bindingsFile string
	bindingsMu   sync.RWMutex
	lastScan     time.Time
}

func NewServer(config *Config) (*Server, error) {
	s := &Server{
		config:       config,
		bindings:     make(map[string]string),
		bindingsFile: filepath.Join(config.ConfigDir, "bindings.json"),
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
			GetCertificate: s.certManager.GetCertificate,
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

	if s.httpServer != nil {
		s.httpServer.Shutdown(ctx)
	}

	if s.httpsServer != nil {
		s.httpsServer.Shutdown(ctx)
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
	project, err := GetProject(projectDir, s.config.UseFirejail)
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
			s.bindingsMu.RUnlock()
			return dir, nil
		}
	}
	s.bindingsMu.RUnlock()

	// Scan for project directory
	s.bindingsMu.Lock()
	defer s.bindingsMu.Unlock()

	// Double-check after acquiring write lock
	if time.Since(s.lastScan) < 10*time.Second {
		if dir, ok := s.bindings[domain]; ok {
			return dir, nil
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

func (s *Server) approveHost(ctx context.Context, host string) error {
	// Validate that we have a project for this domain
	_, err := s.getProjectDir(host)
	if err != nil {
		return fmt.Errorf("no project found for host: %s", host)
	}

	return nil
}
