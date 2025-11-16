package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

type Config struct {
	Email        string
	Projects     string
	ConfigDir    string
	HTTPSPort    int
	HTTPPort     int
	RedirectHTTP bool
	RedirectWWW  bool
	UseFirejail  bool
	ACMEUrl      string
	ACMEVersion  string
	PruneLogs    int
}

func main() {
	config := parseArgs()

	if config.HTTPSPort > 0 && config.Email == "" {
		log.Fatal("--email is required when HTTPS is enabled")
	}

	// Initialize the server
	server, err := NewServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start the server
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	<-sigChan
	fmt.Println("\nReceived shutdown signal, stopping...")

	// Stop all projects and servers
	StopAllProjects()
	server.Stop()

	fmt.Println("Shutdown complete")
}

func parseArgs() *Config {
	config := &Config{}

	// Determine defaults based on whether running as root
	isRoot := os.Geteuid() == 0
	defaultProjects := os.Getenv("HOME") + "/webcentral-projects"
	defaultConfig := os.Getenv("HOME") + "/.webcentral"

	if isRoot {
		defaultProjects = "/home/*/webcentral-projects"
		defaultConfig = "/var/lib/webcentral"
	}

	email := flag.String("email", os.Getenv("EMAIL"), "Email for LetsEncrypt certificate registration")
	projects := flag.String("projects", defaultProjects, "Projects directory pattern")
	configDir := flag.String("config", defaultConfig, "Config and certificate storage directory")
	httpsPort := flag.Int("https", 443, "HTTPS port (0 to disable)")
	httpPort := flag.Int("http", 80, "HTTP port (0 to disable)")

	// RedirectHTTP defaults to true if both HTTP and HTTPS are enabled
	defaultRedirectHTTP := (*httpsPort > 0 && *httpPort > 0)
	redirectHTTP := flag.Bool("redirect-http", defaultRedirectHTTP, "Redirect HTTP to HTTPS")

	redirectWWW := flag.Bool("redirect-www", true, "Auto-redirect www variants")
	useFirejail := flag.Bool("firejail", true, "Use Firejail sandboxing")
	acmeUrl := flag.String("acme-url", "https://acme-v02.api.letsencrypt.org/directory", "ACME service endpoint")
	acmeVersion := flag.String("acme-version", "draft-11", "ACME protocol version")
	pruneLogs := flag.Int("prune-logs", 28, "Number of days to keep log files (0 to disable)")

	flag.Parse()

	config.Email = *email
	config.Projects = *projects
	config.ConfigDir = *configDir
	config.HTTPSPort = *httpsPort
	config.HTTPPort = *httpPort
	config.RedirectHTTP = *redirectHTTP
	config.RedirectWWW = *redirectWWW
	config.UseFirejail = *useFirejail
	config.ACMEUrl = *acmeUrl
	config.ACMEVersion = *acmeVersion
	config.PruneLogs = *pruneLogs

	return config
}
