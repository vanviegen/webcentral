package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type INIConfig struct {
	sections map[string]map[string]interface{}
}

func ParseINI(path string) (*INIConfig, []string) {
	file, err := os.Open(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("Failed to open webcentral.ini: %v", err)}
	}
	defer file.Close()

	config := &INIConfig{
		sections: make(map[string]map[string]interface{}),
	}
	config.sections[""] = make(map[string]interface{})

	var parseErrors []string
	currentSection := ""
	scanner := bufio.NewScanner(file)
	lineRegex := regexp.MustCompile(`^\s*([^=]+?)\s*=\s*(.*)$`)
	sectionRegex := regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for section header
		if matches := sectionRegex.FindStringSubmatch(line); matches != nil {
			currentSection = matches[1]
			if config.sections[currentSection] == nil {
				config.sections[currentSection] = make(map[string]interface{})
			}
			continue
		}

		// Parse key=value
		if matches := lineRegex.FindStringSubmatch(line); matches != nil {
			key := matches[1]
			value := matches[2]

			// Handle array keys (key[] = value)
			if strings.HasSuffix(key, "[]") {
				key = strings.TrimSuffix(key, "[]")
				existing, ok := config.sections[currentSection][key]
				if !ok {
					config.sections[currentSection][key] = []string{value}
				} else if arr, ok := existing.([]string); ok {
					config.sections[currentSection][key] = append(arr, value)
				}
			} else {
				config.sections[currentSection][key] = value
			}
		} else {
			// Line doesn't match any known pattern
			parseErrors = append(parseErrors, fmt.Sprintf("Invalid syntax in webcentral.ini at line %d: %s", lineNum, line))
		}
	}

	if err := scanner.Err(); err != nil {
		parseErrors = append(parseErrors, fmt.Sprintf("Error reading webcentral.ini: %v", err))
	}

	return config, parseErrors
}

func (c *INIConfig) Get(section, key string) (string, bool) {
	if sec, ok := c.sections[section]; ok {
		if val, ok := sec[key]; ok {
			delete(sec, key) // Remove key as it's consumed
			if str, ok := val.(string); ok {
				return str, true
			}
		}
	}
	return "", false
}

func (c *INIConfig) GetArray(section, key string) []string {
	if sec, ok := c.sections[section]; ok {
		if val, ok := sec[key]; ok {
			delete(sec, key) // Remove key as it's consumed
			if arr, ok := val.([]string); ok {
				return arr
			}
			if str, ok := val.(string); ok {
				return []string{str}
			}
		}
	}
	return nil
}

func (c *INIConfig) GetBool(section, key string, defaultValue bool) bool {
	val, ok := c.Get(section, key)
	if !ok {
		return defaultValue
	}
	val = strings.ToLower(val)
	return val == "true" || val == "1" || val == "yes"
}

func (c *INIConfig) GetInt(section, key string, defaultValue int) int {
	val, ok := c.Get(section, key)
	if !ok {
		return defaultValue
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return defaultValue
	}
	return i
}

func (c *INIConfig) GetSection(section string) map[string]interface{} {
	if sec, ok := c.sections[section]; ok {
		return sec
	}
	return make(map[string]interface{})
}

func (c *INIConfig) HasSection(section string) bool {
	_, ok := c.sections[section]
	return ok
}

type PackageJSON struct {
	Scripts map[string]string `json:"scripts"`
}

func ParsePackageJSON(path string) (*PackageJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	return &pkg, nil
}

type Procfile struct {
	Processes map[string]string
}

func ParseProcfile(path string) (*Procfile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	procfile := &Procfile{
		Processes: make(map[string]string),
	}

	scanner := bufio.NewScanner(file)
	lineRegex := regexp.MustCompile(`^([a-zA-Z0-9_]+)\s*:\s*(.+)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse process: command
		if matches := lineRegex.FindStringSubmatch(line); matches != nil {
			processType := matches[1]
			command := matches[2]
			procfile.Processes[processType] = command
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return procfile, nil
}

type ProjectConfig struct {
	Dir          string
	Command      string
	CommandArray []string
	Workers      map[string]string
	Port         int
	Host         string
	SocketPath   string
	Redirect     string
	Proxy        string
	LogRequests  bool
	RedirectHTTP *bool
	RedirectHTTPS *bool
	Environment  map[string]string
	Docker       *DockerConfig
	Reload       *ReloadConfig
	Rewrites     map[string]string
	ConfigErrors []string
}

type DockerConfig struct {
	Base         string
	Packages     []string
	Commands     []string
	HTTPPort     int
	AppDir       string
	MountAppDir  bool
	Mounts       []string
}

type ReloadConfig struct {
	Timeout int
	Include []string
	Exclude []string
}

func LoadProjectConfig(dir string) (*ProjectConfig, error) {
	config := &ProjectConfig{
		Dir:         dir,
		Environment: make(map[string]string),
		Rewrites:    make(map[string]string),
		Workers:     make(map[string]string),
	}

	// Try to load webcentral.ini
	iniPath := filepath.Join(dir, "webcentral.ini")
	if _, err := os.Stat(iniPath); err == nil {
		ini, parseErrors := ParseINI(iniPath)

		// Add parse errors to config errors
		config.ConfigErrors = append(config.ConfigErrors, parseErrors...)

		// If ini parsing failed completely, skip loading config values
		if ini != nil {
			// Load root section
		if cmd, ok := ini.Get("", "command"); ok {
			config.Command = cmd
		}

		// Load workers (support both 'worker' and 'worker:name' syntax)
		// Need to get list of worker keys first since Get() modifies the map
		rootSection := ini.GetSection("")
		var workerKeys []string
		for key := range rootSection {
			if key == "worker" || strings.HasPrefix(key, "worker:") {
				workerKeys = append(workerKeys, key)
			}
		}
		for _, key := range workerKeys {
			if val, ok := ini.Get("", key); ok {
				if key == "worker" {
					config.Workers["default"] = val
				} else {
					name := strings.TrimPrefix(key, "worker:")
					config.Workers[name] = val
				}
			}
		}

		config.Port = ini.GetInt("", "port", 0)

		if host, ok := ini.Get("", "host"); ok {
			config.Host = host
		} else {
			config.Host = "localhost"
		}

		if socketPath, ok := ini.Get("", "socket_path"); ok {
			config.SocketPath = socketPath
		}

		if redirect, ok := ini.Get("", "redirect"); ok {
			config.Redirect = redirect
		}
		if proxy, ok := ini.Get("", "proxy"); ok {
			config.Proxy = proxy
		}

		config.LogRequests = ini.GetBool("", "log_requests", false)

		if val, ok := ini.Get("", "redirect_http"); ok {
			b := val == "true" || val == "1" || val == "yes"
			config.RedirectHTTP = &b
		}
		if val, ok := ini.Get("", "redirect_https"); ok {
			b := val == "true" || val == "1" || val == "yes"
			config.RedirectHTTPS = &b
		}

		// Validate root section - anything left is unknown
		for key := range ini.GetSection("") {
			config.ConfigErrors = append(config.ConfigErrors, "Unknown key '"+key+"' in root section")
		}

		// Load environment variables (all keys are valid, consume them all)
		var envKeys []string
		for key := range ini.GetSection("environment") {
			envKeys = append(envKeys, key)
		}
		for _, key := range envKeys {
			if val, ok := ini.Get("environment", key); ok {
				config.Environment[key] = val
			}
		}

		// Load Docker configuration
		if ini.HasSection("docker") {
			dockerConfig := &DockerConfig{
				Base:        "alpine",
				HTTPPort:    8000,
				AppDir:      "/app",
				MountAppDir: true,
			}

			if base, ok := ini.Get("docker", "base"); ok {
				dockerConfig.Base = base
			}
			dockerConfig.Packages = ini.GetArray("docker", "packages")
			dockerConfig.Commands = ini.GetArray("docker", "commands")
			dockerConfig.HTTPPort = ini.GetInt("docker", "http_port", 8000)
			if appDir, ok := ini.Get("docker", "app_dir"); ok {
				dockerConfig.AppDir = appDir
			}
			dockerConfig.MountAppDir = ini.GetBool("docker", "mount_app_dir", true)
			dockerConfig.Mounts = ini.GetArray("docker", "mounts")

			config.Docker = dockerConfig

			// Validate docker section - anything left is unknown
			for key := range ini.GetSection("docker") {
				config.ConfigErrors = append(config.ConfigErrors, "Unknown key '"+key+"' in [docker] section")
			}
		}

		// Load reload configuration
		reloadConfig := &ReloadConfig{
			Timeout: 300,
		}
		if ini.HasSection("reload") {
			reloadConfig.Timeout = ini.GetInt("reload", "timeout", 300)
			reloadConfig.Include = ini.GetArray("reload", "include")
			reloadConfig.Exclude = ini.GetArray("reload", "exclude")

			// Validate reload section - anything left is unknown
			for key := range ini.GetSection("reload") {
				config.ConfigErrors = append(config.ConfigErrors, "Unknown key '"+key+"' in [reload] section")
			}
		}
		config.Reload = reloadConfig

		// Load rewrites (all keys are valid, consume them all)
		var rewriteKeys []string
		for key := range ini.GetSection("rewrite") {
			rewriteKeys = append(rewriteKeys, key)
		}
		for _, pattern := range rewriteKeys {
			if target, ok := ini.Get("rewrite", pattern); ok {
				config.Rewrites[pattern] = target
			}
		}

			// Validate for unrecognized sections
			knownSections := map[string]bool{"": true, "environment": true, "docker": true, "reload": true, "rewrite": true}
			for section := range ini.sections {
				if !knownSections[section] {
					config.ConfigErrors = append(config.ConfigErrors, "Unknown section ["+section+"] in webcentral.ini")
				}
			}
		}

		// Set default reload config if not set
		if config.Reload == nil {
			config.Reload = &ReloadConfig{Timeout: 300}
		}
	} else {
		// No webcentral.ini, use defaults for reload
		config.Reload = &ReloadConfig{
			Timeout: 300,
		}
	}

	// If no command found, check for Procfile
	if config.Command == "" && config.Docker == nil && config.Port == 0 && config.SocketPath == "" && config.Redirect == "" && config.Proxy == "" {
		procfilePath := filepath.Join(dir, "Procfile")
		if _, err := os.Stat(procfilePath); err == nil {
			procfile, err := ParseProcfile(procfilePath)
			if err == nil {
				// Check for 'web' process type
				if webCmd, ok := procfile.Processes["web"]; ok {
					config.Command = webCmd
				}

				// Check for worker processes (use numeric names: 0, 1, 2, etc.)
				workerIndex := 0
				for processType, cmd := range procfile.Processes {
					if processType == "worker" || processType == "urgentworker" {
						config.Workers[strconv.Itoa(workerIndex)] = cmd
						workerIndex++
					} else if processType != "web" {
						config.ConfigErrors = append(config.ConfigErrors, "Procfile process type '"+processType+"' is not supported and will be ignored")
					}
				}
			}
		}
	}

	// If still no command found, check for package.json
	if config.Command == "" && config.Docker == nil && config.Port == 0 && config.SocketPath == "" && config.Redirect == "" && config.Proxy == "" {
		pkgPath := filepath.Join(dir, "package.json")
		if _, err := os.Stat(pkgPath); err == nil {
			pkg, err := ParsePackageJSON(pkgPath)
			if err == nil && pkg.Scripts["start"] != "" {
				config.Command = "npm start"
			}
		}
	}

	return config, nil
}
