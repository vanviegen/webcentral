package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type INIConfig struct {
	sections map[string]map[string]interface{}
}

func ParseINI(path string) (*INIConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &INIConfig{
		sections: make(map[string]map[string]interface{}),
	}
	config.sections[""] = make(map[string]interface{})

	currentSection := ""
	scanner := bufio.NewScanner(file)
	lineRegex := regexp.MustCompile(`^\s*([^=]+?)\s*=\s*(.*)$`)
	sectionRegex := regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)

	for scanner.Scan() {
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
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *INIConfig) Get(section, key string) (string, bool) {
	if sec, ok := c.sections[section]; ok {
		if val, ok := sec[key]; ok {
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
		ini, err := ParseINI(iniPath)
		if err != nil {
			return nil, err
		}

		// Load root section
		rootSection := ini.GetSection("")
		validRootKeys := map[string]bool{}

		if cmd, ok := ini.Get("", "command"); ok {
			config.Command = cmd
			validRootKeys["command"] = true
		}

		// Load workers (support both 'worker' and 'worker:name' syntax)
		for key, val := range rootSection {
			if key == "worker" {
				if str, ok := val.(string); ok {
					config.Workers["default"] = str
					validRootKeys[key] = true
				}
			} else if strings.HasPrefix(key, "worker:") {
				name := strings.TrimPrefix(key, "worker:")
				if str, ok := val.(string); ok {
					config.Workers[name] = str
					validRootKeys[key] = true
				}
			}
		}

		config.Port = ini.GetInt("", "port", 0)
		if config.Port != 0 {
			validRootKeys["port"] = true
		}

		if host, ok := ini.Get("", "host"); ok {
			config.Host = host
			validRootKeys["host"] = true
		} else {
			config.Host = "localhost"
		}

		if socketPath, ok := ini.Get("", "socket_path"); ok {
			config.SocketPath = socketPath
			validRootKeys["socket_path"] = true
		}

		if redirect, ok := ini.Get("", "redirect"); ok {
			config.Redirect = redirect
			validRootKeys["redirect"] = true
		}
		if proxy, ok := ini.Get("", "proxy"); ok {
			config.Proxy = proxy
			validRootKeys["proxy"] = true
		}

		config.LogRequests = ini.GetBool("", "log_requests", false)
		if config.LogRequests {
			validRootKeys["log_requests"] = true
		}

		if _, ok := ini.Get("", "redirect_http"); ok {
			b := ini.GetBool("", "redirect_http", false)
			config.RedirectHTTP = &b
			validRootKeys["redirect_http"] = true
		}
		if _, ok := ini.Get("", "redirect_https"); ok {
			b := ini.GetBool("", "redirect_https", false)
			config.RedirectHTTPS = &b
			validRootKeys["redirect_https"] = true
		}

		// Validate root section keys
		for key := range rootSection {
			if !validRootKeys[key] {
				config.ConfigErrors = append(config.ConfigErrors, "Unknown key '"+key+"' in root section")
			}
		}

		// Load environment variables
		envSection := ini.GetSection("environment")
		for key, val := range envSection {
			if str, ok := val.(string); ok {
				config.Environment[key] = str
			}
		}

		// Load Docker configuration
		if ini.HasSection("docker") {
			dockerSection := ini.GetSection("docker")
			validDockerKeys := map[string]bool{}

			dockerConfig := &DockerConfig{
				Base:        "alpine",
				HTTPPort:    8000,
				AppDir:      "/app",
				MountAppDir: true,
			}

			if base, ok := ini.Get("docker", "base"); ok {
				dockerConfig.Base = base
				validDockerKeys["base"] = true
			}
			if packages := ini.GetArray("docker", "packages"); packages != nil {
				dockerConfig.Packages = packages
				validDockerKeys["packages"] = true
			}
			if commands := ini.GetArray("docker", "commands"); commands != nil {
				dockerConfig.Commands = commands
				validDockerKeys["commands"] = true
			}
			dockerConfig.HTTPPort = ini.GetInt("docker", "http_port", 8000)
			if dockerConfig.HTTPPort != 8000 {
				validDockerKeys["http_port"] = true
			}
			if appDir, ok := ini.Get("docker", "app_dir"); ok {
				dockerConfig.AppDir = appDir
				validDockerKeys["app_dir"] = true
			}
			dockerConfig.MountAppDir = ini.GetBool("docker", "mount_app_dir", true)
			if !dockerConfig.MountAppDir {
				validDockerKeys["mount_app_dir"] = true
			}
			if mounts := ini.GetArray("docker", "mounts"); mounts != nil {
				dockerConfig.Mounts = mounts
				validDockerKeys["mounts"] = true
			}

			config.Docker = dockerConfig

			// Validate docker section keys
			for key := range dockerSection {
				if !validDockerKeys[key] {
					config.ConfigErrors = append(config.ConfigErrors, "Unknown key '"+key+"' in [docker] section")
				}
			}
		}

		// Load reload configuration
		reloadConfig := &ReloadConfig{
			Timeout: 300,
		}
		if ini.HasSection("reload") {
			reloadSection := ini.GetSection("reload")
			validReloadKeys := map[string]bool{}

			reloadConfig.Timeout = ini.GetInt("reload", "timeout", 300)
			if reloadConfig.Timeout != 300 {
				validReloadKeys["timeout"] = true
			}
			if include := ini.GetArray("reload", "include"); include != nil {
				reloadConfig.Include = include
				validReloadKeys["include"] = true
			}
			if exclude := ini.GetArray("reload", "exclude"); exclude != nil {
				reloadConfig.Exclude = exclude
				validReloadKeys["exclude"] = true
			}

			// Validate reload section keys
			for key := range reloadSection {
				if !validReloadKeys[key] {
					config.ConfigErrors = append(config.ConfigErrors, "Unknown key '"+key+"' in [reload] section")
				}
			}
		}
		config.Reload = reloadConfig

		// Load rewrites
		rewriteSection := ini.GetSection("rewrite")
		for pattern, target := range rewriteSection {
			if str, ok := target.(string); ok {
				config.Rewrites[pattern] = str
			}
		}

		// Validate for unrecognized sections
		validSections := map[string]bool{"": true, "environment": true, "docker": true, "reload": true, "rewrite": true}
		for section := range ini.sections {
			if !validSections[section] {
				config.ConfigErrors = append(config.ConfigErrors, "Unknown section ["+section+"] in webcentral.ini")
			}
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
