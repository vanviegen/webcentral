use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// Helper struct for parsing INI files into a flat HashMap
struct IniMap {
    map: HashMap<String, Vec<String>>,
    errors: Vec<String>,
}

impl IniMap {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            errors: Vec::new(),
        }
    }

    // Parse INI file into flat HashMap with dotted keys
    fn parse(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to open webcentral.ini")?;

        let mut ini_map = Self::new();
        let mut current_section = String::new();

        let line_regex = Regex::new(r"^\s*([^=]+?)\s*=\s*(.*)$").unwrap();
        let section_regex = Regex::new(r"^\s*\[([^\]]+)\]\s*$").unwrap();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }

            // Check for section header
            if let Some(caps) = section_regex.captures(line) {
                current_section = caps[1].to_string();
                continue;
            }

            // Parse key=value
            if let Some(caps) = line_regex.captures(line) {
                let key = caps[1].trim().to_string();
                let value = caps[2].to_string();

                // Handle array syntax (key[])
                let actual_key = if key.ends_with("[]") {
                    key.trim_end_matches("[]").to_string()
                } else {
                    key
                };

                // Combine section and key with a dot
                let full_key = if current_section.is_empty() {
                    actual_key
                } else {
                    format!("{}.{}", current_section, actual_key)
                };

                // Store in map
                ini_map
                    .map
                    .entry(full_key)
                    .or_insert_with(Vec::new)
                    .push(value);
            } else {
                ini_map.errors.push(format!(
                    "Invalid syntax in webcentral.ini at line {}: {}",
                    line_num + 1,
                    line
                ));
            }
        }

        Ok(ini_map)
    }

    // Fetch a single value, removing it from the map
    // Logs error if multiple values found
    fn fetch(&mut self, key: &str) -> Option<String> {
        if let Some(values) = self.map.remove(key) {
            if values.len() > 1 {
                self.errors
                    .push(format!("Key '{}' has multiple values, using last one", key));
            }
            values.into_iter().last()
        } else {
            None
        }
    }

    // Fetch a value and parse it as a type
    fn fetch_parse_default<T: std::str::FromStr>(&mut self, key: &str, default: T) -> T {
        self.fetch(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    // Fetch a value and parse it as a type
    fn fetch_parse<T: std::str::FromStr>(&mut self, key: &str) -> Option<T> {
        if let Some(value) = self.fetch(key) {
            if let Ok(parse) = value.parse() {
                return Some(parse);
            }
        }
        return None;
    }

    // Fetch a boolean value (true/1/yes = true, anything else = false)
    fn fetch_bool(&mut self, key: &str) -> Option<bool> {
        self.fetch(key).map(|v| {
            let v = v.to_lowercase();
            v == "true" || v == "1" || v == "yes"
        })
    }

    // Fetch an array of values, removing them from the map
    fn fetch_array(&mut self, key: &str) -> Vec<String> {
        self.map.remove(key).unwrap_or_default()
    }

    // Fetch all keys with a given prefix, returning a HashMap
    fn fetch_prefix(&mut self, prefix: &str) -> HashMap<String, String> {
        let prefix_with_dot = format!("{}.", prefix);
        let mut result = HashMap::new();

        let keys: Vec<String> = self
            .map
            .keys()
            .filter(|k| k.starts_with(&prefix_with_dot))
            .cloned()
            .collect();

        for key in keys {
            if let Some(values) = self.map.remove(&key) {
                let suffix = &key[prefix_with_dot.len()..];
                if values.len() > 1 {
                    self.errors
                        .push(format!("Key '{}' has multiple values, using last one", key));
                }
                if let Some(value) = values.into_iter().last() {
                    result.insert(suffix.to_string(), value);
                }
            }
        }

        result
    }

    // Get remaining keys (for error reporting)
    fn remaining_keys(&self) -> Vec<String> {
        let mut keys: Vec<_> = self.map.keys().cloned().collect();
        keys.sort();
        keys
    }
}

// Build ProjectConfig directly from IniMap
fn build_project_config(dir: String, ini_map: &mut IniMap) -> ProjectConfig {
    // Determine project type by checking for type-specific keys
    // Priority: type=dashboard > redirect > proxy > forward (socket/port) > application > static
    let project_type = if ini_map.fetch("type").as_deref() == Some("dashboard") {
        ProjectType::Dashboard
    } else if let Some(target) = ini_map.fetch("redirect") {
        ProjectType::Redirect { target: target.trim_end_matches('/').to_string() }
    } else if let Some(target) = ini_map.fetch("proxy") {
        ProjectType::Proxy { target }
    } else if let Some(socket_path) = ini_map.fetch("socket_path") {
        ProjectType::UnixForward { socket_path }
    } else if let Some(port) = ini_map.fetch_parse::<i32>("port") {
        let host = ini_map.fetch("host").unwrap_or_else(|| "localhost".to_string());
        ProjectType::TcpForward { address: format!("{}:{}", host, port) }
    } else if let Some(host) = ini_map.fetch("host") {
        let port = ini_map.fetch_parse_default("port", 80);
        ProjectType::TcpForward { address: format!("{}:{}", host, port) }
    } else if ini_map.map.contains_key("command") || ini_map.map.keys().any(|k| k.starts_with("docker.")) {
        let command = ini_map.fetch("command").unwrap_or_default();

        let mut workers = HashMap::new();
        if let Some(worker_cmd) = ini_map.fetch("worker") {
            workers.insert("default".to_string(), worker_cmd);
        }
        for key in ini_map.map.keys().filter(|k| k.starts_with("worker:")).cloned().collect::<Vec<_>>() {
            if let Some(cmd) = ini_map.fetch(&key) {
                workers.insert(key[7..].to_string(), cmd);
            }
        }

        let docker = if ini_map.map.keys().any(|k| k.starts_with("docker.")) {
            Some(DockerConfig {
                base: ini_map.fetch("docker.base").unwrap_or_else(|| "alpine".to_string()),
                packages: ini_map.fetch_array("docker.packages"),
                commands: ini_map.fetch_array("docker.commands"),
                http_port: ini_map.fetch_parse_default("docker.http_port", 8000),
                app_dir: ini_map.fetch("docker.app_dir").unwrap_or_else(|| "/app".to_string()),
                mount_app_dir: ini_map.fetch_bool("docker.mount_app_dir").unwrap_or(true),
                mounts: ini_map.fetch_array("docker.mounts"),
            })
        } else {
            None
        };

        ProjectType::Application { command, docker, workers }
    } else {
        ProjectType::Static
    };

    let mut include = if ini_map.map.contains_key("reload.include") {
        ini_map.fetch_array("reload.include")
    } else if let ProjectType::Application { .. } = project_type {
        vec!["**/*".to_string()]
    } else {
        vec!["/Procfile".to_string()]
    };

    // *Always* include webcentral.ini, to make sure we won't get into an unchangeable state
    include.push("/webcentral.ini".to_string());

    let mut exclude = ini_map.fetch_array("reload.exclude");
    exclude.extend(DEFAULT_EXCLUDES.iter().map(|s| s.to_string()));

    // Parse [auth] section - users are specified as auth.<username> = <password_hash>
    let auth = ini_map.fetch_prefix("auth");

    // Read common configuration
    let mut config = ProjectConfig {
        dir,
        project_type,
        log_requests: ini_map.fetch_bool("log_requests").unwrap_or(false),
        redirect_http: ini_map.fetch_bool("redirect_http"),
        redirect_https: ini_map.fetch_bool("redirect_https"),
        environment: ini_map.fetch_prefix("environment"),
        reload: ReloadConfig {
            timeout: ini_map.fetch_parse_default("reload.timeout", 300),
            startup_deadline: ini_map.fetch_parse_default("startup_deadline", 30),
            include,
            exclude,
        },
        rewrites: ini_map.fetch_prefix("rewrite"),
        auth,
        config_errors: ini_map.errors.clone(),
    };

    // Check for unexpected keys
    for key in ini_map.remaining_keys() {
        config
            .config_errors
            .push(format!("Unexpected key '{}'", key));
    }

    config
}

#[derive(Debug, Deserialize)]
pub struct PackageJson {
    #[serde(default)]
    pub scripts: HashMap<String, String>,
}

impl PackageJson {
    pub fn parse(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }
}

#[derive(Debug)]
pub struct Procfile {
    pub processes: HashMap<String, String>,
}

impl Procfile {
    pub fn parse(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut processes = HashMap::new();

        let line_regex = Regex::new(r"^([a-zA-Z0-9_]+)\s*:\s*(.+)$").unwrap();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse process: command
            if let Some(caps) = line_regex.captures(line) {
                processes.insert(caps[1].to_string(), caps[2].to_string());
            }
        }

        Ok(Procfile { processes })
    }
}

#[derive(Debug, Clone)]
pub enum ProjectType {
    // Application that needs to be started (command or docker)
    Application {
        command: String,
        docker: Option<DockerConfig>,
        workers: HashMap<String, String>,
    },
    // Static file server (serves from public/ directory)
    Static,
    // HTTP redirect
    Redirect { target: String, },
    // Reverse proxy to external URL
    Proxy { target: String },
    // Forward to local port or unix socket
    UnixForward { socket_path: String },
    TcpForward { address: String },
    // Dashboard showing server status
    Dashboard,
}

#[derive(Debug, Clone)]
pub struct ProjectConfig {
    #[allow(dead_code)]
    pub dir: String,
    pub project_type: ProjectType,
    pub log_requests: bool,
    pub redirect_http: Option<bool>,
    pub redirect_https: Option<bool>,
    pub environment: HashMap<String, String>,
    pub reload: ReloadConfig,
    pub rewrites: HashMap<String, String>,
    /// Map of username to password hash (argon2) for basic auth
    pub auth: HashMap<String, String>,
    pub config_errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DockerConfig {
    pub base: String,
    pub packages: Vec<String>,
    pub commands: Vec<String>,
    pub http_port: i32,
    pub app_dir: String,
    pub mount_app_dir: bool,
    pub mounts: Vec<String>,
}

/// Default file patterns to exclude from file watching.
/// These patterns are always excluded from triggering reloads.
pub const DEFAULT_EXCLUDES: &[&str] = &[
    "/_webcentral_data",
    "node_modules",
    "*.bak",
    "*.sw?", // vim swap files
    ".*", // hidden files
    "data",
    "*.log",
    "log",
    "logs",
];

#[derive(Debug, Clone)]
pub struct ReloadConfig {
    pub timeout: i64,
    pub startup_deadline: u64,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl Default for ReloadConfig {
    fn default() -> Self {
        ReloadConfig {
            timeout: 300,
            startup_deadline: 30,
            include: Vec::new(),
            exclude: Vec::new(),
        }
    }
}


impl ProjectConfig {
    pub fn load(dir: &Path) -> Result<Self> {
        // Try to load webcentral.ini
        let ini_path = dir.join("webcentral.ini");
        if ini_path.exists() {
            match IniMap::parse(&ini_path) {
                Ok(mut ini_map) => {
                    return Ok(build_project_config(
                        dir.to_string_lossy().to_string(),
                        &mut ini_map,
                    ));
                }
                Err(e) => {
                    // Failed to parse ini file, fall through to check Procfile/package.json
                    let mut ini_map = IniMap::new();
                    ini_map
                        .errors
                        .push(format!("Failed to parse webcentral.ini: {}", e));
                    return Ok(build_project_config(
                        dir.to_string_lossy().to_string(),
                        &mut ini_map,
                    ));
                }
            }
        }

        // No webcentral.ini, check for Procfile
        let procfile_path = dir.join("Procfile");
        if procfile_path.exists() {
            if let Ok(procfile) = Procfile::parse(&procfile_path) {
                let mut ini_map = IniMap::new();

                if let Some(web_cmd) = procfile.processes.get("web") {
                    ini_map
                        .map
                        .insert("command".to_string(), vec![web_cmd.clone()]);
                }

                // Check for worker processes
                let mut worker_index = 0;
                for (process_type, cmd) in &procfile.processes {
                    if process_type == "worker" || process_type == "urgentworker" {
                        ini_map
                            .map
                            .insert(format!("worker:{}", worker_index), vec![cmd.clone()]);
                        worker_index += 1;
                    } else if process_type != "web" {
                        ini_map.errors.push(format!(
                            "Procfile process type '{}' is not supported and will be ignored",
                            process_type
                        ));
                    }
                }

                return Ok(build_project_config(
                    dir.to_string_lossy().to_string(),
                    &mut ini_map,
                ));
            }
        }

        // No Procfile, check for package.json
        let pkg_path = dir.join("package.json");
        if pkg_path.exists() {
            if let Ok(pkg) = PackageJson::parse(&pkg_path) {
                if let Some(start_script) = pkg.scripts.get("start") {
                    if !start_script.is_empty() {
                        let mut ini_map = IniMap::new();
                        ini_map
                            .map
                            .insert("command".to_string(), vec!["npm start".to_string()]);
                        return Ok(build_project_config(
                            dir.to_string_lossy().to_string(),
                            &mut ini_map,
                        ));
                    }
                }
            }
        }

        // No configuration found, create empty static project
        let mut ini_map = IniMap::new();
        Ok(build_project_config(
            dir.to_string_lossy().to_string(),
            &mut ini_map,
        ))
    }
}


