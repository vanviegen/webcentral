use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct IniConfig {
    sections: HashMap<String, HashMap<String, IniValue>>,
}

#[derive(Debug, Clone)]
enum IniValue {
    String(String),
    Array(Vec<String>),
}

impl IniConfig {
    pub fn parse(path: &Path) -> Result<(Self, Vec<String>)> {
        let content = fs::read_to_string(path)
            .context("Failed to open webcentral.ini")?;

        let mut config = IniConfig {
            sections: HashMap::new(),
        };
        config.sections.insert(String::new(), HashMap::new());

        let mut parse_errors = Vec::new();
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
                config.sections.entry(current_section.clone()).or_insert_with(HashMap::new);
                continue;
            }

            // Parse key=value
            if let Some(caps) = line_regex.captures(line) {
                let mut key = caps[1].to_string();
                let value = caps[2].to_string();

                // Handle array keys (key[] = value)
                if key.ends_with("[]") {
                    key = key.trim_end_matches("[]").to_string();
                    let section = config.sections.get_mut(&current_section).unwrap();
                    match section.get_mut(&key) {
                        Some(IniValue::Array(arr)) => {
                            arr.push(value);
                        }
                        _ => {
                            section.insert(key, IniValue::Array(vec![value]));
                        }
                    }
                } else {
                    let section = config.sections.get_mut(&current_section).unwrap();
                    section.insert(key, IniValue::String(value));
                }
            } else {
                parse_errors.push(format!("Invalid syntax in webcentral.ini at line {}: {}", line_num + 1, line));
            }
        }

        Ok((config, parse_errors))
    }

    pub fn get(&mut self, section: &str, key: &str) -> Option<String> {
        self.sections.get_mut(section)?.remove(key).and_then(|v| match v {
            IniValue::String(s) => Some(s),
            _ => None,
        })
    }

    pub fn get_array(&mut self, section: &str, key: &str) -> Vec<String> {
        self.sections
            .get_mut(section)
            .and_then(|sec| sec.remove(key))
            .map(|v| match v {
                IniValue::Array(arr) => arr,
                IniValue::String(s) => vec![s],
            })
            .unwrap_or_default()
    }

    pub fn get_bool(&mut self, section: &str, key: &str, default: bool) -> bool {
        self.get(section, key)
            .map(|v| {
                let v = v.to_lowercase();
                v == "true" || v == "1" || v == "yes"
            })
            .unwrap_or(default)
    }

    pub fn get_int(&mut self, section: &str, key: &str, default: i32) -> i32 {
        self.get(section, key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    pub fn get_section(&self, section: &str) -> HashMap<String, String> {
        self.sections
            .get(section)
            .map(|sec| {
                sec.iter()
                    .filter_map(|(k, v)| match v {
                        IniValue::String(s) => Some((k.clone(), s.clone())),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn has_section(&self, section: &str) -> bool {
        self.sections.contains_key(section)
    }

    pub fn remaining_keys(&self, section: &str) -> Vec<String> {
        self.sections
            .get(section)
            .map(|sec| sec.keys().cloned().collect())
            .unwrap_or_default()
    }
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
pub struct ProjectConfig {
    #[allow(dead_code)]
    pub dir: String,
    pub command: String,
    pub workers: HashMap<String, String>,
    pub port: i32,
    pub host: String,
    pub socket_path: String,
    pub redirect: String,
    pub proxy: String,
    pub log_requests: bool,
    pub redirect_http: Option<bool>,
    pub redirect_https: Option<bool>,
    pub environment: HashMap<String, String>,
    pub docker: Option<DockerConfig>,
    pub reload: ReloadConfig,
    pub rewrites: HashMap<String, String>,
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

#[derive(Debug, Clone)]
pub struct ReloadConfig {
    pub timeout: i64,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl ProjectConfig {
    pub fn load(dir: &Path) -> Result<Self> {
        let mut config = ProjectConfig {
            dir: dir.to_string_lossy().to_string(),
            command: String::new(),
            workers: HashMap::new(),
            port: 0,
            host: String::from("localhost"),
            socket_path: String::new(),
            redirect: String::new(),
            proxy: String::new(),
            log_requests: false,
            redirect_http: None,
            redirect_https: None,
            environment: HashMap::new(),
            docker: None,
            reload: ReloadConfig {
                timeout: 300,
                include: Vec::new(),
                exclude: Vec::new(),
            },
            rewrites: HashMap::new(),
            config_errors: Vec::new(),
        };

        // Try to load webcentral.ini
        let ini_path = dir.join("webcentral.ini");
        if ini_path.exists() {
            match IniConfig::parse(&ini_path) {
                Ok((mut ini, parse_errors)) => {
                    config.config_errors.extend(parse_errors);

                    // Load root section
                    if let Some(cmd) = ini.get("", "command") {
                        config.command = cmd;
                    }

                    // Load workers
                    let root_keys: Vec<_> = ini.get_section("").keys()
                        .filter(|k| k.as_str() == "worker" || k.starts_with("worker:"))
                        .cloned()
                        .collect();

                    for key in root_keys {
                        if let Some(val) = ini.get("", &key) {
                            if key == "worker" {
                                config.workers.insert("default".to_string(), val);
                            } else if let Some(name) = key.strip_prefix("worker:") {
                                config.workers.insert(name.to_string(), val);
                            }
                        }
                    }

                    config.port = ini.get_int("", "port", 0);
                    if let Some(host) = ini.get("", "host") {
                        config.host = host;
                    }
                    if let Some(socket_path) = ini.get("", "socket_path") {
                        config.socket_path = socket_path;
                    }
                    if let Some(redirect) = ini.get("", "redirect") {
                        config.redirect = redirect;
                    }
                    if let Some(proxy) = ini.get("", "proxy") {
                        config.proxy = proxy;
                    }

                    config.log_requests = ini.get_bool("", "log_requests", false);

                    if let Some(val) = ini.get("", "redirect_http") {
                        let b = val == "true" || val == "1" || val == "yes";
                        config.redirect_http = Some(b);
                    }
                    if let Some(val) = ini.get("", "redirect_https") {
                        let b = val == "true" || val == "1" || val == "yes";
                        config.redirect_https = Some(b);
                    }

                    // Validate root section
                    for key in ini.remaining_keys("") {
                        config.config_errors.push(format!("Unknown key '{}' in root section", key));
                    }

                    // Load environment variables
                    let env_keys: Vec<_> = ini.get_section("environment").keys().cloned().collect();
                    for key in env_keys {
                        if let Some(val) = ini.get("environment", &key) {
                            config.environment.insert(key, val);
                        }
                    }

                    // Load Docker configuration
                    if ini.has_section("docker") {
                        let mut docker = DockerConfig {
                            base: "alpine".to_string(),
                            packages: Vec::new(),
                            commands: Vec::new(),
                            http_port: 8000,
                            app_dir: "/app".to_string(),
                            mount_app_dir: true,
                            mounts: Vec::new(),
                        };

                        if let Some(base) = ini.get("docker", "base") {
                            docker.base = base;
                        }
                        docker.packages = ini.get_array("docker", "packages");
                        docker.commands = ini.get_array("docker", "commands");
                        docker.http_port = ini.get_int("docker", "http_port", 8000);
                        if let Some(app_dir) = ini.get("docker", "app_dir") {
                            docker.app_dir = app_dir;
                        }
                        docker.mount_app_dir = ini.get_bool("docker", "mount_app_dir", true);
                        docker.mounts = ini.get_array("docker", "mounts");

                        config.docker = Some(docker);

                        // Validate docker section
                        for key in ini.remaining_keys("docker") {
                            config.config_errors.push(format!("Unknown key '{}' in [docker] section", key));
                        }
                    }

                    // Load reload configuration
                    if ini.has_section("reload") {
                        config.reload.timeout = ini.get_int("reload", "timeout", 300) as i64;
                        config.reload.include = ini.get_array("reload", "include");
                        config.reload.exclude = ini.get_array("reload", "exclude");

                        // Validate reload section
                        for key in ini.remaining_keys("reload") {
                            config.config_errors.push(format!("Unknown key '{}' in [reload] section", key));
                        }
                    }

                    // Load rewrites
                    let rewrite_keys: Vec<_> = ini.get_section("rewrite").keys().cloned().collect();
                    for pattern in rewrite_keys {
                        if let Some(target) = ini.get("rewrite", &pattern) {
                            config.rewrites.insert(pattern, target);
                        }
                    }

                    // Validate for unrecognized sections
                    let known_sections = ["", "environment", "docker", "reload", "rewrite"];
                    for section in ini.sections.keys() {
                        if !known_sections.contains(&section.as_str()) {
                            config.config_errors.push(format!("Unknown section [{}] in webcentral.ini", section));
                        }
                    }
                }
                Err(e) => {
                    config.config_errors.push(format!("Failed to parse webcentral.ini: {}", e));
                }
            }
        }

        // If no command found, check for Procfile
        if config.command.is_empty() && config.docker.is_none() && config.port == 0
            && config.socket_path.is_empty() && config.redirect.is_empty() && config.proxy.is_empty() {
            let procfile_path = dir.join("Procfile");
            if procfile_path.exists() {
                if let Ok(procfile) = Procfile::parse(&procfile_path) {
                    if let Some(web_cmd) = procfile.processes.get("web") {
                        config.command = web_cmd.clone();
                    }

                    // Check for worker processes
                    let mut worker_index = 0;
                    for (process_type, cmd) in &procfile.processes {
                        if process_type == "worker" || process_type == "urgentworker" {
                            config.workers.insert(worker_index.to_string(), cmd.clone());
                            worker_index += 1;
                        } else if process_type != "web" {
                            config.config_errors.push(format!("Procfile process type '{}' is not supported and will be ignored", process_type));
                        }
                    }
                }
            }
        }

        // If still no command, check for package.json
        if config.command.is_empty() && config.docker.is_none() && config.port == 0
            && config.socket_path.is_empty() && config.redirect.is_empty() && config.proxy.is_empty() {
            let pkg_path = dir.join("package.json");
            if pkg_path.exists() {
                if let Ok(pkg) = PackageJson::parse(&pkg_path) {
                    if let Some(start_script) = pkg.scripts.get("start") {
                        if !start_script.is_empty() {
                            config.command = "npm start".to_string();
                        }
                    }
                }
            }
        }

        Ok(config)
    }
}
