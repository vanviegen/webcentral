use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
enum IniValue {
    String(String),
    Array(Vec<String>),
}

impl IniValue {
    fn as_string(self) -> String {
        match self {
            IniValue::String(s) => s,
            IniValue::Array(mut arr) => arr.pop().unwrap_or_default(),
        }
    }

    fn as_array(self) -> Vec<String> {
        match self {
            IniValue::String(s) => vec![s],
            IniValue::Array(arr) => arr,
        }
    }
}

struct IniConfig;

impl IniConfig {
    pub fn parse(path: &Path, config: &mut ProjectConfig) -> Result<Vec<String>> {
        let content = fs::read_to_string(path)
            .context("Failed to open webcentral.ini")?;

        let mut parse_errors = Vec::new();
        let mut current_section = String::new();
        let mut docker = None::<DockerConfig>;

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
                if current_section == "docker" {
                    docker = Some(DockerConfig {
                        base: "alpine".to_string(),
                        packages: Vec::new(),
                        commands: Vec::new(),
                        http_port: 8000,
                        app_dir: "/app".to_string(),
                        mount_app_dir: true,
                        mounts: Vec::new(),
                    });
                }
                continue;
            }

            // Parse key=value
            if let Some(caps) = line_regex.captures(line) {
                let key = caps[1].to_string();
                let value = caps[2].to_string();

                let (actual_key, ini_value) = if key.ends_with("[]") {
                    (key.trim_end_matches("[]").to_string(), IniValue::Array(vec![value]))
                } else {
                    (key, IniValue::String(value))
                };

                // Combine section and key with a dot
                let full_key = if current_section.is_empty() {
                    actual_key.clone()
                } else {
                    format!("{}.{}", current_section, actual_key)
                };

                let known = Self::handle_key(config, &mut docker, &full_key, ini_value);

                if !known {
                    let location = if current_section.is_empty() {
                        "root section".to_string()
                    } else {
                        format!("[{}] section", current_section)
                    };
                    parse_errors.push(format!("Unknown key '{}' in {}", actual_key, location));
                }
            } else {
                parse_errors.push(format!("Invalid syntax in webcentral.ini at line {}: {}", line_num + 1, line));
            }
        }

        if let Some(d) = docker {
            config.docker = Some(d);
        }

        Ok(parse_errors)
    }

    fn handle_key(config: &mut ProjectConfig, docker: &mut Option<DockerConfig>, key: &str, value: IniValue) -> bool {
        match key {
            "command" => config.command = value.as_string(),
            "worker" => { config.workers.insert("default".to_string(), value.as_string()); }
            key if key.starts_with("worker:") => { config.workers.insert(key[7..].to_string(), value.as_string()); }
            "port" => config.port = value.as_string().parse().unwrap_or(0),
            "host" => config.host = value.as_string(),
            "socket_path" => config.socket_path = value.as_string(),
            "redirect" => config.redirect = value.as_string(),
            "proxy" => config.proxy = value.as_string(),
            "log_requests" => {
                let v = value.as_string().to_lowercase();
                config.log_requests = v == "true" || v == "1" || v == "yes";
            }
            "redirect_http" => {
                let v = value.as_string().to_lowercase();
                config.redirect_http = Some(v == "true" || v == "1" || v == "yes");
            }
            "redirect_https" => {
                let v = value.as_string().to_lowercase();
                config.redirect_https = Some(v == "true" || v == "1" || v == "yes");
            }
            key if key.starts_with("environment.") => {
                config.environment.insert(key[12..].to_string(), value.as_string());
            }
            "docker.base" => { docker.as_mut().map(|d| d.base = value.as_string()); }
            "docker.packages" => { docker.as_mut().map(|d| d.packages = value.as_array()); }
            "docker.commands" => { docker.as_mut().map(|d| d.commands = value.as_array()); }
            "docker.http_port" => { docker.as_mut().map(|d| d.http_port = value.as_string().parse().unwrap_or(8000)); }
            "docker.app_dir" => { docker.as_mut().map(|d| d.app_dir = value.as_string()); }
            "docker.mount_app_dir" => {
                let v = value.as_string().to_lowercase();
                docker.as_mut().map(|d| d.mount_app_dir = v == "true" || v == "1" || v == "yes");
            }
            "docker.mounts" => { docker.as_mut().map(|d| d.mounts = value.as_array()); }
            "reload.timeout" => config.reload.timeout = value.as_string().parse().unwrap_or(300),
            "reload.include" => config.reload.include = value.as_array(),
            "reload.exclude" => config.reload.exclude = value.as_array(),
            key if key.starts_with("rewrite.") => {
                config.rewrites.insert(key[8..].to_string(), value.as_string());
            }
            _ => return false,
        }
        true
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
            match IniConfig::parse(&ini_path, &mut config) {
                Ok(errors) => config.config_errors.extend(errors),
                Err(e) => config.config_errors.push(format!("Failed to parse webcentral.ini: {}", e)),
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
