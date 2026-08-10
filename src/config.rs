//! The webcentral configuration language: model, parser and defaults.
//!
//! A `webcentral.conf` is a list of statements:
//!
//!     verb positional... name=value... [{ ... }]
//!
//! Some verbs are *declarations* (`service`, `settings`); their block holds `key = value`
//! settings. The rest are *routing statements*, and their block holds more statements. Nothing
//! else is a setting, so `=` is an ordinary character everywhere a statement's arguments are
//! read - which is why patterns like `/a=b` need no quoting.
//!
//! Declarations are hoisted: their position relative to the routing statements doesn't matter.
//! Routing statements run top to bottom for every request. An implicit tail is appended to every
//! script - `serve` when a server named `default` exists, otherwise `serve_dir public` when that
//! directory exists - so a project with no configuration at all still does the obvious thing.

use crate::parser::{is_argument_name, Diagnostic, Scanner, Word};
use crate::script::{Pattern, Stmt, Template, Vars};
use anyhow::Result;
use regex::Regex;

use std::fs;
use std::path::Path;

pub const CONFIG_FILE: &str = "webcentral.conf";

/// Request variables that only ever describe what arrived, so `set` refuses them. `path` and
/// `query` are deliberately absent: assigning those is how a request is re-pointed.
const READ_ONLY_VARS: &[&str] =
    &["method", "host", "domain", "redirected_from", "redirected_by"];

/// The image a service is built from unless it says otherwise: small, and `packages` adds to it
/// quickly enough that carrying a language runtime by default would not pay for itself.
pub const DEFAULT_BASE_IMAGE: &str = "alpine";
/// Consulted only when the configuration doesn't say how to serve anything.
const AUTO_DETECT_FILES: &[&str] = &["Procfile", "package.json"];

/// The files that *define* a project, as opposed to the ones its servers run from. A change to any
/// of them replaces the project wholesale, since the script and the set of servers may both be
/// different. They are watched centrally for every project at once (see the config watcher in `server.rs`),
/// because one inotify instance per project is what runs into the per-user cap first.
pub const PROJECT_FILES: &[&str] = &[CONFIG_FILE, "Procfile", "package.json"];

/// What a service restarts for when it names no `reload_include` of its own: the code that
/// plausibly *serves* the requests, rather than everything. Restarting is disruptive and most
/// files in a project are not program text - assets, uploads, fixtures and generated output all
/// change without the process needing to know. A project whose sources live elsewhere says so
/// with `reload_include`.
pub const DEFAULT_INCLUDES: &[&str] = &[
    // Directories an application's own code conventionally lives in
    "src",
    "app",
    "lib",
    "server",
    "api",
    "bin",
    "cgi-bin",
    // Languages that commonly serve HTTP, wherever in the tree their files live
    "*.py",
    "*.rb",
    "*.php",
    "*.pl",
    "*.lua",
    "*.sh",
    "*.[cm]?js",
    "*.[cm]?ts",
    "*.[jt]sx",
    "*.go",
    "*.rs",
    "*.java",
    "*.kt",
    "*.cs",
    "*.ex",
    "*.exs",
    "*.erl",
    "*.clj",
    // Dependency manifests: whatever installs from them has to run again
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile.lock",
    "Gemfile",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
];

/// Patterns never watched for reloads, whatever a server's `reload_include` says.
pub const DEFAULT_EXCLUDES: &[&str] = &[
    "/_webcentral_data",
    "node_modules",
    "__pycache__",
    // Not hidden files in general - an `env_file` is usually one - but a checkout churns through
    // thousands of writes in here, and none of them are the project's own code.
    ".git",
    "*.bak",
    "*.sw?", // vim swap files
    "data",
    "*.log",
    "log",
    "logs",
];

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub name: String,
    /// The command to run inside the container. Empty means the image's own entrypoint.
    pub command: String,
    pub env: Vec<(String, String)>,
    /// Idle seconds before the server is stopped again; 0 keeps it running.
    pub shutdown_time: u64,
    /// Seconds to wait for the port to answer before declaring the startup failed.
    pub startup_time: u64,
    /// Which files restart this server. Defaults to the project's `settings`, then to everything.
    pub reload_include: Vec<String>,
    pub reload_exclude: Vec<String>,
    /// Services started and stopped with this one - a database, a cache, a queue runner. Each gets
    /// its own port, published to the group as `<NAME>_PORT` and `<NAME>_HOST`.
    pub sidecars: Vec<ServerConfig>,

    /// The image built from. `None` means the default: `alpine` for a top-level service, and
    /// for a sidecar its parent's (fully prepared) image, so a nested service can run another
    /// command in the same environment or layer `packages` on top of it.
    pub base: Option<String>,
    pub packages: Vec<String>,
    pub build: Vec<String>,
    /// Files copied into the image before `build` runs, so a build command can see them. Paths
    /// are relative to the project directory and may not leave it.
    pub copy: Vec<String>,
    /// The port the command listens on inside the container.
    pub port: u16,
    /// Where the project directory is mounted inside the container; `None` (written
    /// `app_dir = none`) mounts nothing, for images that carry the application themselves.
    pub app_dir: Option<String>,
    /// Persistent directories, kept on the host under `_webcentral_data/mounts`.
    pub mounts: Vec<String>,
    /// Who the container runs as *inside*. Either `project` (add the project owner to the image
    /// and run as them), `image` (keep whatever the image declares), an explicit numeric `uid:gid`
    /// pair, or a name defined in the image. Defaults to `project` when the project directory is
    /// mounted and `image` when it isn't. Host-side, files the container writes always land owned
    /// by the project owner - see `AppServer::add_userns_args`.
    pub user: String,
}

impl ServerConfig {
    fn new(name: String) -> Self {
        ServerConfig {
            name,
            command: String::new(),
            env: Vec::new(),
            shutdown_time: 300,
            startup_time: 60,
            reload_include: Vec::new(),
            reload_exclude: Vec::new(),
            sidecars: Vec::new(),
            base: None,
            packages: Vec::new(),
            build: Vec::new(),
            copy: Vec::new(),
            port: 8000,
            app_dir: Some("/app".to_string()),
            mounts: Vec::new(),
            user: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProjectConfig {
    pub log_requests: bool,
    pub redirect_http: Option<bool>,
    pub redirect_https: Option<bool>,
    pub servers: Vec<ServerConfig>,
    pub script: Vec<Stmt>,
    /// The constants the file's top-level `set` statements defined, copied into every request.
    pub vars: Vars,
    /// Files that reload the entire project when touched (the config, and whatever was
    /// auto-detected in its absence).
    pub config_files: Vec<String>,
    /// The default reload rules for servers that declare none of their own.
    pub reload_include: Vec<String>,
    pub reload_exclude: Vec<String>,
    /// Problems that stop something from working, which `webcentral check` fails on.
    pub errors: Vec<String>,
    /// Things worth saying that the project still runs with, which it does not.
    pub warnings: Vec<String>,
}

impl ProjectConfig {
    pub fn server(&self, name: &str) -> Option<&ServerConfig> {
        self.servers.iter().find(|s| s.name == name)
    }

    /// A one-line summary for the dashboard and the startup log line.
    pub fn summary(&self) -> String {
        if self.servers.is_empty() {
            "Static".to_string()
        } else {
            let names: Vec<String> = self
                .servers
                .iter()
                .map(|s| format!("{} ({})", s.name, s.base.as_deref().unwrap_or(DEFAULT_BASE_IMAGE)))
                .collect();
            names.join(", ")
        }
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let config_path = dir.join(CONFIG_FILE);
        let source = if config_path.exists() { fs::read_to_string(&config_path)? } else { String::new() };

        let mut config = parse(&source, Some(dir));
        let mut detected = false;

        // A configuration that declares no server and never says how to answer a request leaves
        // room for the directory to speak for itself, whether or not a webcentral.conf exists.
        // The detected server is called `default`, so the implicit tail picks it up.
        if config.servers.is_empty() && !serves_anything(&config.script) {
            config.config_files.extend(AUTO_DETECT_FILES.iter().map(|f| f.to_string()));
            if let Some((snippet, warnings)) = auto_detect(dir) {
                let parsed = parse(&snippet, Some(dir));
                config.servers = parsed.servers;
                config.errors.extend(parsed.errors);
                config.warnings.extend(parsed.warnings);
                config.warnings.extend(warnings);
                detected = true;
            }
        } else if config.servers.iter().any(|s| s.command.is_empty() && s.app_dir.is_some()) {
            // A declared service with no command and the project directory mounted runs the
            // project's own code, so its command is auto-detected too - that is how a Procfile
            // project adds `packages` or reload rules without giving up detection. Without the
            // mount there is nothing of the project to run, so the image's entrypoint stands.
            config.config_files.extend(AUTO_DETECT_FILES.iter().map(|f| f.to_string()));
            detected = true;
            let donor = auto_detect(dir).map(|(snippet, warnings)| {
                let detected = parse(&snippet, Some(dir));
                config.errors.extend(detected.errors.iter().cloned());
                config.warnings.extend(detected.warnings.iter().cloned());
                config.warnings.extend(warnings);
                detected.servers.into_iter().next()
            });
            let mut errors = Vec::new();
            for server in
                config.servers.iter_mut().filter(|s| s.command.is_empty() && s.app_dir.is_some())
            {
                match donor.as_ref().and_then(|d| d.as_ref()) {
                    Some(donor) => {
                        server.command = donor.command.clone();
                        server.sidecars.extend(donor.sidecars.iter().cloned());
                        // The detected runtime, unless the service named an image of its own -
                        // which is then trusted to carry one.
                        if server.base.is_none() {
                            server.base = donor.base.clone();
                        }
                    }
                    None => errors.push(format!(
                        "service '{}' has no command, and no Procfile or package.json to detect \
                         one from - add 'command =', or 'app_dir = none' to run the image's \
                         own entrypoint",
                        server.name
                    )),
                }
            }
            config.errors.extend(errors);
        }

        // Said once the image is actually settled: a service declared in the file may have
        // supplied the base that detection could not find.
        if detected && config.servers.iter().any(|server| server.base.is_none()) {
            config.warnings.push(
                "No requirements.txt, Gemfile, go.mod or package.json next to the Procfile, so \
                 its commands run on a bare alpine image - name a 'base' or 'packages' if they \
                 need a runtime"
                    .to_string(),
            );
        }

        add_implicit_tail(&mut config, dir);

        // Reload rules fall back to the project's settings and then to everything, and are only
        // resolved now because a `settings` block may come after the servers it applies to.
        let (default_include, default_exclude) =
            (config.reload_include.clone(), config.reload_exclude.clone());
        for server in &mut config.servers {
            if server.reload_include.is_empty() {
                server.reload_include = if default_include.is_empty() {
                    DEFAULT_INCLUDES.iter().map(|s| s.to_string()).collect()
                } else {
                    default_include.clone()
                };
            }
            // A copied file is baked into the image, so editing it has to rebuild and restart -
            // whatever the reload rules otherwise say, and including a sidecar's, since the whole
            // group restarts together.
            let copied: Vec<String> = server
                .copy
                .iter()
                .chain(server.sidecars.iter().flat_map(|s| s.copy.iter()))
                .map(|path| format!("/{}", path))
                .collect();
            server.reload_include.extend(copied);

            server.reload_exclude.extend(default_exclude.iter().cloned());
            server.reload_exclude.extend(DEFAULT_EXCLUDES.iter().map(|s| s.to_string()));
            // A change to one of these replaces the project rather than restarting a server.
            server.reload_exclude.extend(PROJECT_FILES.iter().map(|f| format!("/{}", f)));
        }

        Ok(config)
    }
}

/// Whether the script already decides how some request is answered. Tells a configuration that
/// only tweaks settings from one that takes over routing.
fn serves_anything(stmts: &[Stmt]) -> bool {
    walk(stmts, &mut |stmt| {
        matches!(
            stmt,
            Stmt::Match { .. }
                | Stmt::ServeApp(_)
                | Stmt::ServeDir { .. }
                | Stmt::ServeFile { .. }
                | Stmt::Forward(_)
                | Stmt::Proxy(_)
                | Stmt::Redirect { .. }
                | Stmt::Respond { .. }
                | Stmt::Dashboard { .. }
                | Stmt::CheckFile { .. }
        )
    })
}

/// The implicit tail appended to every script: a `default` server if there is one, else the
/// `public` directory if it exists, else nothing (which leaves the interpreter's own 404).
/// Appending it unconditionally means one rule to learn rather than a special case for scripts
/// that already end in a terminal statement.
fn add_implicit_tail(config: &mut ProjectConfig, dir: &Path) {
    if config.server("default").is_some() {
        config.script.push(Stmt::ServeApp("default".to_string()));
    } else if dir.join("public").is_dir() {
        config.script.push(Stmt::ServeDir {
            dir: Template::literal("public"),
            index: "index.html".to_string(),
            fallthrough: false,
        });
    }
}

/// Synthesise a server declaration for a project that doesn't configure one, from Procfile or
/// package.json. The generated source is what gets parsed, so there is one code path for both.
/// The image a `Procfile` project needs, guessed from the manifest files beside it.
///
/// A Procfile says how to *start* an application but never what to start it with: on Heroku a
/// buildpack decides that from exactly these files. Webcentral has no buildpacks, so it reads the
/// same ones and picks an official image, which also gets the binary names right - a Procfile
/// says `python`, and alpine's python3 package provides only `python3`.
///
/// The runtime, not the dependencies: nothing here runs `pip install`, because what that takes
/// varies too much to guess. `copy` plus `build` is how a project says it (see the README).
fn detected_base(dir: &Path) -> Option<&'static str> {
    // package.json is last: plenty of Python and Ruby projects carry one for their front-end
    // tooling, while the reverse is rare.
    for (marker, image) in [
        ("requirements.txt", "python:3-alpine"),
        ("Pipfile", "python:3-alpine"),
        ("pyproject.toml", "python:3-alpine"),
        ("Gemfile", "ruby:3-alpine"),
        ("go.mod", "golang:alpine"),
        ("composer.json", "php:8-cli-alpine"),
        ("package.json", "node:22-alpine"),
    ] {
        if dir.join(marker).exists() {
            return Some(image);
        }
    }
    None
}

fn auto_detect(dir: &Path) -> Option<(String, Vec<String>)> {
    let procfile = dir.join("Procfile");
    if procfile.exists() {
        if let Ok(content) = fs::read_to_string(&procfile) {
            let mut command = String::new();
            let mut workers = String::new();
            let mut warnings = Vec::new();
            let mut worker_index = 0;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some((name, value)) = line.split_once(':') else { continue };
                match name.trim() {
                    "web" => command = value.trim().to_string(),
                    "worker" | "urgentworker" => {
                        // A nested service with no image settings of its own runs in the
                        // parent's image, which is exactly what a Procfile worker is.
                        workers.push_str(&format!(
                            "  service w{} {{ command = {} }}\n",
                            worker_index,
                            value.trim()
                        ));
                        worker_index += 1;
                    }
                    other => warnings.push(format!(
                        "Procfile process type '{}' is not supported and will be ignored",
                        other
                    )),
                }
            }
            if !command.is_empty() {
                let mut source = String::from("service {\n");
                if let Some(base) = detected_base(dir) {
                    source.push_str(&format!("  base = {}\n", base));
                }
                source.push_str(&format!("  command = {}\n", command));
                source.push_str(&workers);
                source.push_str("}\n");
                return Some((source, warnings));
            }
        }
    }

    let package_json = dir.join("package.json");
    if package_json.exists() {
        if let Ok(content) = fs::read_to_string(&package_json) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
                let start = value.get("scripts").and_then(|s| s.get("start")).and_then(|s| s.as_str());
                if start.map(|s| !s.is_empty()).unwrap_or(false) {
                    return Some((
                        "service {\n  base = node:22-alpine\n  command = npm start\n}\n"
                            .to_string(),
                        Vec::new(),
                    ));
                }
            }
        }
    }

    None
}

// --- Statement signatures ---
//
// Every statement declares what it accepts, and one binder turns a line into those values. That
// keeps the rules identical everywhere: positional arguments come first and may also be given by
// name, `name=value` arguments are optional modifiers, an unknown name is reported rather than
// silently taken as a positional argument, and anything given twice is an error.

/// What a parameter's word is turned into.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// Interpolated per request: `$1`, `${name}` and the request variables.
    Template,
    /// Substituted once, when the file is read: a server name, a header name, a pattern.
    Word,
    /// The name a `set` assigns to, which is not itself substituted. A leading `$` is optional.
    Variable,
    /// An HTTP status code.
    Status,
}

struct Param {
    name: &'static str,
    kind: Kind,
    required: bool,
}

const fn req(name: &'static str, kind: Kind) -> Param {
    Param { name, kind, required: true }
}

const fn opt(name: &'static str, kind: Kind) -> Param {
    Param { name, kind, required: false }
}

#[derive(Clone, Copy)]
struct Signature {
    /// Parameters that may be given positionally, in order, or by `name=value`.
    positional: &'static [Param],
    /// Modifiers, which only make sense named.
    named: &'static [Param],
    /// Whether a `{ ... }` block or an inline statement follows. Argument reading stops at the
    /// first word that isn't an argument, instead of complaining about it.
    body: bool,
}

const fn sig(positional: &'static [Param], named: &'static [Param]) -> Signature {
    Signature { positional, named, body: false }
}

// `match` tests one variable against one pattern, so `$1` is never in doubt. Nest matches to
// test more, and name the variable with `subject=` to test something other than the path.
const MATCH: Signature = Signature {
    positional: &[req("pattern", Kind::Word)],
    named: &[
        opt("subject", Kind::Template),
        opt("matcher", Kind::Word),
        opt("anchored", Kind::Word),
    ],
    body: true,
};
const SET: Signature = sig(&[req("name", Kind::Variable), req("value", Kind::Template)], &[]);
const SERVE: Signature = sig(&[opt("server", Kind::Word)], &[]);
const SERVE_FILE: Signature =
    sig(&[req("path", Kind::Template)], &[opt("fallthrough", Kind::Word)]);
const SERVE_DIR: Signature = sig(
    &[req("dir", Kind::Template)],
    &[opt("index", Kind::Word), opt("fallthrough", Kind::Word)],
);
// `check_file` guards its body the way `check_auth` does: what follows runs either way.
const CHECK_FILE: Signature = Signature {
    positional: &[req("path", Kind::Template)],
    named: &[],
    body: true,
};
const FORWARD: Signature = sig(&[req("target", Kind::Template)], &[]);
const PROXY: Signature = sig(&[req("url", Kind::Template)], &[]);
const REDIRECT: Signature =
    sig(&[req("url", Kind::Template)], &[opt("status", Kind::Status)]);
const RESPOND: Signature = sig(
    &[req("status", Kind::Status), opt("body", Kind::Template)],
    &[opt("type", Kind::Word)],
);
// `check_auth` guards its body, like `match` guards its own: what follows still runs either way.
const CHECK_AUTH: Signature = Signature {
    positional: &[req("secret", Kind::Word)],
    named: &[],
    body: true,
};
const SET_HEADER: Signature =
    sig(&[req("name", Kind::Word), req("value", Kind::Template)], &[]);
const LOG: Signature = sig(&[req("message", Kind::Template)], &[]);
const DASHBOARD: Signature = sig(&[], &[]);

/// The signature of every routing statement.
fn signature(verb: &str) -> Option<Signature> {
    Some(match verb {
        "match" => MATCH,
        "set" => SET,
        "serve" => SERVE,
        "serve_file" => SERVE_FILE,
        "serve_dir" => SERVE_DIR,
        "check_file" => CHECK_FILE,
        "forward" => FORWARD,
        "proxy" => PROXY,
        "redirect" => REDIRECT,
        "respond" => RESPOND,
        "check_auth" => CHECK_AUTH,
        "set_header" => SET_HEADER,
        "log" => LOG,
        "project_dashboard" | "admin_dashboard" => DASHBOARD,
        _ => return None,
    })
}

enum Value {
    Template(Template),
    Word(Word),
    Status(u16),
}

/// The bound arguments of one statement. Values are taken out by name; a parameter that was
/// missing or unusable yields `None`, having already been reported.
struct Args {
    values: Vec<Option<Value>>,
    params: Vec<&'static Param>,
}

impl Args {
    fn take(&mut self, name: &str) -> Option<Value> {
        let index = self.params.iter().position(|p| p.name == name)?;
        self.values[index].take()
    }

    fn template(&mut self, name: &str) -> Option<Template> {
        match self.take(name)? {
            Value::Template(template) => Some(template),
            _ => None,
        }
    }

    fn word(&mut self, name: &str) -> Option<Word> {
        match self.take(name)? {
            Value::Word(word) => Some(word),
            _ => None,
        }
    }

    fn text(&mut self, name: &str) -> Option<String> {
        self.word(name).map(|w| w.text)
    }

    fn status(&mut self, name: &str) -> Option<u16> {
        match self.take(name)? {
            Value::Status(status) => Some(status),
            _ => None,
        }
    }
}

// --- Parsing ---

struct Builder<'a> {
    scanner: Scanner<'a>,
    /// Where the project lives, for `env_file`. Absent when a snippet is parsed on its own.
    dir: Option<std::path::PathBuf>,
    config: ProjectConfig,
    /// Constants defined by top-level `set` statements, available to everything the parser reads
    /// after them - and the starting point for every request's variables.
    vars: Vars,
    /// Every `$name` the file reads, checked at the end against everything it defines.
    referenced: Vec<(String, usize)>,
    /// Every name the file can define: constants, `set` targets and named capture groups.
    defined: std::collections::HashSet<String>,
    /// Names referenced by `serve`, checked once every server has been declared.
    served: Vec<Word>,
}

pub fn parse(source: &str, dir: Option<&Path>) -> ProjectConfig {
    let mut builder = Builder {
        scanner: Scanner::new(source),
        dir: dir.map(|d| d.to_path_buf()),
        config: ProjectConfig {
            log_requests: false,
            redirect_http: None,
            redirect_https: None,
            servers: Vec::new(),
            script: Vec::new(),
            vars: Vars::default(),
            config_files: vec![CONFIG_FILE.to_string()],
            reload_include: Vec::new(),
            reload_exclude: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
        },
        vars: Vars::default(),
        referenced: Vec::new(),
        defined: [
            "path",
            "query",
            "method",
            "host",
            "domain",
            "redirected_from",
            "redirected_by",
        ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        served: Vec::new(),
    };

    let script = builder.statements(true);
    builder.config.script = script;
    builder.config.vars = builder.vars.clone();
    builder.finish()
}

impl<'a> Builder<'a> {
    fn finish(mut self) -> ProjectConfig {
        for word in std::mem::take(&mut self.served) {
            if self.config.server(&word.text).is_none() {
                let known: Vec<&str> = self.config.servers.iter().map(|s| s.name.as_str()).collect();
                let hint = if known.is_empty() {
                    "no servers are declared".to_string()
                } else {
                    format!("declared: {}", known.join(", "))
                };
                self.scanner
                    .error_at(word.pos, format!("Unknown server '{}' ({})", word.text, hint));
            }
        }
        // A server nobody serves is dead configuration: a warning rather than an error, since
        // the project still runs.
        let mut warnings = Vec::new();
        for server in &self.config.servers {
            let name = &server.name;
            let served = name == "default"
                || walk(&self.config.script, &mut |s| matches!(s, Stmt::ServeApp(n) if n == name));
            if !served {
                warnings.push(format!(
                    "server '{}' is declared but never served - add 'serve {}'",
                    name, name
                ));
            }
        }

        // A `$name` nothing defines is empty at runtime, which is a typo far more often than it
        // is intent. The check is file-wide rather than per branch: knowing a name is defined
        // *somewhere* is enough to keep it from being a mistake, and avoids false alarms.
        for (name, pos) in std::mem::take(&mut self.referenced) {
            if !self.defined.contains(&name) {
                self.scanner.error_at(
                    pos,
                    format!("'${{{}}}' is never set, so it is always empty", name),
                );
            }
        }

        let diagnostics: Vec<Diagnostic> = std::mem::take(&mut self.scanner.errors);
        let mut errors: Vec<String> =
            diagnostics.iter().map(|d| format!("{}: {}", CONFIG_FILE, d)).collect();
        errors.extend(std::mem::take(&mut self.config.errors));
        self.config.errors = errors;
        self.config.warnings.extend(warnings);
        self.config
    }

    /// Parse statements until the end of the file (`top`) or a closing brace.
    fn statements(&mut self, top: bool) -> Vec<Stmt> {
        let mut stmts: Vec<Stmt> = Vec::new();
        loop {
            self.scanner.skip_separators();
            if self.scanner.at_eof() {
                if !top {
                    self.scanner.error("Unclosed '{'".to_string());
                }
                return stmts;
            }
            if self.scanner.at_block_close() {
                if !top {
                    self.scanner.read_block_close();
                    return stmts;
                }
                self.scanner.read_block_close();
                self.scanner.error("Unexpected '}'".to_string());
                continue;
            }

            let Some(verb) = self.scanner.read_word() else {
                self.scanner.error("Expected a statement".to_string());
                self.scanner.skip_line();
                continue;
            };
            self.statement(verb, top, &mut stmts);
        }
    }

    /// Read a statement's arguments into the slots its signature declares.
    fn bind(&mut self, verb: &Word, signature: &Signature) -> Option<Args> {
        let params: Vec<&Param> =
            signature.positional.iter().chain(signature.named.iter()).collect();
        let mut values: Vec<Option<Value>> = params.iter().map(|_| None).collect();
        let positionals = signature.positional.len();

        loop {
            let mark = self.scanner.mark();
            let Some(word) = self.scanner.read_word() else { break };

            // `else` always starts a new statement, so `match /x respond 404 else ...` reads the
            // way it looks. An argument that really is the word "else" can be quoted.
            if word.text == "else" && word.eq_at.is_none() {
                self.scanner.reset(mark);
                break;
            }

            let (index, value) = match word.split_eq() {
                Some((name, value)) if is_argument_name(name) => {
                    let Some(index) = params.iter().position(|p| p.name == name) else {
                        let accepted: Vec<&str> = params.iter().map(|p| p.name).collect();
                        let takes = if accepted.is_empty() {
                            "it takes no arguments".to_string()
                        } else {
                            format!("it takes {}", accepted.join(", "))
                        };
                        self.scanner.error_at(
                            word.pos,
                            format!(
                                "'{}' is not an argument of '{}' ({}) - quote the value if the \
                                 '=' is part of it",
                                name, verb.text, takes
                            ),
                        );
                        continue;
                    };
                    (index, word.named_value(value))
                }
                _ => {
                    // The next free positional slot, so naming one out of order still works.
                    match (0..positionals).find(|i| values[*i].is_none()) {
                        Some(index) => (index, word),
                        None if signature.body => {
                            self.scanner.reset(mark);
                            break;
                        }
                        None => {
                            self.scanner.error_at(
                                word.pos,
                                format!(
                                    "'{}' takes {} argument(s), so '{}' is one too many",
                                    verb.text, positionals, word.text
                                ),
                            );
                            continue;
                        }
                    }
                }
            };

            if values[index].is_some() {
                self.scanner
                    .error_at(value.pos, format!("'{}' was given twice", params[index].name));
                continue;
            }
            values[index] = self.value(&value, params[index].kind);
        }

        for (index, param) in params.iter().enumerate() {
            if param.required && values[index].is_none() {
                self.scanner
                    .error_at(verb.pos, format!("'{}' needs a value for '{}'", verb.text, param.name));
                return None;
            }
        }

        Some(Args { values, params })
    }

    /// Substitute a setting's value. Declaration blocks get the constants defined above them,
    /// which is the whole point of a top-level `set`.
    fn expand(&mut self, word: &Word) -> String {
        match Template::parse(word) {
            Ok(template) => {
                self.note_names(&template, word.pos);
                template.render(&self.vars)
            }
            Err(e) => {
                self.scanner.error_at(word.pos, e);
                word.text.clone()
            }
        }
    }

    /// The same, for values read as raw text to the end of the line. There are no quotes to
    /// honour there, but `$PORT` still belongs to the shell and `$$` still escapes.
    fn expand_line(&mut self, text: String, pos: usize) -> String {
        self.expand(&Word::new(text, pos))
    }

    /// Remember which names a template reads, so ones that are never defined can be reported.
    fn note_names(&mut self, template: &Template, pos: usize) {
        for name in template.names() {
            self.referenced.push((name.to_string(), pos));
        }
    }

    fn value(&mut self, word: &Word, kind: Kind) -> Option<Value> {
        match kind {
            // A name is not a use of the variable, so it is taken as written - `set foo x` and
            // `set ${foo} x` both name `foo`.
            Kind::Variable => {
                let mut name = word.clone();
                let text = name.text.clone();
                name.text = text
                    .strip_prefix("${")
                    .and_then(|rest| rest.strip_suffix('}'))
                    .unwrap_or_else(|| text.trim_start_matches('$'))
                    .to_string();
                Some(Value::Word(name))
            }
            // Consumed as the file is read, so it sees the constants defined above it.
            Kind::Word => {
                let mut rendered = word.clone();
                rendered.text = self.expand(word);
                Some(Value::Word(rendered))
            }
            Kind::Template => match Template::parse(word) {
                Ok(template) => {
                    self.note_names(&template, word.pos);
                    Some(Value::Template(template))
                }
                Err(e) => {
                    self.scanner.error_at(word.pos, e);
                    None
                }
            },
            Kind::Status => match word.text.parse::<u16>() {
                Ok(status) if (100..=599).contains(&status) => Some(Value::Status(status)),
                _ => {
                    self.scanner.error_at(
                        word.pos,
                        format!("Expected a status code (100-599), got '{}'", word.text),
                    );
                    None
                }
            },
        }
    }

    fn statement(&mut self, verb: Word, top: bool, stmts: &mut Vec<Stmt>) {
        match verb.text.as_str() {
            "service" | "settings" => {
                if !top {
                    self.scanner.error_at(
                        verb.pos,
                        format!("'{}' can only be declared at the top level of the file", verb.text),
                    );
                    self.skip_block();
                    return;
                }
                self.declaration(&verb);
            }
            "env_file" => {
                if !top {
                    self.scanner.error_at(
                        verb.pos,
                        "'env_file' can only be used at the top level of the file".to_string(),
                    );
                    self.scanner.skip_line();
                    return;
                }
                match self.scanner.read_word() {
                    Some(word) => {
                        let path = self.expand(&word);
                        self.load_env_file(&path, word.pos);
                    }
                    None => self
                        .scanner
                        .error_at(verb.pos, "'env_file' needs a file to read".to_string()),
                }
            }
            "else" => {
                let Some(branch) = self.body(&verb) else { return };
                match stmts.last_mut() {
                    Some(previous) if previous.is_fallible() => {
                        previous.set_otherwise(branch);
                    }
                    Some(_) => self.scanner.error_at(
                        verb.pos,
                        "'else' can only follow 'match', 'check_auth' or 'check_file' - anything \
                         else either answers or carries on by itself, so the branch could never \
                         run"
                            .to_string(),
                    ),
                    None => self
                        .scanner
                        .error_at(verb.pos, "'else' must follow a statement".to_string()),
                }
            }
            _ => {
                if let Some(stmt) = self.action(&verb) {
                    // A `set` at the top level doubles as a constant: everything the parser reads
                    // after it can use the value, and it is re-evaluated per request as well, so
                    // `set now $path` still means what it says.
                    if top {
                        if let Stmt::Set { name, value } = &stmt {
                            let rendered = value.render(&self.vars);
                            self.vars.set(name.clone(), rendered);
                        }
                    }
                    stmts.push(stmt);
                }
            }
        }
    }

    /// Read `KEY=value` lines into the file's constants, so a secret can live somewhere that is
    /// not the configuration - and reach exactly the `env` blocks and statements that name it,
    /// rather than every process. Values are taken as written: a secret is not a template.
    fn load_env_file(&mut self, path: &str, pos: usize) {
        // The same containment rule as `copy`. Under a root webcentral an absolute path would let
        // any project read any file on the machine.
        if path.starts_with('/') || Path::new(path).components().any(|c| c.as_os_str() == "..") {
            self.scanner.error_at(
                pos,
                format!("'{}' is outside the project directory - env_file can only read within it", path),
            );
            return;
        }
        let Some(dir) = self.dir.clone() else { return };
        let content = match fs::read_to_string(dir.join(path)) {
            Ok(content) => content,
            Err(e) => {
                self.scanner.error_at(pos, format!("Could not read '{}': {}", path, e));
                return;
            }
        };
        // Changing it changes what the configuration means, so it reloads the project.
        self.config.config_files.push(path.to_string());

        for (number, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.strip_prefix("export ").unwrap_or(line).split_once('=')
            else {
                self.scanner.error_at(
                    pos,
                    format!("{} line {}: expected 'KEY=value'", path, number + 1),
                );
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            // One layer of quotes comes off, which is how .env files are usually written.
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(value);
            self.vars.set(key, value);
            self.defined.insert(key.to_string());
        }
    }

    /// The body of `match` or `else`: a block, or a single inline statement.
    fn body(&mut self, verb: &Word) -> Option<Vec<Stmt>> {
        if self.scanner.read_block_open() {
            return Some(self.statements(false));
        }
        let Some(inner_verb) = self.scanner.read_word() else {
            self.scanner
                .error_at(verb.pos, format!("'{}' needs a statement or a '{{ ... }}' block", verb.text));
            self.scanner.skip_line();
            return None;
        };
        let mut inner = Vec::new();
        self.statement(inner_verb, false, &mut inner);
        Some(inner)
    }

    /// Skip a statement that failed to parse, including whatever body follows it, so that an
    /// inline `match /x respond 200 y` doesn't leave `respond 200 y` behind as a statement of its
    /// own. A block always opens on the statement's own line, so there is nothing to look for
    /// beyond it.
    fn skip_block(&mut self) {
        let mut depth = 0;
        loop {
            if self.scanner.read_block_open() {
                depth += 1;
            } else if self.scanner.read_block_close() {
                depth -= 1;
                if depth <= 0 {
                    return;
                }
            } else if self.scanner.read_word().is_some() {
                continue;
            } else if self.scanner.at_eof() {
                return;
            } else if depth == 0 {
                self.scanner.skip_line();
                return;
            } else {
                self.scanner.skip_separators();
            }
        }
    }

    // --- Routing statements ---

    fn action(&mut self, verb: &Word) -> Option<Stmt> {
        let Some(signature) = signature(&verb.text) else {
            self.scanner.error_at(verb.pos, format!("Unknown statement '{}'", verb.text));
            self.scanner.skip_line();
            return None;
        };
        let Some(mut args) = self.bind(verb, &signature) else {
            // Drop the body too, or it would be left behind as a statement of its own.
            if signature.body {
                self.skip_block();
            }
            return None;
        };

        match verb.text.as_str() {
            "match" => self.match_statement(verb, args),

            "set" => {
                let name = args.word("name")?;
                // `path`, `query` and `uri` are the request itself, so assigning one changes what
                // is served or forwarded. The rest of the request's variables describe what
                // arrived and cannot be rewritten into something else.
                if READ_ONLY_VARS.contains(&name.text.as_str()) {
                    self.scanner.error_at(
                        name.pos,
                        format!(
                            "'{}' describes the request as it arrived and cannot be set",
                            name.text
                        ),
                    );
                    return None;
                }
                let value = args.template("value")?;
                // A literal target can be checked now rather than on every request.
                if name.text == "path" {
                    if let Some(literal) = value.as_literal() {
                        if !literal.starts_with('/') {
                            self.scanner.error_at(
                                name.pos,
                                format!("'set path {}' must start with '/'", literal),
                            );
                            return None;
                        }
                    }
                }
                self.defined.insert(name.text.clone());
                Some(Stmt::Set { name: name.text, value })
            }

            "serve" => {
                // The name is remembered for a cross-check once every server has been declared.
                let name = args.word("server").unwrap_or(Word::new("default", verb.pos));
                self.served.push(name.clone());
                Some(Stmt::ServeApp(name.text))
            }

            "serve_file" => Some(Stmt::ServeFile {
                path: args.template("path")?,
                fallthrough: self.flag(&mut args, "fallthrough")?,
            }),

            "serve_dir" => Some(Stmt::ServeDir {
                dir: args.template("dir")?,
                index: args.text("index").unwrap_or_else(|| "index.html".to_string()),
                fallthrough: self.flag(&mut args, "fallthrough")?,
            }),

            "check_file" => {
                let path = args.template("path")?;
                let body = self.body(verb)?;
                Some(Stmt::CheckFile { path, body, otherwise: None })
            }

            "forward" => Some(Stmt::Forward(args.template("target")?)),
            "proxy" => Some(Stmt::Proxy(args.template("url")?)),
            "log" => Some(Stmt::Log(args.template("message")?)),
            "project_dashboard" => Some(Stmt::Dashboard { admin: false }),
            "admin_dashboard" => Some(Stmt::Dashboard { admin: true }),

            "redirect" => Some(Stmt::Redirect {
                target: args.template("url")?,
                status: args.status("status").unwrap_or(302),
            }),

            "respond" => Some(Stmt::Respond {
                status: args.status("status")?,
                body: args.template("body"),
                content_type: args
                    .text("type")
                    .unwrap_or_else(|| "text/plain; charset=utf-8".to_string()),
            }),

            "check_auth" => {
                let secret = args.text("secret")?;
                let body = self.body(verb)?;
                Some(Stmt::CheckAuth { secret, body, otherwise: None })
            }

            "set_header" => {
                let name = args.word("name")?;
                // Checked here rather than per request, where it could only be logged and ignored.
                if http::HeaderName::try_from(name.text.as_str()).is_err() {
                    self.scanner
                        .error_at(name.pos, format!("'{}' is not a valid header name", name.text));
                    return None;
                }
                Some(Stmt::SetHeader(name.text, args.template("value")?))
            }

            other => unreachable!("no handler for '{}', which has a signature", other),
        }
    }

    /// A `true`/`false` modifier on a statement, defaulting to false when it is absent.
    fn flag(&mut self, args: &mut Args, name: &str) -> Option<bool> {
        let Some(word) = args.word(name) else { return Some(false) };
        match word.text.as_str() {
            "true" | "yes" | "on" | "1" => Some(true),
            "false" | "no" | "off" | "0" => Some(false),
            other => {
                self.scanner.error_at(
                    word.pos,
                    format!("Expected {}=true or {}=false, got '{}'", name, name, other),
                );
                None
            }
        }
    }

    /// `match` compares one variable against one pattern. The variable is `path` unless
    /// `subject=` names another, and the pattern is a regex unless `matcher=literal` says
    /// otherwise. Everything after the pattern is the body.
    fn match_statement(&mut self, verb: &Word, mut args: Args) -> Option<Stmt> {
        let subject = args.template("subject").unwrap_or_else(|| Template::variable("path"));
        let literal = match args.word("matcher") {
            Some(word) => match word.text.as_str() {
                "literal" => true,
                "regex" => false,
                other => {
                    self.scanner.error_at(
                        word.pos,
                        format!("Expected matcher=regex or matcher=literal, got '{}'", other),
                    );
                    self.skip_block();
                    return None;
                }
            },
            None => false,
        };
        let anchored = match args.word("anchored") {
            Some(word) => match word.text.as_str() {
                "true" | "yes" => true,
                "false" | "no" => false,
                other => {
                    self.scanner.error_at(
                        word.pos,
                        format!("Expected anchored=true or anchored=false, got '{}'", other),
                    );
                    self.skip_block();
                    return None;
                }
            },
            None => true,
        };
        let text = args.word("pattern")?;

        let pattern = if literal {
            Pattern::Literal { text: text.text.clone(), anchored }
        } else {
            // Anchored: a pattern always describes the whole value, so a rule can't accidentally
            // match a fragment of a longer path. Anchors written by hand are then at best
            // redundant and at worst silently unsatisfiable (`\.css$` becomes `^(?:\.css$)$`,
            // which only matches the path ".css").
            if anchored
                && (text.text.starts_with('^')
                    || (text.text.ends_with('$') && !text.text.ends_with("\\$")))
            {
                self.scanner.error_at(
                    text.pos,
                    format!(
                        "Pattern '{}' has its own '^' or '$', but patterns already match the whole \
                         value - write '.*{}', or pass anchored=false",
                        text.text,
                        text.text.trim_start_matches('^').trim_end_matches('$')
                    ),
                );
            }
            let source =
                if anchored { format!("^(?:{})$", text.text) } else { text.text.clone() };
            match Regex::new(&source) {
                Ok(regex) => {
                    // Group 0 is skipped: `set_captures` never writes `$0`, so counting it as
                    // defined would exempt it from the never-defined check.
                    for (index, name) in regex.capture_names().enumerate().skip(1) {
                        self.defined.insert(index.to_string());
                        if let Some(name) = name {
                            self.defined.insert(name.to_string());
                        }
                    }
                    Pattern::Regex(regex)
                }
                Err(e) => {
                    let message = e.to_string();
                    let detail = message.lines().last().unwrap_or(&message).trim().to_string();
                    self.scanner
                        .error_at(text.pos, format!("Invalid pattern '{}': {}", text.text, detail));
                    self.skip_block();
                    return None;
                }
            }
        };

        let body = self.body(verb)?;
        Some(Stmt::Match { subject, pattern, body, otherwise: None })
    }

    // --- Declarations ---

    fn declaration(&mut self, verb: &Word) {
        if verb.text == "settings" {
            if !self.expect_block(verb) {
                return;
            }
            self.settings_block();
            return;
        }

        // The name is optional and defaults to `default`, which is what a bare `serve` and the
        // implicit tail look for - so an unnamed declaration needs no wiring at all.
        let name = match self.scanner.read_word() {
            Some(word) => word,
            None => Word::new("default", verb.pos),
        };
        if !self.expect_block(verb) {
            return;
        }

        if self.config.server(&name.text).is_some() {
            self.scanner
                .error_at(name.pos, format!("Duplicate server '{}'", name.text));
        }

        let mut server = ServerConfig::new(name.text.clone());
        self.server_block(&mut server, 0);
        self.finish_server(&mut server);
        inherit_into_sidecars(&mut server);
        self.config.servers.push(server);
    }

    /// Parse a nested server declaration. Sidecars share their parent's lifetime, so nesting them
    /// further would have nothing left to mean.
    fn sidecar(&mut self, verb: &Word, depth: usize) -> Option<ServerConfig> {
        let name = match self.scanner.read_word() {
            Some(word) => word,
            None => {
                self.scanner
                    .error_at(verb.pos, "A sidecar needs a name, used for its $<NAME>_PORT".to_string());
                self.skip_block();
                return None;
            }
        };
        if depth > 0 {
            self.scanner.error_at(
                verb.pos,
                "A sidecar cannot have sidecars of its own - it already shares its parent's life"
                    .to_string(),
            );
            self.skip_block();
            return None;
        }
        if !self.expect_block(verb) {
            return None;
        }

        let mut sidecar = ServerConfig::new(name.text.clone());
        self.server_block(&mut sidecar, depth + 1);
        self.finish_server(&mut sidecar);
        Some(sidecar)
    }

    fn expect_block(&mut self, verb: &Word) -> bool {
        if self.scanner.read_block_open() {
            return true;
        }
        self.scanner
            .error_at(verb.pos, format!("'{}' needs a '{{ ... }}' block", verb.text));
        self.scanner.skip_line();
        false
    }

    /// Read one `key = value` line. Returns the key; the value is left for the caller to read in
    /// whatever form the key calls for.
    fn setting_key(&mut self) -> Option<Word> {
        let key = self.scanner.read_key()?;
        if !self.scanner.read_eq() {
            self.scanner
                .error_at(key.pos, format!("Expected '{} = ...'", key.text));
            self.scanner.skip_line();
            return None;
        }
        Some(key)
    }

    /// Iterate the `key = value` lines of a block, calling `each` with the key.
    fn each_setting(&mut self, mut each: impl FnMut(&mut Self, Word)) {
        loop {
            self.scanner.skip_separators();
            if self.scanner.read_block_close() || self.scanner.at_eof() {
                return;
            }
            match self.setting_key() {
                Some(key) => {
                    each(self, key);
                    self.end_of_setting();
                }
                None => continue,
            }
        }
    }

    fn end_of_setting(&mut self) {
        if self.scanner.at_statement_end() || self.scanner.at_block_close() || self.scanner.at_eof() {
            return;
        }
        let leftover = self.scanner.read_word().map(|w| w.text).unwrap_or_default();
        self.scanner
            .error(format!("Unexpected '{}' after the value (quote it if it belongs to the value)", leftover));
        self.scanner.skip_line();
    }

    fn settings_block(&mut self) {
        self.each_setting(|me, key| match key.text.as_str() {
            "log_requests" => {
                if let Some(value) = me.bool_value() {
                    me.config.log_requests = value;
                }
            }
            "redirect_http" => me.config.redirect_http = me.bool_value(),
            "redirect_https" => me.config.redirect_https = me.bool_value(),
            "reload_include" => {
                let list = me.word_list();
                me.config.reload_include.extend(list);
            }
            "reload_exclude" => {
                let list = me.word_list();
                me.config.reload_exclude.extend(list);
            }
            other => {
                me.scanner.error_at(key.pos, format!("Unknown setting '{}'", other));
                me.scanner.skip_line();
            }
        });
    }

    fn map_block(&mut self) -> Vec<(String, String)> {
        let mut entries = Vec::new();
        self.each_setting(|me, key| {
            let value = match me.scanner.read_word() {
                Some(word) => me.expand(&word),
                None => String::new(),
            };
            entries.push((key.text, value));
        });
        entries
    }

    fn bool_value(&mut self) -> Option<bool> {
        let word = self.scanner.read_word()?;
        let text = self.expand(&word);
        match text.as_str() {
            "true" | "yes" | "on" | "1" => Some(true),
            "false" | "no" | "off" | "0" => Some(false),
            other => {
                self.scanner
                    .error_at(word.pos, format!("Expected true or false, got '{}'", other));
                None
            }
        }
    }

    fn word_list(&mut self) -> Vec<String> {
        let mut words = Vec::new();
        while let Some(word) = self.scanner.read_word() {
            words.push(self.expand(&word));
        }
        words
    }

    fn duration_value(&mut self) -> Option<u64> {
        let word = self.scanner.read_word()?;
        let text = self.expand(&word);
        let (number, multiplier) = match text.chars().last() {
            Some('s') => (&text[..text.len() - 1], 1),
            Some('m') => (&text[..text.len() - 1], 60),
            Some('h') => (&text[..text.len() - 1], 3600),
            _ => (text.as_str(), 1),
        };
        match number.parse::<u64>() {
            Ok(value) => Some(value * multiplier),
            Err(_) => {
                self.scanner.error_at(
                    word.pos,
                    format!("Expected a duration like 30, 90s, 5m or 2h, got '{}'", text),
                );
                None
            }
        }
    }

    fn server_block(&mut self, server: &mut ServerConfig, depth: usize) {
        loop {
            self.scanner.skip_separators();
            if self.scanner.read_block_close() || self.scanner.at_eof() {
                return;
            }

            // `env` is a map, written as a nested block rather than a value.
            let Some(key) = self.scanner.read_key() else {
                self.scanner.error("Expected a setting".to_string());
                self.scanner.skip_line();
                continue;
            };

            // A nested server declaration is a sidecar: it shares this server's lifetime.
            if key.text == "service" {
                match self.sidecar(&key, depth) {
                    Some(sidecar) => server.sidecars.push(sidecar),
                    None => continue,
                }
                continue;
            }

            // Settings that govern a lifecycle of one's own. A sidecar has none - it lives and
            // dies with its parent, whose reload rules and timing also cover it - so accepting
            // these would silently mean nothing.
            if depth > 0
                && matches!(
                    key.text.as_str(),
                    "reload_include" | "reload_exclude" | "shutdown_time" | "startup_time"
                )
            {
                self.scanner.error_at(
                    key.pos,
                    format!(
                        "'{}' is not available in a sidecar - a sidecar lives and dies with its \
                         parent, whose reload rules and timing cover it",
                        key.text
                    ),
                );
                self.skip_block();
                continue;
            }
            if key.text == "env" && !self.scanner.read_eq() {
                if !self.expect_block(&key) {
                    continue;
                }
                server.env.extend(self.map_block());
                continue;
            }
            if !self.scanner.read_eq() {
                self.scanner
                    .error_at(key.pos, format!("Expected '{} = ...'", key.text));
                self.scanner.skip_line();
                continue;
            }
            self.server_setting(server, &key);
            self.end_of_setting();
        }
    }

    fn server_setting(&mut self, server: &mut ServerConfig, key: &Word) {
        match key.text.as_str() {
            // Handed to /bin/sh verbatim, so it takes the rest of the line and keeps its quoting.
            "command" => {
                let (line, pos) = (self.scanner.read_rest_of_line(), key.pos);
                server.command = self.expand_line(line, pos);
            }
            "shutdown_time" => {
                if let Some(value) = self.duration_value() {
                    server.shutdown_time = value;
                }
            }
            "startup_time" => {
                if let Some(value) = self.duration_value() {
                    server.startup_time = value;
                }
            }
            "reload_include" => {
                let list = self.word_list();
                server.reload_include.extend(list);
            }
            "reload_exclude" => {
                let list = self.word_list();
                server.reload_exclude.extend(list);
            }

            "base" | "packages" | "build" | "copy" | "mounts" | "port" | "app_dir" | "user" => {
                self.container_setting(server, key)
            }

            other => {
                self.scanner
                    .error_at(key.pos, format!("Unknown setting '{}'", other));
                self.scanner.skip_line();
            }
        }
    }

    fn container_setting(&mut self, server: &mut ServerConfig, key: &Word) {
        // Values are read before re-borrowing the podman config, so the scanner stays free.
        match key.text.as_str() {
            "base" => {
                let value = self.scanner.read_word().map(|w| self.expand(&w));
                if let Some(value) = value {
                    server.base = Some(value);
                }
            }
            "app_dir" => {
                let Some(word) = self.scanner.read_word() else { return };
                let text = self.expand(&word);
                // `none` means the project directory is not mounted at all: the image carries
                // the application itself, so there is nothing of the project to run from.
                server.app_dir = match text.as_str() {
                    "none" => None,
                    path if path.starts_with('/') => Some(text),
                    _ => {
                        self.scanner.error_at(
                            word.pos,
                            format!(
                                "app_dir must be an absolute path, or 'none' to not mount the \
                                 project directory - got '{}'",
                                text
                            ),
                        );
                        return;
                    }
                };
            }
            "packages" => {
                let list = self.word_list();
                server.packages.extend(list);
            }
            "mounts" => {
                let list = self.word_list();
                server.mounts.extend(list);
            }
            "build" => {
                let command = self.scanner.read_rest_of_line();
                let command = self.expand_line(command, key.pos);
                server.build.push(command);
            }
            "copy" => {
                // The build context is the project directory, so a path that climbs out of it
                // would either fail obscurely or reach a file the project does not own. Refused
                // here, and checked again against symlinks when the image is actually built.
                for path in self.word_list() {
                    let escapes = path.starts_with('/')
                        || Path::new(&path).components().any(|c| c.as_os_str() == "..");
                    if escapes {
                        self.scanner.error_at(
                            key.pos,
                            format!(
                                "'{}' is outside the project directory - copy can only take \
                                 paths within it",
                                path
                            ),
                        );
                        continue;
                    }
                    server.copy.push(path);
                }
            }
            "port" => {
                let Some(word) = self.scanner.read_word() else { return };
                let text = self.expand(&word);
                match text.parse::<u16>() {
                    Ok(port) => {
                        server.port = port;
                    }
                    Err(_) => self
                        .scanner
                        .error_at(word.pos, format!("Invalid port '{}'", text)),
                }
            }
            "user" => {
                let Some(word) = self.scanner.read_word() else { return };
                let text = self.expand(&word);
                // Only uid:gid pairs, keywords and image-defined names are meaningful. A bare
                // numeric uid is rejected rather than guessed at: the gid it pairs with depends on
                // the image's /etc/passwd, and everything downstream needs both ids exactly.
                let valid = match text.as_str() {
                    "project" | "image" => true,
                    spec => match spec.split_once(':') {
                        Some((uid, gid)) => uid.parse::<u32>().is_ok() && gid.parse::<u32>().is_ok(),
                        None => !spec.is_empty() && !spec.chars().all(|c| c.is_ascii_digit()),
                    },
                };
                if valid {
                    server.user = text;
                } else {
                    self.scanner.error_at(
                        word.pos,
                        format!(
                            "Invalid user '{}': use 'project', 'image', a numeric 'uid:gid' pair, \
                             or a user name defined in the image",
                            text
                        ),
                    );
                }
            }
            _ => unreachable!("container_setting called with {}", key.text),
        }
    }

    fn finish_server(&mut self, server: &mut ServerConfig) {
        if server.app_dir.is_none() {
            for mount in &server.mounts {
                if !mount.starts_with('/') {
                    self.scanner.error(format!(
                        "mount '{}' is relative, which needs a mounted project directory - use \
                         an absolute container path, or drop 'app_dir = none'",
                        mount
                    ));
                }
            }
        }
        if server.user.is_empty() {
            // Mounting the project directory means webcentral owns the image, and an application
            // writing into the user's own directory has to write as them. A complete third-party
            // image instead knows which user it needs.
            server.user =
                if server.app_dir.is_some() { "project" } else { "image" }.to_string();
        }
    }
}

/// A sidecar that runs in its parent's image is the same application with another command, so it
/// starts from the same environment - anything it sets itself wins. One that names a `base` of its
/// own is a different program entirely and inherits nothing.
fn inherit_into_sidecars(server: &mut ServerConfig) {
    let parent = server.env.clone();
    for sidecar in &mut server.sidecars {
        if sidecar.base.is_some() {
            continue;
        }
        let mut env: Vec<(String, String)> = parent
            .iter()
            .filter(|(key, _)| !sidecar.env.iter().any(|(own, _)| own == key))
            .cloned()
            .collect();
        env.append(&mut sidecar.env);
        sidecar.env = env;
    }
}

fn walk(stmts: &[Stmt], predicate: &mut impl FnMut(&Stmt) -> bool) -> bool {
    for stmt in stmts {
        if predicate(stmt) {
            return true;
        }
        let (body, otherwise) = match stmt {
            Stmt::Match { body, otherwise, .. }
            | Stmt::CheckAuth { body, otherwise, .. }
            | Stmt::CheckFile { body, otherwise, .. } => (Some(body), otherwise),
            _ => (None, &None),
        };
        if let Some(body) = body {
            if walk(body, predicate) {
                return true;
            }
        }
        if let Some(branch) = otherwise {
            if walk(branch, predicate) {
                return true;
            }
        }
    }
    false
}
