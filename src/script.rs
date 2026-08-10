//! The per-request routing script: its statements, capture scoping, and the interpreter.
//!
//! A script is a flat sequence of statements run top to bottom for every request. Statements are
//! either *terminal* (they decide the response and stop the script) or not. Three of them are
//! *conditionals* - `match`, `check_auth` and `check_file` - running their body when they hold and
//! otherwise taking an `else` branch, if one follows, or carrying on. `serve_file` and `serve_dir`
//! answer 404 when they find nothing, unless `fallthrough` leaves the request to the statements
//! below - which is the only way a serve declines, and it is written on the statement itself.
//!
//! Variables are one flat map per request, seeded with the constants the file's top-level `set`
//! statements defined. `match` writes the groups it captured into it, and the request's own
//! `path`, `query`, `method` and `host` are there from the start. The first two *are* the request
//! rather than a copy: assigning one re-points what gets served or forwarded, which is what
//! `set_target` does, and a path may carry its own `?query`. Last write wins; there is no scope to reason about.

use crate::logger::Logger;
use crate::parser::Word;
use crate::project::{body_from, empty_body, StreamBody};
use anyhow::Result;
use http::{HeaderName, HeaderValue, Request, Response};
use http_body_util::combinators::BoxBody;
use regex::Regex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// How a `match` compares: as a regex or as plain text, anchored to the whole value or not. The
/// two axes are separate because naming their four combinations would be worse than saying which
/// of the two things you meant.
#[derive(Debug, Clone)]
pub enum Pattern {
    /// Anchoring is baked into the regex itself, at load time.
    Regex(Regex),
    Literal { text: String, anchored: bool },
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Match {
        /// What is being tested - `$path` unless `subject=` says otherwise. An ordinary argument,
        /// so `subject=$host$path` tests the two joined together.
        subject: Template,
        pattern: Pattern,
        body: Vec<Stmt>,
        otherwise: Option<Vec<Stmt>>,
    },
    /// Assign a variable, for a constant at the top of the file or a value worth naming.
    Set { name: String, value: Template },
    /// `serve_file`, which answers 404 when the file is missing unless `fallthrough` lets the
    /// script carry on to the next statement instead.
    ServeFile { path: Template, fallthrough: bool },
    /// `serve_dir`: the request path is resolved below `dir`.
    ServeDir {
        dir: Template,
        /// File served for a directory; `index=` overrides it.
        index: String,
        fallthrough: bool,
    },
    /// Hand the request to a managed server, starting it if needed.
    ServeApp(String),
    Forward(Template),
    Proxy(Template),
    Redirect { target: Template, status: u16 },
    Respond { status: u16, body: Option<Template>, content_type: String },
    /// Run the body only when the request carries `secret` - as `Authorization: Bearer` or a
    /// `?secret=` query parameter. What follows the statement still runs either way, exactly like
    /// a `match`.
    CheckAuth {
        secret: String,
        body: Vec<Stmt>,
        otherwise: Option<Vec<Stmt>>,
    },
    /// Run the body only when `path` names a file that exists, so headers and other decisions can
    /// be made once, before committing to serve it.
    CheckFile {
        path: Template,
        body: Vec<Stmt>,
        otherwise: Option<Vec<Stmt>>,
    },
    SetHeader(String, Template),
    Log(Template),
    /// The status page: the whole server's for `admin_dashboard`, this project's own slice for
    /// `project_dashboard`.
    Dashboard { admin: bool },
}

impl Stmt {
    pub fn is_fallible(&self) -> bool {
        matches!(self, Stmt::Match { .. } | Stmt::CheckAuth { .. } | Stmt::CheckFile { .. })
    }

    /// Attach an `else` branch. Fails for statements that can never decline, which would make the
    /// branch dead code.
    pub fn set_otherwise(&mut self, branch: Vec<Stmt>) -> bool {
        match self {
            Stmt::Match { otherwise, .. }
            | Stmt::CheckAuth { otherwise, .. }
            | Stmt::CheckFile { otherwise, .. } => *otherwise = Some(branch),
            _ => return false,
        }
        true
    }
}

// --- Templates and variables ---

#[derive(Debug, Clone)]
enum Part {
    Literal(String),
    Variable(String),
}

/// A string with `$name` references resolved when it is used.
#[derive(Debug, Clone)]
pub struct Template(Vec<Part>);

impl Template {
    /// `${name}` is the only substitution there is: `${1}` for a capture group, `${path}` for a
    /// request variable, `${anything}` for a constant. A `$` not followed by `{` is an ordinary
    /// character, so a regex's `$` anchor, a shell's `$PORT` and `$$`, and a price of $5 all pass
    /// through untouched with nothing to escape. A literal `${` is written by single-quoting it.
    pub fn parse(word: &Word) -> Result<Template, String> {
        let mut parts: Vec<Part> = Vec::new();
        let mut literal = String::new();
        let chars: Vec<char> = word.text.chars().collect();
        // Literal spans are recorded in bytes; walk them alongside the characters.
        let mut offset = 0;
        let mut index = 0;

        while index < chars.len() {
            let c = chars[index];
            let at = offset;
            offset += c.len_utf8();
            index += 1;

            if c != '$' || chars.get(index) != Some(&'{') || word.is_literal_at(at) {
                literal.push(c);
                continue;
            }
            offset += 1;
            index += 1;

            let mut name = String::new();
            loop {
                match chars.get(index) {
                    Some('}') => {
                        offset += 1;
                        index += 1;
                        break;
                    }
                    Some(c) => {
                        offset += c.len_utf8();
                        index += 1;
                        name.push(*c);
                    }
                    None => return Err("Unclosed '${'".to_string()),
                }
            }
            if name.is_empty() {
                return Err("Empty '${}' reference".to_string());
            }

            if !literal.is_empty() {
                parts.push(Part::Literal(std::mem::take(&mut literal)));
            }
            parts.push(Part::Variable(name));
        }

        if !literal.is_empty() {
            parts.push(Part::Literal(literal));
        }
        Ok(Template(parts))
    }

    /// The variables this template reads, for reporting names that are never defined anywhere.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.iter().filter_map(|part| match part {
            Part::Variable(name) => Some(name.as_str()),
            Part::Literal(_) => None,
        })
    }

    /// The text of a template that reads no variables, so the parser can check a constant target
    /// once instead of leaving it to fail on every request.
    pub fn as_literal(&self) -> Option<&str> {
        match self.0.as_slice() {
            [] => Some(""),
            [Part::Literal(text)] => Some(text),
            _ => None,
        }
    }

    /// A template with no references, for defaults the parser synthesises.
    pub fn literal(text: &str) -> Template {
        Template(vec![Part::Literal(text.to_string())])
    }

    /// A template that is exactly one variable, for defaults like `match`'s `$path` subject.
    pub fn variable(name: &str) -> Template {
        Template(vec![Part::Variable(name.to_string())])
    }

    pub fn render(&self, vars: &Vars) -> String {
        let mut out = String::new();
        for part in &self.0 {
            match part {
                Part::Literal(text) => out.push_str(text),
                Part::Variable(name) => out.push_str(vars.get(name)),
            }
        }
        out
    }
}

/// The variables a script can read: the constants its top-level `set` statements defined, the
/// request's own (`path`, `query`, `method`, `host`), whatever `match` last captured, and anything
/// `set` has since assigned. One flat map, last write wins - there is no scope to reason about.
#[derive(Debug, Clone, Default)]
pub struct Vars(HashMap<String, String>);

impl Vars {
    pub fn get(&self, name: &str) -> &str {
        self.0.get(name).map(String::as_str).unwrap_or("")
    }

    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0.insert(name.into(), value.into());
    }

    /// Refresh the request's own variables. Called before the script runs and after every
    /// `rewrite`, since `$path` and `$query` describe the request as it stands now.
    fn set_request<B>(&mut self, req: &Request<B>) {
        self.set("path", req.uri().path());
        self.set("query", req.uri().query().unwrap_or(""));
        self.set("method", req.method().as_str());
        // The URI's authority, not the Host header: HTTP/2 and HTTP/3 carry the name in
        // `:authority` and send no Host header at all, and the listener folds the HTTP/1.1 Host
        // header into the URI before the script runs. The header remains as a fallback for the
        // HTTP/3 path, which doesn't rewrite the URI.
        let host = req
            .uri()
            .authority()
            .map(|a| a.as_str())
            .or_else(|| req.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()))
            .unwrap_or("");
        self.set("host", host);
    }

    /// Record what a pattern captured: the numbered groups it has, and any named ones. Groups a
    /// pattern doesn't have keep whatever they held, so a nested `match` that captures nothing
    /// leaves its parent's `$1` in place.
    fn set_captures(&mut self, regex: &Regex, caps: &regex::Captures) {
        for (index, group) in caps.iter().enumerate().skip(1) {
            if let Some(m) = group {
                self.set(index.to_string(), m.as_str());
            }
        }
        for name in regex.capture_names().flatten() {
            if let Some(m) = caps.name(name) {
                self.set(name, m.as_str());
            }
        }
    }
}

// --- Execution ---

/// How the request is ultimately answered. Everything that needs the request body or a live
/// connection is handed back to the caller, so the interpreter never has to own the body.
pub enum Terminal {
    Response(Response<StreamBody>),
    /// Delegate to the named managed server.
    ServeApp(String),
    /// Raw forward to `port`, `host:port` or a unix socket path, keeping the Host header.
    Forward(String),
    /// Reverse proxy to an absolute URL, rewriting Host and adding X-Forwarded-*.
    Proxy(String),
}

pub struct Env<'a> {
    pub dir: &'a Path,
    pub logger: &'a Logger,
    /// The project's own domain (as opposed to `$host`, which is whatever the client asked for).
    pub domain: &'a str,
    /// Whether this project may serve the server-wide dashboard: true when the project belongs
    /// to the user webcentral runs as, since that page shows every user's domains.
    pub admin_allowed: bool,
}

/// The result of a run: what to do, plus response decorations gathered along the way.
pub struct Outcome {
    pub terminal: Terminal,
    pub headers: Vec<(HeaderName, HeaderValue)>,
}

struct Run<'a> {
    env: Env<'a>,
    vars: Vars,
    headers: Vec<(HeaderName, HeaderValue)>,
}

/// Run `script` against `req`, mutating its URI as `rewrite` statements ask.
pub async fn run<B>(script: &[Stmt], env: Env<'_>, vars: Vars, req: &mut Request<B>) -> Result<Outcome> {
    let mut run = Run { env, vars, headers: Vec::new() };
    run.vars.set_request(req);
    let terminal = match run.block(script, req).await? {
        Some(terminal) => terminal,
        None => Terminal::Response(status_response(404, "Not Found")?),
    };
    Ok(Outcome { terminal, headers: run.headers })
}

impl<'a> Run<'a> {
    /// Returns `Some` once a statement decides the response, `None` if the block ran out.
    async fn block<B>(&mut self, stmts: &[Stmt], req: &mut Request<B>) -> Result<Option<Terminal>> {
        for stmt in stmts {
            if let Some(terminal) = Box::pin(self.stmt(stmt, req)).await? {
                return Ok(Some(terminal));
            }
        }
        Ok(None)
    }

    async fn stmt<B>(&mut self, stmt: &Stmt, req: &mut Request<B>) -> Result<Option<Terminal>> {
        match stmt {
            Stmt::Match { subject, pattern, body, otherwise } => {
                let value = subject.render(&self.vars);
                let matched = match pattern {
                    Pattern::Regex(regex) => match regex.captures(&value) {
                        Some(caps) => {
                            self.vars.set_captures(regex, &caps);
                            true
                        }
                        None => false,
                    },
                    Pattern::Literal { text, anchored: true } => &value == text,
                    Pattern::Literal { text, anchored: false } => value.contains(text.as_str()),
                };

                if matched {
                    self.block(body, req).await
                } else {
                    match otherwise {
                        Some(branch) => self.block(branch, req).await,
                        None => Ok(None),
                    }
                }
            }

            Stmt::Set { name, value } => {
                let rendered = value.render(&self.vars);
                // `path`, `query` and `uri` are not copies of the request - they *are* the
                // request, so assigning one changes what gets served or forwarded. Everything
                // else is an ordinary variable.
                match name.as_str() {
                    "path" | "query" => {
                        set_target(req, name, &rendered)?;
                        self.vars.set_request(req);
                    }
                    _ => self.vars.set(name.clone(), rendered),
                }
                Ok(None)
            }

            Stmt::ServeFile { path, fallthrough } => {
                let rendered = path.render(&self.vars);
                let file = match resolve_below(self.env.dir, &rendered) {
                    Some(file) => file,
                    None => return self.not_found(*fallthrough),
                };
                match read_file(&file, req).await? {
                    Some(response) => Ok(Some(Terminal::Response(response))),
                    None => self.not_found(*fallthrough),
                }
            }

            Stmt::ServeDir { dir, index, fallthrough } => {
                let rendered = dir.render(&self.vars);
                let Some(base) = resolve_below(self.env.dir, &rendered) else {
                    return self.not_found(*fallthrough);
                };
                let request_path = req.uri().path().to_string();
                let Some(file) = resolve_request_path(&base, &request_path, index) else {
                    return self.not_found(*fallthrough);
                };

                // A directory reached without a trailing slash is redirected rather than served,
                // so relative links inside its index resolve against the right base.
                if file.is_dir() && !request_path.ends_with('/') {
                    let location = format!("{}/", request_path);
                    return Ok(Some(Terminal::Response(
                        Response::builder().status(301).header("Location", location).body(empty_body())?,
                    )));
                }
                let file = if file.is_dir() { file.join(index) } else { file };

                match read_file(&file, req).await? {
                    Some(response) => Ok(Some(Terminal::Response(response))),
                    None => self.not_found(*fallthrough),
                }
            }

            Stmt::ServeApp(name) => Ok(Some(Terminal::ServeApp(name.clone()))),

            Stmt::Forward(target) => Ok(Some(Terminal::Forward(target.render(&self.vars)))),

            Stmt::Proxy(target) => Ok(Some(Terminal::Proxy(target.render(&self.vars)))),

            Stmt::Redirect { target, status } => {
                let location = target.render(&self.vars);
                Ok(Some(Terminal::Response(
                    Response::builder().status(*status).header("Location", location).body(empty_body())?,
                )))
            }

            Stmt::Respond { status, body, content_type } => {
                let text = match body {
                    Some(template) => template.render(&self.vars),
                    None => default_reason(*status).to_string(),
                };
                Ok(Some(Terminal::Response(
                    Response::builder()
                        .status(*status)
                        .header("Content-Type", content_type.as_str())
                        .body(body_from(text))?,
                )))
            }

            Stmt::CheckAuth { secret, body, otherwise } => {
                if secret_matches(secret, presented_secret(req).as_deref()) {
                    self.block(body, req).await
                } else {
                    match otherwise {
                        Some(branch) => self.block(branch, req).await,
                        None => Ok(None),
                    }
                }
            }

            Stmt::CheckFile { path, body, otherwise } => {
                let rendered = path.render(&self.vars);
                let exists = match resolve_below(self.env.dir, &rendered) {
                    Some(file) => tokio::fs::metadata(&file)
                        .await
                        .map(|meta| meta.is_file())
                        .unwrap_or(false),
                    None => false,
                };
                if exists {
                    self.block(body, req).await
                } else {
                    match otherwise {
                        Some(branch) => self.block(branch, req).await,
                        None => Ok(None),
                    }
                }
            }

            Stmt::SetHeader(name, value) => {
                let rendered = value.render(&self.vars);
                match (HeaderName::try_from(name.as_str()), HeaderValue::from_str(&rendered)) {
                    (Ok(name), Ok(value)) => self.headers.push((name, value)),
                    _ => self
                        .env
                        .logger
                        .write("supervisor", &format!("Ignoring invalid header '{}: {}'", name, rendered)),
                }
                Ok(None)
            }

            Stmt::Log(message) => {
                self.env.logger.write("script", &message.render(&self.vars));
                Ok(None)
            }

            Stmt::Dashboard { admin } => {
                if *admin && !self.env.admin_allowed {
                    return Ok(Some(Terminal::Response(status_response(
                        403,
                        "admin_dashboard is only served for projects owned by the user running webcentral",
                    )?)));
                }
                let filter = if *admin { None } else { Some(self.env.domain) };
                Ok(Some(Terminal::Response(crate::dashboard::render(filter)?)))
            }
        }
    }

    /// Shared tail for the `serve_file`/`serve_dir` pair: carry on with the next statement when
    /// `fallthrough` allows it, and answer 404 otherwise.
    fn not_found(&mut self, fallthrough: bool) -> Result<Option<Terminal>> {
        if fallthrough {
            Ok(None)
        } else {
            Ok(Some(Terminal::Response(status_response(404, "Not Found")?)))
        }
    }
}

// --- Helpers ---

fn status_response(code: u16, text: &str) -> Result<Response<StreamBody>> {
    Ok(Response::builder()
        .status(code)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(body_from(text.to_string()))?)
}

fn default_reason(code: u16) -> &'static str {
    http::StatusCode::from_u16(code)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("")
}

/// What a `Range` header turned out to ask for, once weighed against the file's length.
enum Wanted {
    Whole,
    /// Inclusive byte offsets, as HTTP counts them.
    Part(u64, u64),
    Unsatisfiable,
}

/// Parse a single-range `bytes=` header. A multi-range request is answered whole: assembling a
/// `multipart/byteranges` body is a lot of machinery for something browsers use only for exotic
/// media, and ignoring `Range` altogether is explicitly allowed. Anything unparsable is likewise
/// treated as a request for the whole file rather than an error.
fn parse_range(spec: &str, len: u64) -> Wanted {
    let Some(spec) = spec.trim().strip_prefix("bytes=") else { return Wanted::Whole };
    if spec.contains(',') {
        return Wanted::Whole;
    }
    // Every range over an empty file is unsatisfiable, and saying so here keeps the arithmetic
    // below from having to think about `len - 1`.
    if len == 0 {
        return Wanted::Unsatisfiable;
    }
    let Some((first, last)) = spec.split_once('-') else { return Wanted::Whole };
    let (first, last) = (first.trim(), last.trim());

    if first.is_empty() {
        // `-N`: the final N bytes, clamped to the whole file.
        return match last.parse::<u64>() {
            Ok(0) => Wanted::Unsatisfiable,
            Ok(n) => Wanted::Part(len.saturating_sub(n), len - 1),
            Err(_) => Wanted::Whole,
        };
    }
    let Ok(start) = first.parse::<u64>() else { return Wanted::Whole };
    if start >= len {
        return Wanted::Unsatisfiable;
    }
    let end = if last.is_empty() {
        len - 1
    } else {
        match last.parse::<u64>() {
            Ok(end) => end.min(len - 1),
            Err(_) => return Wanted::Whole,
        }
    };
    if end < start {
        Wanted::Unsatisfiable
    } else {
        Wanted::Part(start, end)
    }
}

/// A cheap validator: length and mtime together change whenever the file does. Enough for
/// `If-Range`, which is what keeps two different versions of a file from being spliced into one
/// resumed download.
fn file_tag(metadata: &std::fs::Metadata) -> Option<String> {
    let mtime = metadata.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(format!("\"{:x}-{:x}\"", metadata.len(), mtime.as_nanos()))
}

async fn read_file<B>(path: &Path, req: &Request<B>) -> Result<Option<Response<StreamBody>>> {
    let Ok(metadata) = tokio::fs::metadata(path).await else {
        return Ok(None);
    };
    if !metadata.is_file() {
        return Ok(None);
    }
    let Ok(mut file) = tokio::fs::File::open(path).await else {
        return Ok(None);
    };

    let len = metadata.len();
    let tag = file_tag(&metadata);

    // A client resuming a download says which version it already has. If that is not the one on
    // disk now, its range means nothing and it gets the whole file instead.
    let current = match (
        req.headers().get(http::header::IF_RANGE).and_then(|v| v.to_str().ok()),
        &tag,
    ) {
        (Some(given), Some(tag)) => given.trim() == tag,
        (Some(_), None) => false,
        (None, _) => true,
    };
    let wanted = match req.headers().get(http::header::RANGE).and_then(|v| v.to_str().ok()) {
        Some(spec) if current => parse_range(spec, len),
        _ => Wanted::Whole,
    };

    let mut response = Response::builder().header(http::header::ACCEPT_RANGES, "bytes");
    if let Some(tag) = &tag {
        response = response.header(http::header::ETAG, tag);
    }

    let (status, start, length) = match wanted {
        Wanted::Whole => (200, 0, len),
        Wanted::Part(start, end) => {
            response = response.header(
                http::header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", start, end, len),
            );
            (206, start, end - start + 1)
        }
        Wanted::Unsatisfiable => {
            return Ok(Some(
                response
                    .status(416)
                    .header(http::header::CONTENT_RANGE, format!("bytes */{}", len))
                    .body(empty_body())?,
            ));
        }
    };

    if start > 0 {
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(start)).await?;
    }
    // Streamed rather than read into memory, so a download only ever costs one chunk of RAM.
    // The Content-Length comes from the metadata; a file that changes size mid-transfer gets a
    // truncated or over-long body, exactly as it would from any static file server.
    use tokio::io::AsyncReadExt;
    use tokio_stream::StreamExt;
    let stream = tokio_util::io::ReaderStream::new(file.take(length))
        .map(|chunk| chunk.map(hyper::body::Frame::data).map_err(anyhow::Error::from));
    let mime = mime_guess::from_path(path).first_or_octet_stream().to_string();
    Ok(Some(
        response
            .status(status)
            .header(http::header::CONTENT_TYPE, mime)
            .header(http::header::CONTENT_LENGTH, length)
            .body(BoxBody::new(http_body_util::StreamBody::new(stream)))?,
    ))
}

/// Resolve a configured, capture-interpolated path below the project directory. Captures come from
/// the request, so a rule like `serve_file images/${1}` must not be able to reach outside.
///
/// Segments are percent-decoded, exactly as `resolve_request_path` decodes the request's own path:
/// a capture is a slice of the raw URI, so `/files/my%20file.txt` has to find `my file.txt` here
/// too. A literal `%` in a configured path is written `%25`.
fn resolve_below(base: &Path, relative: &str) -> Option<PathBuf> {
    let mut resolved = base.to_path_buf();
    for segment in relative.split('/') {
        let segment = percent_encoding::percent_decode_str(segment).decode_utf8().ok()?;
        match segment.as_ref() {
            "" | "." => {}
            ".." => {
                if !resolved.pop() || !resolved.starts_with(base) {
                    return None;
                }
            }
            segment if segment.contains('/') || segment.contains('\0') => return None,
            segment => resolved.push(segment),
        }
    }
    Some(resolved)
}

/// Resolve a request path below `base`, percent-decoding and normalising before the filesystem is
/// touched: `Path::join` doesn't normalise and `Path::starts_with` compares whole components, so
/// `public/../../etc/passwd` would otherwise pass a containment check and be resolved by the kernel
/// on open. Decoding first is what makes `%2e%2e` equivalent to `..`; a segment that decodes to
/// something containing a separator or a NUL is rejected rather than resolved, since it can only
/// have been an attempt to smuggle one past this function.
pub fn resolve_request_path(base: &Path, path: &str, index: &str) -> Option<PathBuf> {
    let mut segments: Vec<String> = Vec::new();
    for segment in path.split('/') {
        let segment = percent_encoding::percent_decode_str(segment).decode_utf8().ok()?;
        match segment.as_ref() {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            segment if segment.contains('/') || segment.contains('\0') => return None,
            segment => segments.push(segment.to_string()),
        }
    }
    let mut resolved = base.to_path_buf();
    resolved.extend(&segments);
    if segments.is_empty() || path.ends_with('/') {
        resolved.push(index);
    }
    Some(resolved)
}

/// Assign one of the request's own variables, which changes the request itself. A path may carry
/// its own `?query`, the way a link does - `set path /x` leaves the query alone, `set path /x?a=b`
/// replaces it, and `set path /x?` drops it. `set query` changes only that.
fn set_target<B>(req: &mut Request<B>, name: &str, value: &str) -> Result<()> {
    let path_and_query = match name {
        "path" => {
            check_target(name, value)?;
            match (value.split_once('?'), req.uri().query()) {
                // A query written into the path replaces whatever was there, empty included.
                (Some(_), _) => value.to_string(),
                (None, Some(query)) => format!("{}?{}", value, query),
                (None, None) => value.to_string(),
            }
        }
        _ => {
            check_target(name, value)?;
            match value.is_empty() {
                true => req.uri().path().to_string(),
                false => format!("{}?{}", req.uri().path(), value),
            }
        }
    };
    let mut parts = req.uri().clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse().map_err(|e| {
        anyhow::anyhow!("'set {} {}' is not a valid request target: {}", name, value, e)
    })?);
    *req.uri_mut() = http::Uri::from_parts(parts)?;
    Ok(())
}

/// A fragment never reaches a server, so one in a target can only be a mistake, and a path has to
/// start at the root to be one at all.
fn check_target(name: &str, value: &str) -> Result<()> {
    if name == "path" && !value.starts_with('/') {
        anyhow::bail!("'set path {}' must start with '/'", value);
    }
    if value.contains('#') {
        anyhow::bail!("'set {} {}' must not contain '#'", name, value);
    }
    Ok(())
}

// --- Authentication ---

/// The secret a request carries, if any: an `Authorization: Bearer` header, or - so a dashboard
/// can be bookmarked - a `secret=` query parameter.
fn presented_secret<B>(req: &Request<B>) -> Option<String> {
    if let Some(value) =
        req.headers().get(http::header::AUTHORIZATION).and_then(|v| v.to_str().ok())
    {
        if let Some(token) = value.strip_prefix("Bearer ") {
            return Some(token.trim().to_string());
        }
    }
    for pair in req.uri().query()?.split('&') {
        if let Some(value) = pair.strip_prefix("secret=") {
            return percent_encoding::percent_decode_str(value)
                .decode_utf8()
                .ok()
                .map(|s| s.into_owned());
        }
    }
    None
}

/// Constant-time comparison, so `==`'s early exit can't leak how much of a guess was right.
/// (The length still shows; that is fine for a secret of decent length.)
fn secret_matches(expected: &str, presented: Option<&str>) -> bool {
    let Some(presented) = presented else { return false };
    expected.len() == presented.len()
        && expected.bytes().zip(presented.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}
