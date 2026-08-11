//! The built-in status page.
//!
//! A project is no longer one thing with a type - it is a script, some services, and their
//! sidecars - so the page is a section per project rather than a row per project. What a reader
//! wants from it is the shape: which services exist, what each is running and whether it is up,
//! what hangs off it, and which part of the script is actually answering the requests.
//!
//! The admin page lists everyone's projects, so each folds away behind the line that identifies
//! it - domain, certificate, request count. A project's own page has one project on it and
//! nothing to fold.

use crate::project::{body_from, StreamBody};
use anyhow::Result;
use http::Response;

/// A service running inside a container, with the numbers that belong to it rather than to the
/// project as a whole.
pub struct ServerStatus {
    pub name: String,
    /// The image it runs, or `Dockerfile` when the project builds its own.
    pub image: String,
    pub command: String,
    pub state: String,
    pub port: Option<u16>,
    pub total_requests: u64,
    pub pending_requests: u64,
    pub active_upgrades: u64,
    pub idle_seconds: Option<u64>,
    /// Services nested inside this one, which share its lifetime and have no state of their own.
    pub sidecars: Vec<SidecarStatus>,
}

pub struct SidecarStatus {
    pub name: String,
    pub image: String,
    pub command: String,
    /// The port it listens on inside the group's network. Nothing is published to the host, so
    /// `<name>.internal:<port>` is the only way its peers reach it - which is worth saying, since
    /// it has to be written into the configuration by hand.
    pub port: u16,
}

pub struct DomainStatus {
    pub domain: String,
    pub directory: String,
    /// Whether the configuration has been read. Everything below is empty when it hasn't, which
    /// is not the same as a project that has nothing.
    pub loaded: bool,
    pub servers: Vec<ServerStatus>,
    pub total_requests: u64,
    /// Statement kind to the number of requests it answered, busiest first.
    pub answers: Vec<(String, u64)>,
    pub cert_status: Option<String>,
    /// The routing script as parsed, which is what actually answers requests - including the
    /// implicit tail, which no file mentions.
    pub script: Vec<crate::script::Outline>,
    /// Where the configuration came from, for the heading above it.
    pub source_name: String,
    /// Anything the configuration was reported for, so a project that is misbehaving says why on
    /// the page its owner is already looking at.
    pub problems: Vec<String>,
}

/// Render the status page. With a domain in `filter`, only that project and none of the
/// server-wide numbers: that is the `project_dashboard` view, safe to hand to any project owner.
pub fn render(filter: Option<&str>) -> Result<Response<StreamBody>> {
    let mut domains = crate::server::get_domain_status();
    if let Some(domain) = filter {
        domains.retain(|d| d.domain == domain);
    }
    let info = crate::server::get_server_info();

    let mut html = format!("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>Webcentral Dashboard</title>\n<style>\n{}</style>\n</head>\n<body>\n<h1>Webcentral</h1>\n",
        STYLE);

    // The server-wide numbers belong to the admin view alone.
    if filter.is_none() {
        html.push_str(&format!(
            "<div class=\"server-info\">\
             <div class=\"info-card\"><h3>Uptime</h3><div class=\"value\">{}</div></div>\
             <div class=\"info-card\"><h3>Domains</h3><div class=\"value\">{}</div></div>\
             </div>\n",
            format_uptime(info.uptime_seconds),
            info.domain_count
        ));
    }

    for domain in &domains {
        html.push_str(&render_project(domain, filter.is_none()));
    }
    if domains.is_empty() {
        html.push_str("<p class=\"empty\">No projects.</p>\n");
    }

    html.push_str("</body>\n</html>");

    Ok(Response::builder()
        .status(200)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(body_from(html))?)
}

fn render_project(domain: &DomainStatus, collapsible: bool) -> String {
    let (cert_class, cert_text) = match domain.cert_status.as_deref() {
        Some(s) if s.starts_with("Valid") => ("cert-valid", format!("TLS {}", s.to_lowercase())),
        Some(s) if s.starts_with("Error") || s == "Expired" => {
            ("cert-error", format!("TLS {}", s.to_lowercase()))
        }
        Some(s) => ("cert-acquiring", format!("TLS {}", s.to_lowercase())),
        None => ("cert-none", "no TLS".to_string()),
    };
    // The line that identifies the project, and - on the admin page, which lists everyone's - the
    // line you fold the rest away behind.
    let summary = format!(
        "<span class=\"domain\">{}</span><span class=\"{}\">{}</span>\
         <span class=\"count\">{} request{}</span>",
        escape(&domain.domain),
        cert_class,
        escape(&cert_text),
        domain.total_requests,
        if domain.total_requests == 1 { "" } else { "s" },
    );

    let mut html = String::new();
    if collapsible {
        html.push_str(&format!(
            "<details class=\"project\">\n<summary>{}</summary>\n",
            summary
        ));
    } else {
        html.push_str(&format!("<section class=\"project\">\n<div class=\"head\">{}</div>\n", summary));
    }

    html.push_str(&format!("<div class=\"dir\">{}</div>\n", escape(&domain.directory)));
    for problem in &domain.problems {
        html.push_str(&format!("<div class=\"problem\">{}</div>\n", escape(problem)));
    }

    html.push_str("<h3>Services</h3>\n");
    if !domain.loaded {
        html.push_str("<div class=\"none\">Reading its configuration…</div>\n");
    } else if domain.servers.is_empty() {
        html.push_str("<div class=\"none\">None</div>\n");
    }
    for server in &domain.servers {
        html.push_str(&render_service(server));
    }
    if !domain.script.is_empty() {
        html.push_str(&format!(
            "<h3>Routing <span class=\"from\">{}</span></h3>\n",
            escape(&domain.source_name)
        ));
        html.push_str(&render_statements(&domain.script));
        if !domain.answers.is_empty() {
            html.push_str("<div class=\"answers\"><span class=\"label\">Answered by</span>");
            for (kind, count) in &domain.answers {
                html.push_str(&format!(
                    "<span class=\"answer\">{} <b>{}</b></span>",
                    escape(kind),
                    count
                ));
            }
            html.push_str("</div>\n");
        }
    }

    html.push_str(if collapsible { "</details>\n" } else { "</section>\n" });
    html
}

fn render_service(server: &ServerStatus) -> String {
    let state = match (server.state.as_str(), server.port) {
        ("Running", Some(port)) => format!("Running on port {}", port),
        _ => server.state.clone(),
    };
    let mut html = format!(
        "<div class=\"service\">\n<div class=\"service-head\"><span class=\"name\">{}</span>\
         {}<span class=\"state {}\">{}</span></div>\n",
        escape(&server.name),
        describe_run(&server.image, &server.command),
        status_class(&server.state),
        escape(&state),
    );

    // Only what is worth reading: a service with nothing pending, no websockets and no idle time
    // to report says so by saying nothing, rather than by three zeroes.
    let mut numbers = vec![format!(
        "{} request{}",
        server.total_requests,
        if server.total_requests == 1 { "" } else { "s" }
    )];
    if server.pending_requests > 0 {
        numbers.push(format!("{} pending", server.pending_requests));
    }
    if server.active_upgrades > 0 {
        numbers.push(format!(
            "{} websocket{} open",
            server.active_upgrades,
            if server.active_upgrades == 1 { "" } else { "s" }
        ));
    } else if let Some(seconds) = server.idle_seconds {
        numbers.push(format!("idle {}", format_idle(seconds)));
    }
    html.push_str(&format!(
        "<div class=\"numbers\">{}</div>\n",
        numbers
            .iter()
            .map(|n| format!("<span>{}</span>", escape(n)))
            .collect::<String>()
    ));

    for sidecar in &server.sidecars {
        html.push_str(&format!(
            "<div class=\"sidecar\"><span class=\"name\">{}</span>{}             <span class=\"address\">{}.internal:{}</span></div>\n",
            escape(&sidecar.name),
            describe_run(&sidecar.image, &sidecar.command),
            escape(&sidecar.name),
            sidecar.port,
        ));
    }

    html.push_str("</div>\n");
    html
}

/// The script as a nested list, so what a conditional covers is visible from the shape rather
/// than from counting braces.
fn render_statements(stmts: &[crate::script::Outline]) -> String {
    let mut html = String::from("<ul class=\"stmts\">\n");
    for stmt in stmts {
        html.push_str(if stmt.implicit { "<li class=\"implicit\">" } else { "<li>" });
        html.push_str(&format!("<span class=\"verb\">{}</span>", escape(stmt.verb)));
        for arg in &stmt.args {
            html.push_str(&format!("<span class=\"arg\">{}</span>", escape(arg)));
        }
        if !stmt.body.is_empty() {
            html.push_str(&render_statements(&stmt.body));
        }
        if let Some(otherwise) = &stmt.otherwise {
            html.push_str("<div class=\"otherwise\"><span class=\"verb\">else</span></div>");
            html.push_str(&render_statements(otherwise));
        }
        html.push_str("</li>\n");
    }
    html.push_str("</ul>\n");
    html
}

/// What a container runs: its image, and the command if it isn't the image's own entrypoint.
fn describe_run(image: &str, command: &str) -> String {
    let mut html = format!("<span class=\"image\">{}</span>", escape(image));
    if !command.is_empty() {
        html.push_str(&format!("<code>{}</code>", escape(command)));
    }
    html
}

fn status_class(status: &str) -> &'static str {
    match status {
        "Running" => "status-running",
        "Stopped" => "status-stopped",
        "Starting" => "status-starting",
        "Failed" => "status-failed",
        _ => "",
    }
}

fn format_uptime(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else if seconds < 86400 {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    } else {
        format!("{}d {}h", seconds / 86400, (seconds % 86400) / 3600)
    }
}

fn format_idle(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else {
        format!("{}h", seconds / 3600)
    }
}

/// Domain names, directories and configuration all come from the filesystem, so they are
/// attacker-influenced on a shared host - the dashboard must not turn any of them into markup.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

const STYLE: &str = r#"
:root { color-scheme: light dark; }
body { font-family: system-ui, sans-serif; margin: 0 auto; padding: 2em 1.5em; max-width: 60em;
       background: #f5f5f5; color: #222; line-height: 1.5; }
h1 { font-size: 1.4em; color: #555; font-weight: 600; margin: 0 0 1em 0; }

/* A project: its identifying line, and everything else under it. */
.project { background: white; border-radius: 6px; padding: 1em 1.3em; margin-bottom: 0.8em;
           box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.project > summary, .project > .head { display: flex; flex-wrap: wrap; gap: 0.5em 1.2em;
                                       align-items: baseline; }
.project > summary { cursor: pointer; }
.project > summary::marker { color: #bbb; }
.domain { font-size: 1.1em; font-weight: 600; }
.count { color: #999; font-size: 0.85em; margin-left: auto; }
.dir { font-family: ui-monospace, monospace; font-size: 0.8em; color: #aaa; margin-top: 0.2em;
       word-break: break-all; }

/* Section headings inside a project, for Services and Routing alike. */
h3 { font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.06em; color: #aaa;
     font-weight: 600; margin: 1.4em 0 0.5em 0; }
h3 .from { text-transform: none; letter-spacing: 0; font-family: ui-monospace, monospace;
           margin-left: 0.6em; color: #bbb; }
.none { color: #999; font-size: 0.9em; }

/* One service, or one thing the script routes to. */
.service { padding: 0.55em 0.8em; margin-bottom: 0.4em; background: #fafafa; border-radius: 5px;
           border-left: 3px solid #d8d8d8; }
.service-head { display: flex; flex-wrap: wrap; gap: 0.2em 0.7em; align-items: baseline; }
.service-head .name { font-weight: 600; }
.state { font-size: 0.85em; margin-left: auto; }
.image { color: #999; font-size: 0.85em; }
code { font-family: ui-monospace, monospace; background: #efefef; padding: 0.05em 0.4em;
       border-radius: 3px; font-size: 0.85em; }
.numbers { display: flex; flex-wrap: wrap; gap: 0.3em 1.2em; font-size: 0.8em; color: #999;
           margin-top: 0.3em; }
.sidecar { margin: 0.45em 0 0 1em; padding-left: 0.8em; border-left: 2px solid #e0e0e0;
           font-size: 0.85em; color: #666; }
.sidecar .name { font-weight: 600; color: #555; margin-right: 0.7em; }
.sidecar .address { font-family: ui-monospace, monospace; color: #aaa; margin-left: 0.7em; }

/* The script, nested as it is written. */
.stmts { list-style: none; margin: 0; padding: 0; font-size: 0.85em; }
.stmts .stmts { margin: 0.2em 0 0.2em 0.5em; padding-left: 0.9em; border-left: 2px solid #e3e3e3; }
.stmts li { padding: 0.1em 0; }
.stmts .verb { font-family: ui-monospace, monospace; font-weight: 600; color: #456; }
.stmts .arg { font-family: ui-monospace, monospace; color: #888; margin-left: 0.6em;
              word-break: break-word; }
.otherwise { margin-top: 0.2em; }
.stmts .implicit { opacity: 0.6; }
.stmts .implicit::after { content: " implicit"; font-size: 0.85em; color: #bbb;
                          margin-left: 0.6em; }
.answers { margin-top: 0.8em; font-size: 0.8em; color: #888; display: flex; flex-wrap: wrap;
           gap: 0.3em 1.2em; align-items: baseline; }
.answers .label { color: #bbb; text-transform: uppercase; font-size: 0.9em;
                  letter-spacing: 0.05em; }
.answers b { color: #444; }

.problem { margin-top: 0.5em; font-size: 0.85em; color: #c22; }
.status-running { color: #2a2; }
.status-stopped { color: #999; }
.status-starting { color: #f90; }
.status-failed { color: #c22; }
.cert-valid { color: #2a2; font-size: 0.85em; }
.cert-error { color: #c22; font-size: 0.85em; }
.cert-acquiring { color: #f90; font-size: 0.85em; }
.cert-none { color: #bbb; font-size: 0.85em; }
.server-info { display: flex; gap: 1em; flex-wrap: wrap; margin-bottom: 1.5em; }
.info-card { background: white; border-radius: 6px; padding: 0.8em 1.4em;
             box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.info-card h3 { margin: 0; color: #aaa; }
.info-card .value { font-size: 1.3em; }
.empty { color: #999; }

@media (prefers-color-scheme: dark) {
  body { background: #16181c; color: #ddd; }
  h1, .sidecar .name { color: #aaa; }
  .project, .info-card { background: #1f2228; box-shadow: none; }
  .service { background: #23262d; border-left-color: #3a3f48; }
  code { background: #23262d; }
  .stmts .verb { color: #8fb8d8; }
  .stmts .stmts, .sidecar { border-left-color: #3a3f48; }
  .answers b, .info-card .value { color: #eee; }
}
"#;
