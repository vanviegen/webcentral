//! The built-in status page.
//!
//! A project is no longer one thing with a type - it is a script, some services, and their
//! sidecars - so the page is a section per project rather than a row per project. What a reader
//! wants from it is the shape: which services exist, what each is running and whether it is up,
//! what hangs off it, and which part of the script is actually answering the requests.

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
    pub servers: Vec<ServerStatus>,
    pub total_requests: u64,
    /// Statement kind to the number of requests it answered, busiest first.
    pub answers: Vec<(String, u64)>,
    pub cert_status: Option<String>,
    /// The configuration as it was parsed - the file itself, or what was detected in its absence.
    pub source: String,
    /// Where that came from, for the heading above it.
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
        html.push_str(&render_project(domain));
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

fn render_project(domain: &DomainStatus) -> String {
    let mut html = String::new();
    html.push_str("<section class=\"project\">\n");
    html.push_str(&format!("<h2>{}</h2>\n", escape(&domain.domain)));

    // One line of context: where it lives, what its certificate is doing, how busy it has been.
    let (cert_class, cert_text) = match domain.cert_status.as_deref() {
        Some(s) if s.starts_with("Valid") => ("cert-valid", s),
        Some(s) if s.starts_with("Error") || s == "Expired" => ("cert-error", s),
        Some(s) => ("cert-acquiring", s),
        None => ("cert-none", "no certificate"),
    };
    html.push_str(&format!(
        "<div class=\"meta\"><span class=\"dir\">{}</span><span class=\"{}\">{}</span>\
         <span>{} request{}</span></div>\n",
        escape(&domain.directory),
        cert_class,
        escape(cert_text),
        domain.total_requests,
        if domain.total_requests == 1 { "" } else { "s" },
    ));

    for problem in &domain.problems {
        html.push_str(&format!("<div class=\"problem\">{}</div>\n", escape(problem)));
    }

    // Which kind of statement answered, which is the part of the script actually in use.
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

    if domain.servers.is_empty() {
        html.push_str(
            "<div class=\"no-services\">No services: this project is answered from its files and \
             its script alone.</div>\n",
        );
    }
    for server in &domain.servers {
        html.push_str(&render_service(server));
    }

    if !domain.source.trim().is_empty() {
        html.push_str(&format!(
            "<details class=\"config\"><summary>{}</summary><pre>{}</pre></details>\n",
            escape(&domain.source_name),
            escape(domain.source.trim_end())
        ));
    }

    html.push_str("</section>\n");
    html
}

fn render_service(server: &ServerStatus) -> String {
    let state = match (server.state.as_str(), server.port) {
        ("Running", Some(port)) => format!("Running on port {}", port),
        _ => server.state.clone(),
    };
    let mut html = format!(
        "<div class=\"service\">\n<div class=\"service-head\"><span class=\"name\">{}</span>\
         <span class=\"state {}\">{}</span></div>\n",
        escape(&server.name),
        status_class(&server.state),
        escape(&state),
    );
    html.push_str(&format!("<div class=\"runs\">{}</div>\n", describe_run(&server.image, &server.command)));

    // Idle time and websockets are the same question - how long could this be stopped for - so
    // they share a place rather than a column each.
    let idle = if server.active_upgrades > 0 {
        format!(
            "{} websocket{} open",
            server.active_upgrades,
            if server.active_upgrades == 1 { "" } else { "s" }
        )
    } else {
        match server.idle_seconds {
            Some(seconds) => format!("idle {}", format_idle(seconds)),
            None => "not running".to_string(),
        }
    };
    html.push_str(&format!(
        "<div class=\"numbers\"><span>{} request{}</span><span>{} pending</span><span>{}</span></div>\n",
        server.total_requests,
        if server.total_requests == 1 { "" } else { "s" },
        server.pending_requests,
        escape(&idle),
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

/// What a container runs: its image, and the command if it isn't the image's own entrypoint.
fn describe_run(image: &str, command: &str) -> String {
    if command.is_empty() {
        format!("<span class=\"image\">{}</span>", escape(image))
    } else {
        format!(
            "<span class=\"image\">{}</span><code>{}</code>",
            escape(image),
            escape(command)
        )
    }
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
h2 { font-size: 1.25em; margin: 0; }
.project { background: white; border-radius: 6px; padding: 1.2em 1.4em; margin-bottom: 1.2em;
           box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.meta { display: flex; flex-wrap: wrap; gap: 0.4em 1.2em; font-size: 0.85em; color: #777;
        margin-top: 0.3em; }
.meta .dir { font-family: ui-monospace, monospace; }
.answers { margin-top: 0.9em; font-size: 0.85em; color: #666; display: flex; flex-wrap: wrap;
           gap: 0.3em 1.2em; align-items: baseline; }
.answers .label { color: #999; text-transform: uppercase; font-size: 0.85em;
                  letter-spacing: 0.05em; }
.answers b { color: #222; }
.service { margin-top: 1em; padding: 0.7em 0.9em; background: #fafafa; border-radius: 5px;
           border-left: 3px solid #ddd; }
.service-head { display: flex; flex-wrap: wrap; gap: 0.8em; align-items: baseline; }
.service-head .name { font-weight: 600; }
.state { font-size: 0.85em; }
.runs { font-size: 0.85em; color: #666; margin-top: 0.2em; }
.image { color: #888; margin-right: 0.7em; }
code { font-family: ui-monospace, monospace; background: #efefef; padding: 0.05em 0.4em;
       border-radius: 3px; }
.numbers { display: flex; flex-wrap: wrap; gap: 0.3em 1.2em; font-size: 0.8em; color: #888;
           margin-top: 0.35em; }
.sidecar { margin: 0.5em 0 0 1.2em; padding-left: 0.8em; border-left: 2px solid #e0e0e0;
           font-size: 0.85em; color: #666; }
.sidecar .name { font-weight: 600; color: #555; margin-right: 0.7em; }
.sidecar .address { font-family: ui-monospace, monospace; color: #999; margin-left: 0.7em; }
.no-services { margin-top: 0.8em; font-size: 0.85em; color: #888; }
.problem { margin-top: 0.6em; font-size: 0.85em; color: #c22; }
.config { margin-top: 1em; font-size: 0.85em; }
.config summary { cursor: pointer; color: #777; }
.config pre { background: #fafafa; padding: 0.8em 1em; border-radius: 5px; overflow-x: auto;
              margin: 0.6em 0 0 0; font-size: 0.95em; }
.status-running { color: #2a2; }
.status-stopped { color: #888; }
.status-starting { color: #f90; }
.status-failed { color: #c22; }
.cert-valid { color: #2a2; }
.cert-error { color: #c22; }
.cert-acquiring { color: #f90; }
.cert-none { color: #aaa; }
.server-info { display: flex; gap: 1em; flex-wrap: wrap; margin-bottom: 1.5em; }
.info-card { background: white; border-radius: 6px; padding: 0.8em 1.4em;
             box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.info-card h3 { margin: 0; color: #999; font-size: 0.75em; text-transform: uppercase;
                letter-spacing: 0.05em; font-weight: 600; }
.info-card .value { font-size: 1.3em; }
.empty { color: #888; }
@media (prefers-color-scheme: dark) {
  body { background: #16181c; color: #ddd; }
  h1, .sidecar .name { color: #aaa; }
  .project, .info-card { background: #1f2228; box-shadow: none; }
  .service { background: #23262d; border-left-color: #3a3f48; }
  .config pre, code { background: #23262d; }
  .answers b, .info-card .value { color: #eee; }
  .sidecar { border-left-color: #3a3f48; }
}
"#;
