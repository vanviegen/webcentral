//! The built-in status page.
//!
//! A project is no longer one thing with a type - it is a script, some services, and their
//! sidecars - so the page is a section per project rather than a row per project. What a reader
//! wants from it is the shape: which services exist, what each is running and whether it is up,
//! what hangs off it, and which part of the script is actually answering the requests.
//!
//! Everything a project is, is one table of labelled rows - directory, owner, configuration,
//! settings, a row per service, routing - so the eye finds the same thing in the same place on
//! every project, and a row that has nothing to say is left out rather than saying "none". A
//! service's row holds a table of the same shape, and a sidecar's row inside that one holds
//! another, so the nesting on the page is the nesting in the configuration.
//!
//! The admin page lists everyone's projects, so each folds away behind the line that identifies
//! it - domain, certificate, how many of its services are up, request count. A project's own page
//! has one project on it and nothing to fold.

use crate::project::{body_from, StreamBody};
use anyhow::Result;
use http::Response;

/// One service. A sidecar is the same thing nested inside it: everything the page says about a
/// service it can say about a sidecar too, minus the questions that are its parent's to answer.
pub struct ServiceStatus {
    pub name: String,
    /// The image it runs, `Dockerfile` when the project builds its own, or its parent's.
    pub image: String,
    pub command: String,
    /// `None` for a sidecar, which is up exactly when its parent is.
    pub state: Option<String>,
    /// The host port the parent is published on while it is up. Nothing else is published.
    pub host_port: Option<u16>,
    pub pending_requests: u64,
    pub active_upgrades: u64,
    pub idle_seconds: Option<u64>,
    /// The port it listens on inside its container.
    pub port: u16,
    /// `<name>.internal:<port>`, the only way its peers reach it - worth saying, since it has to
    /// be written into the configuration by hand. Only services in a group have one.
    pub address: Option<String>,
    /// Where the project directory is mounted inside, if it is.
    pub app_dir: Option<String>,
    pub user: String,
    pub mounts: Vec<String>,
    pub packages: Vec<String>,
    pub build: Vec<String>,
    pub copy: Vec<String>,
    /// Idle seconds before it is stopped again, 0 being never. Empty for a sidecar.
    pub shutdown_time: Option<u64>,
    pub startup_time: Option<u64>,
    /// What restarts it: each pattern, and whether it came from webcentral's own default set
    /// rather than from the service.
    pub reload_include: Vec<(String, bool)>,
    pub reload_exclude: Vec<(String, bool)>,
    /// What the container is given, values masked - see `mask`.
    pub env: Vec<(String, String)>,
    /// Services nested in this one, sharing its lifetime.
    pub sidecars: Vec<ServiceStatus>,
}

pub struct DomainStatus {
    pub domain: String,
    pub directory: String,
    /// Whether the configuration has been read. Everything below is empty when it hasn't, which
    /// is not the same as a project that has nothing.
    pub loaded: bool,
    pub services: Vec<ServiceStatus>,
    pub total_requests: u64,
    pub cert_status: Option<String>,
    /// The routing script as parsed, which is what actually answers requests - including the
    /// implicit tail, which no file mentions.
    pub script: Vec<crate::script::Outline>,
    /// Where the configuration came from, for the row that names it.
    pub source_name: String,
    /// The other files that reread the whole project when touched, so the page answers "why
    /// didn't my change take" without anyone having to know the rules.
    pub config_files: Vec<String>,
    /// What the project's `settings` block decides, with webcentral's own defaults filled in.
    pub settings: Vec<Setting>,
    /// The request headers the script reads, and so the only ones a request copies.
    pub read_headers: Vec<String>,
    /// Who the directory belongs to, and so who every container of this project runs as.
    pub owner: String,
    /// Anything the configuration was reported for, so a project that is misbehaving says why on
    /// the page its owner is already looking at.
    pub problems: Vec<String>,
}

/// One project-wide setting, shown with its effective value rather than "unset": what a request
/// actually does is the question, and a value that came from a webcentral-wide default is worth
/// marking because changing it is not the project owner's to do.
pub struct Setting {
    pub name: &'static str,
    pub value: String,
    pub explicit: bool,
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
    let mut summary = format!(
        "<span class=\"domain\">{}</span><span class=\"{}\">{}</span>",
        escape(&domain.domain),
        cert_class,
        escape(&cert_text),
    );
    // How much of the project is up, which is the one thing you want to know before deciding to
    // unfold it. Sidecars have no state of their own - they live and die with their parent - so
    // they are not counted.
    if !domain.services.is_empty() {
        let running =
            domain.services.iter().filter(|s| s.state.as_deref() == Some("Running")).count();
        let class = if running == domain.services.len() {
            "running-all"
        } else if running > 0 {
            "running-some"
        } else {
            "running-none"
        };
        summary.push_str(&format!(
            "<span class=\"{}\">{}/{} running</span>",
            class,
            running,
            domain.services.len()
        ));
    }
    summary.push_str(&format!(
        "<span class=\"count\">{} request{}</span>",
        domain.total_requests,
        if domain.total_requests == 1 { "" } else { "s" },
    ));

    let mut html = String::new();
    if collapsible {
        html.push_str(&format!(
            "<details class=\"project\">\n<summary>{}</summary>\n",
            summary
        ));
    } else {
        html.push_str(&format!("<section class=\"project\">\n<div class=\"head\">{}</div>\n", summary));
    }

    html.push_str("<table class=\"detail\">\n<tbody>\n");
    // First, because a project that is broken should not need scrolling past to find out.
    if !domain.problems.is_empty() {
        let problems: String = domain
            .problems
            .iter()
            .map(|p| format!("<div>{}</div>", escape(p)))
            .collect();
        html.push_str(&row("problems", "Problems", &problems));
    }
    html.push_str(&row("", "Directory", &format!("<span class=\"path\">{}</span>", escape(&domain.directory))));
    if !domain.owner.is_empty() {
        html.push_str(&row("", "Owner", &escape(&domain.owner)));
    }

    if !domain.loaded {
        html.push_str(&row("", "Config", "<span class=\"none\">Reading its configuration…</span>"));
        html.push_str("</tbody>\n</table>\n");
        html.push_str(if collapsible { "</details>\n" } else { "</section>\n" });
        return html;
    }

    // The file the configuration came from, and the others that reread the project when touched -
    // an `env_file`, or whatever spoke for a project that has no configuration of its own. The
    // source name is `<file> (detected)` when it was the latter, so it names its own file already.
    let mut files = format!("<span class=\"chip\">{}</span> ", escape(&domain.source_name));
    for file in &domain.config_files {
        if !domain.source_name.starts_with(file.as_str()) {
            files.push_str(&format!("<span class=\"chip\">{}</span> ", escape(file)));
        }
    }
    html.push_str(&row("", "Config", &files));

    if !domain.settings.is_empty() {
        let mut settings = String::from("<table class=\"detail inner\">\n<tbody>\n");
        for setting in &domain.settings {
            settings.push_str(&row(
                "",
                setting.name,
                &format!(
                    "{}{}",
                    escape(&setting.value),
                    if setting.explicit { "" } else { "<span class=\"tag\">default</span>" }
                ),
            ));
        }
        settings.push_str("</tbody>\n</table>\n");
        html.push_str(&row("wide", "Settings", &settings));
    }

    for service in &domain.services {
        html.push_str(&row(
            "wide named",
            &format!("Service <b>{}</b>", escape(&service.name)),
            &render_service(service, &domain.owner),
        ));
    }
    if !domain.script.is_empty() {
        html.push_str(&row("wide", "Routing", &render_statements(&domain.script)));
    }
    if !domain.read_headers.is_empty() {
        let headers: String = domain
            .read_headers
            .iter()
            .map(|name| format!("<span class=\"chip\">{}</span> ", escape(name)))
            .collect();
        html.push_str(&row("", "Reads headers", &headers));
    }
    html.push_str("</tbody>\n</table>\n");

    html.push_str(if collapsible { "</details>\n" } else { "</section>\n" });
    html
}

/// One labelled row of the project table. `class` marks the rows that are styled differently:
/// `problems` for the red one, `wide` for the two whose value is a block rather than a phrase.
fn row(class: &str, label: &str, value: &str) -> String {
    format!("<tr class=\"{}\"><th>{}</th><td>{}</td></tr>\n", class, label, value)
}

/// One service, as a table of the same shape as the project's own: a labelled row per thing worth
/// knowing, and a row left out entirely when this service has nothing to say for it. `owner` is
/// what `user = project` resolves to, which is a name rather than the word "project".
fn render_service(service: &ServiceStatus, owner: &str) -> String {
    let mut html = String::from("<table class=\"detail inner\">\n<tbody>\n");
    let mut add = |label: &str, value: String| {
        if !value.is_empty() {
            html.push_str(&row("", label, &value));
        }
    };

    add("Image", format!("<span class=\"mono\">{}</span>", escape(&service.image)));
    add("Command", command_cell(&service.command));

    if let Some(state) = &service.state {
        // Only what is worth reading: a service with nothing pending and no websockets says so by
        // saying nothing rather than by a row of zeroes.
        let mut notes = Vec::new();
        if service.pending_requests > 0 {
            notes.push(format!("{} pending", service.pending_requests));
        }
        add(
            "State",
            format!("<span class=\"{}\">{}</span>{}", status_class(state), escape(state), note(&notes)),
        );
    }

    // One row for the port, since the two or three numbers around it are the same question asked
    // from inside the container, from the host, and from a peer - and reading them apart is how
    // "why can't I reach it" starts.
    let mut reached = Vec::new();
    if let Some(port) = service.host_port {
        reached.push(format!("from the host at 127.0.0.1:{}", port));
    }
    if let Some(address) = &service.address {
        reached.push(format!("by its peers at {}", address));
    }
    add(
        "Port",
        format!(
            "<span class=\"mono\">{}</span><span class=\"sub\">inside the container{}</span>",
            service.port,
            if reached.is_empty() {
                String::new()
            } else {
                format!("; reached {}", reached.join(", "))
            }
        ),
    );

    add(
        "Project dir",
        match &service.app_dir {
            Some(dir) => format!("<span class=\"mono\">{}</span>", escape(dir)),
            None => "<span class=\"none\">not mounted</span>".to_string(),
        },
    );
    // `project` and `image` say who *decides*, not who it is; the page answers the question
    // instead, since "runs as image" is not a user anybody has.
    add(
        "Runs as",
        match service.user.as_str() {
            "project" => format!("{}<span class=\"sub\">the project's owner</span>", escape(owner)),
            "image" => "<span class=\"none\">whoever the image declares</span>".to_string(),
            other => escape(other),
        },
    );
    add("Persists", chips(&service.mounts));
    add("Packages", chips(&service.packages));
    add("Builds with", commands(&service.build));
    add("Copies in", chips(&service.copy));
    add(
        "Stops when idle",
        match service.shutdown_time {
            Some(0) => "<span class=\"none\">never</span>".to_string(),
            // Idle time counts towards exactly this timeout, so it belongs here rather than next
            // to the state - as does an open websocket, which is what stops the count entirely.
            Some(seconds) => {
                let mut why = Vec::new();
                if service.state.as_deref() == Some("Running") {
                    if service.active_upgrades > 0 {
                        why.push(format!(
                            "{} websocket{} open, so not counting",
                            service.active_upgrades,
                            if service.active_upgrades == 1 { "" } else { "s" }
                        ));
                    } else if let Some(idle) = service.idle_seconds {
                        why.push(format!("idle {}", format_idle(idle)));
                    }
                }
                format!("{}{}", escape(&format_idle(seconds)), note(&why))
            }
            None => String::new(),
        },
    );
    add(
        "Start times out",
        service.startup_time.map_or(String::new(), |t| escape(&format_idle(t))),
    );
    add("Restart includes", watched(&service.reload_include));
    add("Restart excludes", watched(&service.reload_exclude));
    add(
        "Environment",
        service
            .env
            .iter()
            .map(|(name, value)| {
                format!("<span class=\"var\"><b>{}</b>={}</span>", escape(name), escape(value))
            })
            .collect(),
    );

    // A sidecar is the same table again, minus the questions its parent answers for it.
    for sidecar in &service.sidecars {
        html.push_str(&row(
            "wide named",
            &format!("Sidecar <b>{}</b>", escape(&sidecar.name)),
            &render_service(sidecar, owner),
        ));
    }

    html.push_str("</tbody>\n</table>\n");
    html
}

/// A list of short literal values - patterns, package names, paths - as one wrapping run. The
/// space between them is written out: adjacent spans give a line nowhere to break, so a long list
/// would run off the side rather than wrap.
fn chips(values: &[String]) -> String {
    values.iter().map(|v| format!("<span class=\"chip\">{}</span> ", escape(v))).collect()
}

/// Reload patterns, with one `default` tag after each run of webcentral's own rather than one per
/// pattern - they arrive in a block, and forty tags would say the same thing forty times.
fn watched(patterns: &[(String, bool)]) -> String {
    let mut html = String::new();
    for (index, (pattern, default)) in patterns.iter().enumerate() {
        html.push_str(&format!("<span class=\"chip\">{}</span> ", escape(pattern)));
        if *default && !matches!(patterns.get(index + 1), Some((_, true))) {
            html.push_str("<span class=\"tag\">default</span> ");
        }
    }
    html
}

fn commands(values: &[String]) -> String {
    values.iter().map(|v| format!("<code>{}</code>", escape(v))).collect()
}

/// What qualifies a row's answer without competing with it.
fn note(notes: &[String]) -> String {
    if notes.is_empty() {
        return String::new();
    }
    format!("<span class=\"sub\">{}</span>", escape(&notes.join(" · ")))
}

/// The command a container runs - or, when it runs the image's own, that said in words rather
/// than by an empty cell, since "nothing was configured" and "nothing runs" look the same.
fn command_cell(command: &str) -> String {
    if command.is_empty() {
        "<span class=\"none\">entrypoint</span>".to_string()
    } else {
        format!("<code>{}</code>", escape(command))
    }
}

/// The script as a nested list, so what a conditional covers is visible from the shape rather
/// than from counting braces, each statement carrying how many requests reached it.
fn render_statements(stmts: &[crate::script::Outline]) -> String {
    let mut html = String::from("<ul class=\"stmts\">\n");
    for stmt in stmts {
        html.push_str("<li>");
        html.push_str(&format!("<span class=\"verb\">{}</span>", escape(stmt.verb)));
        for arg in &stmt.args {
            html.push_str(&format!("<span class=\"arg\">{}</span>", escape(arg)));
        }
        if stmt.implicit {
            html.push_str("<span class=\"tag\">implicit</span>");
        }
        // How often the statement ran. Zero is worth seeing - a rule that never fires is usually
        // a rule in the wrong place - and a conditional's own count next to its body's says how
        // often it held.
        html.push_str(&format!("<span class=\"ran\">{}</span>", stmt.count));
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
/* A flex summary has no disclosure marker of its own in any browser, so it gets one. */
.project > summary { cursor: pointer; list-style: none; }
.project > summary::-webkit-details-marker { display: none; }
.project > summary::before { content: "▸"; color: #bbb; margin-right: -0.6em; }
.project[open] > summary::before { content: "▾"; }
.domain { font-size: 1.1em; font-weight: 600; }
.count { color: #999; font-size: 0.85em; margin-left: auto; }
.running-all { color: #2a2; font-size: 0.85em; }
.running-some { color: #d80; font-size: 0.85em; }
.running-none { font-size: 0.85em; }

/* Everything the project is - and everything each of its services is - one labelled row at a
   time. The child combinators keep each table's rules off the tables nested inside its rows. */
.detail { border-collapse: collapse; width: 100%; margin-top: 0.7em; table-layout: fixed; }
/* Wide enough for the longest label, so every project's values start at the same place - and
   wrapping rather than overrunning its column if a longer one ever turns up. */
.detail > tbody > tr > th { width: 9em; text-align: left;
                    vertical-align: baseline; padding: 0.35em 1.2em 0.35em 0; font-size: 0.75em;
                    font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em;
                    color: #aaa; }
.detail > tbody > tr > td { vertical-align: baseline; padding: 0.35em 0; }
/* The rows whose value is a block rather than a phrase, and so needs the room. */
.detail > tbody > tr.wide > th { padding-top: 0.6em; }
.detail > tbody > tr.wide > td { padding: 0.5em 0; }
.detail > tbody > tr.problems > td { color: #c22; font-size: 0.9em; }
/* A service's own name is a name, not a label: it keeps its case and its weight. */
.detail > tbody > tr.named > th { white-space: normal; }
.detail > tbody > tr.named > th b { display: block; text-transform: none; letter-spacing: 0;
                                    font-size: 1.25em; color: #555; margin-top: 0.1em; }
/* A service's labels are the long ones (`Restart excludes`), so its table gives them more room
   than the project's own. */
.detail.inner { margin: 0; border-top: 1px solid #eee; }
.detail.inner > tbody > tr > th { width: 10.5em; }
.detail.inner > tbody > tr:first-child > * { padding-top: 0.5em; }
/* Values are all one thing, whatever they are about: what varies is the label beside them, not
   the type. The only two departures are a note *under* a value and the absence of one, which are
   different kinds of content rather than differently important values of the same kind. */
.sub { display: block; font-size: 0.8em; color: #aaa; font-style: normal; }
.none { color: #aaa; font-style: italic; }
/* One monospace treatment, for everything that is a literal: a path, a pattern, a package name,
   a value out of an env file. The size correction is what keeps it level with the text. */
.mono, .path, .chip, .var, code { font-family: ui-monospace, monospace; font-size: 0.92em; }
.path { word-break: break-all; }
/* The gap is a real space in the markup - see `chips` - so this only widens it. A pattern never
   breaks in half: `*.[cm]?js` is one thing, and half of it is a different pattern. */
.chip { margin-right: 0.5em; white-space: nowrap; }
.tag { font-size: 0.7em; text-transform: uppercase; letter-spacing: 0.05em; color: #999;
       background: #ececec; border-radius: 3px; padding: 0.1em 0.4em; margin-left: 0.6em;
       vertical-align: 0.1em; }
code { background: #efefef; padding: 0.05em 0.4em; border-radius: 3px; word-break: break-word;
       margin-right: 0.4em; }
/* One variable per line, never broken across two: values are masked and so short, and a name
   split in half reads as a different name. */
.var { display: block; white-space: nowrap; }
.var b { font-weight: 600; }

/* The script, nested as it is written. */
.stmts { list-style: none; margin: 0; padding: 0; font-size: 0.85em; }
/* Nesting is shown by the rule down the left, not by shrinking: a rule three deep is no less
   worth reading than one at the top. */
.stmts .stmts { margin: 0.2em 0 0.2em 0.5em; padding-left: 0.9em; border-left: 2px solid #e3e3e3;
                font-size: 1em; }
.stmts li { padding: 0.1em 0; }
/* How often the statement ran, out at the right where the eye can run down the column. */
.stmts .ran { float: right; color: #bbb; font-variant-numeric: tabular-nums; margin-left: 1em; }
.stmts .verb { font-family: ui-monospace, monospace; font-weight: 600; color: #456; }
.stmts .arg { font-family: ui-monospace, monospace; color: #888; margin-left: 0.6em;
              word-break: break-word; }
.otherwise { margin-top: 0.2em; }
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
.info-card h3 { margin: 0; color: #aaa; font-size: 0.75em; font-weight: 600;
                text-transform: uppercase; letter-spacing: 0.06em; }
.info-card .value { font-size: 1.3em; }
.empty { color: #999; }

@media (prefers-color-scheme: dark) {
  body { background: #16181c; color: #ddd; }
  h1 { color: #aaa; }
  .project, .info-card { background: #1f2228; box-shadow: none; }
  code, .tag { background: #2a2e36; }
  .stmts .verb { color: #8fb8d8; }
  .stmts .stmts { border-left-color: #3a3f48; }
  .detail.inner { border-top-color: #2b2f36; }
  .detail > tbody > tr.named > th b { color: #bbb; }
  .info-card .value { color: #eee; }
}
"#;
