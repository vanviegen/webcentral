//! The built-in status page, reachable from a project whose script contains `dashboard`.
//!
//! A project can now run several servers, so the table has a row per server nested under its
//! domain, and domains with none (pure static or proxy projects) get a single summary row.

use crate::project::{body_from, StreamBody};
use anyhow::Result;
use http::Response;

pub struct ServerStatus {
    pub name: String,
    pub kind: String,
    pub state: String,
    pub port: Option<u16>,
    /// What the container runs, shown so the row says which process this is.
    pub command: String,
    pub total_requests: u64,
    pub pending_requests: u64,
    pub active_upgrades: u64,
    pub idle_seconds: Option<u64>,
}

pub struct DomainStatus {
    pub domain: String,
    pub directory: String,
    /// What the project is made of, e.g. "app (alpine), api (node:22)" or "Static".
    pub summary: String,
    pub servers: Vec<ServerStatus>,
    pub total_requests: u64,
    /// Statement kind to the number of requests it answered, busiest first.
    pub answers: Vec<(String, u64)>,
    pub cert_status: Option<String>,
}

/// Render the status page. With a domain in `filter`, only that project's rows and none of the
/// server-wide numbers: that is the `project_dashboard` view, safe to hand to any project owner.
pub fn render(filter: Option<&str>) -> Result<Response<StreamBody>> {
    let mut domains = crate::server::get_domain_status();
    if let Some(domain) = filter {
        domains.retain(|d| d.domain == domain);
    }
    let info = crate::server::get_server_info();

    let mut html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Webcentral Dashboard</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2em; background: #f5f5f5; color: #222; }}
h1 {{ color: #333; }}
h2 {{ color: #555; margin-top: 2em; }}
table {{ border-collapse: collapse; width: 100%; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
th, td {{ border: 1px solid #ddd; padding: 0.6em 1em; text-align: left; }}
th {{ background: #f8f8f8; }}
tr.domain td {{ background: #fafafa; font-weight: 600; }}
tr.server td:first-child {{ padding-left: 2.5em; font-weight: normal; color: #555; }}
tr.answers td {{ padding-left: 2.5em; color: #666; font-size: 0.85em; background: #fcfcfc; }}
tr.answers .answer {{ display: inline-block; margin-right: 1.5em; }}
tr.answers .answer b {{ color: #333; font-weight: 600; }}
.cmd {{ display: block; font-size: 0.8em; color: #888; font-family: ui-monospace, monospace; }}
.status-running {{ color: #2a2; }}
.status-stopped {{ color: #888; }}
.status-starting {{ color: #f90; }}
.status-failed {{ color: #c22; }}
.status-active {{ color: #2a2; }}
.cert-valid {{ color: #2a2; }}
.cert-error {{ color: #c22; }}
.cert-acquiring {{ color: #f90; }}
.server-info {{ display: flex; gap: 2em; margin-bottom: 2em; flex-wrap: wrap; }}
.info-card {{ background: white; padding: 1em 1.5em; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.info-card h3 {{ margin: 0 0 0.5em 0; color: #666; font-size: 0.9em; }}
.info-card .value {{ font-size: 1.5em; color: #333; }}
.num {{ text-align: right; }}
.dir {{ font-size: 0.85em; color: #666; max-width: 300px; overflow: hidden; text-overflow: ellipsis; }}
</style>
</head>
<body>
<h1>Webcentral Dashboard</h1>
"#
    );

    // The server-wide numbers belong to the admin view alone.
    if filter.is_none() {
        html.push_str(&format!(
            r#"<div class="server-info">
<div class="info-card"><h3>Uptime</h3><div class="value">{}</div></div>
<div class="info-card"><h3>Domains</h3><div class="value">{}</div></div>
</div>
"#,
            format_uptime(info.uptime_seconds),
            info.domain_count
        ));
    }

    html.push_str(
        "<table>\n<tr><th>Domain / server</th><th>Type</th><th>Status</th><th>TLS</th>\
         <th>Requests</th><th>Pending</th><th>Idle</th><th>Directory</th></tr>\n",
    );

    for domain in domains {
        let (cert_class, cert_text) = match domain.cert_status.as_deref() {
            Some(s) if s.starts_with("Valid") => ("cert-valid", s),
            Some(s) if s.starts_with("Error") || s == "Expired" => ("cert-error", s),
            Some(s) => ("cert-acquiring", s),
            None => ("", "-"),
        };

        // A project with no servers has nothing to expand, so its own row carries the status.
        let status = if domain.servers.is_empty() { "Active" } else { "" };
        html.push_str(&format!(
            "<tr class=\"domain\"><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td class=\"{}\">{}</td>\
             <td class=\"num\">{}</td><td class=\"num\"></td><td></td><td class=\"dir\" title=\"{}\">{}</td></tr>\n",
            escape(&domain.domain),
            escape(&domain.summary),
            status_class(status),
            status,
            cert_class,
            escape(cert_text),
            domain.total_requests,
            escape(&domain.directory),
            escape(&domain.directory),
        ));

        // What answered the requests, which is the part of the script that is actually in use.
        if !domain.answers.is_empty() {
            let tally: String = domain
                .answers
                .iter()
                .map(|(kind, count)| {
                    format!("<span class=\"answer\">{} <b>{}</b></span>", escape(kind), count)
                })
                .collect();
            html.push_str(&format!(
                "<tr class=\"answers\"><td colspan=\"8\">{}</td></tr>\n",
                tally
            ));
        }

        for server in &domain.servers {
            let state = match (server.state.as_str(), server.port) {
                ("Running", Some(port)) => format!("Running (port {})", port),
                _ => server.state.clone(),
            };
            let idle = if server.active_upgrades > 0 {
                format!("{} websocket{}", server.active_upgrades, if server.active_upgrades == 1 { "" } else { "s" })
            } else {
                server.idle_seconds.map(format_idle).unwrap_or_else(|| "-".to_string())
            };
            html.push_str(&format!(
                "<tr class=\"server\"><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td></td>\
                 <td class=\"num\">{}</td><td class=\"num\">{}</td><td>{}</td><td></td></tr>\n",
                escape(&server.name),
                if server.command.is_empty() {
                    escape(&server.kind)
                } else {
                    format!(
                        "{}<span class=\"cmd\">{}</span>",
                        escape(&server.kind),
                        escape(&server.command)
                    )
                },
                status_class(&server.state),
                escape(&state),
                server.total_requests,
                server.pending_requests,
                escape(&idle),
            ));
        }
    }

    html.push_str("</table>\n</body>\n</html>");

    Ok(Response::builder()
        .status(200)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(body_from(html))?)
}

fn status_class(status: &str) -> &'static str {
    match status {
        "Running" => "status-running",
        "Stopped" => "status-stopped",
        "Starting" => "status-starting",
        "Failed" => "status-failed",
        "Active" => "status-active",
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

/// Domain names and directories come from the filesystem, so they are attacker-influenced on a
/// shared host - the dashboard must not turn a directory name into markup.
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
