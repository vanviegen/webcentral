mod acme;
mod project_config;
mod logger;
mod project;
mod server;

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::signal;

#[derive(Debug, Clone, Parser)]
#[command(name = "webcentral")]
#[command(about = "A reverse proxy that runs multiple web applications on a single server")]
pub struct GlobalConfig {
    #[arg(long, help = "Email for LetsEncrypt certificate registration")]
    pub email: Option<String>,

    #[arg(long, default_value_t = default_projects(), help = "Projects directory pattern")]
    pub projects: String,

    #[arg(long, default_value_t = default_config(), help = "Certificates and bindings storage directory (defaults to ~/.config/webcentral/)")]
    pub data_dir: String,

    #[arg(long, default_value = "443", help = "HTTPS port (0 to disable)")]
    pub https: u16,

    #[arg(long, default_value = "80", help = "HTTP port (0 to disable)")]
    pub http: u16,

    #[arg(long, value_parser = clap::value_parser!(bool), num_args = 0..=1, default_missing_value = "true", help = "Redirect HTTP to HTTPS")]
    pub redirect_http: Option<bool>,

    #[arg(long, value_parser = clap::value_parser!(bool), num_args = 0..=1, default_value = "true", default_missing_value = "true", help = "Auto-redirect www variants")]
    pub redirect_www: bool,

    #[arg(long, value_parser = clap::value_parser!(bool), num_args = 0..=1, default_value = "true", default_missing_value = "true", help = "Use Firejail sandboxing")]
    pub firejail: bool,

    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory", help = "ACME service endpoint")]
    pub acme_url: String,

    #[arg(long, default_value = "draft-11", help = "ACME protocol version")]
    pub acme_version: String,

    #[arg(long, default_value = "28", help = "Number of days to keep log files (0 to disable)")]
    pub prune_logs: i64,
}

fn default_projects() -> String {
    if nix::unistd::geteuid().is_root() {
        "/home/*/webcentral-projects".to_string()
    } else {
        format!("{}/webcentral-projects", std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
    }
}

fn default_config() -> String {
    if nix::unistd::geteuid().is_root() {
        "/var/lib/webcentral".to_string()
    } else {
        format!("{}/.webcentral", std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
    }
}

impl GlobalConfig {
    pub fn redirect_http(&self) -> bool {
        self.redirect_http.unwrap_or(self.https > 0 && self.http > 0)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = GlobalConfig::parse();

    if config.https > 0 && config.email.is_none() {
        anyhow::bail!("--email is required when HTTPS is enabled");
    }

    // Initialize and start the server
    let server = Arc::new(server::Server::new(config).await?);
    server.clone().start().await?;

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    println!("\nReceived shutdown signal, stopping...");

    server.stop().await;
    server::stop_all_projects().await;

    println!("Shutdown complete");

    Ok(())
}
