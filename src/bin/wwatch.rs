// wwatch - A file watcher CLI tool
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "wwatch")]
#[command(author = "WebCentral")]
#[command(version = "1.0")]
#[command(about = "Watch files and directories for changes", long_about = None)]
struct Args {
    /// Directory to watch
    #[arg(value_name = "PATH")]
    path: PathBuf,

    /// Include patterns (glob-style)
    #[arg(short = 'i', long = "include", value_name = "PATTERN")]
    includes: Vec<String>,

    /// Exclude patterns (glob-style)
    #[arg(short = 'e', long = "exclude", value_name = "PATTERN")]
    excludes: Vec<String>,

    /// Watch for file/directory creation events
    #[arg(long = "create", default_value = "true", action = clap::ArgAction::Set)]
    watch_create: bool,

    /// Watch for file/directory deletion events
    #[arg(long = "delete", default_value = "true", action = clap::ArgAction::Set)]
    watch_delete: bool,

    /// Watch for file modification events
    #[arg(long = "modify", default_value = "true", action = clap::ArgAction::Set)]
    watch_modify: bool,

    /// Match regular files
    #[arg(long = "files", default_value = "true", action = clap::ArgAction::Set)]
    match_files: bool,

    /// Match directories
    #[arg(long = "dirs", default_value = "true", action = clap::ArgAction::Set)]
    match_dirs: bool,

    /// Output format: 'default' (CREATE/DELETE/UPDATE + path), 'path' (path only), 'silent' (no output)
    #[arg(short = 'f', long = "format", value_name = "FORMAT", default_value = "default")]
    format: String,

    /// Exit on first change detected
    #[arg(short = 'x', long = "exit")]
    exit_on_first: bool,

    /// Combine changes with debouncing (outputs "CHANGES" after quiet period)
    #[arg(short = 'c', long = "combine", value_name = "MS")]
    combine: Option<u64>,

    /// Quiet mode (suppress initial status messages)
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum OutputFormat {
    Default,  // CREATE/DELETE/UPDATE + path
    Path,     // path only
    Silent,   // no output
}

impl OutputFormat {
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "default" => Ok(OutputFormat::Default),
            "path" => Ok(OutputFormat::Path),
            "silent" => Ok(OutputFormat::Silent),
            _ => Err(format!("Invalid format '{}'. Valid options: default, path, silent", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum EventType {
    Create,
    Delete,
    Update,
}

impl EventType {
    fn as_str(&self) -> &'static str {
        match self {
            EventType::Create => "CREATE",
            EventType::Delete => "DELETE",
            EventType::Update => "UPDATE",
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Validate format
    let format = OutputFormat::from_str(&args.format)
        .map_err(|e| anyhow::anyhow!(e))?;

    // If format is silent, imply exit-on-first-change
    let exit_on_first = args.exit_on_first || format == OutputFormat::Silent;

    // If no includes specified, watch everything
    let includes = if args.includes.is_empty() {
        vec!["**/*".to_string()]
    } else {
        args.includes
    };

    // Print initial status unless quiet
    if !args.quiet {
        eprintln!("Watching: {}", args.path.display());
        eprintln!("Includes: {:?}", includes);
        if !args.excludes.is_empty() {
            eprintln!("Excludes: {:?}", args.excludes);
        }
        eprintln!("Format: {:?}", format);
        if exit_on_first {
            eprintln!("Exit on first change: enabled");
        }
        if let Some(ms) = args.combine {
            eprintln!("Combine mode: {}ms debounce", ms);
        }
        eprintln!("---");
    }

    // Build the watcher
    let builder = webcentral::file_watcher::WatchBuilder::new()
        .set_base_dir(&args.path)
        .add_includes(includes)
        .add_excludes(args.excludes)
        .watch_create(args.watch_create)
        .watch_delete(args.watch_delete)
        .watch_update(args.watch_modify)
        .match_files(args.match_files)
        .match_dirs(args.match_dirs);

    // Handle combine mode (debounced)
    if let Some(debounce_ms) = args.combine {
        if exit_on_first {
            // In combine mode with exit-on-first, we just wait for the first CHANGES output
            builder.run_debounced(debounce_ms, move || {
                // In combine mode, just output "CHANGES"
                println!("CHANGES");
                std::process::exit(0);
            }).await?;
        } else {
            // In combine mode without exit, run forever
            builder.run_debounced(debounce_ms, move || {
                println!("CHANGES");
            }).await?;
        }
    } else {
        // Normal mode - output individual changes
        if exit_on_first {
            builder.run(move |event, path| {
                let event_type = match event {
                    webcentral::file_watcher::WatchEvent::Create => EventType::Create,
                    webcentral::file_watcher::WatchEvent::Delete => EventType::Delete,
                    webcentral::file_watcher::WatchEvent::Update => EventType::Update,
                    webcentral::file_watcher::WatchEvent::DebugWatch => return, // Ignore debug events
                };
                
                // Output based on format
                match format {
                    OutputFormat::Default => {
                        println!("{} {}", event_type.as_str(), path.display());
                    }
                    OutputFormat::Path => {
                        println!("{}", path.display());
                    }
                    OutputFormat::Silent => {
                        // No output
                    }
                }
                
                // Exit immediately after first change
                std::process::exit(0);
            }).await?;
        } else {
            builder.run(move |event, path| {
                let event_type = match event {
                    webcentral::file_watcher::WatchEvent::Create => EventType::Create,
                    webcentral::file_watcher::WatchEvent::Delete => EventType::Delete,
                    webcentral::file_watcher::WatchEvent::Update => EventType::Update,
                    webcentral::file_watcher::WatchEvent::DebugWatch => return, // Ignore debug events
                };
                
                // Output based on format
                match format {
                    OutputFormat::Default => {
                        println!("{} {}", event_type.as_str(), path.display());
                    }
                    OutputFormat::Path => {
                        println!("{}", path.display());
                    }
                    OutputFormat::Silent => {
                        // No output
                    }
                }
            }).await?;
        }
    }

    Ok(())
}

