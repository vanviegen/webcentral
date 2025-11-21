use anyhow::Result;
use chrono::Local;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

#[derive(Debug)]
pub struct Logger {
    dir: PathBuf,
    file: Mutex<Option<File>>,
    current_date: Mutex<String>,
    uid: u32,
    gid: u32,
    pub prune_days: i64,
}

impl Logger {
    pub fn new(dir: PathBuf, uid: u32, gid: u32, prune_days: i64) -> Result<Self> {
        fs::create_dir_all(&dir)?;

        Ok(Logger {
            dir,
            file: Mutex::new(None),
            current_date: Mutex::new(String::new()),
            uid,
            gid,
            prune_days,
        })
    }

    pub fn write(&self, topic: &str, message: &str) {
        let date = get_date();

        let mut current_date = self.current_date.lock().unwrap();
        if *current_date != date {
            let _ = self.rotate(&date);
            *current_date = date.clone();
        }
        drop(current_date);

        let timestamp = Local::now().format("%H:%M:%S");

        let msg = message.trim();
        if msg.is_empty() {
            return;
        }

        // Calculate prefix for multi-line continuation
        let prefix_len = if topic.is_empty() {
            9 // "HH:MM:SS "
        } else {
            9 + topic.len() + 3 // "HH:MM:SS [topic] "
        };
        let prefix = format!("\n{}", " ".repeat(prefix_len));

        // Format message with optional topic
        let formatted_msg = if topic.is_empty() {
            msg.replace('\n', &prefix)
        } else {
            let msg_with_topic = format!("[{}] {}", topic, msg);
            msg_with_topic.replace('\n', &prefix)
        };

        let output = format!("{} {}\n", timestamp, formatted_msg);

        let mut file = self.file.lock().unwrap();
        if let Some(ref mut f) = *file {
            let _ = f.write_all(output.as_bytes());
            let _ = f.sync_all();
        }
    }

    fn rotate(&self, date: &str) -> Result<()> {
        let mut file = self.file.lock().unwrap();

        // Close current file
        *file = None;

        // Open new log file
        let log_path = self.dir.join(format!("{}.log", date));
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        // Set ownership if running as root
        #[cfg(target_os = "linux")]
        {
            if nix::unistd::geteuid().is_root() && (self.uid > 0 || self.gid > 0) {
                unsafe {
                    let path_cstr = std::ffi::CString::new(log_path.to_str().unwrap()).unwrap();
                    let _ = libc::chown(path_cstr.as_ptr(), self.uid, self.gid);
                }
            }
        }

        *file = Some(new_file);

        #[cfg(unix)]
        {
            // Create/update 'current' symlink
            let symlink_path = self.dir.join("current");
            let log_filename = format!("{}.log", date);
            let _ = fs::remove_file(&symlink_path); // Remove old symlink if exists
            use std::os::unix::fs::symlink;
            let _ = symlink(&log_filename, &symlink_path);
        }

        // Clean up old log files if pruning is enabled
        if self.prune_days > 0 {
            let dir = self.dir.clone();
            let prune_days = self.prune_days;
            tokio::spawn(async move {
                let _ = cleanup_old_logs(&dir, prune_days);
            });
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn close(&self) -> Result<()> {
        let mut file = self.file.lock().unwrap();
        *file = None;
        Ok(())
    }
}

fn get_date() -> String {
    Local::now().format("%Y-%m-%d").to_string()
}

fn cleanup_old_logs(dir: &PathBuf, prune_days: i64) -> Result<()> {
    let cutoff = SystemTime::now() - std::time::Duration::from_secs((prune_days * 86400) as u64);

    let entries = fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("log") {
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    if modified < cutoff {
                        let _ = fs::remove_file(&path);
                    }
                }
            }
        }
    }

    Ok(())
}
