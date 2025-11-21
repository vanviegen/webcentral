use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::unix::AsyncFd;

// --- Pattern Parsing ---

#[derive(Debug, Clone, PartialEq)]
enum Segment {
    Exact(String),
    Wildcard(glob::Pattern),
    DoubleWildcard, // **
}

#[derive(Debug, Clone)]
struct Pattern {
    segments: Vec<Segment>,
}

impl Pattern {
    pub fn parse(pattern: &str) -> Self {
        // Split pattern into segments
        let mut segments = Vec::new();

        let effective_pattern = if !pattern.contains('/') {
            format!("**/{}", pattern)
        } else {
            pattern.trim_start_matches('/').to_string()
        };

        // Normalize path separators and remove redundant slashes
        let normalized = effective_pattern.replace("//", "/");
        
        for part in normalized.split('/') {
            if part.is_empty() || part == "." {
                continue;
            }
            
            if part == "**" {
                segments.push(Segment::DoubleWildcard);
            } else if part.contains('*') || part.contains('?') || part.contains('[') {
                if let Ok(p) = glob::Pattern::new(part) {
                    segments.push(Segment::Wildcard(p));
                } else {
                    // Fallback to exact if invalid glob (unlikely for simple patterns)
                    segments.push(Segment::Exact(part.to_string()));
                }
            } else {
                segments.push(Segment::Exact(part.to_string()));
            }
        }
        
        Pattern { segments }
    }
    
    fn check(&self, path_segments: &[String], allow_prefix: bool) -> bool {
        let pattern_segments = &self.segments;
        let mut path_index = 0;

        for pattern_index in 0..pattern_segments.len() {
            let pattern_segment = &pattern_segments[pattern_index];

            if path_index >= path_segments.len() {
                // We ran out of path segments
                if pattern_segment == &Segment::DoubleWildcard && pattern_index == pattern_segments.len() - 1 {
                    // There's a trailing ** behind past the end of the path we're making. We'll count this 
                    // as a match even in exact mode.
                    return true;
                }
                return allow_prefix;
            }

            match &pattern_segment {
                Segment::Exact(s) => {
                    if s != &path_segments[path_index] {
                        return false;
                    }
                    path_index += 1;
                }
                Segment::Wildcard(p) => {
                    if !p.matches(&path_segments[path_index]) {
                        return false;
                    }
                    path_index += 1;
                }
                Segment::DoubleWildcard => {

                    if allow_prefix {
                        // All segments behind the ** could potentially be matched in the part that comes
                        // after our path prefix.
                        return true;
                    }

                    let patterns_left = pattern_segments.len() - (pattern_index + 1);
                    let next_path_index = path_segments.len() - patterns_left;
                    if next_path_index < path_index {
                        // Not enough segments left to match the rest of the pattern
                        return false;
                    }
                    path_index = next_path_index;                
                }
            }
        }

        // We've consumed all pattern segments.
        // In prefix mode, this is always a match.
        // In exact mode, we must have consumed all path segments too.
        return allow_prefix || path_index == path_segments.len();
    }
}

// --- Inotify Wrapper ---

struct Inotify {
    fd: AsyncFd<i32>,
}

impl Inotify {
    fn new() -> Result<Self> {
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("inotify_init1 failed");
        }
        Ok(Self {
            fd: AsyncFd::new(fd)?,
        })
    }

    fn add_watch(&self, path: &Path, mask: u32) -> Result<i32> {
        let c_path = CString::new(path.as_os_str().as_bytes())?;
        let wd = unsafe {
            libc::inotify_add_watch(
                self.fd.as_raw_fd(),
                c_path.as_ptr(),
                mask,
            )
        };
        if wd < 0 {
            return Err(std::io::Error::last_os_error()).context(format!("inotify_add_watch failed for {}", path.display()));
        }
        Ok(wd)
    }

    async fn read_events(&self, buffer: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                let res = unsafe {
                    libc::read(
                        inner.as_raw_fd(),
                        buffer.as_mut_ptr() as *mut _,
                        buffer.len(),
                    )
                };
                if res < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(res as usize)
                }
            }) {
                Ok(Ok(len)) => return Ok(len),
                Ok(Err(e)) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    return Err(e.into());
                }
                Err(_) => continue,
            }
        }
    }
}

impl Drop for Inotify {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd.as_raw_fd()) };
    }
}

// --- Watcher Builder ---

/// Resolve base_dir to an absolute path
fn resolve_base_dir(base_dir: PathBuf) -> PathBuf {
    if base_dir.is_absolute() {
        base_dir
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(base_dir)
    }
}

/// Convert a relative path to segments for pattern matching
fn path_to_segments(path: &Path) -> Vec<String> {
    let path_str = path.to_string_lossy();
    let path_str = path_str.replace("//", "/");
    path_str.split('/').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect()
}

/// Check if a directory should be watched
/// Takes relative paths
fn should_watch(
    relative_path: &Path,
    include_patterns: &[Pattern],
    exclude_patterns: &[Pattern],
    is_dir: bool,
) -> bool {
    let segments = path_to_segments(relative_path);

    // Check excludes first - if a directory matches an exclude pattern exactly, skip it
    if exclude_patterns.iter().any(|p| p.check(&segments, false)) {
        return false;
    }
    
    // Check includes (prefix match)
    include_patterns.iter().any(|p| p.check(&segments, is_dir))
}

/// Recursively add watches to directories
/// Works with relative paths internally, converts to full paths for inotify
fn add_watch_recursive<F>(
    start_rel_path: PathBuf,
    root: &Path,
    inotify: &Inotify,
    watches: &mut HashMap<i32, PathBuf>,
    paths: &mut HashSet<PathBuf>,
    include_patterns: &[Pattern],
    exclude_patterns: &[Pattern],
    debug_watches_enabled: bool,
    return_absolute: bool,
    callback: &mut F,
) where
    F: FnMut(WatchEvent, PathBuf),
{
    let mut stack = vec![start_rel_path];
    while let Some(rel_path) = stack.pop() {
        if !should_watch(&rel_path, include_patterns, exclude_patterns, true) {
            continue;
        }
        
        // Add watch
        if paths.contains(&rel_path) {
            continue;
        }
        
        // Convert to full path for inotify
        let full_path = if rel_path.as_os_str().is_empty() {
            root.to_path_buf()
        } else {
            root.join(&rel_path)
        };
        
        // Only watch directories that exist
        if !full_path.is_dir() {
            continue;
        }
        
        // Watch for everything interesting
        let mask = libc::IN_MODIFY | libc::IN_CLOSE_WRITE | libc::IN_CREATE | libc::IN_DELETE | libc::IN_MOVED_FROM | libc::IN_MOVED_TO | libc::IN_DONT_FOLLOW;
        match inotify.add_watch(&full_path, mask as u32) {
            Ok(wd) => {
                paths.insert(rel_path.clone());
                watches.insert(wd, rel_path.clone());
                
                // Emit debug watch event if enabled
                if debug_watches_enabled {
                    let callback_path = if return_absolute {
                        full_path.clone()
                    } else {
                        rel_path.clone()
                    };
                    callback(WatchEvent::DebugWatch, callback_path);
                }
                
                // Read dir to find children
                if let Ok(entries) = std::fs::read_dir(&full_path) {
                    for entry in entries.flatten() {
                        if let Ok(ft) = entry.file_type() {
                            if ft.is_dir() {
                                let child_rel_path = if rel_path.as_os_str().is_empty() {
                                    PathBuf::from(entry.file_name())
                                } else {
                                    rel_path.join(entry.file_name())
                                };
                                stack.push(child_rel_path);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("{}", e);
            }
        }
    }
}

/// Find the starting directory to watch for a given pattern
/// Returns a relative path - returns empty PathBuf for root directory
fn find_watch_start_dir(pattern: &Pattern, root: &Path) -> PathBuf {
    let mut current_path = PathBuf::new();
    let mut found_wildcard = false;
    
    // Walk through the pattern segments to find the longest exact prefix
    for segment in &pattern.segments {
        match segment {
            Segment::Exact(s) => {
                if !found_wildcard {
                    current_path.push(s);
                }
            }
            _ => {
                found_wildcard = true;
                break;
            }
        }
    }
    
    // If we hit a wildcard, pop back to the parent directory
    if found_wildcard && !current_path.as_os_str().is_empty() {
        current_path.pop();
    }
    
    // If we didn't hit a wildcard, we built the full path - pop to get parent
    if !found_wildcard && !current_path.as_os_str().is_empty() {
        current_path.pop();
    }
    
    // Walk back to find an existing directory
    loop {
        let full_path = if current_path.as_os_str().is_empty() {
            root.to_path_buf()
        } else {
            root.join(&current_path)
        };
        
        if full_path.exists() && full_path.is_dir() {
            break;
        }
        
        if current_path.as_os_str().is_empty() {
            // We're already at root, can't go further
            break;
        }
        
        current_path.pop();
    }
    
    current_path
}

/// Parse inotify events from buffer
fn parse_inotify_events(buffer: &[u8], len: usize) -> Vec<(i32, u32, String)> {
    let mut events = Vec::new();
    let mut ptr = buffer.as_ptr();
    let end = unsafe { ptr.add(len) };
    
    while ptr < end {
        let event = unsafe { &*(ptr as *const libc::inotify_event) };
        let name_len = event.len as usize;
        
        if name_len > 0 {
            let name_ptr = unsafe { ptr.add(std::mem::size_of::<libc::inotify_event>()) };
            let name_slice = unsafe { std::slice::from_raw_parts(name_ptr as *const u8, name_len) };
            let name_str = String::from_utf8_lossy(name_slice).trim_matches(char::from(0)).to_string();
            events.push((event.wd, event.mask, name_str));
        }
        
        ptr = unsafe { ptr.add(std::mem::size_of::<libc::inotify_event>() + name_len) };
    }
    
    events
}

/// Type of file system event
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchEvent {
    /// File or directory was created
    Create,
    /// File or directory was deleted
    Delete,
    /// File was modified
    Update,
    /// Debug event: directory watch added (only emitted when debug_watches is enabled)
    DebugWatch,
}

pub struct WatchBuilder {
    includes: Option<Vec<String>>,
    excludes: Vec<String>,
    base_dir: PathBuf,
    watch_create: bool,
    watch_delete: bool,
    watch_update: bool,
    match_files: bool,
    match_dirs: bool,
    return_absolute: bool,
    debug_watches_enabled: bool,
}

impl WatchBuilder {
    /// Create a new file watcher builder with default settings
    pub fn new() -> Self {
        WatchBuilder {
            includes: Some(Vec::new()),
            excludes: Vec::new(),
            base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
            watch_create: true,
            watch_delete: true,
            watch_update: true,
            match_files: true,
            match_dirs: true,
            return_absolute: false,
            debug_watches_enabled: false,
        }
    }

    /// Enable debug watch events
    /// When enabled, DebugWatch events will be emitted for each directory that is watched
    #[allow(dead_code)]
    pub fn debug_watches(mut self, enabled: bool) -> Self {
        self.debug_watches_enabled = enabled;
        self
    }

    /// Enable debug tracking of watched directories (for testing)
    /// Pass in a set that will be updated with all watched directories
    #[allow(dead_code)]
    #[deprecated(note = "Use debug_watches(true) instead and handle DebugWatch events")]
    pub fn with_debug_tracking(mut self, _set: Arc<Mutex<HashSet<PathBuf>>>) -> Self {
        self.debug_watches_enabled = true;
        self
    }

    /// Add a single include pattern
    #[allow(dead_code)]
    pub fn add_include(mut self, pattern: impl Into<String>) -> Self {
        if self.includes.is_none() {
            self.includes = Some(Vec::new());
        }
        self.includes.as_mut().unwrap().push(pattern.into());
        self
    }

    /// Add multiple include patterns
    pub fn add_includes(mut self, patterns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        if self.includes.is_none() {
            self.includes = Some(Vec::new());
        }
        self.includes.as_mut().unwrap().extend(patterns.into_iter().map(|p| p.into()));
        self
    }

    /// Add a single exclude pattern
    #[allow(dead_code)]
    pub fn add_exclude(mut self, pattern: impl Into<String>) -> Self {
        self.excludes.push(pattern.into());
        self
    }

    /// Add multiple exclude patterns
    pub fn add_excludes(mut self, patterns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.excludes.extend(patterns.into_iter().map(|p| p.into()));
        self
    }

    /// Set the base directory for relative patterns
    pub fn set_base_dir(mut self, base_dir: impl Into<PathBuf>) -> Self {
        self.base_dir = base_dir.into();
        self
    }



    /// Set whether to watch for file/directory creation events
    #[allow(dead_code)]
    pub fn watch_create(mut self, enabled: bool) -> Self {
        self.watch_create = enabled;
        self
    }

    /// Set whether to watch for file/directory deletion events
    #[allow(dead_code)]
    pub fn watch_delete(mut self, enabled: bool) -> Self {
        self.watch_delete = enabled;
        self
    }

    /// Set whether to watch for file modification events
    #[allow(dead_code)]
    pub fn watch_update(mut self, enabled: bool) -> Self {
        self.watch_update = enabled;
        self
    }

    /// Set whether to match regular files
    #[allow(dead_code)] // Used by wwatch binary
    pub fn match_files(mut self, enabled: bool) -> Self {
        self.match_files = enabled;
        self
    }

    /// Set whether to match directories
    #[allow(dead_code)] // Used by wwatch binary
    pub fn match_dirs(mut self, enabled: bool) -> Self {
        self.match_dirs = enabled;
        self
    }

    /// Set whether to return absolute paths (true) or relative paths (false)
    /// Default is false (relative paths)
    pub fn return_absolute(mut self, enabled: bool) -> Self {
        self.return_absolute = enabled;
        self
    }

    /// Run the watcher with the provided callback
    pub async fn run<F>(self, mut callback: F) -> Result<()>
    where
        F: FnMut(WatchEvent, PathBuf),
    {
        let includes = if let Some(includes) = self.includes {
            includes
        } else { // Default to watching everything
            vec!["**".to_string()]
        };
        // If no includes are specified, just sleep forever
        if includes.is_empty() {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        }

        let excludes = self.excludes;
        let root = self.base_dir.clone();
        let watch_create = self.watch_create;
        let watch_delete = self.watch_delete;
        let watch_update = self.watch_update;
        let match_files = self.match_files;
        let match_dirs = self.match_dirs;
        let return_absolute = self.return_absolute;
        let debug_watches_enabled = self.debug_watches_enabled;
        
        let root = resolve_base_dir(root);

        let include_patterns: Vec<Pattern> = includes.iter().map(|p| Pattern::parse(p)).collect();
        let exclude_patterns: Vec<Pattern> = excludes.iter().map(|p| Pattern::parse(p)).collect();

        let inotify = Inotify::new()?;
        let mut watches = HashMap::<i32, PathBuf>::new(); // watch descriptor -> relative PathBuf
        let mut paths = HashSet::<PathBuf>::new();        // relative PathBuf set

        // Initial scan
        for pattern in &include_patterns {
            let watch_dir = find_watch_start_dir(pattern, &root);
            add_watch_recursive(
                watch_dir,
                &root,
                &inotify,
                &mut watches,
                &mut paths,
                &include_patterns,
                &exclude_patterns,
                debug_watches_enabled,
                return_absolute,
                &mut callback,
            );
        }

        // Event loop
        let mut buffer = [0u8; 8192];
        loop {
            match inotify.read_events(&mut buffer).await {
                Ok(len) => {
                    let events = parse_inotify_events(&buffer, len);

                    // Process events
                    for (wd, mask, name_str) in events {
                        let rel_path = {
                            // Handle IN_IGNORED (watch removed)
                            if (mask & libc::IN_IGNORED as u32) != 0 {
                                if let Some(path) = watches.remove(&wd) {
                                    paths.remove(&path);
                                }
                                continue;
                            }
                            if let Some(dir_path) = watches.get(&wd) {
                                Some(dir_path.join(&name_str))
                            } else {
                                None
                            }
                        };

                        if let Some(rel_path) = rel_path {
                            // Handle directory creation
                            if (mask & libc::IN_ISDIR as u32) != 0 {
                                if (mask & libc::IN_CREATE as u32) != 0 || (mask & libc::IN_MOVED_TO as u32) != 0 {
                                    add_watch_recursive(
                                        rel_path.clone(),
                                        &root,
                                        &inotify,
                                        &mut watches,
                                        &mut paths,
                                        &include_patterns,
                                        &exclude_patterns,
                                        debug_watches_enabled,
                                        return_absolute,
                                        &mut callback,
                                    );
                                }
                            }

                            if should_watch(&rel_path, &include_patterns, &exclude_patterns, false) {
                                let is_create = (mask & libc::IN_CREATE as u32) != 0 || (mask & libc::IN_MOVED_TO as u32) != 0;
                                let is_delete = (mask & libc::IN_DELETE as u32) != 0 || (mask & libc::IN_MOVED_FROM as u32) != 0;
                                let is_update = (mask & libc::IN_MODIFY as u32) != 0 || (mask & libc::IN_CLOSE_WRITE as u32) != 0;
                                
                                let event_type = if is_create && watch_create {
                                    Some(WatchEvent::Create)
                                } else if is_delete && watch_delete {
                                    Some(WatchEvent::Delete)
                                } else if is_update && watch_update {
                                    Some(WatchEvent::Update)
                                } else {
                                    None
                                };
                                
                                if let Some(event_type) = event_type {
                                    let is_dir = (mask & libc::IN_ISDIR as u32) != 0;
                                    let should_match_type = if is_dir { match_dirs } else { match_files };
                                    
                                    if should_match_type {
                                        // Convert to absolute path if requested
                                        let callback_path = if return_absolute {
                                            if rel_path.as_os_str().is_empty() {
                                                root.clone()
                                            } else {
                                                root.join(&rel_path)
                                            }
                                        } else {
                                            rel_path
                                        };
                                        callback(event_type, callback_path);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading inotify events: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Run the watcher with debouncing
    /// 
    /// This method watches for file changes and fires the callback after at least one event
    /// has occurred, followed by a quiet period of at least `ms` milliseconds without any events.
    /// The callback accepts no arguments.
    pub async fn run_debounced<F>(self, ms: u64, mut callback: F) -> Result<()>
    where
        F: FnMut(),
    {
        use tokio::sync::mpsc;
        
        let (tx, mut rx) = mpsc::unbounded_channel();
        
        // Spawn the watcher task
        let mut watcher_task = {
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = self.run(move |_event, _path| {
                    // Send a signal that an event occurred (we don't care about the path or event type)
                    let _ = tx.send(());
                }).await;
            })
        };
        
        // Debounce logic: wait for events to stop for `debounce_duration` before firing callback
        let debounce_duration = Duration::from_millis(ms);
        // Track whether timer is armed (events pending)
        let mut timer_armed = false;
        let mut sleep_future = std::pin::pin!(tokio::time::sleep(Duration::from_secs(86400 * 365 * 100)));

        loop {
            tokio::select! {
                // Watcher task completed (shouldn't normally happen)
                _ = &mut watcher_task => break,
                
                // New event received
                Some(()) = rx.recv() => {
                    // Reset the debounce timer
                    sleep_future.as_mut().reset(tokio::time::Instant::now() + debounce_duration);
                    timer_armed = true;
                }
                
                // Debounce timer expired - fire callback
                _ = &mut sleep_future, if timer_armed => {
                    // Drain any events that arrived during the select
                    while rx.try_recv().is_ok() {}

                    callback();

                    // Disable timer until next event
                    timer_armed = false;
                }
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::collections::HashSet;
    use tokio::task::JoinHandle;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    enum EventType {
        Create,
        Delete,
        Update,
        DebugWatch,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct Event {
        path: PathBuf,
        event_type: EventType,
    }

    type EventTracker = Arc<Mutex<Vec<Event>>>;

    struct TestInstance {
        test_dir: PathBuf,
        tracker: EventTracker,
        watcher_handle: Option<JoinHandle<()>>,
    }

    impl TestInstance {
        async fn new<F>(test_name: &str, configure: F) -> Self
        where
            F: FnOnce(WatchBuilder) -> WatchBuilder + Send + 'static,
        {
            // Setup test directory
            let test_dir = std::env::current_dir()
                .unwrap()
                .join(format!(".file-watcher-test-{}", test_name));
            
            if test_dir.exists() {
                std::fs::remove_dir_all(&test_dir).unwrap();
            }
            std::fs::create_dir(&test_dir).unwrap();

            // Create trackers
            let tracker = Arc::new(Mutex::new(Vec::new()));

            // Spawn watcher
            let tracker_clone = tracker.clone();
            let test_dir_clone = test_dir.clone();
            
            let watcher_handle = tokio::spawn(async move {
                let builder = WatchBuilder::new()
                    .set_base_dir(&test_dir_clone)
                    .debug_watches(true);
                
                let builder = configure(builder);
                
                let _ = builder.run(move |event_type, path| {
                    tracker_clone.lock().unwrap().push(Event {
                        path: path.clone(),
                        event_type: match event_type {
                            WatchEvent::Create => EventType::Create,
                            WatchEvent::Delete => EventType::Delete,
                            WatchEvent::Update => EventType::Update,
                            WatchEvent::DebugWatch => EventType::DebugWatch,
                        },
                    });
                }).await;
            });

            // Give watcher time to start
            tokio::time::sleep(Duration::from_millis(100)).await;

            let instance = Self {
                test_dir,
                tracker,
                watcher_handle: Some(watcher_handle),
            };
            
            // Clear initial root watch event
            instance.assert_events(&[], &[], &[], &[""]).await;
            
            instance
        }

        fn create_dir(&self, path: &str) {
            std::fs::create_dir(self.test_dir.join(path)).unwrap();
        }

        fn write_file(&self, path: &str, content: &str) {
            let full_path = self.test_dir.join(path);
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(full_path, content).unwrap();
        }

        fn remove_file(&self, path: &str) {
            std::fs::remove_file(self.test_dir.join(path)).unwrap();
        }

        fn rename(&self, from: &str, to: &str) {
            std::fs::rename(self.test_dir.join(from), self.test_dir.join(to)).unwrap();
        }

        async fn assert_events(
            &self,
            creates: &[&str],
            deletes: &[&str],
            updates: &[&str],
            watches: &[&str],
        ) {
            // Wait for events
            tokio::time::sleep(Duration::from_millis(200)).await;
            
            let events = self.tracker.lock().unwrap().clone();
            let mut expected = HashSet::new();
            
            for create in creates {
                expected.insert(Event {
                    path: PathBuf::from(create),
                    event_type: EventType::Create,
                });
            }
            
            for delete in deletes {
                expected.insert(Event {
                    path: PathBuf::from(delete),
                    event_type: EventType::Delete,
                });
            }
            
            for update in updates {
                expected.insert(Event {
                    path: PathBuf::from(update),
                    event_type: EventType::Update,
                });
            }
            
            for watch in watches {
                expected.insert(Event {
                    path: PathBuf::from(watch),
                    event_type: EventType::DebugWatch,
                });
            }
            
            let actual: HashSet<Event> = events.iter().cloned().collect();
            
            // Check for unexpected events
            for event in &actual {
                if !expected.contains(event) {
                    panic!("Unexpected event: {:?}", event);
                }
            }
            
            // Check for missing events
            for event in &expected {
                if !actual.contains(event) {
                    panic!("Missing expected event: {:?}\nActual events: {:?}", event, actual);
                }
            }
            
            // Clear events for next check
            self.tracker.lock().unwrap().clear();
        }

        async fn assert_no_events(&self) {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let events = self.tracker.lock().unwrap();
            assert_eq!(events.len(), 0, "Expected no events, but got: {:?}", events);
        }
    }

    impl Drop for TestInstance {
        fn drop(&mut self) {
            if let Some(handle) = self.watcher_handle.take() {
                handle.abort();
            }
            if self.test_dir.exists() {
                let _ = std::fs::remove_dir_all(&self.test_dir);
            }
        }
    }

    #[tokio::test]
    async fn test_file_create_update_delete() {
        let test = TestInstance::new("create_update_delete", |b| {
            b.add_include("**/*")
        }).await;
        
        // Test 1: Create file (std::fs::write triggers both CREATE and CLOSE_WRITE events)
        test.write_file("test.txt", "");
        test.assert_events(&["test.txt"], &[], &["test.txt"], &[]).await;
        
        // Test 2: Update file
        test.write_file("test.txt", "hello");
        test.assert_events(&[], &[], &["test.txt"], &[]).await;
        
        // Test 3: Delete file
        test.remove_file("test.txt");
        test.assert_events(&[], &["test.txt"], &[], &[]).await;
    }

    #[tokio::test]
    async fn test_directory_operations() {
        let test = TestInstance::new("directory_operations", |b| {
            b.add_include("**/*")
        }).await;
        
        // Test: Create directory
        test.create_dir("subdir");
        test.assert_events(&["subdir"], &[], &[], &["subdir"]).await;
        
        // Test: Create file in directory (triggers both create and update)
        test.write_file("subdir/file.txt", "");
        test.assert_events(&["subdir/file.txt"], &[], &["subdir/file.txt"], &[]).await;
    }

    #[tokio::test]
    async fn test_move_operations() {
        let test = TestInstance::new("move_operations", |b| {
            b.add_include("**/*")
        }).await;
        
        // Create initial file - std::fs::write triggers both create and update
        test.write_file("old.txt", "content");
        test.assert_events(&["old.txt"], &[], &["old.txt"], &[]).await;
        
        // Move file (generates delete + create)
        test.rename("old.txt", "new.txt");
        test.assert_events(&["new.txt"], &["old.txt"], &[], &[]).await;
    }

    #[tokio::test]
    async fn test_event_filtering() {
        let test = TestInstance::new("event_filtering", |b| {
            b.add_include("**/*")
                .watch_create(true)
                .watch_delete(false)
                .watch_update(false)
        }).await;
        
        // Create file - should be detected
        test.write_file("test.txt", "");
        test.assert_events(&["test.txt"], &[], &[], &[]).await;
        
        // Update file - should NOT be detected
        test.write_file("test.txt", "hello");
        test.assert_no_events().await;
        
        // Delete file - should NOT be detected
        test.remove_file("test.txt");
        test.assert_no_events().await;
    }

    #[tokio::test]
    async fn test_pattern_matching() {
        let test = TestInstance::new("pattern_matching", |b| {
            b.add_include("**/*.txt")
        }).await;
        
        // Create .txt file - should be detected (both create and update)
        test.write_file("test.txt", "");
        test.assert_events(&["test.txt"], &[], &["test.txt"], &[]).await;
        
        // Create .rs file - should NOT be detected
        test.write_file("test.rs", "");
        test.assert_no_events().await;
    }

    #[tokio::test]
    async fn test_relative_paths() {
        let test = TestInstance::new("relative_paths", |b| {
            b.add_include("**/*")
        }).await;
        
        // Create file (triggers both create and update)
        test.write_file("test.txt", "");
        test.assert_events(&["test.txt"], &[], &["test.txt"], &[]).await;
    }

    #[tokio::test]
    async fn test_watch_parent_directory_for_simple_pattern() {
        let test = TestInstance::new("watch_parent_simple", |b| {
            b.add_include("subdir/file.txt")
        }).await;
        
        // Create the subdir directory
        test.create_dir("subdir");
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        // Should have added one more watch for subdir
        test.assert_events(&[], &[], &[], &["subdir"]).await;
        
        // Create the file - should be detected (both create and update)
        test.write_file("subdir/file.txt", "");
        test.assert_events(&["subdir/file.txt"], &[], &["subdir/file.txt"], &[]).await;
    }

    #[tokio::test]
    async fn test_watch_parent_directory_with_wildcard() {
        let test = TestInstance::new("watch_parent_wildcard", |b| {
            b.add_include("src/*/module.rs")
        }).await;
        
        // Create the src directory
        test.create_dir("src");
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        // Should have added watch for src
        test.assert_events(&[], &[], &[], &["src"]).await;
        
        // Create subdirectory
        test.create_dir("src/component");
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        // Should have added watch for component
        test.assert_events(&[], &[], &[], &["src/component"]).await;
        
        // Create matching file - should be detected (both create and update)
        test.write_file("src/component/module.rs", "");
        test.assert_events(&["src/component/module.rs"], &[], &["src/component/module.rs"], &[]).await;
        
        // Create non-matching file - should NOT be detected
        test.write_file("src/component/other.rs", "");
        test.assert_no_events().await;
    }

    #[tokio::test]
    async fn test_watch_all_directories_with_double_wildcard() {
        let test = TestInstance::new("watch_double_wildcard", |b| {
            b.add_include("**/target")
        }).await;
        
        // Create nested directories
        test.create_dir("a");
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        test.create_dir("a/b");
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        test.create_dir("a/b/c");
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        // Clear all the intermediate directory watches created (including initial root)
        test.assert_events(&[], &[], &[], &["a", "a/b", "a/b/c"]).await;
        
        // Create matching directory at various levels - should be detected
        test.create_dir("target");
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        test.create_dir("a/target");
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        test.create_dir("a/b/c/target");
        
        test.assert_events(&["target", "a/target", "a/b/c/target"], &[], &[], &["target", "a/target", "a/b/c/target"]).await;
    }

    #[tokio::test]
    async fn test_exclude_prevents_watching() {
        let test = TestInstance::new("exclude_prevents_watch", |b| {
            b.add_include("**/*")
                .add_exclude("node_modules/**")
        }).await;
        
        // Create node_modules directory
        test.create_dir("node_modules");
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        // Create file in node_modules - should NOT be detected
        test.write_file("node_modules/package.json", "");
        test.assert_no_events().await;
        
        // Create file outside node_modules - should be detected (both create and update)
        test.write_file("test.txt", "");
        test.assert_events(&["test.txt"], &[], &["test.txt"], &[]).await;
    }

    #[tokio::test]
    async fn test_exclude_with_exact_path() {
        let test = TestInstance::new("exclude_exact_path", |b| {
            b.add_include("**/*")
                .add_exclude("temp/cache")
        }).await;
        
        // Create temp directory - should be detected
        test.create_dir("temp");
        test.assert_events(&["temp"], &[], &[], &["temp"]).await;
        
        // Create cache directory - should NOT be detected (it's excluded)
        test.create_dir("temp/cache");
        test.assert_no_events().await;
        
        // Files inside temp/cache should NOT be detected (because it's excluded)
        test.write_file("temp/cache/data.txt", "");
        test.assert_no_events().await;
        
        // Files in temp but not in cache should be detected (both create and update)
        test.write_file("temp/other.txt", "");
        test.assert_events(&["temp/other.txt"], &[], &["temp/other.txt"], &[]).await;
    }

    #[tokio::test]
    async fn test_uninteresting_directories_not_watched() {
        let test = TestInstance::new("uninteresting_dirs", |b| {
            b.add_include("target/file.txt")
        }).await;
        
        // Create unrelated directories - should NOT add watches
        test.create_dir("src");
        test.create_dir("docs");
        test.create_dir("build");
        tokio::time::sleep(Duration::from_millis(300)).await;
        
        test.assert_events(&[], &[], &[], &[]).await;
        
        // Create the target directory - should add watch
        test.create_dir("target");
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        test.assert_events(&[], &[], &[], &["target"]).await;
        
        // Create file in target - should be detected (both create and update)
        test.write_file("target/file.txt", "");
        test.assert_events(&["target/file.txt"], &[], &["target/file.txt"], &[]).await;
        
        // Create files in other directories - should NOT be detected
        test.write_file("src/main.rs", "");
        test.write_file("docs/readme.md", "");
        test.assert_no_events().await;
    }

    #[tokio::test]
    async fn test_return_absolute_paths() {
        // Setup test directory
        let test_dir = std::env::current_dir()
            .unwrap()
            .join(".file-watcher-test-absolute");
        
        if test_dir.exists() {
            std::fs::remove_dir_all(&test_dir).unwrap();
        }
        std::fs::create_dir(&test_dir).unwrap();

        let tracker = Arc::new(Mutex::new(Vec::new()));
        let tracker_clone = tracker.clone();
        let test_dir_clone = test_dir.clone();
        
        let watcher_handle = tokio::spawn(async move {
            let _ = WatchBuilder::new()
                .set_base_dir(&test_dir_clone)
                .add_include("**/*")
                .return_absolute(true)
                .run(move |event_type, path| {
                    tracker_clone.lock().unwrap().push((event_type, path));
                }).await;
        });

        // Give watcher time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Create a file
        std::fs::write(test_dir.join("test.txt"), "").unwrap();
        
        // Wait for events
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        let events = tracker.lock().unwrap().clone();
        
        // Check that paths are absolute
        for (_event_type, path) in &events {
            assert!(path.is_absolute(), "Expected absolute path, got: {:?}", path);
            assert!(path.starts_with(&test_dir), "Expected path to start with test_dir");
        }
        
        // Cleanup
        watcher_handle.abort();
        std::fs::remove_dir_all(&test_dir).unwrap();
    }
}
