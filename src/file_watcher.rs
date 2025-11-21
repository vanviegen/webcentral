use anyhow::{Context, Result};
use std::collections::HashMap;
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
    pub fn parse(pattern: &str, base_dir: &Path) -> Self {
        // Split pattern into segments
        let mut segments = Vec::new();
        
        // If pattern doesn't start with /, it's relative to base_dir
        // But if it doesn't contain ANY /, it is treated as **/<pattern>
        // The prompt said: "Patterns without a '/' should be read as **/<pattern>"
        // "Patterns that don't start with a '/' should be prefixed by the cwd (or an optional base_dir provided as an arg)."
        
        let effective_pattern = if !pattern.contains('/') {
            let base_str = base_dir.to_string_lossy();
            let base_str = base_str.trim_end_matches('/');
            format!("{}/**/{}", base_str, pattern)
        } else if !pattern.starts_with('/') {
            // Prefix with base_dir
            let base_str = base_dir.to_string_lossy();
            let base_str = base_str.trim_end_matches('/');
            format!("{}/{}", base_str, pattern)
        } else {
            pattern.to_string()
        };

        // Normalize path separators and remove redundant slashes
        let normalized = effective_pattern.replace("//", "/");
        
        for part in normalized.split('/') {
            if part.is_empty() || part == "." {
                continue;
            }
            
            if part == ".." {
                // Disallow parent directory traversal in patterns for security/simplicity
                // or handle it if needed. For now, let's treat it as invalid or just ignore?
                // The prompt said: "Disallow /../ terms"
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

    // Check if the directory path is a valid prefix for this pattern (for traversal)
    fn matches_prefix(&self, path_segments: &[String]) -> bool {
        // Check if path_segments is a prefix of something that could match the pattern
        // OR if the pattern matches the path_segments (or a prefix of it with **)
        
        if path_segments.is_empty() {
            return true;
        }

        let mut p_idx = 0;
        let mut s_idx = 0;

        while p_idx < self.segments.len() && s_idx < path_segments.len() {
            match &self.segments[p_idx] {
                Segment::DoubleWildcard => {
                    // If we have a double wildcard, we can match the rest of the path
                    // But we need to be careful. ** matches zero or more segments.
                    // If we are at the end of pattern, we match everything.
                    if p_idx == self.segments.len() - 1 {
                        return true;
                    }
                    // Otherwise, we need to see if the rest of the pattern can match the rest of the path
                    // This is hard for "prefix" check. 
                    // But for "should we traverse", if we see **, we generally should traverse.
                    return true; 
                }
                Segment::Wildcard(p) => {
                    if !p.matches(&path_segments[s_idx]) {
                        return false;
                    }
                    p_idx += 1;
                    s_idx += 1;
                }
                Segment::Exact(s) => {
                    if s != &path_segments[s_idx] {
                        return false;
                    }
                    p_idx += 1;
                    s_idx += 1;
                }
            }
        }

        // If we consumed all path segments, it's a valid prefix
        if s_idx == path_segments.len() {
            return true;
        }

        // If we consumed all pattern segments but still have path segments,
        // it's NOT a match unless the last pattern segment was **
        // (which we handled above).
        // Example: Pattern /a/b, Path /a/b/c -> False
        false
    }

    // Check if the path matches the pattern exactly (for filtering/excludes)
    fn matches_exact(&self, path_segments: &[String]) -> bool {
        let res = match_segments(&self.segments, path_segments, true);
        res
    }
}

fn match_segments(pattern: &[Segment], path: &[String], exact: bool) -> bool {
    let mut p_idx = 0;
    let mut d_idx = 0;

    while p_idx < pattern.len() && d_idx < path.len() {
        match &pattern[p_idx] {
            Segment::Exact(s) => {
                if s != &path[d_idx] {
                    return false;
                }
                p_idx += 1;
                d_idx += 1;
            }
            Segment::Wildcard(p) => {
                if !p.matches(&path[d_idx]) {
                    return false;
                }
                p_idx += 1;
                d_idx += 1;
            }
            Segment::DoubleWildcard => {
                // If ** is the last segment, it matches everything remaining.
                if p_idx == pattern.len() - 1 {
                    return true;
                }
                
                // Otherwise, ** matches until the rest of the pattern matches.
                // We need to find a suffix of path that matches pattern[p_idx+1..].
                // This is a search.
                let remaining_pattern = &pattern[p_idx + 1..];
                
                // Try to match remaining pattern starting from every possible position in path
                for i in d_idx..path.len() {
                    // If we are in exact mode, we need to match the WHOLE remaining path.
                    // If we are in prefix mode, we just need to match the prefix of remaining path?
                    // No, if we skipped some segments with **, we are now aligned.
                    
                    // Let's recurse.
                    // We consume 'i - d_idx' segments with **.
                    // Then we try to match the rest.
                    if match_segments(remaining_pattern, &path[i..], exact) {
                        return true;
                    }
                }
                
                // If we are in prefix mode, and we consumed everything with **, 
                // and we still have pattern left?
                // e.g. Pattern: **/a/b, Path: /foo/bar.
                // ** consumes foo/bar. Remaining pattern a/b.
                // Does it match? No.
                // But is it a prefix? 
                // /foo/bar could be a prefix of /foo/bar/a/b.
                // So if we are in prefix mode, ** can consume everything and we are still "good" (we haven't failed yet).
                if !exact {
                    return true;
                }
                
                return false;
            }
        }
    }

    // If we ran out of path segments
    if d_idx == path.len() {
        if exact {
            // For exact match, we must have consumed the whole pattern too.
            // Exception: if pattern ends in **, it can match empty suffix?
            // e.g. Pattern: /a/**, Path: /a. Yes.
            if p_idx == pattern.len() {
                return true;
            }
            if p_idx == pattern.len() - 1 && matches!(pattern[p_idx], Segment::DoubleWildcard) {
                return true;
            }
            return false;
        } else {
            // For prefix match, if we ran out of path, we are a valid prefix.
            return true;
        }
    }

    // If we ran out of pattern segments but have path left
    if p_idx == pattern.len() {
        // If exact match, this is a failure (pattern too short).
        // Unless the last segment was **? 
        // But we handled ** above (it consumes).
        // Wait, if pattern is `*`, and path is `a`.
        // Loop runs once. p_idx=1, d_idx=1.
        // Loop ends.
        // d_idx == path.len() -> returns true.
        
        // If pattern is `*`, and path is `a/b`.
        // Loop runs once. p_idx=1, d_idx=1.
        // Loop ends.
        // d_idx < path.len().
        // p_idx == pattern.len().
        // Return false. (Correct, * matches one segment).
        
        // If pattern is `**`, and path is `a/b`.
        // Loop runs. ** handles it.
        
        return false;
    }

    false
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

    #[allow(dead_code)]
    fn rm_watch(&self, wd: i32) -> Result<()> {
        let ret = unsafe { libc::inotify_rm_watch(self.fd.as_raw_fd(), wd) };
        if ret < 0 {
            // Ignore EINVAL (watch descriptor removed)
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINVAL) {
                 return Err(err).context("inotify_rm_watch failed");
            }
        }
        Ok(())
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

pub struct WatchBuilder {
    includes: Vec<String>,
    excludes: Vec<String>,
    base_dir: PathBuf,
    watch_create: bool,
    watch_delete: bool,
    watch_update: bool,
}

impl WatchBuilder {
    /// Add a single include pattern
    #[allow(dead_code)]
    pub fn add_include(mut self, pattern: impl Into<String>) -> Self {
        self.includes.push(pattern.into());
        self
    }

    /// Add multiple include patterns
    pub fn add_includes(mut self, patterns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.includes.extend(patterns.into_iter().map(|p| p.into()));
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

    /// Run the watcher with the provided callback
    pub async fn run<F, Fut>(self, mut callback: F) -> Result<()>
    where
        F: FnMut(PathBuf) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let includes = self.includes;
        let excludes = self.excludes;
        let root = self.base_dir.clone();
        let watch_create = self.watch_create;
        let watch_delete = self.watch_delete;
        let watch_update = self.watch_update;
        
        // Determine if we should return relative paths
        let base_dir_for_relative = if root.to_string_lossy() == "/" {
            None
        } else {
            Some(root.clone())
        };

        // If no includes are specified, the callback will never fire
        if includes.is_empty() {
            // Just wait forever without watching anything
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        }
    // Parse patterns
    // Use root as base_dir for relative patterns
    let include_patterns: Vec<Pattern> = includes
        .iter()
        .map(|p| Pattern::parse(p, &root))
        .collect();

    let exclude_patterns: Vec<Pattern> = excludes
        .iter()
        .map(|p| Pattern::parse(p, &root))
        .collect();

    let inotify = Arc::new(Inotify::new()?);
    let watches = Arc::new(Mutex::new(HashMap::new())); // wd -> PathBuf
    let paths = Arc::new(Mutex::new(HashMap::new()));   // PathBuf -> wd

    // Helper to check if we should watch/enter a directory
    let should_watch_dir = |path: &Path| -> bool {
        let path_str = path.to_string_lossy();
        let path_str = path_str.replace("//", "/"); 
        let segments: Vec<String> = path_str.split('/').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();

        // Check excludes first
        // If a directory matches an exclude pattern exactly, we skip it.
        // Note: We assume exclude patterns like `**/target` mean "exclude target directory and its contents".
        if exclude_patterns.iter().any(|p| p.matches_exact(&segments)) {
            return false;
        }

        // Check includes (prefix match)
        include_patterns.iter().any(|p| p.matches_prefix(&segments))
    };

    // Helper to add watch recursively
    let add_watch_recursive = {
        let inotify = inotify.clone();
        let watches = watches.clone();
        let paths = paths.clone();
        let should_watch_dir = should_watch_dir.clone();
        
        move |start_path: PathBuf| {
            let mut stack = vec![start_path];
            while let Some(path) = stack.pop() {
                if !should_watch_dir(&path) {
                    continue;
                }
                
                // Add watch
                let mut p_lock = paths.lock().unwrap();
                if p_lock.contains_key(&path) {
                    continue;
                }
                
                // Watch for everything interesting
                let mask = libc::IN_MODIFY | libc::IN_CLOSE_WRITE | libc::IN_CREATE | libc::IN_DELETE | libc::IN_MOVED_FROM | libc::IN_MOVED_TO;
                match inotify.add_watch(&path, mask as u32) {
                    Ok(wd) => {
                        p_lock.insert(path.clone(), wd);
                        watches.lock().unwrap().insert(wd, path.clone());
                        
                        // Read dir to find children
                        if let Ok(entries) = std::fs::read_dir(&path) {
                            for entry in entries.flatten() {
                                if let Ok(ft) = entry.file_type() {
                                    if ft.is_dir() {
                                        stack.push(entry.path());
                                    }
                                }
                            }
                        }
                    }
                    Err(_e) => {
                        // Ignore errors (e.g. permission denied)
                    }
                }
            }
        }
    };

    // Initial scan
    for pattern in &include_patterns {
        let mut current_path = PathBuf::from("/");
        for segment in &pattern.segments {
            match segment {
                Segment::Exact(s) => current_path.push(s),
                _ => break, // Stop at first wildcard
            }
        }
        add_watch_recursive(current_path);
    }

    // Event loop
    let mut buffer = [0u8; 4096];

    loop {
        match inotify.read_events(&mut buffer).await {
            Ok(len) => {
                // Parse events into a Vec to avoid holding raw pointers across await
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

                // Process events
                for (wd, mask, name_str) in events {
                    let full_path = {
                        let watches_lock = watches.lock().unwrap();
                        if let Some(dir_path) = watches_lock.get(&wd) {
                            Some(dir_path.join(&name_str))
                        } else {
                            None
                        }
                    };

                    if let Some(full_path) = full_path {
                        // Handle directory creation
                        if (mask & libc::IN_ISDIR as u32) != 0 {
                            if (mask & libc::IN_CREATE as u32) != 0 || (mask & libc::IN_MOVED_TO as u32) != 0 {
                                add_watch_recursive(full_path.clone());
                            }
                        }

                        // Check if we should notify
                        let path_str = full_path.to_string_lossy();
                        let path_str = path_str.replace("//", "/");
                        let segments: Vec<String> = path_str.split('/').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
                        
                        let is_excluded = exclude_patterns.iter().any(|p| p.matches_exact(&segments));
                        let is_included = include_patterns.iter().any(|p| p.matches_exact(&segments));
                        
                        if !is_excluded && is_included {
                            // Determine event type
                            let is_create = (mask & libc::IN_CREATE as u32) != 0 || (mask & libc::IN_MOVED_TO as u32) != 0;
                            let is_delete = (mask & libc::IN_DELETE as u32) != 0 || (mask & libc::IN_MOVED_FROM as u32) != 0;
                            let is_update = (mask & libc::IN_MODIFY as u32) != 0 || (mask & libc::IN_CLOSE_WRITE as u32) != 0;
                            
                            // Filter based on watch flags
                            let should_notify = (is_create && watch_create) || (is_delete && watch_delete) || (is_update && watch_update);
                            
                            if should_notify {
                                // Convert to relative path if appropriate
                                let callback_path = if let Some(ref base) = base_dir_for_relative {
                                    full_path.strip_prefix(base).unwrap_or(&full_path).to_path_buf()
                                } else {
                                    full_path
                                };
                                
                                callback(callback_path).await;
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
    pub async fn run_debounced<F, Fut>(self, ms: u64, mut callback: F) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        use tokio::sync::mpsc;
        
        let (tx, mut rx) = mpsc::unbounded_channel();
        
        // Spawn the watcher task
        let watcher_task = {
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = self.run(move |_path| {
                    let tx = tx.clone();
                    async move {
                        // Send a signal that an event occurred (we don't care about the path)
                        let _ = tx.send(());
                    }
                }).await;
            })
        };
        
        // Debounce logic
        let debounce_duration = Duration::from_millis(ms);
        let mut pending = false;
        let mut watcher_task = watcher_task;
        
        loop {
            tokio::select! {
                biased;
                
                // Handle watcher task completion (shouldn't normally happen)
                _ = &mut watcher_task => {
                    break;
                }
                // Receive an event
                Some(()) = rx.recv() => {
                    pending = true;
                }
                // Wait for quiet period
                _ = tokio::time::sleep(debounce_duration), if pending => {
                    // Check if there are more events in the queue
                    let mut has_more = false;
                    while rx.try_recv().is_ok() {
                        has_more = true;
                    }
                    
                    if !has_more {
                        // No more events, fire the callback
                        pending = false;
                        callback().await;
                    }
                    // If has_more, we stay pending and loop again
                }
            }
        }
        
        Ok(())
    }
}

/// Create a new file watcher builder with default settings
pub fn build_watcher() -> WatchBuilder {
    WatchBuilder {
        includes: Vec::new(),
        excludes: Vec::new(),
        base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        watch_create: true,
        watch_delete: true,
        watch_update: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::collections::HashSet;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    enum EventType {
        Create,
        Delete,
        Update,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct Event {
        path: PathBuf,
        event_type: EventType,
    }

    // Helper to track events
    type EventTracker = Arc<Mutex<Vec<Event>>>;

    fn create_tracker() -> EventTracker {
        Arc::new(Mutex::new(Vec::new()))
    }

    // Macro to check events
    macro_rules! check_events {
        ($tracker:expr, creates: [$($create:expr),*], deletes: [$($delete:expr),*], updates: [$($update:expr),*]) => {{
            // Wait up to 500ms for events
            tokio::time::sleep(Duration::from_millis(500)).await;
            
            let events = $tracker.lock().unwrap().clone();
            let mut expected = HashSet::new();
            
            $(
                expected.insert(Event {
                    path: PathBuf::from($create),
                    event_type: EventType::Create,
                });
            )*
            
            $(
                expected.insert(Event {
                    path: PathBuf::from($delete),
                    event_type: EventType::Delete,
                });
            )*
            
            $(
                expected.insert(Event {
                    path: PathBuf::from($update),
                    event_type: EventType::Update,
                });
            )*
            
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
            $tracker.lock().unwrap().clear();
        }};
    }

    async fn setup_test_dir(test_name: &str) -> PathBuf {
        let test_dir = std::env::current_dir().unwrap().join(format!(".file-watcher-test-{}", test_name));
        
        // Remove if exists
        if test_dir.exists() {
            std::fs::remove_dir_all(&test_dir).unwrap();
        }
        
        // Create fresh
        std::fs::create_dir(&test_dir).unwrap();
        test_dir
    }

    fn cleanup_test_dir(test_dir: &Path) {
        if test_dir.exists() {
            let _ = std::fs::remove_dir_all(test_dir);
        }
    }

    #[tokio::test]
    async fn test_file_create_update_delete() {
        let test_dir = setup_test_dir("create_update_delete").await;
        let tracker = create_tracker();
        let tracker_clone = tracker.clone();
        
        // Start watcher
        let watcher_handle = {
            let test_dir = test_dir.clone();
            tokio::spawn(async move {
                build_watcher()
                    .set_base_dir(&test_dir)
                    .add_include("**/*")
                    .run(move |path| {
                        let tracker = tracker_clone.clone();
                        let test_dir = test_dir.clone();
                        async move {
                            // Determine event type based on file existence
                            let full_path = test_dir.join(&path);
                            let event_type = if full_path.exists() {
                                if full_path.metadata().map(|m| m.len()).unwrap_or(0) > 0 {
                                    EventType::Update
                                } else {
                                    EventType::Create
                                }
                            } else {
                                EventType::Delete
                            };
                            
                            tracker.lock().unwrap().push(Event {
                                path: path.clone(),
                                event_type,
                            });
                        }
                    })
                    .await
            })
        };
        
        // Give watcher time to start
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Test 1: Create file
        std::fs::write(test_dir.join("test.txt"), "").unwrap();
        check_events!(tracker, creates: ["test.txt"], deletes: [], updates: []);
        
        // Test 2: Update file
        std::fs::write(test_dir.join("test.txt"), "hello").unwrap();
        check_events!(tracker, creates: [], deletes: [], updates: ["test.txt"]);
        
        // Test 3: Delete file
        std::fs::remove_file(test_dir.join("test.txt")).unwrap();
        check_events!(tracker, creates: [], deletes: ["test.txt"], updates: []);
        
        // Cleanup
        watcher_handle.abort();
        cleanup_test_dir(&test_dir);
    }

    #[tokio::test]
    async fn test_directory_operations() {
        let test_dir = setup_test_dir("directory_operations").await;
        let tracker = create_tracker();
        let tracker_clone = tracker.clone();
        
        // Start watcher
        let watcher_handle = {
            let test_dir = test_dir.clone();
            tokio::spawn(async move {
                build_watcher()
                    .set_base_dir(&test_dir)
                    .add_include("**/*")
                    .run(move |path| {
                        let tracker = tracker_clone.clone();
                        let test_dir = test_dir.clone();
                        async move {
                            let full_path = test_dir.join(&path);
                            let event_type = if full_path.exists() {
                                EventType::Create
                            } else {
                                EventType::Delete
                            };
                            
                            tracker.lock().unwrap().push(Event {
                                path: path.clone(),
                                event_type,
                            });
                        }
                    })
                    .await
            })
        };
        
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Test: Create directory
        std::fs::create_dir(test_dir.join("subdir")).unwrap();
        check_events!(tracker, creates: ["subdir"], deletes: [], updates: []);
        
        // Test: Create file in directory
        std::fs::write(test_dir.join("subdir/file.txt"), "").unwrap();
        check_events!(tracker, creates: ["subdir/file.txt"], deletes: [], updates: []);
        
        // Cleanup
        watcher_handle.abort();
        cleanup_test_dir(&test_dir);
    }

    #[tokio::test]
    async fn test_move_operations() {
        let test_dir = setup_test_dir("move_operations").await;
        let tracker = create_tracker();
        let tracker_clone = tracker.clone();
        
        // Start watcher
        let watcher_handle = {
            let test_dir = test_dir.clone();
            tokio::spawn(async move {
                build_watcher()
                    .set_base_dir(&test_dir)
                    .add_include("**/*")
                    .run(move |path| {
                        let tracker = tracker_clone.clone();
                        let test_dir = test_dir.clone();
                        async move {
                            let full_path = test_dir.join(&path);
                            let event_type = if full_path.exists() {
                                EventType::Create
                            } else {
                                EventType::Delete
                            };
                            
                            tracker.lock().unwrap().push(Event {
                                path: path.clone(),
                                event_type,
                            });
                        }
                    })
                    .await
            })
        };
        
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Create initial file
        std::fs::write(test_dir.join("old.txt"), "content").unwrap();
        check_events!(tracker, creates: ["old.txt"], deletes: [], updates: []);
        
        // Move file (generates delete + create)
        std::fs::rename(test_dir.join("old.txt"), test_dir.join("new.txt")).unwrap();
        check_events!(tracker, creates: ["new.txt"], deletes: ["old.txt"], updates: []);
        
        // Cleanup
        watcher_handle.abort();
        cleanup_test_dir(&test_dir);
    }

    #[tokio::test]
    async fn test_event_filtering() {
        let test_dir = setup_test_dir("event_filtering").await;
        let tracker = create_tracker();
        let tracker_clone = tracker.clone();
        
        // Start watcher with only create events
        let watcher_handle = {
            let test_dir = test_dir.clone();
            tokio::spawn(async move {
                build_watcher()
                    .set_base_dir(&test_dir)
                    .add_include("**/*")
                    .watch_create(true)
                    .watch_delete(false)
                    .watch_update(false)
                    .run(move |path| {
                        let tracker = tracker_clone.clone();
                        async move {
                            tracker.lock().unwrap().push(Event {
                                path: path.clone(),
                                event_type: EventType::Create,
                            });
                        }
                    })
                    .await
            })
        };
        
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Create file - should be detected
        std::fs::write(test_dir.join("test.txt"), "").unwrap();
        check_events!(tracker, creates: ["test.txt"], deletes: [], updates: []);
        
        // Update file - should NOT be detected
        std::fs::write(test_dir.join("test.txt"), "hello").unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(tracker.lock().unwrap().len(), 0, "Update event should not be detected");
        
        // Delete file - should NOT be detected
        std::fs::remove_file(test_dir.join("test.txt")).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(tracker.lock().unwrap().len(), 0, "Delete event should not be detected");
        
        // Cleanup
        watcher_handle.abort();
        cleanup_test_dir(&test_dir);
    }

    #[tokio::test]
    async fn test_pattern_matching() {
        let test_dir = setup_test_dir("pattern_matching").await;
        let tracker = create_tracker();
        let tracker_clone = tracker.clone();
        
        // Start watcher with pattern
        let watcher_handle = {
            let test_dir = test_dir.clone();
            tokio::spawn(async move {
                build_watcher()
                    .set_base_dir(&test_dir)
                    .add_include("**/*.txt")
                    .run(move |path| {
                        let tracker = tracker_clone.clone();
                        async move {
                            tracker.lock().unwrap().push(Event {
                                path: path.clone(),
                                event_type: EventType::Create,
                            });
                        }
                    })
                    .await
            })
        };
        
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Create .txt file - should be detected
        std::fs::write(test_dir.join("test.txt"), "").unwrap();
        check_events!(tracker, creates: ["test.txt"], deletes: [], updates: []);
        
        // Create .rs file - should NOT be detected
        std::fs::write(test_dir.join("test.rs"), "").unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(tracker.lock().unwrap().len(), 0, ".rs file should not be detected");
        
        // Cleanup
        watcher_handle.abort();
        cleanup_test_dir(&test_dir);
    }

    #[tokio::test]
    async fn test_relative_paths() {
        let test_dir = setup_test_dir("relative_paths").await;
        let tracker = create_tracker();
        let tracker_clone = tracker.clone();
        
        // Start watcher
        let watcher_handle = {
            let test_dir = test_dir.clone();
            tokio::spawn(async move {
                build_watcher()
                    .set_base_dir(&test_dir)
                    .add_include("**/*")
                    .run(move |path| {
                        let tracker = tracker_clone.clone();
                        async move {
                            // Path should be relative
                            assert!(!path.is_absolute(), "Path should be relative: {:?}", path);
                            
                            tracker.lock().unwrap().push(Event {
                                path: path.clone(),
                                event_type: EventType::Create,
                            });
                        }
                    })
                    .await
            })
        };
        
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Create file
        std::fs::write(test_dir.join("test.txt"), "").unwrap();
        check_events!(tracker, creates: ["test.txt"], deletes: [], updates: []);
        
        // Cleanup
        watcher_handle.abort();
        cleanup_test_dir(&test_dir);
    }
}
