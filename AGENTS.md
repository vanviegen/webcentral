# Webcentral

A reverse proxy that runs multiple web applications on a single server. Just put your apps in directories named after their domains (like `myapp.example.com`), point its DNS at the server, and you're done! The apps will start (and shutdown) on-demand, and reload when their files change.


## Architecture

### Files

`src/main.rs` - Entry point, command-line args, starts server, handles shutdown

`src/server.rs` - HTTP/HTTPS listeners, ACME certificate management, domain routing, www/HTTPS redirects, directory watching

`src/project.rs` - Per-domain lifecycle manager supporting: applications (Firejail/Docker), static files, redirects, proxies, forwards. Handles file watching, auto-reload, inactivity timeouts, URL rewrites

`src/logger.rs` - Daily-rotated logs with configurable retention

`src/project_config.rs` - Parses `webcentral.ini`, `Procfile`, and `package.json`

`src/file_watcher.rs` - File system watching with include/exclude patterns

`src/streams.rs` - Stream abstraction (AnyConnector/AnyStream) for HTTP/TCP/Unix socket connections

`src/acme.rs` - ACME/Let's Encrypt certificate acquisition using HTTP-01 challenges

`test.py` - Test suite and harness

### State Machine

Each Project uses `Arc<Mutex<ProjectState>>` for lifecycle management. Three states:

- **Stopped** → `Starting` (applications) or remains `Stopped` (static/proxy/forward don't need startup)
- **Starting** → `Running` (port ready) or `Stopped` (failure), requests wait for startup
- **Running** → `Stopped` (file change/timeout)

No explicit stopping state—process termination handled asynchronously in background.

### Concurrency Model

**Runtime:** Tokio async/await with task spawning

**Per-project tasks:**
1. **File watcher** - Spawned once, aborted on reload, handle stored in `watcher_task` mutex
2. **Inactivity timer** - Periodic checks, stops project on timeout
3. **Process monitor** - Polls process status, transitions to `Stopped` when process exits
4. **Log streamers** - 2 per process (stdout/stderr), plus 2 per worker
5. **Stop handler** - Background task for graceful shutdown (5s grace period)
6. **Request handlers** - Hyper-managed tasks, wait for `ensure_started()` completion

**Server-level tasks:**
- HTTP listener - Spawns connection handler per TCP connection
- HTTPS listener - TLS handshake then spawns connection handler
- Directory watcher - Detects new/removed project directories
- Certificate acquisition - One task per domain, deduplicated via atomic flag

### Synchronization

**Project-level:**
- `Arc<Mutex<ProjectState>>` - Serializes state transitions (Stopped/Starting/Running)
- `Arc<Mutex<Instant>>` - Tracks last activity for timeout
- `Mutex<Option<JoinHandle>>` - File watcher task handle for aborting on reload
- State read during request handling, written during lifecycle transitions

**Server-level:**
- `DashMap<String, DomainInfo>` - Concurrent domain → project mapping (lock-free reads)
- `DomainInfo::project: RwLock<Option<Arc<Project>>>` - Per-domain project instance
- `DomainInfo::cert_acquiring: AtomicBool` - Deduplicates certificate requests
- `DomainInfo::cert_ready: Notify` - Wakes waiters when certificate ready
- `CertManager::account: RwLock<Option<Account>>` - Shared ACME account
- `CertManager::challenges: RwLock<HashMap>` - HTTP-01 challenge storage

**Logger:** Internal mutex for concurrent writes, automatic log rotation on date change

### Process Management

**Firejail sandboxing** (when enabled, non-Docker):
- Private /tmp and /dev
- Read-only root, read-write project dir
- Whitelist project directory only

**Docker** (when configured):
- Custom Dockerfile generation
- Port mapping from internal to host
- Volume mounts for app dir and additional paths
- User/group mapping from host
- Dynamic image naming based on project dir hash

**Workers:** Additional processes spawned alongside main application, share PORT env var

### File Watching

**Project-level:** Recursive watch on project directory

**Default excludes:** `_webcentral_data/**`, `node_modules/**`, `**/*.log`, `**/.*`, `data/**`, `log/**`, `logs/**`

**Reload triggers:** Configurable includes/excludes, defaults to all files for applications, only config files for static/proxy

**On change:** Project calls `stop()` which uses `remove_project_if_current()` with Arc ptr equality to remove from DOMAINS only if still active, then aborts watcher task and kills processes. New instance created on next request.

**Server-level:** Non-recursive watch on project parent directories for domain additions/removals


### Test Infrastructure

**test.py** - Python test harness that:
- Creates temporary project directories
- Starts webcentral with HTTP-only mode on random port
- Provides helpers: `write_file`, `assert_http`, `await_log`, `assert_log`, `mark_log_read`
- Automatically tracks log positions per-project for incremental reading
- Shows log output on test failure, preserves test directory for inspection
- Supports running individual tests or full suite
- Can disable Firejail with `--firejail=false` flag

**Test patterns:**
- Each test auto-creates domain from test name: `test_foo_bar` → `foo-bar.test`
- Create files: `t.write_file('path', 'content')` (auto-prefixed with test domain)
- Mark logs read: `t.mark_log_read()` (defaults to test domain)
- Wait for log: `t.await_log('text', timeout=2)` (defaults to test domain)
- Assert HTTP: `t.assert_http('/path', check_body='text')` (defaults to test domain)
- Count logs: `t.assert_log('text', count=1)` (defaults to test domain)

**file_watcher.rs** - Module with its own unit tests
- Use: `cargo build && cargo test --lib file_watcher`

## Developers notes

- Keep AGENTS.md up-to-date when making architectural changes. Be succinct—no repetition, no code examples, bullet points over paragraphs.
- Build and test using `cargo build && ./test.py --firejail false` (or `--firejail true` if Firejail is installed).
- Run `./test.py` to execute the test suite. To run a single test: `./test.py test_name_of_test`. For new features, add tests in `test.py`. Don't create ad-hoc test scripts. When writing tests, you should not need to sleep (except in test-apps being run by webcentral to simulate loading times) - use `await_log` and/or `assert_http` instead. If a test fails, don't just work around it in the test code, but investigate deeply if there may be an actual bug (or unexpected behavior) in webcentral.
- Add code comments only for explaining non-obvious logic, why things are done a certain way, and how thread-safety is ensured. Don't add comments describing what you're changing and why, as comments should reflect the final code, not the change history.
- When you notice unexpected behavior or a bug at any time, create an issue on your todo-list for later investigation. Never let bugs go uninvestigated nor work around them.
- When trying to debug problems, do not fiddle around with ad-hoc shell commands too much. The user needs to approve all of these. Instead, extend `test.py` to clearly demonstrate the problem, and if needed add (temporary, with a `TODO: remove` comment) logging to the code (but prefer to just improve error logging).

## AI guidance

- AI agents should be succinct in their textual output. Especially when in 'thinking' mode, they should restrict verbosity to the absolute minimum, leaving out social niceties and sacrificing grammar for brevity.
