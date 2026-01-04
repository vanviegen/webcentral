# Webcentral

A reverse proxy that runs multiple web applications for multiple users on a single server. Just put your app in a directory named like the target domain (eg `myapp.example.com/`), point DNS at the server, and you're done! The app will start (and shutdown) on-demand, and reload when its files change.


## Architecture

### Files

`src/main.rs` - Entry point, command-line args, starts server, handles shutdown

`src/server.rs` - HTTP/HTTPS/HTTP3 listeners, ACME certificate management, domain routing, www/HTTPS redirects, directory watching

`src/project.rs` - Per-domain lifecycle manager supporting: applications (Firejail/Docker), static files, redirects, proxies, forwards. Handles file watching, auto-reload, inactivity timeouts, URL rewrites

`src/logger.rs` - Daily-rotated logs with configurable retention

`src/project_config.rs` - Parses `webcentral.ini`, `Procfile`, and `package.json`

`src/streams.rs` - Stream abstraction (AnyConnector/AnyStream) for HTTP/TCP/Unix socket connections

`src/acme.rs` - ACME/Let's Encrypt certificate acquisition using HTTP-01 challenges

`test.py` - Test suite and harness

### State Machine

Application projects use `AppState` enum with explicit state machine in `lifecycle_task`:

- **Stopped** - Waiting for request (triggers startup via `pending_requests` counter)
- **Starting** - Spawning processes, waiting for port ready, detecting process exit
- **Running** - Processing requests, monitoring for stop triggers (file change, inactivity, process exit, shutdown)
- **Failed** - After 2 startup failures, deregisters from server

Non-Application types (Static, Proxy, Forward, Redirect) don't have a lifecycle_task but listen for FileChange via `stop_listener`.

### Concurrency Model

**Runtime:** Tokio async/await with task spawning

**Per-project tasks:**
1. **File watcher** - Spawned once, aborted on reload, handle stored in `watcher_task` mutex
2. **Lifecycle task** (Application) - State machine managing Stopped→Starting→Running→Stopped transitions
3. **Stop listener** (non-Application) - Simple listener for FileChange to trigger deregistration
4. **Log streamers** - 2 per process (stdout/stderr), plus 2 per worker

**Server-level tasks:**
- HTTP listener - Spawns connection handler per TCP connection
- HTTPS listener - TLS handshake then spawns connection handler
- Directory watcher - Detects new/removed project directories
- Certificate acquisition - One task per domain, deduplicated via atomic flag

### Synchronization

**Project-level:**
- `watch::channel<AppState>` - State broadcasting, requests wait via `wait_for()`
- `mpsc::channel<StopReason>` - Stop signals (FileChange, Inactivity, ProcessExit, Shutdown)
- `AtomicUsize` pending_requests - Tracks in-flight requests, triggers startup
- `Notify` state_changed - Wakes lifecycle_task when pending_requests changes
- `Mutex<Option<AppConnection>>` - Dynamic port/client per restart cycle
- `Mutex<Instant>` last_activity - Tracks for inactivity timeout
- `Mutex<Option<JoinHandle>>` watcher_task - For aborting file watcher

**Server-level:**
- `DashMap<String, DomainInfo>` - Concurrent domain → project mapping (lock-free reads)
- `DomainInfo::project: Option<Arc<Project>>` - Per-domain project instance (None after deregister)
- `deregister_project()` - Called on FileChange/Failed, sets project to None, next request creates new

**Logger:** Internal mutex for concurrent writes, automatic log rotation on date change

### Process Management

**Graceful shutdown:** On stop signal, SIGTERM with 5s grace period then SIGKILL. Processes killed via reference to avoid racing with restart.

**Dynamic port allocation:** New port allocated on each startup cycle to avoid TIME_WAIT conflicts.

**Process exit detection:** `wait_for_port_ready` polls `try_wait()` to detect early process exit during startup.

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

**On change:** File watcher sends `StopReason::FileChange` to lifecycle_task/stop_listener. For Applications, deregisters immediately in `run_until_stop` before killing processes so new requests get new project. For non-Applications, `stop_listener` deregisters and exits. New project instance created on next request.

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

## Developers notes

- Keep AGENTS.md up-to-date when making architectural changes. Be succinct—no repetition, no code examples, bullet points over paragraphs.
- Build and test using `cargo build && ./test.py --firejail false` (or `--firejail true` if Firejail is installed).
- For async task debugging, build with `cargo build --features console` and connect via `~/.cargo/bin/tokio-console` (install with `cargo install tokio-console`).
- Run `./test.py` to execute the test suite. To run a single test: `./test.py test_name_of_test`. For new features, add tests in `test.py`. Don't create ad-hoc test scripts. When writing tests, you should not need to sleep (except in test-apps being run by webcentral to simulate loading times) - use `await_log` and/or `assert_http` instead. If a test fails, don't just work around it in the test code, but investigate deeply if there may be an actual bug (or unexpected behavior) in webcentral.
- Add code comments only for explaining non-obvious logic, why things are done a certain way, and how thread-safety is ensured. Don't add comments describing what you're changing and why, as comments should reflect the final code, not the change history.
- When you notice unexpected behavior or a bug at any time, create an issue on your todo-list for later investigation. Never let bugs go uninvestigated nor work around them.
- When trying to debug problems, do not fiddle around with ad-hoc shell commands too much. The user needs to approve all of these. Instead, extend `test.py` to clearly demonstrate the problem, and if needed add (temporary, with a `TODO: remove` comment) logging to the code (but prefer to just improve error logging).

## AI guidance

- AI agents should be succinct in their textual output. Especially when in 'thinking' mode, they should restrict verbosity to the absolute minimum, leaving out social niceties and sacrificing grammar for brevity.
