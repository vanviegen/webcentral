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
- Certificate acquisition - One task per domain, stored in `DomainInfo::cert_task` and aborted
  when that is dropped

One certificate per domain, covering the domain and - when `redirect_www` is on - its www/non-www
counterpart, stored under the registered domain's name (so the SNI resolver falls back to the
counterpart's file). Before ordering, `points_at_us()` fetches `/.well-known/webcentral-self-check`
over port 80 for each name and compares the response with a token generated fresh each run. This
is the same round trip the ACME server makes, so it establishes up front whether an HTTP-01
challenge would succeed, without burning Let's Encrypt rate limits: a counterpart that doesn't
resolve here (the common case) is left off the certificate, and a domain that doesn't resolve here
is an error, retried hourly. Both names are re-checked on every cycle, including while the
certificate is still valid, so a name that starts or stops pointing here is picked up (comparing
against the stored certificate's SANs) long before renewal.

Accept loops must never return on an `accept()` error: that drops the `TcpListener` and stops
listening for the rest of the process lifetime, while the process stays alive so systemd's
`Restart=always` never fires. Errors go to `handle_accept_error`, which retries and backs off
500ms on resource exhaustion (retrying immediately would spin, as the pending connection keeps
the listener readable). `main` also raises `RLIMIT_NOFILE` to the hard limit at startup.

### Synchronization

**Project-level:**
- `watch::channel<AppState>` - State broadcasting, requests wait via `wait_for()`
- `mpsc::channel<StopReason>` - Stop signals (FileChange, Inactivity, ProcessExit, Shutdown)
- `AtomicUsize` pending_requests - Tracks in-flight requests, triggers startup
- `AtomicUsize` active_upgrades - Tracks active WebSocket/upgraded connections. Inactivity timeout only triggers when count is 0.
- `Notify` state_changed - Wakes lifecycle_task when pending_requests changes
- `Mutex<Option<AppConnection>>` - Dynamic port/client per restart cycle
- `Mutex<Instant>` last_activity - Tracks for inactivity timeout
- `Mutex<Option<JoinHandle>>` watcher_task - For aborting file watcher

**Server-level:**
- `DashMap<String, DomainInfo>` - Concurrent domain → project mapping (lock-free reads)
- `DomainInfo::project: Option<Arc<Project>>` - Per-domain project instance (None after deregister)
- `deregister_project()` - Called from the file watcher callback and on Failed, sets project to None, next request creates new

**Logger:** Internal mutex for concurrent writes, automatic log rotation on date change

### Process Management

**Graceful shutdown:** On stop signal, SIGTERM with 5s grace period then SIGKILL. Processes killed via reference to avoid racing with restart.

**Dynamic port allocation:** New port allocated on each startup cycle to avoid TIME_WAIT conflicts.

**Process exit detection:** `wait_for_port_ready` polls `try_wait()` to detect early process exit during startup.

**Firejail sandboxing** (when enabled, non-Docker):
- Private /tmp and /dev
- Read-only root, read-write project dir
- Whitelist project directory only

**Docker/Podman** (when configured), driven by `get_engine()`, which prefers podman and records
which engine it found (only podman can remap uids per mount):
- Custom Dockerfile generation: packages, build commands, and - when the project dir is mounted -
  the project owner appended to `/etc/passwd`+`/etc/group` followed by a `USER` directive
- Image tagged `webcentral-<dir hash>:<Dockerfile hash>`, so an unchanged config skips the build
- Stale container of the same name force-removed before `run` (a container outliving its webcentral
  otherwise wedges the project with a name conflict)
- Port mapping from internal to host
- Volume mounts for app dir and additional paths

**Container user:** whoever the *image* declares, rather than a runtime `--user`, so both cases work
the same way. With `mount_app_dir = true` webcentral owns the image and bakes the project owner into
it (otherwise the app writes root-owned files into the user's project dir); with `mount_app_dir =
false` the image is a third-party application that keeps its own user (forcing one breaks
image-baked directories). `[docker] user` overrides either. `mounts[]` directories are chowned to
the uid/gid the container actually runs as - found via `container_user_ids()`, which runs `id` in
the image and caches per image+user - since otherwise a non-root container gets EACCES. Skipped
when that's root, which can write regardless. `[docker] idmap` (rootful podman only - the kernel
forbids idmapped mounts for unprivileged users, and docker has no per-container equivalent) shifts
uids per mount instead, so files land owned by the project user. Podman's triplets are
`<backing-fs-id>-<mapped-id>-<count>`, `;` between uids and gids.

**Workers:** Additional processes spawned alongside main application, share PORT env var

### File Watching

**Project-level:** Recursive watch on project directory

**Default excludes:** `_webcentral_data/**`, `node_modules/**`, `**/*.log`, `**/.*`, `data/**`, `log/**`, `logs/**`

**Reload triggers:** Configurable includes/excludes, defaults to all files for applications, only config files for static/proxy

**On change:** The file watcher callback calls `deregister_project()` itself, then sends `StopReason::FileChange` to lifecycle_task/stop_listener, which tear down the old instance. Deregistering in the callback rather than in the receiving task closes the window in which requests would still be routed to the outgoing project. New project instance created on next request.

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
- Build and test using `cargo build && ./test.py --firejail false` (or `--firejail true` if Firejail is installed). Builds default to musl target for static linking (configured in `.cargo/config.toml`).
- For async task debugging, build with `cargo build --features console` and connect via `~/.cargo/bin/tokio-console` (install with `cargo install tokio-console`).
- Run `./test.py` to execute the test suite. To run a single test: `./test.py test_name_of_test`. For new features, add tests in `test.py`. Don't create ad-hoc test scripts. When writing tests, you should not need to sleep (except in test-apps being run by webcentral to simulate loading times) - use `await_log` and/or `assert_http` instead. If a test fails, don't just work around it in the test code, but investigate deeply if there may be an actual bug (or unexpected behavior) in webcentral.
- Add code comments only for explaining non-obvious logic, why things are done a certain way, and how thread-safety is ensured. Don't add comments describing what you're changing and why, as comments should reflect the final code, not the change history.
- When you notice unexpected behavior or a bug at any time, create an issue on your todo-list for later investigation. Never let bugs go uninvestigated nor work around them.
- When trying to debug problems, do not fiddle around with ad-hoc shell commands too much. The user needs to approve all of these. Instead, extend `test.py` to clearly demonstrate the problem, and if needed add (temporary, with a `TODO: remove` comment) logging to the code (but prefer to just improve error logging).
- **Releases:** Increment version in `Cargo.toml` (x.y.z: x for rewrites, y for major features, z for minor/bugfixes) and add changelog entry in README.md. Create release by pushing git tag: `git tag v2.4.3 && git push origin v2.4.3`. GitHub Actions (`.github/workflows/release.yml` via cargo-dist) builds static binaries (musl x86_64, aarch64 gnu, x86_64 gnu) and creates GitHub Release with artifacts and installer script. Regular commits to main don't trigger releases.

## AI guidance

- AI agents should be succinct in their textual output. Especially when in 'thinking' mode, they should restrict verbosity to the absolute minimum, leaving out social niceties and sacrificing grammar for brevity.
