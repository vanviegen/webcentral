# Webcentral

A reverse proxy that runs multiple web applications on a single server. Just put your apps in directories named after their domains (like `myapp.example.com`), point its DNS at the server, and you're done! The apps will start (and shutdown) on-demand, and reload when their files change.


## Architecture

### Files

`server.go` - HTTP/HTTPS listeners, ACME certificate management, domain routing, www/HTTPS redirects, directory watching

`project.go` - Per-domain lifecycle manager supporting: applications (Firejail/Docker), static files, redirects, proxies, forwards. Handles file watching, auto-reload, inactivity timeouts, URL rewrites

`logger.go` - Daily-rotated logs with configurable retention

`config.go` - Parses `webcentral.ini` and `package.json`

`main.go` - Entry point, command-line args, starts server

`test.py` - Test suite and harness

### State Machine

Each Project has one lifecycle goroutine owning all mutable state. Four phases:

- **stopped** → `starting` (apps) or `running` (static/proxy)
- **starting** → `running` (port ready) or `stopped` (failure), queues requests
- **running** → `stopping` (file change/timeout)
- **stopping** → `stopped` (after SIGTERM/SIGKILL), queues requests, auto-restarts if queued

Events sent via buffered channel (`eventCh`): `start`, `process_started`, `ready`, `exit`, `file_changed`, `timeout`, `stop_complete`

### Goroutines

**Per-project:**
1. **Lifecycle** - Sole owner of state, processes events from `eventCh`
2. **Process monitors** - Wait on `cmd.Wait()`, send `exit` events
3. **Port waiter** - Polls port availability (30s timeout), sends `ready`/`exit`
4. **Stop handler** - Sends `stop_complete` after 2.5s grace period
5. **File watcher** - One-shot: sends `file_changed` then exits (recreated on restart)
6. **Inactivity timer** - Periodic `timeout` events (if configured)
7. **Log streamers** - 2 per process (stdout/stderr)
8. **Request handlers** - HTTP server managed, stateless, block on completion channels

**Server-level:**
- HTTP/HTTPS listeners
- Certificate acquisition
- Directory watcher

### Locking

**Project-level: None needed**
- Actor model: lifecycle goroutine owns all mutable state
- Other goroutines use message passing via `eventCh`
- Immutable fields (`dir`, `config`, `logger`, `uid`, `gid`, `useFirejail`, `pruneLogs`) safe to read anywhere

**Server-level: Four mutexes for shared caches**
1. `projectsMu` - Protects `projects` map (domain → Project)
2. `bindingsMu` (RWMutex) - Domain → directory cache with double-checked locking
3. `certRequestsMu` - Deduplicates certificate requests
4. `approvedHostsMu` (RWMutex) - ACME approval cache

**Logger:** Internal locking for concurrent writes


## Developers notes

- Keep AGENTS.md up-to-date when making architectural changes. Be succinct—no repetition, no code examples, bullet points over paragraphs.
- Build using `go build`.
- Run `./test.py` to execute the test suite. To run a single test: `./test.py test_name_of_test`. For new features, add tests in `test.py`. Don't create ad-hoc test scripts. When writing tests, you should not need to sleep (except in test-apps being run by webcentral to simulate loading times) - use `await_log` and/or `assert_http` instead. If a test fails, don't just work around it in the test code, but investigate deeply if there may be an actual bug (or unexpected behavior) in webcentral.
- When you notice unexpected behavior or a like bug at any time, create an issue on your todo-list for later investigation. Never let bugs uninvestigated nor work around them.
- Add code comments only for explaining non-obvious logic, why things are done a certain way, and how thread-safety is ensured. Don't add comments describing what you're changing and why, as comments should reflect the final code, not the change history.
