# Webcentral

A reverse proxy that runs multiple web applications for multiple users on a single server. Just put your app in a directory named like the target domain (eg `myapp.example.com/`), point DNS at the server, and you're done! The app will start (and shutdown) on-demand, and reload when its files change.

## Architecture

### Files

`src/main.rs` - Entry point, command-line args, starts server, handles shutdown

`src/server.rs` - HTTP/HTTPS/HTTP3 listeners, ACME certificate management, domain routing, www/HTTPS redirects, directory watching

`src/project.rs` - Per-domain glue: owns the config, the servers, the file watcher, and the
request entry point (running the script, then forwarding/proxying/upgrading as it decided)

`src/app_server.rs` - One managed service: lifecycle state machine, image preparation, podman
command construction, container user/ownership policy

`src/script.rs` - The routing script: statement AST, capture scoping, templates, and the
interpreter. Also static-file resolution (streamed, with `Range`/`If-Range` support) and the
`check_auth` secret comparison

`src/config.rs` - The configuration model and the parser for `webcentral.conf`; auto-detection
synthesises the same language rather than a separate code path. Only a `Dockerfile` (which answers
every question there is) and `package.json`, because `scripts.start` is the one other convention
that says how to *start* something - other manifests say what to install, which is a different
question

`src/parser.rs` - Scanner for the configuration language: words, quoting, blocks, diagnostics

(Include/exclude path matching lives in the `include-exclude-watcher` crate's public `Matcher`,
which webcentral uses to decide which server a changed file belongs to.)

`src/owner.rs` - Who a project belongs to: resolves the owner, checks the host can run rootless
podman as them (subordinate ids present and not overlapping, `newuidmap` installed, every
directory above the project traversable), and hands out a `Command` that will - which means
re-pointing *everything* a child inherits that could name the wrong user: the XDG directories, the
container config overrides, and the working directory

`src/dashboard.rs` - The built-in status page. A section per project rather than a row, since a
project is a script, some services and their sidecars rather than one thing with a type: each
service's image/command/state/port and counts, its sidecars nested under it with the
`<name>.internal:<port>` their peers use, a tally of which *kind* of statement answered, and the
script itself as a nested list. The script is rendered from the AST (`script::outline`) rather
than from the file, so it shows what actually runs - including the implicit tail, which is marked
as such because it is the one statement a reader cannot find in the file. `check_auth`'s secret is
never rendered. The tally is per kind rather than per statement, so no statement has to carry an
identity; `script::Outcome::answered_by` names it as the terminal is produced

`src/logger.rs` - Daily-rotated logs with configurable retention

`src/streams.rs` - Stream abstraction (AnyConnector/AnyStream) for HTTP/HTTPS/TCP/Unix socket
connections; `upstream_tls` builds the client config once from the system trust store

`src/acme.rs` - ACME/Let's Encrypt certificate acquisition using HTTP-01 challenges

`test.py` - Test suite and harness

`MIGRATION-v3.md` - Converting a 2.x project; linked from the README's announcement and its
**Upgrading from 2.x** section, so a change to the language belongs here too

### Configuration language

`webcentral.conf` is a list of `verb argument... name=value...` statements, some with a `{ ... }`
block. Which of the two shapes a line has is known from the enclosing block, never from the line
itself: server/env/settings blocks hold `key = value` settings, everywhere else holds
statements. That is what keeps `=` an ordinary character in patterns and secrets. Braces are
structure only when they stand alone as a word, so a `{2}` quantifier needs no quoting.

Declarations (`settings`, `service`) are top-level only and hoisted - except that a
`service` nested inside another is a *sidecar*, sharing its parent's lifetime (and, when it
names no `base` of its own, its parent's image - which is how an extra worker process is
declared; there is no separate worker concept). Everything else forms the script. Errors are collected with line/column and the scanner
skips to the next line (and its body, so a `match /x { respond 200 y }` that fails to parse
doesn't leave `respond 200 y` behind), so one parse reports every problem. A conditional's body is
always a `{ ... }` block, on one line or many - never a bare statement.

Every statement declares a `Signature`: positional parameters, which may also be given as
`name=value`, then named-only modifiers, each with a `Kind` saying what its word becomes. One
binder turns a line into those values, so the rules - unknown names reported, values given twice
refused, required ones checked - are identical everywhere. `Kind` also decides substitution:
`Word` is rendered as the file is read (so it sees the constants above it), `Template` is kept for
request time, and `Variable` is a name and so is left alone. Declaration settings are rendered the
same way through `Builder::expand`; nothing is exempt.

`${name}` is the *only* substitution: a `$` not followed by `{` is an ordinary character, so
regexes, prices and a shell's `$PORT`/`$HOME`/`$$` pass through with nothing to escape, and a
literal `${` is single-quoted. A brace only counts as block structure when it *starts* a word,
which is what lets `${1}` end one and `x{2}` be a quantifier. Every name a template reads is
collected and checked at the end against everything the file defines, so a typo is reported
rather than being silently empty.

`env_file <path>` reads `KEY=value` lines into those same constants, in file order like `set`, so
a secret lives outside `webcentral.conf` and reaches only what names it - nothing is injected into
any process by itself. The path must be inside the project directory (an absolute one would let a
project read anything a root webcentral can), it joins `config_files` so editing it reloads the
project, and nothing it defines is injected anywhere by itself.

**Container environment** is handed over through podman's *own* environment: `add_env_args` sets
each variable on the `podman run` child and names it with a valueless `-e NAME`. `podman run`
lives as long as its container and `/proc/<pid>/cmdline` is world-readable, so `-e NAME=value`
would let any user on the machine read another project's secrets with `ps`; `/proc/<pid>/environ`
is 0400 instead, and nothing is written to disk. The exception is `PODMAN_READS_ENV` - `HOME`,
`PATH`, the `XDG_*` and `CONTAINERS_*` names - which configure podman itself and so must stay on
the command line; they are paths and locales rather than secrets, and `describe()` still hides
their values in the log.

### Request handling

`script::run` walks the statements against the request, mutating its URI when `path` or `query`
are assigned and collecting response headers, and returns a `Terminal` describing what should
answer:
a ready `Response`, or a `ServeApp`/`Forward`/`Proxy` for `project.rs` to perform with the request
body it still owns. Keeping the body out of the interpreter is what lets the same script drive
both ordinary requests and protocol upgrades.

Three statements are conditionals (`match`, `check_auth`, `check_file`) and carry an optional
`else` branch, attached at parse time to the statement it follows. `serve_file`/`serve_dir` take
`fallthrough=true` instead of declining into an `else`, so what a statement does is legible from
the statement rather than from a branch below it. Everything else is terminal or a modifier. An
implicit tail (`serve` / `serve_dir public` / 404) is appended to every script.

`forward` and `proxy` targets are checked when the file is read, but only when they are written
out in full - one built from `${...}` is whatever the request makes it. `proxy https://...`
connects over TLS (`AnyConnector::Https`), verifying the upstream against the system trust store.

Request and response bodies are streamed end to end (`retry_canceled_requests` is off, since a
partly-sent streamed body can never be replayed). An upstream response carrying
`X-Accel-Redirect: /path` is discarded and the request re-run through the script as a bodyless GET
for that path, with `$redirected_from`/`$redirected_by` set and the redirecting response's other
headers carried onto the final one; one redirect per request, no chains.

Variables are one flat `Vars` map per request, cloned from the constants the file's top-level
`set` statements defined. `match` writes the groups it captured (only those it has, so a nested
match that captures nothing leaves its parent's `$1` alone), `set` writes what it is given, and
`path`/`query`/`method`/`host` are refreshed whenever the request changes. The first two *are* the
request: `set path` and `set query` re-point what is served or forwarded (`script::set_target`),
and a path may carry its own `?query` - a lone `?` drops it. The rest are read-only and `set`
refuses them. Last write wins; there
is no scope. Single-quoted parts of a word are recorded as literal spans by the scanner, so the
template parser can leave their `$` alone.

### State Machine

Each server uses the `AppState` enum with an explicit state machine in `AppServer::lifecycle_task`:

- **Stopped** - Waiting for a request (triggers startup via the `pending_requests` counter)
- **Starting** - Spawning processes, waiting for port ready, detecting process exit
- **Running** - Serving, monitoring for stop triggers (file change, inactivity, process exit, shutdown)
- **Failed** - Startup failed; waiting requests get a 502 and a later file change retries

A project with no servers (static, proxy, redirect, forward) has no lifecycle task at all.

### Reading a project

A project's configuration is read when its directory appears, not when the first request arrives,
so a configuration error reaches its log while whoever wrote it is still looking and the dashboard
can show a project nobody has visited (`server::load_project`). Reading starts no containers - a
request does that - but it does *prepare* images, so a global semaphore (`app_server::image_work`,
4 permits) keeps sixty projects from pulling sixty images at once on startup.

Reading is delayed by `SETTLE` (2s), because a directory usually appears because a deploy is in
progress: reading it while its files are still landing would answer from half a project. A request
arriving first reads it itself, which makes the delayed read a no-op. For the same reason the
implicit static tail is *not* conditional on `public/` existing at read time - `serve_dir public`
404s by itself when there is nothing there, and a tail chosen from an empty directory would go on
404ing after the files arrived.

A change to a project-defining file tears the project down and reads it again straight away
(`Project::reload` -> `server::reload_project_by_dir`), rather than leaving it for the next
request.

### Concurrency Model

**Runtime:** Tokio async/await with task spawning

**Per-project tasks:**
1. **Change debouncer** - Collects file changes from the process-wide watcher until they stop
   arriving, then acts on the batch. Holds a `Weak<Project>` so it ends with the project
2. **Lifecycle task** - One per declared server, managing Stopped→Starting→Running→Stopped
3. **Log streamers** - 2 per process (stdout/stderr), plus 2 per sidecar

**Server-level tasks:**
- HTTP listener - Spawns connection handler per TCP connection
- HTTPS listener - TLS handshake then spawns connection handler
- Directory watcher - Detects new/removed project directories
- File watcher - **One for every project at once.** An inotify *instance* is a scarce per-user
  resource (`fs.inotify.max_user_instances`, 128 by default) while the *watches* it holds are not
  (hundreds of thousands), so one watcher for the whole tree costs the same in watches as one per
  project and nothing in instances - 60 projects go from 61 instances to 2. Which project, and
  which of its servers, an event concerns is decided in-process by the
  `include-exclude-watcher` crate's `Matcher`. It is not
  debounced at the watcher: a debounce window is global to it, and the crate reports only the
  first path of a batch, so a busy moment on one project would swallow another's event. Each
  project debounces its own changes instead. `Project::reload` ignores an event whose file mtime
  equals the snapshot taken when the project loaded (the watcher runs from before any project
  exists, so the write that created a project can be reported just after it was built); it
  compares for *difference* rather than newness because deploy tools like `rsync -a` preserve
  mtimes
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

**Per-server:**
- `watch::channel<AppState>` - State broadcasting, requests wait via `wait_for()`
- `mpsc::channel<StopReason>` - Stop signals (FileChange, Inactivity, ProcessExit, Shutdown)
- `AtomicU64` pending_requests - Tracks in-flight requests, triggers startup
- `AtomicU64` active_upgrades - Tracks active WebSocket/upgraded connections. Inactivity timeout only triggers when count is 0.
- `Notify` state_changed - Wakes lifecycle_task when pending_requests changes
- `Mutex<Option<AppConnection>>` - Dynamic port/client per restart cycle
- `Mutex<Instant>` last_activity - Tracks for inactivity timeout

**Server-level:**
- `DashMap<String, DomainInfo>` - Concurrent domain → project mapping (lock-free reads)
- `DomainInfo::project: Option<Arc<Project>>` - Per-domain project instance (None after deregister)
- `deregister_project_by_dir()` - Called from the config watcher before tearing a project down,
  sets project to None so requests stop reaching the outgoing instance; next request creates new

**Logger:** Internal mutex for concurrent writes, automatic log rotation on date change

### Process Management

**Graceful shutdown:** On stop signal, SIGTERM with 5s grace period then SIGKILL. Processes killed via reference to avoid racing with restart.

**Process shutdown** listens for SIGINT *and* SIGTERM (systemd and `podman stop` send the latter),
and `stop_all_projects` awaits each server's `wait_finished` - a watch flag the lifecycle task sets
as it ends - under a 20s cap. Signalling without waiting exits before the lifecycle tasks run,
which orphans every container permanently: nothing else ever stops them, and `--rm` only fires
when the container itself exits.

**Dynamic port allocation:** New port allocated on each startup cycle to avoid TIME_WAIT conflicts.
Published as `127.0.0.1:<host>:<container>` - podman publishes IPv4 only, so anything addressing it
as `localhost` would reach `::1` and fail.

**Image preparation** happens when the service is declared, not when the first request arrives:
`ensure_prepared` pulls or builds the image and settles which user the container runs as, caching
both per service name. A start that lands mid-preparation waits on the same lock. Failures are not
cached, so the next attempt retries.

**Stopping** issues `podman stop --time 2` for each of the service's containers *before* signalling
the `podman run` clients. Signalling the client alone is not enough: it forwards the signal and
then waits for the container's own stop timeout, which outlasts the grace period - so the client
gets killed and the container keeps running.

**Process exit detection:** `wait_for_port_ready` polls `try_wait()` to detect early process exit during startup.

**Podman** is the only way a service runs; there is no unsandboxed path. Via `get_podman_path()`:
- A project's own `Dockerfile` is built with the project directory as context, which podman
  confines - `COPY ../x` is refused and symlinks resolve inside it. Its tag is fixed and the build
  is re-run whenever the image is prepared, since podman's cache makes an unchanged one cheap and
  nothing else would notice a changed context
- Otherwise, custom Dockerfile generation: packages, `copy`ed project files (into `/webcentral-build`, since
  `/app` is shadowed by the run-time mount), build commands, and - for `user = project` - the
  project owner appended to `/etc/passwd`+`/etc/group` followed by a `USER` directive
- `copy` contents are hashed into the image tag and their paths added to `reload_include`, and a
  file-change restart clears the `prepared` cache when a service copies anything - otherwise an
  edited `requirements.txt` would go on running from the image built from the old one
- Image tagged `webcentral-<hash of dir + server name>:<hash of Dockerfile + base image ID>`, so an unchanged config
  skips the build while a pulled base update still triggers one; after each build the project's
  stale sibling tags are removed (they are named, so `image prune` would never reclaim them)
- Stale container of the same name force-removed before `run` (a container outliving its webcentral
  otherwise wedges the project with a name conflict)
- Port mapping from internal to host
- Volume mounts for app dir and additional paths

**Podman always runs as the project's owner.** `Owner::podman()` is the only place a podman
command is made: when webcentral is root it drops to the owner in a `pre_exec` hook - setgroups,
setgid, setuid in that order, because `Command::uid` would apply too late to shed root's
supplementary groups - and passes `--root`/`--runroot` for a store of webcentral's own under that
user's home. That store cannot be the user's own: podman records the run root in the store's
database, so a second one fails with a configuration mismatch, and webcentral claiming theirs first
would break their `podman`. It also passes `--cgroup-manager=cgroupfs`, because an owner who has
never logged in has no systemd user session: crun would ask the session bus for a scope, be told
"interactive authentication required", and the container would not start. Podman's own fallback
warns and then lets the runtime reach for sd-bus anyway. When webcentral already *is* the owner, podman's defaults are right and
nothing is set. Owners are resolved once and cached per uid, with subuid/subgid and
`newuidmap`/`newgidmap` checked then - reported to both webcentral's output and the project's log.

**Container user:** a service's `user` only decides who the container runs as *inside*, defaulting
(resolved at parse time) to `project` when the project directory is mounted (`app_dir` is not
`none`) and `image` when it isn't.
Under a root webcentral, `project` bakes the project owner into the image as a real user; under a
non-root one it forces `--user 0:0`, since rootless podman's container root *is* the invoking
user (and a base image's own USER must not sneak in an unmapped uid). `image` keeps what the
image declares (forcing a user breaks image-baked directories). Bare numeric uids are rejected at
parse - the gid they pair with depends on the image's passwd. Unknown ids are resolved by
`container_user_ids()` (runs `id` in the image, cached per image+user, assumes root on failure).

**Host-side ownership is structural, not maintained:** podman runs as the owner, so container
root - which is what `user = project` resolves to - is that owner, and what it writes is theirs
without any mapping. The one case where podman is *not* rootless is a root-owned project on a root
webcentral (`Owner::runs_rootless`), where a container's uid is already a host uid; an explicit
non-root `user =` there is warned about rather than silently mapped. Only an explicitly requested *other* uid needs `--userns=keep-id` (podman >=
4.3, and broken on some podman/kernel combinations, containers/podman#27785), which is why the
mapping only covers the resolved user: an image that switches at runtime to a uid it does not
declare writes as that uid.

**Declared volumes:** an image's `VOLUME` paths are inspected when the image is prepared and
given a directory under `_webcentral_data/mounts`, because podman's anonymous volume for one goes
away with `--rm` - silently, and only on the first restart. A `mounts` entry covering the path
wins, and so does `app_dir`, since the project directory already persists. What the image ships
at that path is copied into the directory while it is empty: podman copies into a volume it
creates itself, but a bind mount just covers what was there, and an image that seeds its volume
would look as though it had lost it.

**Sidecars:** Nested server declarations, spawned before their parent and killed with it. One
without a `base` of its own inherits the parent's prepared image *and* its `env` (its own entries
winning), which is what replaced the worker concept. A
service and its sidecars share a private podman network (created on demand, never removed) on
which each member carries a `<name>.internal` alias; nothing is published to the host and no
addresses are injected into the environment - a peer is addressed by that name, and each
container only learns its own port as `$PORT`. Only the parent's port is probed for readiness

### File Watching

Two levels, and which one sees a change decides what happens to the project:

**Server files** (`reload_include`/`reload_exclude`, per service, defaulting to the project's
`settings` and then to `DEFAULT_INCLUDES` - a whitelist of source directories, source extensions
and dependency manifests, rather than everything, since a restart is disruptive and assets are
re-read from disk anyway): each server is asked whether a changed path is its business, and
the ones that say yes get `StopReason::FileChange` and restart from the new files on the next
request. A pattern naming a directory covers its contents; the `include-exclude-watcher` crate's
`Matcher` decides this, the same matching the watcher itself uses for its excludes. A service
built from a `dockerfile` defaults to `**/*` instead: its build context is the project directory,
so any file in it can change the image, and a whitelist of source extensions would miss the
`COPY` that brought in something else. The default excludes still apply, and a project that
rebuilds too eagerly narrows it with `reload_include`.

**Default excludes:** `_webcentral_data/**`, `node_modules/**`, `**/*.log`, `**/*.bak`, `**/.*`,
`data/**`, `log/**`, `logs/**`, plus the project files below.

**Project-defining files** (`webcentral.conf`, `package.json`): watched centrally for
all projects at once, since the script and the set of servers may both be different afterwards.
The project is deregistered *before* being torn down, closing the window in which requests would
still reach the outgoing instance; the next request builds a new one.

**Server-level:** Non-recursive watch on project parent directories for domain additions/removals

### Test Infrastructure

**test.py** - Python test harness that:
- Builds `webcentral-test-base` (alpine + python3) once, and gives every `service` block that
  names no `base`/`packages` that image plus a 5s `shutdown_time` - appended to the block's own
  line, so diagnostics' line numbers stay put. Without it each test would build its own image and
  leave a container running for five minutes
- Creates temporary project directories
- Starts webcentral with HTTP-only mode on random port
- Provides helpers: `write_file`, `assert_http`, `await_log`, `assert_log`, `mark_log_read`
- Automatically tracks log positions per-project for incremental reading
- Shows log output on test failure, preserves test directory for inspection
- Supports running individual tests or full suite

**Test patterns:**
- Each test auto-creates domain from test name: `test_foo_bar` → `foo-bar.test`
- Domains are cheap but not free: each project with servers holds an inotify instance, and the
  per-user cap is 128, so prefer asserting several things per domain over one domain per assertion
- Create files: `t.write_file('path', 'content')` (auto-prefixed with test domain)
- Mark logs read: `t.mark_log_read()` (defaults to test domain)
- Wait for log: `t.await_log('text', timeout=2)` (defaults to test domain)
- Assert HTTP: `t.assert_http('/path', check_body='text')` (defaults to test domain)
- Count logs: `t.assert_log('text', count=1)` (defaults to test domain)

## Developers notes

- Keep AGENTS.md up-to-date when making architectural changes. Be succinct—no repetition, no code examples, bullet points over paragraphs.
- Build and test using `cargo build && ./test.py`. Podman is required: every service is a container. Builds are native by default; release artifacts are built for musl by the release workflow.
- For async task debugging, build with `cargo build --features console` and connect via `~/.cargo/bin/tokio-console` (install with `cargo install tokio-console`).
- Run `./test.py` to execute the test suite. To run a single test: `./test.py test_name_of_test`. For new features, add tests in `test.py`. Don't create ad-hoc test scripts. When writing tests, you should not need to sleep (except in test-apps being run by webcentral to simulate loading times) - use `await_log` and/or `assert_http` instead. If a test fails, don't just work around it in the test code, but investigate deeply if there may be an actual bug (or unexpected behavior) in webcentral.
- Add code comments only for explaining non-obvious logic, why things are done a certain way, and how thread-safety is ensured. Don't add comments describing what you're changing and why, as comments should reflect the final code, not the change history.
- When you notice unexpected behavior or a bug at any time, create an issue on your todo-list for later investigation. Never let bugs go uninvestigated nor work around them.
- **Podman honours `XDG_CONFIG_HOME` over `HOME`.** Anything that re-points a podman client at another user has to re-point *every* path variable, not just `HOME` - see `Owner::podman`. A stray `XDG_CONFIG_HOME` from a systemd `Environment=` line or a `sudo -E` otherwise sends it to a `containers/storage.conf` the owner cannot read, and the only symptom is `permission denied` on a path belonging to somebody else.
- **Reproducing a podman problem that only happens under webcentral:** run podman the way `Owner::podman` does rather than the way your shell does - `env -i PATH=... HOME=<owner home> podman --root <store> --runroot <runroot> ...`. A login shell carries `XDG_RUNTIME_DIR`, a systemd user session and a dbus socket that a service user does not have, and every difference we have chased (the sd-bus `Interactive authentication required` failure, store `database configuration mismatch`) came from one of those. Podman's own warnings can mislead: it reported "Falling back to --cgroup-manager=cgroupfs" while still failing for want of exactly that flag.
- When trying to debug problems, do not fiddle around with ad-hoc shell commands too much. The user needs to approve all of these. Instead, extend `test.py` to clearly demonstrate the problem, and if needed add (temporary, with a `TODO: remove` comment) logging to the code (but prefer to just improve error logging).
- **Releases:** Increment version in `Cargo.toml` (x.y.z: x for rewrites, y for major features, z for minor/bugfixes) and add changelog entry in README.md. Create release by pushing git tag: `git tag v2.4.3 && git push origin v2.4.3`. GitHub Actions (`.github/workflows/release.yml` via cargo-dist) builds static binaries (musl x86_64, aarch64 gnu, x86_64 gnu) and creates GitHub Release with artifacts and installer script. Regular commits to main don't trigger releases.

## AI guidance

- AI agents should be succinct in their textual output. Especially when in 'thinking' mode, they should restrict verbosity to the absolute minimum, leaving out social niceties and sacrificing grammar for brevity.
