# Webcentral

A reverse proxy that runs multiple web applications for multiple users on a single server. Just put your app in a directory named like the target domain (eg `myapp.example.com/`), point DNS at the server, and you're done! The app will start (and shutdown) on-demand, and reload when its files change.


## Features

### Per domain request handling
- Run an executable (that should start serving on $PORT) either in a podman container or in a Firejail sandbox
- Port-forward, HTTP-redirect, HTTP-proxy or static-serve requests
- Config file not always needed (detects `Procfile`, `package.json`, `public/`)

### Application lifecycle
- On-demand startup when first accessed
- Zero-downtime application restarts triggered by file changes
- Automatic shutdown after configurable idle period
- Daily log per application files with automatic pruning

### HTTPS & routing
- Let's Encrypt certificates acquired and renewed automatically
- HTTP/3 (QUIC), HTTP/2, and HTTP/1.1 support with automatic protocol negotiation and 0-RTT resumption
- Enabled-by-default HTTP ↔ HTTPS and www redirects
- Transparent WebSocket proxying

### Multi-user & isolation
- When started as root, all local users can host applications (run with their own permissions)
- Firejail or podman (container) sandboxing
- Each application has its own decentralized configuration

**Security Notice:** While Firejail and podman add sandboxing, the integration hasn't been thoroughly audited. Webcentral may introduce additional attack surface. Use appropriate caution.

---

## Quick Start

```sh
# Download and install latest statically linked release
curl -LsSf https://github.com/vanviegen/webcentral/releases/latest/download/webcentral-$(uname -m)-unknown-linux-musl.tar.xz | sudo tar xJf - -C /usr/local/bin --strip-components=1 --wildcards '*/webcentral'
# Or build from source (see below)

# Install optional dependencies for sandboxing
sudo apt install firejail podman  # Debian/Ubuntu
# Or
sudo dnf install firejail podman  # Fedora/RHEL

# Run it (replace email)
sudo webcentral --email you@example.com
# Or set it up as a persistent systemd service and run (recommended)
sudo webcentral --email you@example.com --systemd 
```

The `email` flag is mandatory, as it's needed for Let's Encrypt. Alternatively you can disable HTTPS (`webcentral --https 0`). See `webcentral --help` for more options.

Create a directory at `~/webcentral-projects/someapp.yourdomain.com/` with either:
- A `Procfile` for Heroku-style applications
- A `package.json` for Node.js apps (`npm run` should start a webserver on `$PORT`)
- A `public/` folder for static files
- A `webcentral.ini` for custom configuration (see below)

Point DNS for `someapp.yourdomain.com` at your server. Up and running!

---

## Comparison with Alternatives

| Feature | Webcentral | Caddy | Traefik | Nginx | Dokku | Coolify |
|---------|------------|-------|---------|-------|-------|-------|
| Auto HTTPS (Let's Encrypt) | ✓ | ✓ | ✓ | Manual | ✓ (plugin) | ✓ |
| Zero-config static sites | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| On-demand app startup | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Auto-reload on file change | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ (git&nbsp;push) |
| Idle shutdown | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Multi-user (shared port 80/443) | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Built-in sandboxing | Podman or Firejail | ✗ | Docker | ✗ | Docker | Docker |
| Config complexity | Minimal | Low | Medium | High | Medium | Medium |
| Container orchestration | ✗ | ✗ | ✓ | ✗ | ✓ | ✓ |
| HTTP/3 (QUIC) | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ |

**Caddy/Nginx/Traefik** are pure reverse proxies—they route traffic but don't manage application lifecycles. You need separate tools (systemd, Docker Compose, Kubernetes) to run your apps.

**Dokku/Coolify** are self-hosted PaaS platforms with git-push deployment, but require more setup and resources. They're better suited for team environments with CI/CD pipelines.

**Webcentral** fills the gap for developers who want to quickly host multiple small apps/sites on a single server/VPS without container orchestration overhead. Just drop files in a folder and go. It allows multiple (non-privileged) users to share a single server. Unused apps don't consume resources.

---

## Non-root vs root usage

When run as a regular user, by default Webcentral searches `~/webcentral-projects/` for project directories. When run as root, it searches all `/home/*/webcentral-projects/` directories by default and runs each project with its owner's permissions. This allows multiple users to share the precious ports 80 and 443, without having to give them privileged access to the server.

If you want to run WebCentral as a regular user while still being able to bind to privileged ports, run `sudo setcap 'cap_net_bind_service=+ep' $(which webcentral)` once.

---

## Request Handling

Projects are automatically detected based on their contents:

### 1. Firejailed Command

**Trigger:** `webcentral.ini` with `command` property (without `[podman]` section)

Runs a server process in a Firejail sandbox. The process should start an HTTP server on `$PORT`.

**Firejail sandboxing:**
- Read-only access to system directories (`/bin`, `/usr`)
- No access to home directories or other user files
- Faster startup, lower memory usage

**Example:**
```ini
command = php -S 0.0.0.0:$PORT -file test.php
```

**Worker processes:**

You can run background worker processes alongside the main command:

```ini
command = python app.py --port $PORT
worker = python background_tasks.py
worker:email = python email_processor.py
```

Use `worker` for a single unnamed worker, or `worker:name` for multiple named workers. Workers share the same lifecycle as the main process and have access to the same environment variables.

### 2. Containerized Command

**Trigger:** `webcentral.ini` with `command` property and `[podman]` section (`[docker]` is
accepted as an alias, but the engine is always podman - docker itself is no longer supported)

Runs a server process in a podman container. The process should start an HTTP server on `$PORT` (defaults to 8000).

**Containerization:**
- Completely isolated environment
- Higher memory usage, slower startup
- Whatever user the container runs as inside, files it writes are owned by you (see **Container user** below)
- More configuration options

**Example:**
```ini
command = php -S 0.0.0.0:$PORT -file test.php
[podman]
base = debian
packages[] = php
packages[] = composer
commands[] = composer install
```

**Podman Configuration Options:**
- `base` - Base image (default: `alpine`)
- `commands` - Build commands - run during image build
- `packages` - Packages to install (auto-detects `apk`, `apt-get`, `dnf`, or `yum`)
- `mounts` - Persistent directories, stored in `_webcentral_data/mounts/<path>`
  - Relative paths (e.g., `data`) are mounted relative to `app_dir`
  - Absolute paths (e.g., `/var/lib/data`) are mounted at that exact location in container
- `http_port` - Container HTTP port (default: 8000)
- `app_dir` - Mount point for project directory (default: `/app`)
- `mount_app_dir` - Set to `false` to skip mounting the project directory (default: `true`)
- `user` - Who the container runs as inside (see below)

**Container user:**

`user` decides who the container runs as *inside* the container:

- `project` - run as the project owner. Under a root webcentral they are added to the image as a
  real user (named `webcentral`, with `$HOME` at `_webcentral_data/home`, or at `/tmp` when the
  project directory isn't mounted); under a non-root webcentral the container runs as root inside,
  because that is simply what rootless podman calls the invoking user
- `image` - keep whatever user the image declares
- a numeric `uid:gid` pair, or a user name defined in the image - run as exactly that (a bare
  `uid` is rejected: the gid it would pair with depends on the image)

It defaults to `project` when `mount_app_dir` is `true` and to `image` when it is `false`, which is
almost always what you want: mounting the project directory means webcentral builds the image and
the application works in your own files, while a complete third-party image knows which user it
needs and forcing another one tends to make image-baked directories unwritable.

**Host-side, the container user makes no difference: everything the application writes - in your
project directory or in `mounts` - ends up owned by you, the project directory's owner.** Podman
maps the container's user onto yours, whoever the image wants to be inside. Directories in
`mounts` are created owned by you too (directories that already exist are never touched).

The mapping covers the user the container *runs as*; all other ids pass through unchanged, since
images need them intact for their internal permission juggling. So an image that switches at
runtime to a uid it never declares - a root entrypoint dropping to an app user, as the official
postgres image does - writes as that uid rather than as you. Naming the uid explicitly (e.g.
`user = 999:999`) brings it under the mapping; such images generally support being started as
their app user directly.

Two more caveats, both for a *non-root* webcentral only. It can deliver the ownership promise solely
for projects owned by its own user - for a project owned by anyone else it logs a warning, and
container-written files may end up owned by a meaningless subuid. And a container user other than
`project` or root relies on podman's `keep-id` mapping (podman >= 4.3; broken on some recent
podman/kernel combinations - [containers/podman#27785](https://github.com/containers/podman/issues/27785) -
where such containers fail to start with a `crun: readlink` error rather than leaking ownership).

**Volume mounts:**
- Project directory is mounted at `app_dir` (if `mount_app_dir` is not `false`)
- Custom mounts are created in `_webcentral_data/mounts/`

**Real-world example (Trilium Notes):**
```ini
command = node /usr/src/app/src/www
[podman]
base = zadam/trilium:0.47.6
http_port = 8080
mount_app_dir = false
```

A complete third-party image like this one brings its own application and its own user, so there is
nothing to mount the project directory for. Leaving `mount_app_dir` at its default would default
`user` to `project`, making webcentral add your user to the image and run as it, which such images
generally don't expect.

**Example with persistent data:**
```ini
command = ./server
[podman]
base = alpine
packages[] = nodejs
packages[] = npm
; mounted at /app/data
mounts[] = data
; mounted at /var/cache/app
mounts[] = /var/cache/app
```

Note that `;` only starts a comment at the beginning of a line - anywhere else it is part of the
value.

### 3. Forward

**Trigger:** `webcentral.ini` with `port` or `socket_path` property

Forwards requests to a local port or UNIX socket without modifying the `Host:` header.

```ini
port = 3000
host = 192.168.10.20
```

Or:
```ini
socket_path = /my/path/test.socket
```

### 4. Redirect

**Trigger:** `webcentral.ini` with `redirect` property

Returns HTTP 301 redirect to the specified URL plus the request path and query string.

```ini
redirect = https://new-service-name.example.com
```

### 5. Proxy

**Trigger:** `webcentral.ini` with `proxy` property

**(Experimental!)** Proxies requests to a remote URL with header rewriting (unlike Forward).

```ini
proxy = https://www.google.com
```

### 6. Procfile Application

**Trigger:** `Procfile` exists (no `webcentral.ini` needed)

Runs applications using Heroku's Procfile format. The `web` process should start an HTTP server on `$PORT`.

**Supported process types:**
- `web` - Main HTTP server process (required)
- `worker` - Background worker process (optional, multiple allowed)
- `urgentworker` - Same as worker (alias)

**Unsupported process types** (will be logged and ignored):
- `release`, `console`, and other custom types

**Example Procfile:**
```
web: python app.py --port $PORT
worker: python background_tasks.py
worker: python email_processor.py
```

**Notes:**
- All processes share the same environment variables
- Workers start after the web process is ready
- Workers are stopped when the application stops
- All processes run in the same sandbox (Firejail or podman)

### 7. Node.js Application

**Trigger:** `package.json` exists (no `webcentral.ini` or `Procfile` needed)

Automatically runs `npm start`, which should start an HTTP server on `process.env.PORT`.

### 8. Static Files

**Trigger:** `public/` directory exists (no `webcentral.ini` needed)

Serves files from the `public/` directory.

---

## Configuration

### Auto-Reload

Applications automatically reload when:

1. **Files change** - Watches for changes in the project directory
2. **After inactivity** - Default 5 minutes of no requests

**Default exclusions** (not watched for changes):
- `_webcentral_data`, `data`, `log`, `logs`, `home`
- `node_modules`
- `**/*.log`
- `**/.*` (hidden files)

**Custom reload configuration:**
```ini
command = ./start.sh --production
[reload]
timeout = 0                ; Disable inactivity shutdown (seconds)
include[] = src            ; Only watch src/ directory
include[] = config.yaml    ; And this file
exclude[] = src/build      ; Ignore build directory
exclude[] = **/*.bak       ; Ignore .bak files
```

Note: `webcentral.ini` is always watched, and `_webcentral_data` is always excluded.

### URL Rewrites

**(Experimental!)** Rewrite request paths using regular expressions.

```ini
[rewrite]
/blog/(.*?)/.* = /articles/$1.html              ; Simplify URLs
/favicon.ico = /favicon.ico                     ; Passthrough
/[^/]* = /index.html                            ; Catch-all to index.html
```

Rules are applied in order. First match wins. Use `$1`, `$2`, etc. for captures.

Patterns are anchored: they must match the entire path (without the query string, which is carried
over to the rewritten path unless the target specifies its own). The rewrite happens before the
request is handled, so it works for every project type - static files, applications, proxies and
forwards all see the rewritten path. A target that isn't an absolute path (`https://example.com/x`)
produces a 301 redirect instead.

Write `${1}` rather than `$1` when the capture is followed by a letter, digit or underscore:
`/$1_v2` means "the capture named `1_v2`", which doesn't exist, and expands to nothing.

### Environment Variables

Set environment variables for your application:

```ini
[podman]
base = bitwardenrs/server:alpine
mounts[] = data
mounts[] = web-vault
[environment]
ROCKET_PORT = 8000
WEB_VAULT_ENABLED = true
```

### HTTP/HTTPS Redirects

Control protocol redirects per-project:

```ini
redirect_http = false      ; Don't redirect HTTP to HTTPS
redirect_https = true      ; Redirect HTTPS to HTTP
```

Defaults: `redirect_http = true`, `redirect_https = false` (configurable via `--redirect-http`)

### Request Logging

Enable per-project request logging:

```ini
log_requests = true
```

### Basic Authentication

Protect your application with basic username/password authentication:

```ini
[auth]
alice = $argon2id$v=19$m=19456,t=2,p=1$...
bob = $argon2id$v=19$m=19456,t=2,p=1$...
```

- Passwords are stored as secure argon2id hashes (never plain text)
- Use `webcentral hash mypassword` to generate hashes
- Sessions support browser restart using HTTP-only cookie
- Visit `/webcentral/logout` to log out

---

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--version` (`-V`) | Print the version number and exit. |
| `--email=EMAIL` | Email for Let's Encrypt. Required unless `--https=0`. |
| `--projects=DIR` | Project directory glob. Default: `/home/*/webcentral-projects` (root) or `$HOME/webcentral-projects` (user). |
| `--config=DIR` | Config storage directory. Default: `/var/lib/webcentral` (root) or `$HOME/.webcentral` (user). |
| `--https=PORT` | HTTPS port. Default: `443`. Set to `0` to disable. |
| `--http=PORT` | HTTP port. Default: `80`. Set to `0` to disable. |
| `--redirect-http=BOOL` | Redirect HTTP to HTTPS. Default: `true`. |
| `--redirect-www=BOOL` | Auto-redirect between `example.com` and `www.example.com`. Default: `true`. |
| `--firejail=BOOL` | Enable Firejail sandboxing. Default: `true`. (Disabling risks security and process leaks.) |
| `--prune-logs=DAYS` | Days to keep log files. Default: `28`. Set to `0` to disable pruning. |
| `--acme-url=URL` | ACME directory URL. Default: Let's Encrypt (`https://acme-v02.api.letsencrypt.org/directory`). |
| `--acme-version=VER` | ACME protocol version. Default: `draft-11`. |

---

## Log Files

Application output is written to `_webcentral_data/log/<DATE>.log` in each project directory. Logs rotate daily and are automatically pruned after 28 days (configurable via `--prune-logs`).

---

## Building from Source

For development or if pre-built binaries aren't available for your platform, assuming you have Rust and Cargo installed:

```sh
# Clone and build
git clone https://github.com/vanviegen/webcentral.git
cd webcentral
cargo build  # or: cargo build --release

# Binary is at target/debug/webcentral or target/release/webcentral
```

### Static Builds

For creating portable binaries that work across different Linux distributions (no glibc version dependencies), use musl:

```sh
# Install musl target and build tools
sudo apt install rustup musl-tools  # Debian/Ubuntu
# OR
sudo dnf install rustup musl-gcc    # Fedora/RHEL

rustup-init
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --release --target x86_64-unknown-linux-musl

# Binary is at target/x86_64-unknown-linux-musl/release/webcentral
```

Static musl builds have no runtime dependencies and can be copied to any Linux system regardless of installed libraries. The official release binaries use this approach.

### Development Options

For development with async debugging, use `cargo build --features console` and connect with `tokio-console`.

To compile without HTTP/3 (QUIC) support and dependencies, use `cargo build --no-default-features`.

---

## Changelog

2026-08-05 (2.6.1):
  - **Security:** fix a path traversal in static file serving. `GET /../../etc/passwd` escaped the project's `public/` directory and served any file readable by webcentral (root, in the usual setup). The containment check compared path components without resolving `..`, which the kernel then resolved on open. Request paths are now percent-decoded and normalized before the filesystem is touched. Only projects serving static files were affected
  - Static files whose names need percent-encoding (`/my%20file.txt`) are served instead of 404'd, as the path was previously used raw
  - Fix `[rewrite]` rules never rewriting anything: the rewritten path was computed and then thrown away, so only the redirect form (a target that isn't a path) had any effect. The rewritten path now replaces the request's, for every project type, carrying the query string over
  - `[rewrite]` rules are now really applied in the documented file order, instead of the arbitrary order of a hash map, so a catch-all as the last rule no longer sometimes swallows the rules above it
  - Rewrite patterns are compiled once at load instead of on every request, and an unparsable one is now reported in the project log instead of silently skipped

That's a lot of nastiness that needed to be cleaned up. I guess that's what you get for having an agent port your code to a new language and not thoroughly studying every single line it outputs. :-(

2026-07-31 (2.6.0):
  - Containers are now always run with podman; docker support is dropped. The config section is renamed to `[podman]`, with `[docker]` still accepted as an alias
  - Host-side file ownership is now a promise instead of an accident: whatever user the container runs as inside, everything it writes into the project directory or `mounts[]` lands owned by the project owner. A root webcentral gives the container a per-container uid/gid mapping between its user and the owner; a non-root webcentral (rootless podman) represents the owner as container root and maps explicitly requested other users onto them via `keep-id` (projects owned by anyone else are warned about, being the one thing rootless podman cannot express)
  - New `[podman] user`, deciding who the container runs as *inside*: `project` (default when the project directory is mounted) runs as the project owner - added to the image as a real user named `webcentral` (with `$HOME` in `_webcentral_data/home`) under a root webcentral, or as rootless podman's container root under a non-root one; `image` (default otherwise) keeps whatever the image declares; or give a numeric `uid:gid` or an image-defined user name. A bare uid is rejected as ambiguous. This replaces the `--user` flag plus a bind-mount of the host's `/etc/passwd` over the image's, which broke images defining their own users
  - Fix `EACCES` in `mounts[]`: those host directories were created owned by webcentral (often root) rather than by the project owner the container writes as
  - Fix `[podman] packages` being silently ignored since 2.1.0, installing nothing
  - Skip the image build entirely when the configuration and the base image are unchanged, instead of paying for a cached build on every on-demand start; a pulled base update still triggers a rebuild, and images left behind by older configurations are cleaned up
  - Fix a container outliving its webcentral wedging the project for good, as `run` then hit a name conflict on every restart

2026-07-28 (2.4.20):
  - Added `--version` (`-V`), printing just the version number, and a `Starting webcentral <version>` line at the top of every run's log, so the running version can be identified from the logs

2026-07-28 (2.4.19):
  - Check that a domain actually resolves to this server (by fetching a token only this process can produce, over port 80) before ordering a certificate for it, instead of retrying ACME orders that can only fail. Reported per domain, and rechecked while a certificate is still valid, so a domain that stops pointing here is flagged long before its renewal fails
  - The www/non-www counterpart is included in the domain's certificate only when it too points at this server, which is what made 2.4.18 downgrade to separate certificates. It is added (or dropped) on the next check, without waiting for renewal
  - Fix requests still reaching the outgoing project for a moment after a file change was detected
  - Connection and TLS handshake errors now name the client address they came from (and, for HTTPS, the requested domain), instead of only the error
  - One log line per certificate per cycle, instead of one for the check, one for the validity and one for the acquisition

2026-07-28 (2.4.18):
  - Request a separate certificate for the www/non-www counterpart of a domain instead of adding it as a second name on the domain's own certificate, which failed whenever that name wasn't pointed at this server. The counterpart certificate is requested on demand, the first time a TLS handshake asks for that name (so the first such handshake still fails, and the next one succeeds)
  - Updated deps, fixing a remotely triggerable memory exhaustion in `quinn-proto` (RUSTSEC-2026-0185, high) that affects the HTTP/3 listener

2026-07-27 (2.4.17):
  - Fix the HTTP/HTTPS listeners permanently going away after a transient `accept()` error (such as `EMFILE`): the accept loop returned, dropping the listening socket, while the process stayed alive so systemd never restarted it. Accept errors are now logged and retried, backing off 500ms on resource exhaustion
  - Raise the open-file soft limit to the hard limit at startup, since systemd defaults services to 1024

2026-06-15 (2.4.16):
  - Fix a freeze where a process ignoring SIGTERM was never SIGKILLed (the async `kill()` future was dropped), wedging the lifecycle so the app could not restart or reload
  - Process kills can no longer block the lifecycle indefinitely
  - Restart an app whose port has become unreachable on the next request, instead of disabling the domain
  - Single startup attempt bounded by `startup_deadline` (default 30s → 60s); no forced early error while a startup is still in progress

2026-06-15 (2.4.15):
  - Tear down a domain's watcher and lifecycle on removal/re-registration, instead of leaking zombie watchers
  - Reload config changed while an app is idle, and deregister a domain when its directory is deleted

2026-06-01 (2.4.14):
  - Add www-prefixed variant to certificate for redirect
  - Updates deps

2026-02-18 (2.4.13):
  - Added X-Forwarded-For header and now also send X-Forwarded-Proto header when only doing forwarding (as opposed to proxying)

2026-02-16 (2.4.12):
  - Fix change-reload for symlinked project directories

2026-02-11 (2.4.11):
 - Fix concurrent certificate acquisition bug where one domain's validation completion would clear HTTP-01 challenges for all in-flight domains
 - Improve ACME error logging to show full error chains

2026-01-19 (2.4.10):
 - Ensure webcentral.ini is always watched for changes, even when custom reload.include is specified
 - Don't log spurious errors when clients drop connections

2026-01-16 (2.4.9):
 - When using Firejail, set $HOME to a volatile directory outside the project directory.
 - Show correct running time in dashboard.

2026-01-15 (2.4.8):
 - Add `startup_deadline` config option (default 30s) for application startup timeout
 - Fix startup timeout blocking forever on hung applications

2026-01-15 (2.4.7):
 - Hardened Firejail sandboxing by using private-etc and more restrictive filesystem rules
 - Fix firejail UID handling when running as root

2026-01-10 (2.4.6):
 - WebSocket connections now prevent inactivity shutdown
 - Dashboard Idle column now shows number of active WebSockets

2026-01-06 (2.4.5):
 - Simplified release builds to musl-only static binaries

2026-01-06 (2.4.4):
 - Add `--systemd` flag to create and enable systemd service automatically
 - Changed default build target from musl to native for faster development builds

2026-01-06 (2.4.3):
 - Default to static musl builds for universal Linux compatibility
 - Updated README with pre-built binary installation instructions

2026-01-06 (2.4.2):
 - Log directories and files now created with correct ownership (matching project user)

2026-01-05 (2.4.1):
 - Dashboard shows port number for running apps

2026-01-05 (2.4.0):
 - Add basic authentication with argon2 password hashing (`[auth]` section)
 - Persistent sessions via HTTP-only subdomain-scoped cookies
 - Logout endpoint at `/webcentral/logout`
 - `webcentral hash <password>` subcommand to generate password hashes
 - Disable 0-RTT resumption as it caused issues in some cases

2026-01-04 (2.3.0):
 - Add dashboard project type (`type=dashboard`) showing server status, domain list, request counts, TLS certificate status, and uptime

2026-01-04 (2.2.3):
 - Log which file triggered reload on file change

2026-01-04 (2.2.2):
 - Enable TLS 1.3 0-RTT session resumption for HTTPS and HTTP/3

2026-01-04 (2.2.1):
 - Add HSTS header to all HTTPS responses

2026-01-04 (2.2.0):
 - HTTP/3 (QUIC) support - automatically enabled when HTTPS is active
 - HTTP/2 support via ALPN negotiation

2026-01-03 (2.1.6):
 - Stream response bodies to clients (lower latency and memory usage)

2025-12-28 (2.1.5):
 - Fix potential app reload hang

2025-12-10 (2.1.4):
 - Static file server now sends MIME types based on file extensions

2025-12-08 (2.1.3):
 - Fix config reload on file change (was reusing stale config)
 - Simplified process lifecycle: new Project replaces old, waits for predecessor to stop

2025-12-08 (2.1.2):
 - Await process shutdown before restarting
 - More robust process lifecycle management

2025-12-02 (2.1.1):
 - Keep bindings.json up-to-date when domains are added/removed
 - Code reduction

2025-11-27 (2.1.0):
 - Fix for unnecessary inotify watchers
 - Docker configurations without custom RUN commands or packages don't use a custom build anymore
 - Use Podman (preferred) it it's installed
 - No more Docker user mapping - root inside the container for compatibility
 - Exit immediately if ports cannot be bound

2025-11-26 (2.0.0):
 - Initial AI-driven Rust reimplementation of the [original Node.js version](https://github.com/vanviegen/webcentral/tree/nodejs). It was born out of Node.js dependency rot frustration. It also adds multi-threading, and should be fully compatible with original configuration format and project structure.
 - Added a test suite, mostly for catching configuration-change race conditions.
 - Configurable log retention (`--prune-logs`)
 - Proactive certificate acquisition for newly created projects (no longer awaiting the first request)
 - Added Procfile support (though no `release:` yet)
 - Added support for worker processes alongside main app process (not for Docker yet)

See `git log` for further changes.

2018-09-14:
  - Initial release.

---

## License

ISC
