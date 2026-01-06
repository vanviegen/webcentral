# Webcentral

A reverse proxy that runs multiple web applications for multiple users on a single server. Just put your app in a directory named like the target domain (eg `myapp.example.com/`), point DNS at the server, and you're done! The app will start (and shutdown) on-demand, and reload when its files change.


## Features

### Per domain request handling
- Run an executable (that should start serving on $PORT) either from a Docker image or in a Firejail sandbox
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
- Firejail or Docker sandboxing
- Each application has its own decentralized configuration

**Security Notice:** While Firejail and Docker add sandboxing, the integration hasn't been thoroughly audited. Webcentral may introduce additional attack surface. Use appropriate caution.

---

## Quick Start

```sh
# Download and install latest statically linked release
curl -LsSf https://github.com/vanviegen/webcentral/releases/latest/download/webcentral-$(uname -m)-unknown-linux-musl.tar.xz | sudo tar xJf - -C /usr/local/bin --strip-components=1 '*/webcentral'
# Or build from source (see below)

# Install optional dependencies for sandboxing
sudo apt install firejail docker.io  # Debian/Ubuntu
# Or
sudo dnf install firejail docker     # Fedora/RHEL

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
| Built-in sandboxing | Docker or Firejail | ✗ | Docker | ✗ | Docker | Docker |
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

**Trigger:** `webcentral.ini` with `command` property (without `[docker]` section)

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

### 2. Dockerized Command

**Trigger:** `webcentral.ini` with `command` property and `[docker]` section

Runs a server process in a Docker container. The process should start an HTTP server on `$PORT` (defaults to 8000).

**Docker containerization:**
- Completely isolated environment
- Higher memory usage, slower startup
- Runs as the project owner (uid/gid passed via `--user` flag)
- Automatically mounts `/etc/passwd` and `/etc/group` for user resolution
- More configuration options

**Example:**
```ini
command = php -S 0.0.0.0:$PORT -file test.php
[docker]
base = debian
packages[] = php
packages[] = composer
commands[] = composer install
```

**Docker Configuration Options:**
- `base` - Base Docker image (default: `alpine`)
- `commands` - Build commands (strings or arrays) - run during image build
- `packages` - Packages to install (auto-detects `apk`, `apt-get`, `dnf`, or `yum`)
- `mounts` - Persistent directories (stored in `_webcentral_data/mounts/<path>`, owned by project user)
  - Relative paths (e.g., `data`) are mounted relative to `app_dir`
  - Absolute paths (e.g., `/var/lib/data`) are mounted at that exact location in container
- `http_port` - Container HTTP port (default: 8000)
- `app_dir` - Mount point for project directory (default: `/app`)
- `mount_app_dir` - Set to `false` to skip mounting project directory and to run as root instead of your user (default: `true`)

**Volume mounts:**
- Project directory is mounted at `app_dir` (if `mount_app_dir` is not `false`)
- Home directory is mounted at `_webcentral_data/home` (if `mount_app_dir` is `true`)
- Custom mounts are created in `_webcentral_data/mounts/` with correct ownership

**Real-world example (Trilium Notes):**
```ini
command = node /usr/src/app/src/www
[docker]
base = zadam/trilium:0.47.6
http_port = 8080
```

**Example with persistent data:**
```ini
command = ./server
[docker]
base = alpine
packages = nodejs npm
mounts[] = data              ; Mounted at /app/data
mounts[] = /var/cache/app    ; Mounted at /var/cache/app
```

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
- All processes run in the same sandbox (Firejail or Docker)

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

### Environment Variables

Set environment variables for your application:

```ini
[docker]
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
