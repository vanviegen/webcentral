# Webcentral - Go Implementation

This is a complete reimplementation of Webcentral in Go, maintaining full compatibility with the Node.js version.

## Overview

Webcentral is a multi-tenant hosting platform that runs multiple sandboxed web applications on a single machine. Each application is automatically associated with a DNS domain/subdomain, making it ideal for quickly hosting multiple services using wildcard DNS records.

## Features

All features from the Node.js version are fully implemented:

- **Domain-based auto-routing** - Automatically routes requests based on Host header
- **Multiple hosting modes**:
  - Application with Firejail sandboxing
  - Application with Docker containers
  - Static file server
  - Proxy to remote services
  - Forward to local ports or UNIX sockets
  - HTTP 301 redirects
- **HTTPS/SSL Management** - Automatic HTTPS via LetsEncrypt with Greenlock-compatible ACME
- **Dynamic lifecycle management** - On-demand startup, automatic shutdown, hot reloading
- **URL path rewriting** - Regex-based with capture groups
- **WebSocket support** - Full WebSocket proxying with proper headers
- **Multi-user support** - UID/GID isolation when running as root
- **Request logging** - Per-project configurable logging
- **Log management** - Automatic rotation and 21-day cleanup

## Building

```bash
cd go
go build -o webcentral
```

## Usage

```bash
./webcentral --email your@email.com
```

### Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `--email` | `$EMAIL` env var | Email for LetsEncrypt registration (required for HTTPS) |
| `--projects` | `/home/*/webcentral-projects` (root) or `$HOME/webcentral-projects` | Projects directory pattern |
| `--config` | `/var/lib/webcentral` (root) or `$HOME/.webcentral` | Config and certificate storage |
| `--https` | `443` | HTTPS port (0 to disable) |
| `--http` | `80` | HTTP port (0 to disable) |
| `--redirect-http` | `true` (if both enabled) | Redirect HTTP to HTTPS |
| `--redirect-www` | `true` | Auto-redirect www variants |
| `--firejail` | `true` | Use Firejail sandboxing |
| `--acme-url` | Let's Encrypt | ACME service endpoint |
| `--acme-version` | `draft-11` | ACME protocol version |

## Project Configuration

Projects are configured using `webcentral.ini` in the project directory.

### Basic Application

```ini
command = npm start
```

### Docker Application

```ini
[docker]
base = alpine
packages[] = nodejs
packages[] = npm
commands[] = npm install
http_port = 8000
```

### Forward to Local Port

```ini
port = 3000
host = localhost
```

### Forward to UNIX Socket

```ini
socket_path = /var/run/app.sock
```

### HTTP Redirect

```ini
redirect = https://example.com
```

### Remote Proxy

```ini
proxy = https://remote.example.com
```

### URL Rewriting

```ini
[rewrite]
/api/(.*) = webcentral://api-service/$1
/blog/(.*?)/.* = /articles/$1.html
```

### Environment Variables

```ini
[environment]
NODE_ENV = production
DATABASE_URL = postgres://localhost/myapp
```

### Reload Configuration

```ini
[reload]
timeout = 300
include[] = src
include[] = config.yaml
exclude[] = build
exclude[] = **/*.log
```

### HTTP/HTTPS Redirect Override

```ini
redirect_http = false
redirect_https = true
```

### Request Logging

```ini
log_requests = true
```

## Architecture

The Go implementation is organized into several modules:

- **main.go** - Entry point and CLI argument parsing
- **server.go** - HTTP/HTTPS servers, domain routing, ACME integration
- **project.go** - Project lifecycle management, process spawning, handlers
- **config.go** - INI parser and configuration loading
- **logger.go** - Rotating logger with automatic cleanup

## Compatibility

This Go implementation is fully compatible with the Node.js version:

- Same configuration format (webcentral.ini)
- Same command-line arguments
- Same project directory structure
- Same logging format and location
- Same bindings cache format
- Same ACME certificate storage

You can switch between the Node.js and Go versions seamlessly.

## Differences from Node.js Version

1. **Single binary** - No need for Node.js runtime or npm dependencies
2. **Lower memory footprint** - More efficient resource usage
3. **Better concurrency** - Native Go goroutines handle requests concurrently
4. **Faster startup** - Compiled binary starts instantly

## Dependencies

The Go version uses only standard library and well-maintained packages:

- `golang.org/x/crypto/acme` - ACME/LetsEncrypt client
- `golang.org/x/crypto/acme/autocert` - Automatic certificate management
- `github.com/fsnotify/fsnotify` - File system notifications for hot reload

No runtime dependencies required - just a single static binary.

## Multi-threading

The Go implementation leverages Go's excellent concurrency model:

- Each HTTP request is handled in a separate goroutine
- File watching runs in background goroutines
- Process monitoring runs in background goroutines
- Inactivity checking runs in background goroutines

All concurrency is managed safely with mutexes where needed. This provides excellent performance without adding complexity.

## Security

Same security considerations as the Node.js version:

- Firejail sandboxing for process isolation
- Docker containers for full OS-level isolation
- UID/GID isolation when running as root
- Read-only filesystem access in Firejail mode

## License

ISC (same as the Node.js version)
