# Webcentral Go Architecture

This Go implementation of Webcentral is a reverse proxy and application host that routes incoming HTTP/HTTPS requests to domain-specific projects based on directory names.

## Core Components

### Server (`server.go`)
- Manages HTTP/HTTPS listeners
- Handles TLS certificate acquisition via ACME (Let's Encrypt)
- Routes requests to projects based on domain
- Implements www redirection and HTTP-to-HTTPS redirects
- Caches domain-to-directory mappings
- Watches for new project directories to proactively acquire certificates

### Project (`project.go`)
- Represents a single domain/application
- Manages application lifecycle (start, stop, reload)
- Supports multiple deployment types:
  - **Applications**: Executes commands in Firejail sandbox or Docker
  - **Static files**: Serves from `public/` directory
  - **Redirects**: HTTP 301 redirects
  - **Proxies**: Reverse proxy to remote URLs or local sockets
  - **Forwards**: Forwards to local ports/sockets without header rewriting
- Handles file watching for auto-reload on changes
- Manages inactivity timeouts
- Implements URL rewriting and cross-project routing (`webcentral://`)

### Logger (`logger.go`)
- Writes project output to dated log files (`YYYY-MM-DD.log`)
- Automatically rotates logs daily
- Prunes old logs based on retention policy (configurable via `--prune-logs`)
- Formats multi-line output with proper indentation

### Config (`config.go`)
- Parses INI files (`webcentral.ini`) for project configuration
- Parses `package.json` for Node.js projects
- Supports Docker configuration, environment variables, reload settings, and URL rewrites

## Request Flow

1. **Incoming Request** → Server extracts domain from Host header
2. **Domain Resolution** → Server finds project directory matching domain
3. **Project Routing** → Server creates/retrieves Project instance
4. **Request Handling** → Project applies rewrites, then:
   - Static: Serves files from `public/`
   - Redirect: Returns HTTP 301
   - Proxy/Forward: Proxies to configured target
   - Application: Starts process if needed, proxies to allocated port
5. **Process Management** → If application, monitors for file changes and inactivity

## Key Features

- **Sandboxing**: Firejail for system-level isolation, Docker for containerized environments
- **Zero-downtime Updates**: Automatic restart on file changes
- **Multi-user Support**: Runs applications with directory owner's UID/GID when started as root
- **Automatic HTTPS**: Transparent Let's Encrypt certificate acquisition and renewal
- **WebSocket Support**: Transparent WebSocket proxying
- **Resource Management**: Automatic shutdown after inactivity period

## File Structure

```
/opt/webcentral/go/
├── main.go          # Entry point, CLI argument parsing
├── server.go        # HTTP/HTTPS server, routing, ACME
├── project.go       # Project lifecycle management
├── logger.go        # Log rotation and pruning
└── config.go        # Configuration file parsing
```

## Configuration

Projects are configured via `webcentral.ini` in each project directory. The server itself is configured via command-line flags (see `--help`).
