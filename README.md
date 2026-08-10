# Webcentral

A reverse proxy that runs multiple web applications for multiple users on a single server. Just put your app in a directory named like the target domain (eg `myapp.example.com/`), point DNS at the server, and you're done! The app will start (and shutdown) on-demand, and reload when its files change.


## Features

### Per domain request handling
- A small routing language per project: match on path, method or host, then serve files, delegate
  to an application, forward, proxy, redirect or answer directly
- Run any number of services per project, each in its own container with its own lifecycle,
  started only when a request is actually routed to it
- Config file not always needed (detects `package.json` and `public/`)

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
- Every application runs in a container
- Each application has its own decentralized configuration

**Security Notice:** While podman adds isolation, the integration hasn't been thoroughly audited. Webcentral may introduce additional attack surface. Use appropriate caution.

---

## Quick Start

```sh
# Download and install latest statically linked release
curl -LsSf https://github.com/vanviegen/webcentral/releases/latest/download/webcentral-$(uname -m)-unknown-linux-musl.tar.xz | sudo tar xJf - -C /usr/local/bin --strip-components=1 --wildcards '*/webcentral'
# Or build from source (see below)

# Install podman, which webcentral runs applications in
sudo apt install podman  # Debian/Ubuntu
# Or
sudo dnf install podman  # Fedora/RHEL

# Run it (replace email)
sudo webcentral --email you@example.com
# Or set it up as a persistent systemd service and run (recommended)
sudo webcentral --email you@example.com --systemd 
```

The `email` flag is mandatory, as it's needed for Let's Encrypt. Alternatively you can disable HTTPS (`webcentral --https 0`). See `webcentral --help` for more options.

Create a directory at `~/webcentral-projects/someapp.yourdomain.com/` with either:
- A `package.json` for Node.js apps (`npm start` should start a webserver on `$PORT`)
- A `public/` folder for static files
- A `webcentral.conf` for custom configuration (see below)

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
| Built-in sandboxing | Podman | ✗ | Docker | ✗ | Docker | Docker |
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

## Upgrading from 2.x

`webcentral.ini` is not read any more. Rename it to `webcentral.conf`, rewrite it in the language
below, and run `webcentral check` - it names every line it doesn't understand. What catches people:

- **Everything runs in a container**, so a project that used the host's `python`, `node` or `ruby`
  has to say which image has it: `base = python:3-alpine`, or `packages = ...` on top of alpine.
- **`Procfile` is no longer read.** It only ever supplied a command line, while the runtime and the
  dependencies it assumes came from Heroku's buildpacks - so write the `web:` line as `command =`,
  and its `worker:` lines as nested services.
- **Dependencies are not installed for you.** Heroku's buildpacks do that; webcentral does not.
  Use `copy` and `build` (see **Services**), a `Dockerfile`, or install them in the `command`.
- **There are no accounts or passwords.** `[auth]` and its hashes are gone. `check_auth <secret>`
  guards a dashboard with one shared secret; real logins belong to the application.
- `[rewrite] /a = /b` becomes `match /a set path /b`, and a rewrite target that was a URL becomes
  `redirect`. `type = dashboard` becomes `project_dashboard` or `admin_dashboard`.
- A bare `port`/`host` with no command becomes `forward host:port`.
- `mount_app_dir = false` becomes `app_dir = none`, `startup_deadline` becomes `startup_time`, and
  `[environment]` becomes an `env { }` block - with secrets better kept in `env_file`.

---

## Configuration

A project is a directory named after the domain it serves. Drop files in it and it works; add a
`webcentral.conf` when you want more control.

With **no configuration file at all**, webcentral looks at what the directory holds:

| The directory contains | What happens |
|------------------------|--------------|
| `public/` | its files are served |
| `Dockerfile` | it is built, and its `CMD` is run - whatever language the project is in |
| `package.json` with a `start` script | `npm start` is run as a service, on a node image |

That still applies when a `webcentral.conf` is present but never says how to answer a request - so
a file that only sets `log_requests` doesn't stop a `package.json` from being picked up.

Nothing else is guessed at. `requirements.txt` and `Gemfile` say what to *install*, not what to
run, and inventing a start command from them would be inventing - so every other language says it
in three lines, which is what the rest of this chapter is about.

It even applies to a declared `service` that names no `command` (while the project directory is
mounted, the default): the command is taken from `package.json`, so detection can be *tuned*
rather than given up:

```
service {                # next to a package.json with a `start` script
  packages = imagemagick
}
```

A mounted service with no command and nothing to detect one from is reported as an error; set
`app_dir = none` if the image's own entrypoint is what should run.

Run `webcentral check` in a project directory to parse its configuration and print every problem
found, without starting anything.

### The file

`webcentral.conf` is a list of statements, one per line:

```
verb argument... name=value...
```

Some take a `{ ... }` block. Blank lines are ignored, a `#` at the start of a word begins a
comment, and a `;` ends a statement early if you want two on one line.

There are two kinds of statement:

- **Declarations** - `settings`, `service` - say what the project
  *has*. They may only appear at the top level, their position relative to everything else doesn't
  matter, and their blocks hold `key = value` settings.
- **Routing statements** - everything else - form a small script, run top to bottom for every
  request.

```ini
service {  # defines the 'default' service
  packages = nodejs npm
  command = npm start
}

match /api/(.*) {
  set path /v2/${1}
  serve  # handled by the 'default' service
}
serve_dir public fallthrough=true
serve  # handled by the 'default' service
```

### Words and quoting

A word runs until whitespace. Almost every character is ordinary - `$`, `{`, `#` mid-word, and a
backslash - so regexes, URLs and version constraints need no quoting at all. Two kinds of quote
exist for the cases that do:

| | Use it for | `${...}` inside | Backslash inside |
|---|---|---|---|
| `"double"` | whitespace, a leading `#`, an `=` that isn't an argument separator | substituted | escapes `\n` `\t` `\r` `\"` `\\`; anything else is an error |
| `'single'` | the same, when the text must survive exactly as written | left alone | an ordinary character |

Quotes glue onto the rest of the word, like a shell, so a word can be part bare and part quoted.
**Where the quotes fall decides what the word means**, because only an `=` written *outside* them
separates a name from a value:

```ini
set token whatever-the-upstream-wants

set_header Authorization "Bearer ${token}"      # a value with a space in it
match /html respond 200 body type=text/html     # `type` is a named argument
match /text respond 200 "type=text/html"        # the body is the text `type=text/html`
```

To put a quote inside a word, either switch quote style or escape it:

```ini
match /a respond 200 'say "hi"'          # double quotes inside single ones
match /b respond 200 "she said \"hi\""    # or escaped inside double ones
match /c respond 200 "it's fine"         # an apostrophe inside double quotes
match /d respond 200 'it'"'"'s'          # ...and glued segments in a single-quoted word
```

Single quotes have no escapes at all, which is what makes them right for regexes and hashes -
and why **a regex should never be double-quoted**: `"\.css$"` fails, because `\.` is not an
escape webcentral knows. Leave it bare, or use single quotes:

```ini
match \.css$ anchored=false set_header Cache-Control immutable
match '\.(png|jpg)$' anchored=false set_header Cache-Control immutable
```

### Arguments

Positional arguments come first and are required. Anything shaped like `name=value` is a named
argument, and every positional one can also be given that way, so these are the same statement:

```ini
respond 404 "Not found" type=text/html
respond status=404 type=text/html body="Not found"
```

A name the statement doesn't have is an error rather than a guess - which is why a value that
contains an `=` has to be quoted:

```ini
set_header Cache-Control "max-age=31536000"
```

Without the quotes that reads as an argument called `max-age`, and webcentral says so.

### Variables

`${name}` is a variable, and **it is the only thing webcentral substitutes**. `${1}` to `${9}` are
the groups the last `match` captured; `${anything}` is a name.

A `$` not followed by `{` is an ordinary character. That is the whole rule, and it is what lets a
regex end in `$`, a price be `$5`, and a `command` keep `$PORT`, `$HOME` and `$$` for the shell it
is handed to - with nothing to escape anywhere. To write a literal `${`, single-quote it:
`respond 200 'costs ${5}'`.

These are always there, describing the request as it stands *now*:

| | |
|---|---|
| `${path}` | the request path, percent-encoded as it arrived |
| `${query}` | everything after the `?`, without it |
| `${method}` | `GET`, `POST`, ... |
| `${host}` | the `Host` header - what the client asked for |

**The first two are the request, not a copy of it.** Reading `${path}` gives the path being
served; assigning it changes what gets served or forwarded, which is how a request is re-pointed:

```ini
match /old/(.*) {
  set path /new/${1}                  # the query is left alone
  serve_dir public
}
match /legacy set path /v2/index.html?legacy=1   # a path may carry its own query
match /bare set path /clean?                     # ...and a lone `?` drops it
```

`set query` changes the query on its own. The other request variables describe what arrived and
cannot be assigned; `set` says so rather than pretending.
| `${domain}` | the domain this project is registered under - what it really is |

`set` names anything else. At the top of the file it doubles as a constant: the rest of the file
is read with it already defined, so it can stand in a pattern or a server name too.

```ini
set backend http://10.0.0.5:8080
set assets /var/www/shared
set image node:22-alpine

service {
  base = ${image}                 # constants reach declarations too
  command = npm start --port $PORT
}

match /api/(.*) proxy ${backend}
match /static/(.*) serve_file ${assets}/${1}
serve
```

Inside the script it is an ordinary assignment - useful to keep a capture that a nested `match`
would otherwise overwrite:

```ini
match /(?<lang>[a-z]{2})/docs/(.*) {
  set page ${2}
  match .*\.pdf serve_file downloads/${lang}/${page}
  serve_file docs/${lang}/${page}.html
}
```

There is one flat set of variables per request, seeded with the file's constants; last write wins,
and a `match` only overwrites the groups it actually captured.

**Where substitution happens: everywhere.** Statement arguments, settings inside declaration
blocks, `command` lines - all of them. What differs is *when*, and so what is available:

- Values webcentral reads as it loads the file - every declaration setting, a `match` pattern, a
  server name, a header name - see the constants that `set` defined **above** them.
- Values used while answering a request also see `${path}` and friends, and whatever the script has
  captured or set.

The one exception is a password hash in an `auth` block, which is taken exactly as written: it is
nothing but `$`, and it is a hash rather than text.

A `${name}` that nothing in the file ever sets is reported when the configuration is read - it would
otherwise silently be empty, which is a typo far more often than it is intent.

### Routing statements

Each of these decides something about the request. Most are **terminal** - they answer, and the
script stops. The three *conditionals* - `match`, `check_auth` and `check_file` - run their body
when they hold and otherwise take an `else` branch, if one follows, or carry on with the next
statement. `serve_file` and `serve_dir` answer 404 when they find nothing, unless
`fallthrough=true` tells them to leave the request to the statements below instead.

An implicit tail is appended to every script: `serve` if a service named `default` exists,
otherwise `serve_dir public` if that directory exists, otherwise a 404.

#### match

`match <pattern>` runs its body when the pattern matches, and declines when it doesn't.

`subject=` is what gets tested - `${path}` by default. It is an ordinary argument, so it can be
anything, including several variables joined together. `matcher=literal` compares as plain text
instead of a regex, and `anchored=false` matches anywhere in the value rather than all of it.

```ini
match /admin/(.*) respond 403 Forbidden
match POST subject=${method} respond 405 "read only"
match old.example.com subject=${host} matcher=literal redirect https://example.com${path} status=301
match /internal/ anchored=false matcher=literal respond 403 "not from outside"
match .*\.test/health subject=${host}${path} respond 200 OK
```

#### else

`else` runs when the statement before it declined. It pairs with the statement it follows, so an
inline body belongs to the `match`, and a block is how you attach it to something inside:

```ini
match /files/(.*) {
  serve_file uploads/${1} fallthrough=true
  respond 404 "no such upload"
}
else respond 400 "not a file request"
```

#### set path `set path <path>` changes the request path. Everything after it - including `${path}` - sees the new
one, and the query string is kept unless the new path brings its own.

```ini
match /v1/(.*) set path /api/${1}
```

#### serve

`serve [name]` hands the request to a declared service, starting it if it isn't running. With no
name it means the one called `default`.

```ini
service {
  packages = nodejs npm
  command = npm start
}
serve
```

#### serve_dir

`serve_dir <dir>` serves the request path from below `<dir>`. A directory serves its `index.html`
(`index=` names another) and, reached without a trailing slash, redirects to one. With
`fallthrough=true` a missing file leaves the request to whatever follows instead of answering
404 - which is the whole single-page-application idiom:

```ini
serve_dir public fallthrough=true
serve_file public/index.html
```

#### serve_file

`serve_file <file>` serves exactly that file, whatever the request path was, and takes the same
`fallthrough=true`.

```ini
match /robots.txt serve_file config/robots-production.txt
```

#### check_file

`check_file <path>` runs its body only when that file exists, which is how a decision is made
once and then acted on - setting a header that should not be left behind when the file turns out
to be missing:

```ini
match /static/(.*) {
  set candidate static/${1}.br
  check_file ${candidate} {
    set_header Content-Encoding br
    serve_file ${candidate}
  }
  serve_file static/${1}
}
```

#### forward

`forward <target>` passes the request to a port, a `host:port`, or a unix socket path, leaving the
`Host` header alone - so the backend sees the request as the client sent it.

```ini
match /metrics/(.*) forward 9090
match /socket/(.*) forward /run/app/app.sock
```

#### proxy

`proxy <url>` sends the request to another server, rewriting `Host` to the upstream's and adding
`X-Forwarded-Host`. The request path is appended to the URL.

```ini
match /images/(.*) proxy https://cdn.example.com
```

#### redirect

`redirect <url>` answers 302 - `status=` names another, and `301` is the one worth reaching for
deliberately, since browsers cache it indefinitely. `307` and `308` are there too, for a redirect
that must not turn a POST into a GET.

```ini
match /blog/(.*) redirect https://blog.example.com/${1} status=301
match /beta redirect /signup status=307
```

#### respond

`respond <code> [body]` answers immediately. `type=` sets the content type; without a body the
status's own reason phrase is used.

```ini
match /health respond 200 OK
match /.git/(.*) respond 403
match /teapot respond 418 "<b>short and stout</b>" type=text/html
```

#### check_auth

`check_auth <secret>` runs its block only when the request carries the secret, as an
`Authorization: Bearer` header or a `secret=` query parameter (so a link or bookmark can carry
it). Like `match`, what follows the statement still runs either way - end the script with a
`respond 401` (or use `else`) to actually deny.

```ini
set admin_secret hunter2

match /admin/(.*) {
  check_auth ${admin_secret} serve_dir admin
  else respond 403
}
serve_dir public
```

Webcentral deliberately has no user accounts or passwords of its own: an application that needs
real logins does its own authentication, and can still hand static delivery back to webcentral -
see **Internal redirects** below.

#### set_header

`set_header <name> <value>` adds a header to whatever ends up answering, so it can be stated once
above the statements that do the work.

```ini
match .*\.(js|css|woff2) {
  set_header Cache-Control "max-age=31536000, immutable"
  serve_dir public
}
```

#### log

`log <message>` writes a line to the project's log - handy for working out why a request went
where it did.

```ini
match /webhook/(.*) {
  log "webhook ${1} from ${host}"
  forward 4000
}
```

#### project_dashboard and admin_dashboard

`project_dashboard` serves the built-in status page for this project alone: its services, their
state, ports and request counts.

`admin_dashboard` serves the same page for *every* domain on the server, with server-wide numbers
on top. Since that shows everyone's projects, it only answers (with anything but a 403) from a
project owned by the user webcentral itself runs as.

```ini
check_auth hunter2 admin_dashboard
respond 401
```

### Patterns

Patterns are [regular expressions](https://docs.rs/regex/latest/regex/#syntax) matched against the
**whole** value, so `/api` matches only `/api` and never a fragment of a longer path. Write
`.*\.css` rather than `\.css$`; a pattern carrying its own `^` or `$` is reported, because inside
an already-anchored pattern it is at best redundant.

Groups are available to the body as `${1}`, `${2}`, ... and `(?<name>...)` as `${name}`. Use
`matcher=literal` when the pattern is really just a string - it saves escaping every `.` in a host
name, and is faster - and `anchored=false` when you mean "contains" rather than "is".

Because a pattern is compiled once, a variable in one is substituted then: a constant works,
`${path}` does not.

There is no separate way to declare things conditionally, and none is needed: declaring a server
only prepares its image - `serve` is what starts one. Choose between them at request time.

```ini
service stable {
  command = ./stable-server
}
service canary {
  command = ./canary-server
}

match beta subject=${query} anchored=false serve canary
serve stable
```

### Services

A service is a command webcentral runs for you, in a container: started the first time a request
needs it, stopped again when it has been idle, restarted when its files change. Its image is
prepared as soon as the file is read, so the first request usually finds it ready.

A start is considered done when the port answers: webcentral sends `GET /` until it gets any
HTTP response that is not a 5xx, within `startup_time`. An app whose `/` errors during boot is
simply not ready yet - but one whose `/` *always* answers 5xx will never count as started.

```ini
service {                         # no name, so it is called "default"
  command = python3 app.py --port $PORT
  shutdown_time = 5m
  startup_time = 30s
  reload_include = src templates
  env {
    DATABASE_URL = postgres://localhost/app
  }
  service email {
    command = python3 email_worker.py
  }
}
```

| Setting | Meaning |
|---------|---------|
| `command` | The command to run inside the container, given to `/bin/sh`. It must serve HTTP on `$PORT`, listening on all interfaces rather than only loopback - a published port reaches the container's own interface. Takes the rest of the line, quoting and all. Leave it out to use the image's own entrypoint. |
| `base` | The image to start from. Default `alpine`. |
| `packages` | Packages to add to it (auto-detects `apk`, `apt-get`, `dnf`, `yum`). |
| `build` | A command to run when the image is built. Repeat for more. |
| `copy` | Project files to put in the image before `build` runs, so it can use them (`copy = requirements.txt`). Paths are relative to the project and may not leave it. Editing one rebuilds the image and restarts the service. |
| `dockerfile` | Build the image from a Dockerfile of the project's own - see **Dockerfiles** below. Replaces `base`, `packages`, `build` and `copy`. |
| `port` | The port the command listens on inside the container. Default `8000`. |
| `mounts` | Directories that outlive the container, kept in `_webcentral_data/mounts/`. Relative paths are under `app_dir`. |
| `app_dir` | Where the project directory is mounted. Default `/app`; `none` mounts nothing, for images that carry the application themselves. |
| `user` | Who the container runs as *inside* - see **Container user** below. |
| `shutdown_time` | Idle time before stopping again. `0` keeps it running. Default `300` (seconds; `90s`, `5m` and `2h` also work). |
| `startup_time` | How long to wait for the port to answer before giving up. Default `60`. |
| `reload_include` | Which files restart it. Defaults to the project's `settings`, then to the built-in list below. |
| `reload_exclude` | Which of those to ignore anyway. |
| `env { }` | Environment variables for the command. |
| `service <name> { }` | A *sidecar*: another service sharing this one's lifetime - see **Sidecars** below. Without a `base` of its own it runs in this service's image, which is how an extra worker process is declared. |

`build` runs while the image is being made, which is *before* the project directory exists - so a
build command sees only what the image and `packages` brought, plus whatever `copy` puts there:

```ini
service {
  packages = python3 py3-pip
  copy = requirements.txt
  build = pip install --break-system-packages -r requirements.txt
  command = gunicorn app:app -b 0.0.0.0:$PORT
}
```

Copied files land in a directory of their own, which `build` runs in; `/app` is where the project
gets mounted at run time, so anything put there would be hidden the moment the container starts.
A copied file is part of what the image *is*, so editing it rebuilds the image and restarts the
service.

The base image is `alpine`, and `packages` adds to it - a one-layer build that podman caches, so
the second project asking for the same thing pays nothing:

```ini
service {
  packages = python3
  command = python3 -m http.server $PORT
}
```

A project may declare **several** services. Each starts only when a request is actually routed to
it, so a project can front more than one application without paying for the ones nobody asked for:

```ini
service api {
  packages = nodejs
  command = node api.js
}
service web {
  packages = nodejs
  command = node web.js
}

match /api/(.*) serve api
serve web
```

### Dockerfiles

A project that ships a `Dockerfile` has already answered every question webcentral would otherwise
ask - which runtime, which dependencies, which command - in whatever language it is written in. It
needs no configuration at all:

```
project/
  Dockerfile        # built with the project directory as its context
  ...
```

Or named explicitly, when it is not the whole story:

```ini
service {
  dockerfile = Dockerfile
  port = 3000
}
```

The image carries the application, so **the project directory is not mounted** and `app_dir`
defaults to `none`. That has a consequence worth knowing before you choose: a file change means a
**rebuild**, not a restart - so the edit-and-refresh loop that mounted services get does not apply.
Everything in the directory is watched, since anything in the build context can change what the
image is, and podman's layer cache keeps an unchanged rebuild to about a second.

`dockerfile` and `base`/`packages`/`build`/`copy` are alternatives, and saying both is an error:
the Dockerfile is already the answer to how the image gets built.

A Dockerfile can only reach what is inside the project directory. `COPY ../elsewhere` is refused,
and a symlink pointing out of the project resolves *inside* it and so finds nothing - podman
confines the build context, which is what makes it safe to build one user's Dockerfile on a
machine shared with others. Its `RUN` steps execute as the project's owner, like everything else.

### Sidecars

A service can nest others inside it. These start and stop with it, and each is told where the
others are through `<NAME>_HOST` and `<NAME>_PORT`:

```ini
service app {
  base = node:22-alpine
  command = npm start

  service db {
    base = postgres:16
    port = 5432
    mounts = /var/lib/postgresql/data
  }
}
serve app
```

A service and its sidecars form one group on a private network of their own, where each member
answers to `<name>.internal` - so the app above reaches its database at `db.internal:5432`, and
`db` can call back to `default.internal:8000`. Nothing is published to the host, and no
addresses are injected into the environment: write the name where you need it. Each container is
told its own port as `$PORT` and nothing else. A sidecar does have to listen on all interfaces
rather than only loopback, since its traffic arrives over the group's network rather than from
inside its own container.

When a port is worth stating once, a top-level `set` does it without any magic:

```ini
set api_port 9000

service {
  command = ./app
  env { API_URL = http://api.internal:${api_port} }
  service api {
    port = ${api_port}
    command = python3 api.py --port $PORT
  }
}
```

A sidecar with no `base` of its own runs in its parent's image *and* starts from its parent's
environment, anything it sets itself winning - it is the same application with another command,
which is all an extra worker process ever was. One that names a `base` is a different program and
inherits neither.

Only the server itself is waited for; a sidecar is started alongside and expected to come up on
its own. Sidecars cannot nest further - they already share a lifetime with
the server above them.

### Reload rules

`reload_include` and `reload_exclude` decide which changes restart a service. In `settings` they
are the default for every service in the project; a service can name its own instead, which is how
a change to a PHP file can restart the PHP service and leave the asset builder running:

```ini
service api {
  packages = php
  command = php -S 0.0.0.0:$PORT
  reload_include = *.php lib
}
service assets {
  packages = nodejs
  command = node watch.js
  reload_include = src/assets
}

match /build/(.*) serve assets
serve api
```

A pattern with no `/` matches at any depth (`*.log`, `node_modules`); one starting with `/` is
anchored to the project directory; `**` spans directories; `*`, `?` and `[a-z]` match within one
name. Naming a directory covers everything in it.

Whatever is listed, `_webcentral_data`, `node_modules`, hidden files, `*.log`, `*.bak`, `*.sw?`
and `data`/`log`/`logs` directories are always left out.

Saying nothing means a built-in list of things that plausibly *serve* requests: the `src`, `app`,
`lib`, `server`, `api` and `bin` directories, source files by extension (`.py`, `.rb`, `.php`,
`.js`/`.ts`/`.jsx`/`.tsx`, `.go`, `.rs`, `.java`, `.sh` and friends) wherever they live, and
dependency manifests like `requirements.txt`, `Gemfile.lock` or `go.mod`. Assets, uploads,
fixtures and generated output are *not* on it: a restart is disruptive, and whoever serves a file
reads it from disk anyway. A project whose code lives somewhere unusual - or one that does want a
restart when a template changes - says so with `reload_include`, which replaces the list entirely.

`webcentral.conf` itself is always watched, and changing it reloads the whole project rather than
restarting a service, since the script and the set of services may both be different afterwards.

### Authentication

Webcentral keeps no accounts and no passwords; `check_auth` (see above) compares one shared
secret, which is what a status page or a staging site needs. Anything beyond that - logins,
sessions, users - belongs to the application, which can still leave file delivery to webcentral
through an internal redirect:

### Internal redirects

A response from `serve`, `forward` or `proxy` that carries an `X-Accel-Redirect: /path` header
(the nginx convention, so frameworks emit it already) is not sent to the client. Instead the
request is re-routed through the script as a `GET` for that path, with two extra variables set:
`${redirected_from}` (the original path) and `${redirected_by}` (the server or target that answered).
The redirecting response's other headers carry over onto the final response, so the application
still controls things like `Content-Type` and `Content-Disposition` while webcentral streams the
file:

```ini
service { command = ./app }

match /files/(.*) {
  # Only reachable via the app, which checks who is asking before redirecting here
  match default subject=${redirected_by} matcher=literal serve_dir storage fallthrough=true
  respond 403
}
serve
```

One redirect may follow a request, not a chain; the redirected request has no body (the
application already consumed the original), which is also what keeps redirects compatible with
request streaming.

### Secrets

A password does not belong in `webcentral.conf`, which lives in the project directory and usually
in git. `env_file` reads `KEY=value` lines from somewhere else and makes them constants, so they
reach exactly what names them and nothing else:

```ini
env_file .env

service {
  command = ./app
  env {
    DATABASE_URL = postgres://app:${DB_PASSWORD}@db.internal:5432/app
  }
  service db {
    base = postgres:16
    port = 5432
    user = 999:999
    app_dir = none
    mounts = /var/lib/postgresql/data
    env {
      POSTGRES_PASSWORD = ${DB_PASSWORD}
      POSTGRES_USER = app
      POSTGRES_DB = app
    }
  }
}
check_auth ${DASHBOARD_SECRET} project_dashboard
serve
```

Nothing is injected anywhere by itself: a value reaches a service only where you write
`${NAME}`, so a sidecar never sees a secret it has no use for. Blank lines and `#` comments are
skipped, a leading `export ` is ignored, and one layer of surrounding quotes comes off the value.
The file must live inside the project directory, is read in the order it appears (like `set`), and
changing it reloads the project. Values from it are never re-substituted - a secret is not a
template.

A container's environment is handed to podman through *its* environment rather than its command
line, because `podman run` stays alive for as long as the container does and anyone on the machine
can read another process's command line with `ps`. Nothing is written to disk for it, and the
startup log line records the variable's name without its value.

Keep the file out of git (`.gitignore`) and readable only by the project owner.

### Project settings

```ini
settings {
  log_requests = true         # one log line per request
  redirect_http = false       # don't redirect http:// to https:// for this project
  redirect_https = true       # ...redirect the other way around instead
  reload_include = src public "file with spaces"
  reload_exclude = src/build **/*.bak
}
```

`redirect_http` overrides the server-wide `--redirect-http` for this project alone - useful for a
domain that has to stay reachable over plain HTTP. `redirect_https = true` goes the other way,
sending HTTPS visitors to the plain-HTTP site; there is no server-wide version of that.

### Container user

`user` decides who the container runs as inside it:

- `project` - the project owner. Under a root webcentral they are added to the image as a real
  user named `webcentral` (with `$HOME` in `_webcentral_data/home`); under a non-root webcentral
  the container runs as root inside, which is how rootless podman represents you. This is the
  default when the project directory is mounted.
- `image` - whatever the image itself declares. The default when it isn't.
- `uid:gid` - exactly those ids. A bare uid is refused, because the group it pairs with depends on
  the image.
- A user name defined in the image.

Stock database images are the case that needs `uid:gid` spelled out. The official `postgres`
image declares no user, so webcentral sees *root* - but its entrypoint drops to uid 999 at run
time, after the mapping has been decided. Its data directory then lands owned by an id the project
owner cannot touch, and `initdb` fails outright because the directory webcentral pre-created for
it is the owner's. Naming the id brings it back under the guarantee:

```ini
env_file .env

service app {
  command = ./app
  service db {
    base = postgres:16
    port = 5432
    user = 999:999          # what the postgres image switches to at run time
    app_dir = none
    mounts = /var/lib/postgresql/data
    env { POSTGRES_PASSWORD = ${DB_PASSWORD} }
  }
}
serve app
```

`podman run --rm postgres:16 id -u postgres` says which id an image uses. MySQL and MariaDB
(also 999) and Redis need the same treatment; an image that runs as the user it declares does not.

Whatever it runs as, **everything the container writes into the project directory or its `mounts`
lands on the host owned by the project owner** - because podman itself runs as that owner. (One
exception, which webcentral says out loud: a project owned by *root* on a root webcentral uses
root's own podman, where a container's uid is already a host uid and there is nothing to remap.
Give projects to ordinary users.)
Webcentral never runs a container as root: when it runs as root it becomes the project's owner
before calling podman, and rootless podman maps container root onto whoever invoked it. An image
that switches at runtime to a uid it doesn't declare writes as that uid instead; naming it in
`user` brings it back under the guarantee.

Each owner gets a podman image store of its own, under their home directory. It is separate from
whatever they use podman for themselves, which means webcentral's images do not appear in their
`podman images` - and equally that their `podman system prune` cannot take webcentral's away.
Rootless podman needs a subordinate id range per user (`/etc/subuid` and `/etc/subgid`); webcentral
checks for one when it first sees a project and says exactly what to run if it is missing.

---

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--version` (`-V`) | Print the version number and exit. |
| `--email=EMAIL` | Email for Let's Encrypt. Required unless `--https=0`. |
| `--projects=DIR` | Project directory glob. Default: `/home/*/webcentral-projects` (root) or `$HOME/webcentral-projects` (user). |
| `--data-dir=DIR` | Certificate and binding storage directory. Default: `/var/lib/webcentral` (root) or `$HOME/.webcentral` (user). |
| `--https=PORT` | HTTPS port. Default: `443`. Set to `0` to disable. |
| `--http=PORT` | HTTP port. Default: `80`. Set to `0` to disable. |
| `--http3` | Also serve HTTP/3 (QUIC) on the HTTPS port. |
| `--redirect-http=BOOL` | Redirect HTTP to HTTPS. Default: `true` when both listeners are enabled. |
| `--redirect-www=BOOL` | Auto-redirect between `example.com` and `www.example.com`. Default: `true`. |
| `--systemd` | Install a systemd unit running webcentral as it was invoked, then start it. |
| `--prune-logs=DAYS` | Days to keep log files. Default: `28`. Set to `0` to disable pruning. |
| `--acme-url=URL` | ACME directory URL. Default: Let's Encrypt (`https://acme-v02.api.letsencrypt.org/directory`). |
| `--acme-version=VER` | ACME protocol version. Default: `draft-11`. |

Two subcommands stand on their own:

| Command | Description |
|---------|-------------|
| `webcentral check [path]` | Parse a project's `webcentral.conf` and print every problem found, without starting anything. Exits non-zero if there were any. Takes a project directory or the file itself; defaults to the current directory. |

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

2026-08-10 (3.0.0):
  - `Procfile` is no longer detected: it supplied a command but never the runtime or the dependencies its commands assume, so the compatibility was partial in a way that failed at run time rather than at parse time. `package.json` with a `start` script still is
  - **`webcentral.ini` is replaced by `webcentral.conf`**, a small configuration language. A project's requests are handled by a routing script run top to bottom - `match`, `serve`, `serve_dir`, `check_file`, `forward`, `proxy`, `respond` and friends - which subsumes what used to be fixed project types: a redirect project is now the one-line script `redirect https://example.com status=301`. The old format is not read; see **Configuration** above. Projects that need no configuration file (`public/`, `Procfile`, `package.json`) are unaffected
  - Configuration errors are reported with **line and column**, all of them in one pass, and the rest of the file still runs. `webcentral check` parses a project without starting anything
  - **Containers always run as the project's owner**, through rootless podman, whether webcentral itself runs as root or not. A container - and more sharply a `build` command, which is arbitrary code from the project - therefore has at worst that person's privileges, and "what a container writes is owned by the project owner" stops being a hand-built uid mapping and becomes what podman does by itself. Each owner gets an image store of their own, so nothing is shared with, or prunable by, their own podman
  - A project with a **`Dockerfile`** is built and run from it, in any language and with no configuration - the file already says which runtime, which dependencies and which command. Its build context cannot reach outside the project directory
  - **Everything runs in a container.** Firejail support is gone and with it the choice: one keyword, `service`, and podman as the only external dependency. A project can declare several, each with its own image, port, lifecycle and reload rules, each started only when a request is routed to it. A nested `service` is a *sidecar* sharing its parent's lifetime, image and environment - which is what replaced workers
  - **Authentication belongs to the application.** Basic auth, password hashes and the auth cookie are gone. What remains is `check_auth <secret>` for guarding a dashboard, and `X-Accel-Redirect`, which lets an application authorise a request and hand the delivery back to webcentral
  - `env_file` keeps secrets out of the configuration, and they reach a container through podman's environment rather than its command line, which `ps` exposes to every user on the machine
  - Request bodies and static files are **streamed**, and static files support `Range`, so uploads and video seeking work at any size
  - The whole projects tree is watched with **one** inotify instance rather than one per project (60 projects went from 61 to 2), and reload rules default to a whitelist of program text rather than to everything
  - Fix containers being orphaned on shutdown, both because only SIGINT was handled - not the SIGTERM systemd sends - and because the stop was never waited for
  - Fix services being unreachable on IPv6 hosts: ports are published on `127.0.0.1` and addressed that way

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
