# Migrating to Webcentral 3.0

3.0 replaces the configuration format and the way applications are run. **A 2.x project will not
work until it is converted.** Nothing is read from `webcentral.ini` any more - not even partly, so
there is no half-migrated state to be surprised by.

The conversion is usually five minutes of work per project. Do it, then run:

```sh
webcentral check ~/webcentral-projects/example.com
```

which parses the project and prints every line it doesn't understand, with a line and column,
without starting anything.

---

## The two changes that matter

### 1. Everything runs in a container

Firejail is gone, and so is the unsandboxed path. Podman is now the only way an application runs,
and the only external dependency. **A project that relied on the host's `python`, `node` or `ruby`
has to say which image provides it.**

```ini
service {
  base = python:3-alpine        # or: packages = python3 py3-pip  (on top of alpine)
  command = python3 app.py
}
```

Containers always run **rootless**, as the user who owns the project directory - whether webcentral
itself runs as root or not. That user needs a subordinate id range, which most distributions give
every account by default:

```sh
grep "^$USER:" /etc/subuid || sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 "$USER"
```

Webcentral checks this when it loads a project and says so in the project's log if something is
missing, naming the command that fixes it.

### 2. `webcentral.ini` becomes `webcentral.conf`

The old file was a set of sections that each meant one fixed thing. The new one is a small
language: declarations that say what the project *has*, and a script, run top to bottom, that says
how requests are answered. That is what makes a redirect project and a proxy project and a static
project the same kind of thing.

---

## Converting the file

Rename `webcentral.ini` to `webcentral.conf` and rewrite it with this table. The
**Configuration** chapter of the README is the full reference.

| 2.x | 3.0 |
|---|---|
| `[app]` `command = ...` | `service { command = ... }` |
| `port = 3000` (with a command) | `service { port = 3000 ... }` |
| `port`/`host` with **no** command | `forward host:3000` |
| `type = redirect` + `target = ...` | `redirect https://example.com status=301` |
| `type = static` | `serve_dir public` (or nothing - `public/` is served by itself) |
| `type = dashboard` | `project_dashboard`, or `admin_dashboard` for every domain |
| `[rewrite]` `/a = /b` | `match /a { set path /b }` |
| `[rewrite]` with a URL target | `match /a { redirect https://... }` |
| `[environment]` `KEY = value` | `env { KEY = value }` inside the service - or `env_file .env` |
| `[auth]` and password hashes | gone - see **What was removed** |
| `mount_app_dir = false` | `app_dir = none` |
| `startup_deadline` | `startup_time` |
| `idle_timeout` | `shutdown_time` |
| `[podman]` `image = ...` | `base = ...` inside the service |
| `[podman]` `packages = ...` | `packages = ...` inside the service |
| worker processes | a nested `service` - see **Sidecars** in the README |

### A worked example

Before:

```ini
[app]
command = npm start
port = 3000
idle_timeout = 600

[environment]
NODE_ENV = production
DATABASE_URL = postgres://localhost/app

[rewrite]
/old-blog/(.*) = /blog/$1
```

After:

```ini
service {
  base = node:22-alpine
  command = npm start
  port = 3000
  shutdown_time = 600
  env {
    NODE_ENV = production
    DATABASE_URL = postgres://localhost/app
  }
}

match /old-blog/(.*) { set path /blog/${1} }
serve
```

Three things to notice:

- **`base` is new and usually necessary.** There is no host `node` to fall back on.
- **Capture groups are `${1}`, not `$1`.** `${...}` is the only substitution webcentral makes, which
  is exactly why a `command` can still contain `$PORT` and `$HOME` untouched.
- **`serve` at the end** hands the request to the service. It is implicit when the script would
  otherwise be empty, so a project that only runs an application needs no routing statements at
  all.

---

## What was removed

**`Procfile` is no longer read.** It supplied a command line, but the runtime and the dependencies
its commands assume came from Heroku's buildpacks, which webcentral never had - so the
compatibility was partial in a way that failed at run time rather than when the file was read.
Write the `web:` line as `command =`, and any `worker:` lines as nested services.

**Dependencies are not installed for you.** Use `copy` and `build` in the service, ship a
`Dockerfile`, or install them in the `command`:

```ini
service {
  base = python:3-alpine
  copy = requirements.txt
  build = pip install -r requirements.txt
  command = python3 app.py
}
```

**There are no accounts or passwords.** `[auth]`, its argon2 hashes, `webcentral hash` and the
auth cookie are all gone. Webcentral is a proxy, and a proxy is the wrong place for a login
session. What remains is `check_auth <secret>`, one shared secret for guarding something small
like a dashboard:

```ini
env_file .env                       # DASHBOARD_SECRET=...
check_auth ${DASHBOARD_SECRET} { project_dashboard }
respond 401
```

An application that needs real logins does its own authentication - and can still hand file
delivery back to webcentral with an `X-Accel-Redirect` header, so an authorised download is served
straight from disk. See **Internal redirects** in the README.

---

## Worth doing while you are in there

- **A `Dockerfile` in the project directory now needs no configuration at all.** If your project
  already has one, delete the service block and let it be used.
- **Secrets belong in `env_file`**, not in `webcentral.conf` - which sits in the project directory
  and usually in git. Nothing reaches a container's environment unless the file names it.
- **Reload rules default to a whitelist** of source directories, source extensions and dependency
  manifests, rather than to everything. If your application restarts too rarely, name what it runs
  from with `reload_include`.
