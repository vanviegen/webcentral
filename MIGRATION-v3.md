# Migrating to Webcentral 3.0

3.0 replaces the configuration format and the way applications are run. **A 2.x project will not
work until it is converted.** Nothing is read from `webcentral.ini` any more - not even partly, so
there is no half-migrated state to be surprised by.

The conversion is usually five minutes per project. Do it, then run:

```sh
webcentral check ~/webcentral-projects/example.com
```

which parses the project and prints every problem it finds, with a line and column, without
starting anything.

---

## The three things that changed

### 1. Everything runs in a container

Firejail is gone, and so is the unsandboxed path. Podman is now the only way an application runs,
and the only external dependency. **A project that relied on the host's `python`, `node` or `ruby`
has to say which image provides it** - `base = python:3-alpine`, or `packages` on top of alpine.

Containers always run **rootless**, as the user who owns the project directory, whether webcentral
itself runs as root or not. That user needs a subordinate id range, which most distributions give
every account by default:

```sh
grep "^$USER:" /etc/subuid || sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 "$USER"
```

Webcentral checks this when it loads a project and says so in the project's log if something is
missing, naming the command that fixes it.

### 2. `webcentral.ini` becomes `webcentral.conf`

The old file was a set of sections that each meant one fixed thing, and which of them you wrote
decided what *kind* of project you had. The new one is a small language: declarations saying what
the project *has*, and a script, run top to bottom, saying how requests are answered. That is what
makes a redirect project and a proxy project and a Node project the same kind of thing.

The examples below convert whole files, because settings do not translate one at a time: `port`
meant two different things depending on whether a `command` was present, and in 3.0 it lives
inside a service rather than at the top of the file.

### 3. What triggers a reload has been inverted

**2.x watched every file in the project** except a short exclusion list. **3.0 watches a
whitelist**: source directories (`src`, `app`, `lib`, `server`, `api`, `bin`), source extensions
(`*.py`, `*.js`, `*.rb`, `*.go`, ...) and dependency manifests. A restart is disruptive, and most
files in a project are not program text.

**This is the change most likely to go unnoticed**, because nothing fails - the application simply
keeps running with what it read at startup. A project whose application reads a `config.yaml`, a
`*.toml`, a `*.sql` schema or an HTML template at startup no longer restarts when those change.
Say so explicitly:

```ini
settings {
  reload_include = src config.yaml templates schema.sql
}
```

A service built from a `Dockerfile` is the exception: it watches everything, since anything in the
build context can change the image.

---

## Converting the file

Whole files, simplest first. The old file is on the left of each pair, the new one on the right -
or above and below, depending on how wide your window is.

### A static site, or a Node project

Nothing to do. `public/` and `package.json` are still detected without any configuration file, and
a `Dockerfile` now is too.

### Forward to something already running

**Before** — `webcentral.ini`:

```ini
port = 3000
host = 192.168.10.20
```

**After** — `webcentral.conf`:

```ini
forward 192.168.10.20:3000
```

A unix socket (`socket_path = /run/app.sock`) becomes `forward /run/app.sock`.

### Redirect, and proxy

**Before**:

```ini
redirect = https://new-name.example.com
```

**After** — the status was always 301, and now says so:

```ini
redirect https://new-name.example.com status=301
```

**Before**:

```ini
proxy = https://www.example.com
```

**After**:

```ini
proxy https://www.example.com
```

### An application

**Before** — a firejailed command, using whatever the host had installed:

```ini
command = python3 app.py --port $PORT
```

**After** — the same command, and the image that provides `python3`:

```ini
service {
  base = python:3-alpine
  command = python3 app.py --port $PORT
}
```

`$PORT` survives untouched: `${...}` is the only thing webcentral substitutes, so a command keeps
its shell variables.

### An application with packages, a build step and settings

**Before**:

```ini
command = php -S 0.0.0.0:$PORT -t public
[podman]
base = debian
packages[] = php
packages[] = composer
commands[] = composer install
mounts[] = data
app_dir = /srv
[reload]
timeout = 0
include[] = src
exclude[] = src/build
[environment]
APP_ENV = production
```

**After** — one block, and the settings named as what they do:

```ini
service {
  base = debian
  packages = php composer
  copy = composer.json composer.lock
  build = composer install
  command = php -S 0.0.0.0:$PORT -t public
  mounts = data
  app_dir = /srv
  shutdown_time = 0
  reload_include = src
  reload_exclude = src/build
  env {
    APP_ENV = production
  }
}
```

`copy` is new and usually wanted next to `build`: it names the files the build step needs inside
the image, so `composer install` runs against them and its result is baked in rather than repeated
on every start.

### An application with rewrites, workers and a password

This is where the shape really changes: rewrites and auth were sections that applied to the
project, and they are now statements in the script, in the order you want them run.

**Before**:

```ini
command = python app.py --port $PORT
worker = python background_tasks.py
worker:email = python email_processor.py
log_requests = true

[podman]
base = python:3-alpine

[environment]
DATABASE_URL = postgres://localhost/app

[rewrite]
/blog/(.*?)/.* = /articles/$1.html
/[^/]* = /index.html

[auth]
admin = $argon2id$v=19$m=19456,t=2,p=1$...
```

**After**:

```ini
service {
  base = python:3-alpine
  command = python app.py --port $PORT
  env {
    DATABASE_URL = postgres://localhost/app
  }

  service background { command = python background_tasks.py }
  service email { command = python email_processor.py }
}

log "${method} ${path}"
match /blog/(.*?)/.* { set path /articles/${1}.html }
match /[^/]* { set path /index.html }
serve
```

Five things to notice:

- **Workers are nested services** - *sidecars*. One that names no `base` of its own runs in its
  parent's image and starts from its parent's environment, which is exactly what a worker was.
- **`log_requests` is a `log` statement now**, so the line says what you want it to say and can sit
  behind a `match` if only some requests are worth recording. The client address is the one thing
  the old line had that this doesn't.
- **Capture groups are `${1}`, not `$1`.**
- **The script runs top to bottom**, so the order of the two `match` lines is the order they are
  tried in - where `[rewrite]` used to depend on the order of a hash map.
- **The password is gone.** See below.

---

## What was removed

**`Procfile` is no longer read.** It supplied a command line, but the runtime and the dependencies
its commands assume came from Heroku's buildpacks, which webcentral never had - so the
compatibility was partial in a way that failed at run time rather than when the file was read.
Write the `web:` line as `command =`, and any `worker:` lines as nested services, as above. (If
your Procfile project worked, it was because the host happened to have the runtime installed;
under 3.0 the image provides it.)

**Accounts and passwords are gone**: `[auth]`, its argon2 hashes, the `webcentral hash` subcommand
and the auth cookie. Webcentral is a proxy, and a proxy is the wrong place to keep a login session.

What remains is `check_auth <secret>`, one shared secret, sent as an `Authorization: Bearer`
header or a `secret=` query parameter - enough for something small like a dashboard, and not
pretending to be more:

```ini
env_file .env                       # DASHBOARD_SECRET=...
check_auth ${DASHBOARD_SECRET} { project_dashboard }
respond 401
```

An application that needs real logins does its own authentication - and can still hand delivery
back to webcentral with an `X-Accel-Redirect` header, whether that is a file on disk or anything
else the script can answer with. See **Internal redirects** in the README.

---

## Settings that did not appear above

| 2.x | 3.0 |
|---|---|
| `log_requests = true` | `log "${method} ${path}"` as the first statement |
| `[reload]` `timeout` | `shutdown_time` in the service |
| `startup_deadline` | `startup_time` |
| `[podman]` `http_port` | `port` |
| `[podman]` `commands[]` | `build` |
| `mount_app_dir = false` | `app_dir = none` |
| `[docker]` section | `service { ... }` - the engine was already podman |
| `type = dashboard` | `project_dashboard`, or `admin_dashboard` for every domain |
| `redirect_http` / `redirect_https` | the same, in a `settings { }` block |

---

## Worth doing while you are in there

- **If the project already has a `Dockerfile`, delete the service block** and let it be used. The
  Dockerfile answers every question webcentral would otherwise ask, in any language.
- **Move secrets into `env_file`.** `webcentral.conf` lives in the project directory and usually in
  git; an `env_file` does not have to. Nothing reaches a container's environment unless something
  names it, and values are handed to podman through its own environment rather than its command
  line, which `ps` shows to every user on the machine.
- **Check the reload rules**, per the inversion described above. It is the one change that fails
  silently.
