# Plan: build a project's own `Dockerfile` (target 3.1)

## Why

Webcentral can start anything it is *told* how to start. What it cannot do is work out how to run
a project it has never been configured for, in a language it has no recipe for. 3.0 detects only
`package.json`, because `scripts.start` is the one widespread convention that names a start
command; `requirements.txt`, `Gemfile` and `go.mod` say what to *install*, which is a different
question, and guessing a command from them would be guessing.

A `Dockerfile` answers every one of those questions at once — runtime, dependencies, and the
command — for any language, written by the people who know the project. Plenty of repositories
already have one. Supporting it turns "webcentral can host what you configure" into "webcentral
can host what you already ship", without a single new heuristic.

It also costs no new dependency: webcentral already generates a Dockerfile and calls
`podman build` on it. This is the same machinery pointed at a file the project wrote.

## The blocker that no longer blocks

The reason this was not done under docker: a build could reach outside the project directory, and
on a multi-user host that is somebody else's data. Podman closes it. Measured on podman 5.8.2:

| Attempt | Result |
|---|---|
| `COPY ../outside.txt` | refused: *"possible escaping context directory"* |
| `COPY link.txt` where `link.txt` → `../outside.txt` | refused: resolves to `/outside.txt` *inside the context*, which does not exist |
| `COPY abs.txt` where `abs.txt` → `/etc/passwd` | refused: resolves to `/etc/passwd` *inside the context*, which does not exist |

Podman's `copier` chroots the build context, so symlinks — relative *or* absolute — are resolved
against the context root rather than the host filesystem. There is no path from `COPY` to a file
outside the project directory.

## What is still not free

`RUN` executes arbitrary commands. That is the point of a Dockerfile, and it is also the whole
remaining risk surface. Three things to settle:

1. **Which user a build runs as.** Under a *rootless* webcentral this is already contained: the
   build runs in the invoking user's namespace. Under a **root** webcentral it does not — a
   project owner's `RUN` would execute as real root, which is more than that owner can do on the
   host. `podman build` accepts `--userns-uid-map`/`--userns-gid-map`, so the build should be
   mapped to the project owner exactly as `add_userns_args` maps the run. **This applies to the
   existing `build =` setting today** and should be fixed there first, independently of this plan.
2. **Network during build.** `--network=none` would be airtight but breaks every `apt`/`pip`/`npm`
   line, so it cannot be the default. Leave the network on, and note it.
3. **Build time.** A cold build is minutes, and it happens while a request waits. Preparation
   already runs at declaration time rather than on first request, so this mostly lands off the
   critical path — but `startup_time` should not be what covers a build.

## Shape

A project directory holding a `Dockerfile` and no `webcentral.conf`:

```
project/
  Dockerfile      → built; its CMD/ENTRYPOINT is the command; nothing is mounted
```

- `Dockerfile` joins `PROJECT_FILES`, so editing it reloads the project and rebuilds.
- The image tag hashes the Dockerfile's contents plus the build context's mtimes, the way `copy`
  hashes what it copies today, so an unchanged project skips the build.
- `app_dir` defaults to `none`: the image carries the code, and mounting the project over it would
  shadow what was just built. A project wanting the mount-and-restart loop says so explicitly.
- `user` defaults to `image`, as it does whenever the project directory is not mounted.
- `port` still defaults to 8000 and `$PORT` is still set; an `EXPOSE` line could seed the default.

Explicitly, in a `webcentral.conf`:

```ini
service {
  dockerfile = Dockerfile     # relative to the project, contained like `copy`
  port = 3000
}
```

## The trade to be honest about in the docs

A Dockerfile project does **not** get the reload loop. The code lives in the image, so a file
change means a rebuild, not a restart — seconds become minutes, and the "edit and refresh" story
does not apply. That is a real difference in kind, not a tuning knob, and it should be stated
where people will read it before they choose.

This is also the argument against going further to Cloud Native Buildpacks: they would bring
dependency resolution and a default process type for most languages, but the `pack` CLI plus a
builder image is hundreds of megabytes to over a gigabyte of new dependency, and the result is the
same immutable-image model. Two lifecycles is already one more than ideal; three is worse. If the
Dockerfile path proves popular, buildpacks become an *implementation detail* worth revisiting
(`builder = paketo` producing an image the same way), not a second parallel design.

## `docker-compose.yml`

Tempting — it names services, ports, volumes and dependencies, which is close to what a service
group already expresses, and real projects here use it. But it is an orchestration format, not an
application format: which service takes the domain, what `depends_on` means when starts are
on-demand, healthchecks, profiles, `x-` extensions. Reading it would mean either a faithful
implementation (large) or a subset that fails in ways the file does not suggest (exactly the trap
`Procfile` support fell into).

Recommendation: leave compose alone. A compose project is already served well by running compose
itself and pointing webcentral at the port with `forward`, which is what `photos.vanviegen.net`
does today in one line.

## Steps

1. Map `build =` into the project owner's namespace under a rootful webcentral (a fix on its own).
2. `dockerfile = <path>` in a `service`, contained within the project like `copy`.
3. Auto-detect a root `Dockerfile` when nothing else configures the project; add it to
   `PROJECT_FILES`.
4. Tag on Dockerfile contents + context state; reuse the stale-tag cleanup that exists.
5. Tests: a Dockerfile project serves; editing it rebuilds; a build cannot read outside the
   project (the three cases in the table above); a rootful build writes as the project owner.
6. Document the rebuild-not-restart trade next to the feature, not in a footnote.
