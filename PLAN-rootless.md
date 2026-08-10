# Plan: run every project's podman as its owner (target 3.1 / 4.0)

## The idea

A root webcentral currently talks to *rootful* podman for every project, and then works hard to
put the results back where they belong: `add_userns_args` passes a `--uidmap`/`--gidmap` pair with
the container's user and the project owner swapped, so that whatever the container writes lands
owned by the owner rather than by root.

The alternative is to stop being root for that work at all. `podman run` and `podman build` would
be spawned *as the project owner* — `tokio::process::Command` has `uid()`/`gid()`, so this is a
property of the child, not of webcentral — which makes them ordinary **rootless** podman
invocations, the same thing a non-root webcentral already does today.

## What it buys

1. **A container escape stops being a root escape.** Today a project's container, and more
   sharply its `build` commands, run with real root on the host behind whatever namespacing
   podman applies. Under this change the worst case is the project owner's own privileges — which
   is exactly the boundary the multi-user story claims.
2. **The ownership invariant becomes true by construction.** Rootless podman maps container root
   to the invoking user, so "everything the container writes lands owned by the project owner" is
   simply what happens, rather than something maintained by a hand-built bijective uid map.
3. **It deletes the subtlest code in the project.** The rootful branch of `add_userns_args` and
   all of `swap_map_args` exist only to serve this case. One code path replaces two, and the
   remaining one is the better-tested one: every local test run already exercises it.
4. **`build` is contained too**, closing the gap where a project's build commands run as root
   under a root webcentral.

## Where podman keeps its state, and why that decides the design

The obvious worry is `XDG_RUNTIME_DIR`: rootless podman wants one, and `/run/user/<uid>` only
exists for users who have logged in or had `loginctl enable-linger` set for them. Requiring an
admin to run that for every project owner is a poor answer.

Measured on podman 5.8.2, and it rules out the tempting shortcut:

- Setting `XDG_RUNTIME_DIR` to a directory of our own had **no effect** while `/run/user/<uid>`
  existed — the run root stayed `/run/user/1000/containers`.
- Passing `--runroot` explicitly against the *user's existing storage* fails outright:
  `database run root "/run/user/1000/containers" does not match our run root ...: database
  configuration mismatch`. **Podman pins the run root in the database that belongs to the
  graph root.**

So a scratch runtime directory cannot simply be bolted onto a user's normal podman storage. Worse,
if webcentral got there first and pinned *its* run root into the user's store, the user's own
`podman` would then fail with that same error. That is not an acceptable thing to do to somebody's
machine.

What does work, verified end to end (pulled an image and ran a container in it, with the user's
own podman entirely unaffected):

```
podman --root  <owner home>/.local/share/webcentral/storage \
       --runroot /run/webcentral/<uid> ...
```

**Webcentral gets its own store per owner, and pins its own run root into it.** No
`XDG_RUNTIME_DIR`, no lingering, no logind involvement, and no way to break the user's own podman.

The run root lives under `/run`, which is tmpfs and therefore cleared at boot — which is exactly
the lifetime it should have. It should *not* be cleaned when webcentral starts: a container
orphaned by a previous run in the same boot still refers to it.

Two consequences worth stating plainly rather than discovering later:

- **Images are not shared with the owner's own podman.** They will not appear in that user's
  `podman images`, and an image both use is stored twice.
- **That isolation is also a feature.** A user running `podman system prune` cannot remove the
  images webcentral depends on, and cannot confuse its state.

The alternative — root calling `loginctl enable-linger` for each owner and using their normal
store — shares the image store but makes webcentral mutate system state and depend on systemd.
Worth offering as an option; not the default.

## Checking a host is set up, at startup

Rootless podman also needs a subuid/subgid range per user, and `newuidmap`/`newgidmap` with the
right capabilities (on this machine: `cap_setuid=ep` and `cap_setgid=ep`, not the setuid bit).
When these are missing, podman's own error arrives much later and reads as a container failure
rather than a host configuration problem.

So: when a project directory is first scanned — at startup, and when a new domain appears — look
up its owner and check that owner once, caching the result per uid:

- a range for the user in `/etc/subuid` and `/etc/subgid`
- `newuidmap`/`newgidmap` present and privileged
- the store and run root directories creatable and ownable

Report failures **both** to webcentral's own output, where an administrator sees them, and to the
project's log, where its owner does — naming the remedy exactly:

```
someuser has no subuid range, so its containers cannot start.
Fix with: usermod --add-subuids 100000-165535 --add-subgids 100000-165535 someuser
```

A failing check should not stop the project from being registered: its services will fail at start
anyway, and by then the log already says why in terms the reader can act on.

## Steps

1. Spawn every podman child with `uid()`/`gid()`, the owner's supplementary groups, and `HOME`.
2. Pass `--root` and `--runroot` per owner, creating both 0700 and owned by them.
3. The startup check above, cached per uid.
4. Delete the rootful branch of `add_userns_args` and `swap_map_args` with their tests.
5. Keep a way back: a flag to use rootful podman for a project whose owner cannot run rootless.

## Until then

The narrow version of point 4 is worth doing on its own, and is step 1 of
[PLAN-dockerfile.md](PLAN-dockerfile.md): pass `--userns-uid-map`/`--userns-gid-map` to
`podman build` so build commands are mapped to the project owner exactly as the run already is.
That closes the immediate hole without any of the above.
