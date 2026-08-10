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
   under a root webcentral, without needing a separate `--userns-uid-map` on the build.

## What it costs

- **Per-user image storage.** Each owner gets their own `~/.local/share/containers`, so a base
  image shared by ten users is stored ten times. Podman's `additionalimagestores` can point them
  all at one read-only store, but that is configuration webcentral would have to write.
- **Every owner needs a runtime directory.** Rootless podman wants `XDG_RUNTIME_DIR`. On this
  machine only `/run/user/1000` exists, because only that user has logged in — so webcentral would
  need to either require `loginctl enable-linger <user>`, or create and own a directory itself and
  pass it. This is the part most likely to produce confusing failures, and it needs a clear
  diagnostic rather than a podman error.
- **Every owner needs subuid/subgid ranges.** Usually present (this machine has them for five
  users), but not guaranteed. Being root, webcentral *could* add them - which is a big thing to do
  silently, so it should probably diagnose instead.
- **`HOME` must be right**, since podman finds its storage through it. An owner whose home is on a
  filesystem overlayfs cannot use will fail in a way worth detecting up front.

## What it does not change

Ports are published on loopback above 1024, which rootless podman binds without help. The private
per-group network with `<name>.internal` aliases already works rootless — that is what the test
suite exercises today. `user = <uid>` still needs `--userns=keep-id`, with the podman/crun
fragility that already skips two tests on some hosts.

## Steps

1. Spawn every podman child with `uid()`/`gid()` and the owner's supplementary groups, `HOME`, and
   an `XDG_RUNTIME_DIR` webcentral has made sure exists.
2. Check the preconditions once per owner - subuid/subgid present, runtime directory usable - and
   report them as a project error rather than letting podman fail obscurely.
3. Delete the rootful branch of `add_userns_args` and `swap_map_args` with their tests.
4. Decide on shared image storage; without it, disk use grows with the number of distinct owners.
5. Keep a way back: a flag to use rootful podman for a project whose owner cannot run rootless.

## Until then

The narrow version of point 4 above is worth doing on its own, and is step 1 of
[PLAN-dockerfile.md](PLAN-dockerfile.md): pass `--userns-uid-map`/`--userns-gid-map` to
`podman build` so build commands are mapped to the project owner exactly as the run already is.
That closes the immediate hole without any of the operational requirements above.
