//! Who a project belongs to, and the podman that runs as them.
//!
//! Webcentral never runs podman as root, whatever it runs as itself. Every container - and more
//! sharply every `build` command, which is arbitrary code from the project - therefore has at
//! worst the privileges of the person whose project it is. Rootless podman also maps container
//! root onto the invoking user, so "everything the container writes lands owned by the project
//! owner" stops being an invariant webcentral maintains with hand-built uid maps and becomes
//! simply what happens.
//!
//! A root webcentral spawning podman as somebody else cannot use that person's own podman storage:
//! podman records the run root in the database belonging to the store, so pointing a different one
//! at it fails with a configuration mismatch - and webcentral getting there first would break the
//! user's own `podman` in exactly the same way. It keeps a store of its own per owner instead,
//! which needs no `XDG_RUNTIME_DIR`, no `loginctl enable-linger`, and no logind at all. The price
//! is that those images do not show up in that user's `podman images`; the compensation is that
//! their `podman system prune` cannot take them away.

use anyhow::{Context, Result};
use nix::unistd::{Gid, Uid};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::process::Command;

/// Where a project's containers are run from, and as whom.
#[derive(Debug)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    /// Set when webcentral is root and podman must therefore be told to be somebody else. When it
    /// already *is* the owner, podman's own defaults are right and are left alone.
    identity: Option<Identity>,
    /// Whatever stopped this owner from being usable, said in terms someone can act on.
    pub problems: Vec<String>,
}

#[derive(Debug)]
struct Identity {
    home: PathBuf,
    groups: Vec<nix::unistd::Gid>,
    store: PathBuf,
    runroot: PathBuf,
}

impl Owner {
    /// Resolve who owns `dir`, and make sure podman can be run as them.
    ///
    /// Cached per uid: the checks cost a few file reads, and a host with sixty projects would
    /// otherwise repeat them sixty times and report each failure as many.
    pub fn of(dir: &Path) -> Arc<Owner> {
        use std::collections::HashMap;
        use std::sync::{Mutex, OnceLock};
        static CACHE: OnceLock<Mutex<HashMap<u32, Arc<Owner>>>> = OnceLock::new();

        let (uid, gid) = ownership(dir);
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Some(owner) = cache.lock().unwrap().get(&uid) {
            return owner.clone();
        }
        let owner = Arc::new(Owner::resolve(uid, gid));
        cache.lock().unwrap().insert(uid, owner.clone());
        owner
    }

    fn resolve(uid: u32, gid: u32) -> Owner {
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).ok().flatten();
        let name = user
            .as_ref()
            .map(|u| u.name.clone())
            .unwrap_or_else(|| uid.to_string());
        let mut problems = Vec::new();

        // Already this user: podman's own defaults are what we want, and setting an identity we
        // already have would need privileges we do not have.
        if nix::unistd::geteuid().as_raw() == uid {
            return Owner { uid, gid, name, identity: None, problems };
        }
        if !nix::unistd::geteuid().is_root() {
            problems.push(format!(
                "This project belongs to {} but webcentral runs as {}, and only root can run \
                 podman as someone else. Its containers would run as the wrong user, so it is \
                 left alone.",
                name,
                nix::unistd::geteuid().as_raw()
            ));
            return Owner { uid, gid, name, identity: None, problems };
        }

        let Some(user) = user else {
            problems.push(format!(
                "No account owns uid {}, so there is nobody to run its containers as. Give the \
                 project directory to a real user.",
                uid
            ));
            return Owner { uid, gid, name, identity: None, problems };
        };

        let store = user.dir.join(".local/share/webcentral/storage");
        let runroot = PathBuf::from(format!("/run/webcentral/{}", uid));
        for (path, mode) in [(&store, 0o700), (&runroot, 0o700)] {
            if let Err(e) = make_owned_dir(path, uid, gid, mode) {
                problems.push(format!("Could not prepare {} for {}: {}", path.display(), name, e));
            }
        }

        let groups = nix::unistd::getgrouplist(
            &std::ffi::CString::new(user.name.clone()).unwrap_or_default(),
            nix::unistd::Gid::from_raw(gid),
        )
        .unwrap_or_else(|_| vec![nix::unistd::Gid::from_raw(gid)]);

        Owner {
            uid,
            gid,
            name,
            identity: Some(Identity { home: user.dir, groups, store, runroot }),
            problems,
        }
    }

    /// A podman command that will run as this owner, with the store that belongs to them.
    /// Global flags go on now, so that whatever the caller appends stays a subcommand.
    pub fn podman(&self) -> Command {
        let mut cmd = Command::new(podman_path());
        if let Some(identity) = &self.identity {
            // Done by hand rather than with `Command::uid`/`gid`, because the supplementary
            // groups have to go first - after `setuid` there is no privilege left to drop them
            // with, and `Command`'s own hook runs later still. Root's groups would otherwise
            // survive into a process that is meant to be somebody else entirely.
            let (uid, gid) = (Uid::from_raw(self.uid), Gid::from_raw(self.gid));
            let groups = identity.groups.clone();
            unsafe {
                cmd.as_std_mut().pre_exec(move || {
                    nix::unistd::setgroups(&groups)?;
                    nix::unistd::setgid(gid)?;
                    nix::unistd::setuid(uid)?;
                    Ok(())
                });
            }
            // A child inherits the working directory, and webcentral's is wherever it was started
            // from - which the owner it is about to become may not be allowed to enter, and
            // podman resolves it again as it re-executes itself into a user namespace. Nothing it
            // is asked to do is relative, so the owner's own home is a directory they can always
            // reach.
            cmd.current_dir(&identity.home);
            cmd.env("HOME", &identity.home);
            cmd.env("USER", &self.name);
            cmd.env("LOGNAME", &self.name);
            // Podman finds its own configuration through these, and the child no longer has
            // root's. Setting HOME is not enough: an inherited `XDG_CONFIG_HOME` wins over it and
            // would send podman to the *invoking* user's `containers/storage.conf`, which the
            // owner it has just become cannot read - so every one of them is re-pointed at the
            // owner's own home rather than left to whatever started webcentral.
            cmd.env("XDG_RUNTIME_DIR", &identity.runroot);
            cmd.env("XDG_CONFIG_HOME", identity.home.join(".config"));
            cmd.env("XDG_DATA_HOME", identity.home.join(".local/share"));
            cmd.env("XDG_CACHE_HOME", identity.home.join(".cache"));
            // Named files rather than directories, so there is no owner-relative form to put
            // them at: dropped, which leaves podman with its own defaults under that home.
            for name in [
                "CONTAINERS_CONF",
                "CONTAINERS_CONF_OVERRIDE",
                "CONTAINERS_STORAGE_CONF",
                "CONTAINERS_REGISTRIES_CONF",
                "CONTAINERS_HELPER_BINARY_DIR",
                "REGISTRY_AUTH_FILE",
                "DOCKER_CONFIG",
                "TMPDIR",
            ] {
                cmd.env_remove(name);
            }
            cmd.arg("--root").arg(&identity.store);
            cmd.arg("--runroot").arg(&identity.runroot);
            // Someone who has never logged in has no systemd user session, and so no session bus
            // for the runtime to ask for a scope on. crun tries anyway and is told "interactive
            // authentication required", which surfaces as a container that will not start - so
            // say up front that cgroups are managed directly. Podman's own fallback is not
            // enough: it warns that it is using cgroupfs and still lets the runtime reach for
            // sd-bus. Nothing is lost by it, since webcentral sets no resource limits.
            cmd.args(["--cgroup-manager", "cgroupfs"]);
        }
        cmd
    }
}

impl Owner {
    /// Fix what can be fixed about running podman as this owner, saying what was done - so the
    /// caller can report it and try the same thing again. `Ok(None)` when there was nothing to do,
    /// which is the usual answer and the reason this is only asked after something failed.
    ///
    /// There is exactly one repairable thing: rootless podman maps a container's users onto a
    /// subordinate id range, which most distributions hand out at `useradd` time and some do not.
    /// Only a root webcentral can give one, and only a root webcentral running podman as somebody
    /// else needs one - which is what `identity` is. Written through `usermod`, which takes the
    /// locks that `/etc/subuid` wants and refuses a range that overlaps somebody else's.
    pub fn repair(&self) -> Result<Option<String>, String> {
        const FILES: [&str; 2] = ["/etc/subuid", "/etc/subgid"];
        if self.identity.is_none() || FILES.iter().all(|file| self.has_subids(file)) {
            return Ok(None);
        }
        // After every range anybody holds, so nothing can overlap; 100000 is where distributions
        // start, and each user gets the conventional 65536 ids.
        let start = FILES
            .iter()
            .flat_map(|file| subid_ranges(file))
            .fold(100_000, |top: u64, (start, count)| top.max(start + count));
        let range = format!("{}-{}", start, start + 65535);

        let refused = match std::process::Command::new("usermod")
            .args(["--add-subuids", &range, "--add-subgids", &range, &self.name])
            .output()
        {
            Ok(out) if out.status.success() => {
                return Ok(Some(format!(
                    "{} had no subordinate id range, which rootless podman needs, so it was given \
                     {}. Trying again.",
                    self.name, range
                )))
            }
            Ok(out) => String::from_utf8_lossy(&out.stderr).trim().to_string(),
            Err(e) => e.to_string(),
        };
        Err(format!(
            "{} has no subordinate id range and one could not be added ({}). Fix with: usermod \
             --add-subuids {} --add-subgids {} {}",
            self.name, refused, range, range, self.name
        ))
    }

    fn has_subids(&self, file: &str) -> bool {
        std::fs::read_to_string(file)
            .unwrap_or_default()
            .lines()
            .any(|line| line.split(':').next() == Some(self.name.as_str()))
    }

    /// What podman's own message leaves out, for the failures that name a symptom rather than a
    /// cause. Asked only of something that already went wrong, so it costs nothing until it is
    /// wanted - and answers from the host as it is now rather than as it was at startup.
    pub fn explain(&self, output: &str, dir: &Path) -> Option<String> {
        // Each is a phrase podman writes and the thing it does not say. `{user}` is this owner.
        const HINTS: [(&str, &str); 5] = [
            ("could not find pasta",
             "Rootless podman gives a container its network with pasta, which this host has not \
              got. Install your distribution's passt package (Debian and Ubuntu: apt install \
              passt), or keep using the older helper by putting 'default_rootless_network_cmd = \
              \"slirp4netns\"' under [network] in /etc/containers/containers.conf."),
            ("could not find slirp4netns",
             "Rootless podman gives a container its network with slirp4netns, which this host has \
              not got. Install your distribution's slirp4netns package, or its passt package and \
              podman 5, which uses pasta by default."),
            ("newuidmap",
             "newuidmap and newgidmap are what rootless podman maps user ids with. Install your \
              distribution's uidmap package (Fedora and RHEL: shadow-utils)."),
            ("write to uid_map failed",
             "The kernel refuses a mapping whose ranges overlap. Check /etc/subuid and \
              /etc/subgid for more than one line for {user}, and remove all but one."),
            ("no subuid ranges",
             "Rootless podman needs a subordinate id range. Fix with: usermod --add-subuids \
              100000-165535 --add-subgids 100000-165535 {user}"),
        ];
        if let Some((_, hint)) = HINTS.iter().find(|(phrase, _)| output.contains(phrase)) {
            return Some(hint.replace("{user}", &self.name));
        }
        self.unreachable(dir)
    }

    /// Whether every directory above `dir` can be entered by this owner, since podman becomes them
    /// before it so much as stats the project. A fact about the path rather than about the owner,
    /// and one somebody can change while webcentral runs, so it is worked out when a start fails
    /// rather than kept. Podman's own report of this is `context must be a directory`, which names
    /// neither the directory at fault nor the reason.
    fn unreachable(&self, dir: &Path) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let Some(identity) = &self.identity else { return None };

        let mut prefix = PathBuf::from("/");
        for component in dir.components().skip(1) {
            prefix.push(component);
            let Ok(meta) = std::fs::metadata(&prefix) else { continue };
            let mode = meta.permissions().mode();
            let may_enter = mode & 0o001 != 0
                || (mode & 0o100 != 0 && meta.uid() == self.uid)
                || (mode & 0o010 != 0
                    && identity.groups.iter().any(|g| g.as_raw() == meta.gid()));
            if !may_enter {
                return Some(format!(
                    "{} cannot enter {} (mode {:o}), so podman running as them cannot reach this \
                     project. Fix with: chmod o+x {}",
                    self.name,
                    prefix.display(),
                    mode & 0o7777,
                    prefix.display()
                ));
            }
        }
        None
    }

    /// Whether podman will be rootless for this owner. It is whenever webcentral is not root, and
    /// whenever it is root but becomes somebody else first - which leaves one case where it is
    /// not: a project owned by root on a root webcentral, where podman is root's own and rootless
    /// features like `keep-id` do not exist.
    pub fn runs_rootless(&self) -> bool {
        self.identity.is_some() || !nix::unistd::geteuid().is_root()
    }
}

/// The uid and gid a path belongs to, defaulting to root when it cannot be read.
pub fn ownership(path: &Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| (m.uid(), m.gid())).unwrap_or((0, 0))
}

/// The (start, count) of every subordinate id range in `file`, whoever holds it.
fn subid_ranges(file: &str) -> Vec<(u64, u64)> {
    std::fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':').skip(1);
            Some((fields.next()?.trim().parse().ok()?, fields.next()?.trim().parse().ok()?))
        })
        .collect()
}

/// Create a directory owned by someone else, which only root can do - and only root gets here.
fn make_owned_dir(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    if !path.exists() {
        std::fs::create_dir(path).with_context(|| format!("creating {}", path.display()))?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    if ownership(path) != (uid, gid) {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
    }
    Ok(())
}

/// The podman installation to use, found on PATH once.
pub fn podman_path() -> &'static str {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::OnceLock;
    static PODMAN_PATH: OnceLock<String> = OnceLock::new();

    PODMAN_PATH.get_or_init(|| {
        let path_var = std::env::var("PATH").unwrap_or_default();
        for dir in path_var.split(':') {
            let full_path = PathBuf::from(dir).join("podman");
            if let Ok(meta) = std::fs::metadata(&full_path) {
                if meta.is_file() && (meta.permissions().mode() & 0o111) != 0 {
                    return full_path.to_string_lossy().to_string();
                }
            }
        }
        println!("Warning: podman not found in PATH");
        "podman".to_string()
    })
}
