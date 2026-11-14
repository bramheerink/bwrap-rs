//! Tests that need a real user+mount namespace: the id-map writers, the
//! capability policy (full capability sets inside the new userns) and
//! `ensure_newroot_parents` (which hardcodes `/newroot`).
//!
//! `harness = false`: `clone(2)` is only allowed from a single-threaded
//! process, which libtest's runner is not. Each test does its work in a cloned
//! child and reports through the exit code. Where the environment forbids
//! `clone(CLONE_NEWUSER)` (nested sandboxes) the test prints SKIP and passes.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::ExitCode;

use bwrap_core::caps::{
    cap_last_cap, drop_all_caps, drop_bounding_set, has_caps, initial_requested, set_ambient,
};
use bwrap_core::fs::{NodeType, ensure_newroot_parents, ensure_node_at};
use bwrap_core::types::{CapSet, Capability};
use bwrap_core::userns::{IdMap, disable_user_namespaces};
use bwrap_sys::ForkError;
use bwrap_sys::caps::{bounding_set_contains, capget};
use bwrap_sys::process::clone_into_namespaces;
use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::sched::CloneFlags;
use nix::sys::stat::Mode;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, getegid, geteuid, getgid, getuid};

enum Outcome {
    Pass,
    Skip(String),
    Fail(String),
}

type Check = Result<(), String>;

/// Fail with a message unless `cond`.
fn ensure(cond: bool, msg: impl FnOnce() -> String) -> Check {
    if cond { Ok(()) } else { Err(msg()) }
}

/// Run `body` in a child inside fresh user+mount namespaces.
fn in_userns(body: impl FnOnce() -> Check) -> Outcome {
    match clone_into_namespaces(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS) {
        Ok(ForkResult::Child) => match body() {
            Ok(()) => std::process::exit(0),
            Err(msg) => {
                eprintln!("    {msg}");
                std::process::exit(1)
            }
        },
        Ok(ForkResult::Parent { child }) => match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, 0)) => Outcome::Pass,
            Ok(other) => Outcome::Fail(format!("child ended with {other:?}")),
            Err(e) => Outcome::Fail(format!("waitpid: {e}")),
        },
        Err(ForkError::Sys(Errno::EPERM | Errno::ENOSPC | Errno::EINVAL | Errno::EUSERS)) => {
            Outcome::Skip("clone(CLONE_NEWUSER) not permitted here".into())
        }
        Err(e) => Outcome::Fail(format!("clone: {e}")),
    }
}

fn proc_fd() -> std::os::fd::OwnedFd {
    open("/proc", OFlag::O_PATH | OFlag::O_DIRECTORY, Mode::empty()).unwrap()
}

/// Fields of the single line of a `/proc/self/{uid,gid}_map` file.
fn map_fields(name: &str) -> Vec<u64> {
    fs::read_to_string(format!("/proc/self/{name}"))
        .unwrap()
        .split_whitespace()
        .map(|f| f.parse().unwrap())
        .collect()
}

fn status_field(name: &str) -> String {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix(name))
        .unwrap_or("")
        .trim()
        .to_owned()
}

// ---- userns.rs ----

fn test_id_map_keeps_ids() -> Outcome {
    let (uid, gid) = (getuid().as_raw(), getgid().as_raw());
    in_userns(|| {
        let map = IdMap {
            sandbox_uid: uid,
            parent_uid: uid,
            sandbox_gid: gid,
            parent_gid: gid,
            deny_groups: true,
        };
        map.write(proc_fd().as_fd()).map_err(|e| e.to_string())?;
        let u = map_fields("uid_map");
        let g = map_fields("gid_map");
        ensure(u == [u64::from(uid), u64::from(uid), 1], || {
            format!("uid_map {u:?}")
        })?;
        ensure(g == [u64::from(gid), u64::from(gid), 1], || {
            format!("gid_map {g:?}")
        })?;
        let sg = fs::read_to_string("/proc/self/setgroups").unwrap();
        ensure(sg == "deny\n", || format!("setgroups {sg:?}"))?;
        ensure(getuid().as_raw() == uid && getgid().as_raw() == gid, || {
            "ids changed".into()
        })
    })
}

fn test_id_map_to_root() -> Outcome {
    let (uid, gid) = (getuid().as_raw(), getgid().as_raw());
    in_userns(|| {
        let map = IdMap {
            sandbox_uid: 0,
            parent_uid: uid,
            sandbox_gid: 0,
            parent_gid: gid,
            deny_groups: true,
        };
        map.write(proc_fd().as_fd()).map_err(|e| e.to_string())?;
        ensure(
            getuid().is_root()
                && geteuid().is_root()
                && getgid().as_raw() == 0
                && getegid().as_raw() == 0,
            || "not mapped to 0".into(),
        )?;
        let u = map_fields("uid_map");
        ensure(u == [0, u64::from(uid), 1], || format!("uid_map {u:?}"))
    })
}

fn test_id_map_requires_setgroups_deny() -> Outcome {
    // Without setgroups=deny an unprivileged writer may not write gid_map:
    // this is exactly why bwrap orders the writes the way it does.
    let (uid, gid) = (getuid().as_raw(), getgid().as_raw());
    in_userns(|| {
        let map = IdMap {
            sandbox_uid: uid,
            parent_uid: uid,
            sandbox_gid: gid,
            parent_gid: gid,
            deny_groups: false,
        };
        let r = map.write(proc_fd().as_fd());
        match r {
            Err(e) if e.to_string() == "setting up gid map: Operation not permitted" => {
                // The uid map, written first, did take effect.
                let u = map_fields("uid_map");
                ensure(u == [u64::from(uid), u64::from(uid), 1], || {
                    format!("uid_map {u:?}")
                })
            }
            other => Err(format!("expected gid_map EPERM, got {other:?}")),
        }
    })
}

fn test_disable_userns_is_per_namespace() -> Outcome {
    // user.max_user_namespaces is a per-userns sysctl, so writing it from a
    // fresh namespace limits only that namespace's descendants and leaves the
    // host's value alone (this is how --disable-userns works).
    let host = fs::read_to_string("/proc/sys/user/max_user_namespaces").unwrap();
    let out = in_userns(|| {
        disable_user_namespaces(proc_fd().as_fd()).map_err(|e| e.to_string())?;
        let v = fs::read_to_string("/proc/sys/user/max_user_namespaces").unwrap();
        ensure(v.trim() == "1", || format!("sysctl reads back {v:?}"))
    });
    let after = fs::read_to_string("/proc/sys/user/max_user_namespaces").unwrap();
    if after != host {
        return Outcome::Fail(format!("host sysctl changed: {host:?} -> {after:?}"));
    }
    out
}

fn test_disable_userns_errors_without_sysctl() -> Outcome {
    // A /proc-like directory without sys/user/max_user_namespaces.
    let d = std::env::temp_dir().join(format!("bwrap-noproc-{}", std::process::id()));
    fs::create_dir_all(&d).unwrap();
    let fd = open(&d, OFlag::O_PATH | OFlag::O_DIRECTORY, Mode::empty()).unwrap();
    let r = disable_user_namespaces(fd.as_fd());
    let _ = fs::remove_dir_all(&d);
    match r {
        Err(e)
            if e.to_string()
                == "cannot open /proc/sys/user/max_user_namespaces: No such file or directory" =>
        {
            Outcome::Pass
        }
        other => Outcome::Fail(format!("{other:?}")),
    }
}

// ---- caps.rs ----

fn test_caps_policy() -> Outcome {
    in_userns(|| {
        let state = capget().map_err(|e| e.to_string())?;
        ensure(state.permitted != 0, || "no caps in a fresh userns".into())?;
        ensure(has_caps().map_err(|e| e.to_string())?, || {
            "has_caps false".into()
        })?;

        // cap_last_cap agrees with the bounding-set probe on both sides.
        let last = cap_last_cap();
        ensure(bounding_set_contains(u32::from(last)).is_ok(), || {
            "last cap unreadable".into()
        })?;
        ensure(
            bounding_set_contains(u32::from(last) + 1) == Err(Errno::EINVAL),
            || "last+1 should be EINVAL".into(),
        )?;

        // As "root", the initial requested set is the effective set.
        let init = initial_requested(true).map_err(|e| e.to_string())?;
        ensure(init.bits() == state.effective, || {
            format!("initial {:#x}", init.bits())
        })?;

        let chown = Capability::from_number(0).unwrap();
        let net_raw = Capability::from_name("CAP_NET_RAW").unwrap();
        let sys_admin = Capability::from_name("CAP_SYS_ADMIN").unwrap();
        let mut keep = CapSet::EMPTY;
        keep.insert(chown);
        keep.insert(net_raw);

        // Bounding set: everything else goes, `keep` stays.
        drop_bounding_set(keep).map_err(|e| e.to_string())?;
        for n in 0..=last {
            let want = keep.contains(Capability::from_number(n).unwrap());
            let got = bounding_set_contains(u32::from(n)).map_err(|e| e.to_string())?;
            ensure(got == want, || {
                format!("bounding cap {n}: got {got}, want {want}")
            })?;
        }
        ensure(!keep.contains(sys_admin), || "fixture".into())?;

        // Keep as root with no --cap-add/--cap-drop: capset is skipped.
        drop_all_caps(Some(keep), false, true).map_err(|e| e.to_string())?;
        ensure(capget().unwrap() == state, || "capset not skipped".into())?;

        // With cap ops: exactly `keep` in all three sets.
        drop_all_caps(Some(keep), true, true).map_err(|e| e.to_string())?;
        let now = capget().unwrap();
        ensure(
            now.effective == keep.bits()
                && now.permitted == keep.bits()
                && now.inheritable == keep.bits(),
            || format!("capset result {now:?}"),
        )?;

        // Ambient: raised for kept caps (they are permitted and inheritable now).
        set_ambient(keep).map_err(|e| e.to_string())?;
        let amb = status_field("CapAmb:");
        ensure(amb == format!("{:016x}", keep.bits()), || {
            format!("CapAmb {amb}")
        })?;
        Ok(())
    })
}

fn test_caps_drop_all() -> Outcome {
    in_userns(|| {
        // Dropping the whole bounding set is drop_bounding_set with an empty keep.
        drop_bounding_set(CapSet::EMPTY).map_err(|e| e.to_string())?;
        for n in 0..=cap_last_cap() {
            ensure(bounding_set_contains(u32::from(n)) == Ok(false), || {
                format!("cap {n} still bounded")
            })?;
        }
        drop_all_caps(None, false, false).map_err(|e| e.to_string())?;
        let s = capget().unwrap();
        ensure(
            s.effective == 0 && s.permitted == 0 && s.inheritable == 0,
            || format!("{s:?}"),
        )?;
        ensure(!has_caps().unwrap(), || "has_caps after drop".into())?;
        // Raising caps we no longer hold: EPERM is swallowed, nothing happens.
        set_ambient(CapSet::ALL).map_err(|e| e.to_string())?;
        ensure(status_field("CapAmb:") == "0000000000000000", || {
            "ambient not empty".into()
        })?;
        // Without privilege, getting capset back up is refused (non-root: fatal).
        let mut keep = CapSet::EMPTY;
        keep.insert(Capability::from_number(0).unwrap());
        match drop_all_caps(Some(keep), true, false) {
            Err(e) if e.to_string() == "capset failed: Operation not permitted" => {}
            other => return Err(format!("expected capset EPERM, got {other:?}")),
        }
        // ...but as "root" (is_root) the same EPERM is tolerated.
        drop_all_caps(Some(keep), true, true).map_err(|e| e.to_string())?;
        ensure(capget().unwrap().permitted == 0, || "caps came back".into())
    })
}

// ---- fs/node.rs: ensure_newroot_parents ----

fn test_newroot_parents() -> Outcome {
    let base: PathBuf = std::env::temp_dir().join(format!("bwrap-newroot-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("newroot")).unwrap();
    let b = base.clone();
    let out = in_userns(move || {
        nix::unistd::chroot(&b).map_err(|e| format!("chroot: {e}"))?;
        std::env::set_current_dir("/").map_err(|e| e.to_string())?;
        nix::sys::stat::umask(Mode::empty());
        let mode = Mode::from_bits_truncate(0o750);

        // No components: the parent is /newroot itself.
        for p in [&b""[..], b"/", b"///"] {
            let (fd, last) = ensure_newroot_parents(p, mode).map_err(|e| format!("{p:?}: {e}"))?;
            ensure(last == b".", || format!("last {last:?}"))?;
            ensure(is_at(&fd, "/newroot"), || {
                "fd at wrong directory".to_string()
            })?;
        }

        // One component: nothing is created, the parent is /newroot.
        let (fd, last) = ensure_newroot_parents(b"/usr", mode).map_err(|e| e.to_string())?;
        ensure(last == b"usr" && is_at(&fd, "/newroot"), || {
            format!("{last:?}")
        })?;
        ensure(!std::path::Path::new("/newroot/usr").exists(), || {
            "last component created".into()
        })?;

        // Deep path: parents created with `mode`, last component left alone.
        let (fd, last) = ensure_newroot_parents(b"//a//b/c/d/", mode).map_err(|e| e.to_string())?;
        ensure(last == b"d", || format!("last {last:?}"))?;
        ensure(is_at(&fd, "/newroot/a/b/c"), || {
            "fd at wrong directory".to_string()
        })?;
        ensure(!std::path::Path::new("/newroot/a/b/c/d").exists(), || {
            "d created".into()
        })?;
        for d in ["/newroot/a", "/newroot/a/b", "/newroot/a/b/c"] {
            let m = fs::metadata(d)
                .map_err(|e| e.to_string())?
                .permissions()
                .mode()
                & 0o777;
            ensure(m == 0o750, || format!("{d} mode {m:o}"))?;
        }

        // Existing parents are reused (EEXIST tolerated); a sibling hangs off them.
        let (fd, last) = ensure_newroot_parents(b"a/b/e", mode).map_err(|e| e.to_string())?;
        ensure(last == b"e" && is_at(&fd, "/newroot/a/b"), || {
            "fd at wrong directory".to_string()
        })?;

        // The returned fd is usable with ensure_node_at.
        ensure_node_at(fd.as_fd(), b"e", NodeType::File, None).map_err(|e| e.to_string())?;
        ensure(
            fs::metadata("/newroot/a/b/e").is_ok_and(|m| m.is_file()),
            || "e missing".into(),
        )?;

        // A non-directory parent component fails.
        let r = ensure_newroot_parents(b"a/b/e/x/y", mode);
        ensure(matches!(r, Err(Errno::ENOTDIR | Errno::EEXIST)), || {
            format!("through a file: {:?}", r.map(|(_, l)| l))
        })?;
        Ok(())
    });
    let _ = fs::remove_dir_all(&base);
    out
}

/// Whether `fd` refers to the same inode as `path` (no /proc inside the chroot).
fn is_at(fd: &std::os::fd::OwnedFd, path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(st) = nix::sys::stat::fstat(fd.as_fd()) else {
        return false;
    };
    fs::metadata(path).is_ok_and(|m| m.ino() == st.st_ino && m.dev() == st.st_dev)
}

type Test = (&'static str, fn() -> Outcome);

fn main() -> ExitCode {
    let tests: &[Test] = &[
        ("userns::IdMap::write keeps ids", test_id_map_keeps_ids),
        ("userns::IdMap::write maps to root", test_id_map_to_root),
        (
            "userns::IdMap::write needs setgroups=deny",
            test_id_map_requires_setgroups_deny,
        ),
        (
            "userns::disable_user_namespaces per-namespace",
            test_disable_userns_is_per_namespace,
        ),
        (
            "userns::disable_user_namespaces missing sysctl",
            test_disable_userns_errors_without_sysctl,
        ),
        ("caps policy in a userns", test_caps_policy),
        ("caps drop everything", test_caps_drop_all),
        ("fs::ensure_newroot_parents", test_newroot_parents),
    ];
    // BWRAP_RS_REQUIRE_USERNS=1 (set in CI) turns a skip into a failure, so a
    // run that silently never exercised the namespace paths cannot pass green.
    let require_userns = std::env::var_os("BWRAP_RS_REQUIRE_USERNS").is_some();
    let mut failed = 0;
    for (name, test) in tests {
        match test() {
            Outcome::Pass => println!("test {name} ... ok"),
            Outcome::Skip(why) if require_userns => {
                println!("test {name} ... FAILED (BWRAP_RS_REQUIRE_USERNS set but skipped): {why}");
                failed += 1;
            }
            Outcome::Skip(why) => println!("test {name} ... SKIP ({why})"),
            Outcome::Fail(why) => {
                println!("test {name} ... FAILED: {why}");
                failed += 1;
            }
        }
    }
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
