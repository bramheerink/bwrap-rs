//! End-to-end host test for module 11 (slices 3 + 4): in a real user+mount
//! namespace, build a sandbox root with `pivot_into_newroot`/`setup_newroot`
//! and verify, from inside the new root, that the ops took effect.
//!
//! `harness = false` + its own `main` (single-threaded for the clone). SKIPs
//! when the kernel refuses the namespaces.
#![allow(clippy::unwrap_used)]

use std::os::fd::AsFd;
use std::path::Path;
use std::process::ExitCode;

use bwrap_core::setup::{NewrootCtx, pivot_into_newroot};
use bwrap_core::types::{BindKind, HostPath, Mode, OnMissing, SandboxPath, SetupOp};
use bwrap_core::userns::{IdMap, MapTarget, OverflowIds};
use bwrap_sys::process::{ForkError, clone_into_namespaces};
use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::sched::CloneFlags;
use nix::sys::stat::{Mode as NixMode, fstat};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid};

fn sb(v: &str) -> SandboxPath {
    SandboxPath::parse("--test", v).unwrap()
}
fn host(v: &str) -> HostPath {
    HostPath::parse("--test", v).unwrap()
}

/// Build the sandbox and run the checks. Returns 0 on success, else a step code.
fn child(real_uid: u32, real_gid: u32) -> i32 {
    // Become root in the new user namespace so we may mount.
    let Ok(overflow) = OverflowIds::read() else {
        return 1;
    };
    let Ok(proc_fd) = open(
        Path::new("/proc"),
        OFlag::O_PATH | OFlag::O_CLOEXEC,
        NixMode::empty(),
    ) else {
        return 2;
    };
    let idmap = IdMap {
        sandbox_uid: 0,
        parent_uid: real_uid,
        sandbox_gid: 0,
        parent_gid: real_gid,
        overflow,
        map_root: false,
        deny_groups: true,
    };
    if idmap.write(proc_fd.as_fd(), MapTarget::SelfProc).is_err() {
        return 3;
    }

    // A modest ops list exercising several executor arms.
    let ops = vec![
        SetupOp::Bind {
            src: host("/usr"),
            dest: sb("/usr"),
            kind: BindKind::ReadOnly,
            missing: OnMissing::Fail,
        },
        SetupOp::Proc { dest: sb("/proc") },
        SetupOp::Dir {
            dest: sb("/mydir"),
            perms: Mode::from_bits(0o755),
        },
        SetupOp::Tmpfs {
            dest: sb("/mytmp"),
            perms: Mode::from_bits(0o755),
            size: None,
        },
        SetupOp::Symlink {
            target: host("/usr"),
            dest: sb("/link"),
        },
    ];
    let ctx = NewrootCtx::default(); // unshare_pid=false -> /proc host-bound

    // No op in this test carries a caller fd, so a fresh empty table suffices.
    let mut fds = bwrap_sys::fd::FdTable::new();
    if let Err(e) = pivot_into_newroot(&ops, &ctx, &mut fds) {
        eprintln!("  pivot_into_newroot: {e}");
        return 4;
    }

    // We are now inside the new root. Verify each op landed.
    if !Path::new("/usr/bin").exists() {
        eprintln!("  /usr bind missing");
        return 10;
    }
    if !Path::new("/proc/self").exists() {
        eprintln!("  /proc missing");
        return 11;
    }
    match fstat(
        open(Path::new("/mydir"), OFlag::O_PATH, NixMode::empty())
            .unwrap()
            .as_fd(),
    ) {
        Ok(st) if (st.st_mode & nix::libc::S_IFMT) == nix::libc::S_IFDIR => {}
        other => {
            eprintln!("  /mydir not a dir: {other:?}");
            return 12;
        }
    }
    if !Path::new("/mytmp").exists() {
        eprintln!("  /mytmp tmpfs missing");
        return 13;
    }
    match std::fs::read_link("/link") {
        Ok(t) if t == Path::new("/usr") => {}
        other => {
            eprintln!("  /link wrong target: {other:?}");
            return 14;
        }
    }
    // Isolation: a host path we never bound must be gone from the new root.
    if Path::new("/etc/fedora-release").exists() || Path::new("/home").exists() {
        eprintln!("  new root is not isolated (host paths visible)");
        return 15;
    }
    0
}

fn wait(child: Pid) -> i32 {
    match waitpid(child, None) {
        Ok(WaitStatus::Exited(_, code)) => code,
        other => {
            eprintln!("child ended abnormally: {other:?}");
            99
        }
    }
}

fn main() -> ExitCode {
    let real_uid = nix::unistd::geteuid().as_raw();
    let real_gid = nix::unistd::getegid().as_raw();
    let flags = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS;
    let code = match clone_into_namespaces(flags) {
        Ok(ForkResult::Child) => std::process::exit(child(real_uid, real_gid)),
        Ok(ForkResult::Parent { child: c }) => wait(c),
        Err(ForkError::Sys(Errno::EPERM | Errno::ENOSPC | Errno::EINVAL | Errno::EUSERS)) => {
            if std::env::var_os("BWRAP_RS_REQUIRE_USERNS").is_some() {
                println!(
                    "test newroot_host ... FAILED (BWRAP_RS_REQUIRE_USERNS set but user namespaces unavailable)"
                );
                return ExitCode::FAILURE;
            }
            println!("test newroot_host ... SKIP (user/mount namespaces unavailable)");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            println!("test newroot_host ... FAILED: clone: {e}");
            return ExitCode::FAILURE;
        }
    };
    if code == 0 {
        println!("test newroot_host ... ok");
        ExitCode::SUCCESS
    } else {
        println!("test newroot_host ... FAILED at step {code}");
        ExitCode::FAILURE
    }
}
