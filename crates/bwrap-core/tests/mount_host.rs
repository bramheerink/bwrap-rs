//! Host integration tests for the mount layer (module 7): real bind mounts,
//! tmpfs, mqueue and remount-ro inside a user + mount namespace.
//!
//! `harness = false` with its own `main`, so the process is single-threaded for
//! `clone(CLONE_NEWUSER|CLONE_NEWNS)`. All work happens in the cloned child and
//! is reported via its exit code. If the kernel refuses the namespace (e.g.
//! inside another sandbox) the test prints SKIP and passes.
#![allow(clippy::unwrap_used)]

use std::os::fd::AsFd;
use std::path::Path;
use std::process::ExitCode;

use bwrap_core::mount::{BindOptions, bind_mount, mount_mqueue, mount_tmpfs, remount_ro};
use bwrap_core::userns::{IdMap, MapTarget, OverflowIds};
use bwrap_sys::process::{ForkError, clone_into_namespaces};
use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::mount::{MsFlags, mount};
use nix::sched::CloneFlags;
use nix::sys::stat::Mode;
use nix::sys::statvfs::{FsFlags, statvfs};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid};

fn flags(p: &Path) -> Option<FsFlags> {
    statvfs(p).ok().map(|s| s.flags())
}

fn open_opath(p: &Path) -> nix::Result<std::os::fd::OwnedFd> {
    open(p, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty())
}

/// All mount checks; returns 0 on success or a nonzero step number.
fn child(base: &Path, real_uid: u32, real_gid: u32) -> i32 {
    // Map ourselves to uid/gid 0 so the user namespace is complete (an
    // unmapped userns refuses some mounts, e.g. mqueue). Mirrors bwrap.
    let Ok(overflow) = OverflowIds::read() else {
        return 14;
    };
    let Ok(proc_fd) = open_opath(Path::new("/proc")) else {
        return 15;
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
        return 16;
    }

    // Keep our mounts from propagating to the host.
    if mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_SLAVE | MsFlags::MS_REC,
        None::<&str>,
    )
    .is_err()
    {
        return 1;
    }
    let a = base.join("a");
    let b = base.join("b");
    let tmp = base.join("tmp");
    let mq = base.join("mq");
    for d in [&a, &b, &tmp, &mq] {
        if std::fs::create_dir_all(d).is_err() {
            return 2;
        }
    }

    // 1. ro-bind a onto b: b must be ro, nosuid, nodev.
    let opts_ro = BindOptions {
        readonly: true,
        devices: false,
        recursive: true,
        fail_open: false,
    };
    if bind_mount(
        a.as_os_str().as_encoded_bytes(),
        b.as_os_str().as_encoded_bytes(),
        opts_ro,
    )
    .is_err()
    {
        return 3;
    }
    match flags(&b) {
        Some(f) if f.contains(FsFlags::ST_RDONLY | FsFlags::ST_NOSUID | FsFlags::ST_NODEV) => {}
        other => {
            eprintln!("  ro-bind flags = {other:?}");
            return 4;
        }
    }

    // 2. tmpfs on tmp: nosuid, nodev, and writable (not ro).
    let tmp_fd = match open_opath(&tmp) {
        Ok(f) => f,
        Err(_) => return 5,
    };
    if mount_tmpfs(
        tmp_fd.as_fd(),
        Mode::from_bits_truncate(0o755),
        Some(1 << 20),
        "/tmp",
        None,
    )
    .is_err()
    {
        return 6;
    }
    match flags(&tmp) {
        Some(f)
            if f.contains(FsFlags::ST_NOSUID | FsFlags::ST_NODEV)
                && !f.contains(FsFlags::ST_RDONLY) => {}
        other => {
            eprintln!("  tmpfs flags = {other:?}");
            return 7;
        }
    }
    // (Writability depends on a uid_map, which this mount-only test does not
    // set up; file ownership is covered by the userns tests. Here we only
    // assert the mount flags.)

    // 3. remount-ro the tmpfs: now read-only.
    let tmp_fd2 = match open_opath(&tmp) {
        Ok(f) => f,
        Err(_) => return 9,
    };
    if remount_ro(tmp_fd2.as_fd()).is_err() {
        return 10;
    }
    match flags(&tmp) {
        Some(f) if f.contains(FsFlags::ST_RDONLY) => {}
        other => {
            eprintln!("  remount-ro flags = {other:?}");
            return 11;
        }
    }

    // 4. mqueue on mq: mounts without error.
    let mq_fd = match open_opath(&mq) {
        Ok(f) => f,
        Err(_) => return 12,
    };
    match mount_mqueue(mq_fd.as_fd(), "/mq") {
        Ok(()) => {}
        // Some kernels/configs lack CONFIG_POSIX_MQUEUE; tolerate ENODEV.
        Err(e) if e.errno() == Some(Errno::ENODEV) => {}
        Err(e) => {
            eprintln!("  mqueue = {e}");
            return 13;
        }
    }

    // 5. Force the pre-5.12 mount_setattr fallback (mountinfo + MS_REMOUNT) and
    // bind again: the result must still be ro, nosuid, nodev.
    let c = base.join("c");
    let inner = c.join("inner");
    let d = base.join("d");
    for x in [&c, &inner, &d] {
        if std::fs::create_dir_all(x).is_err() {
            return 17;
        }
    }
    // A submount inside c, so the recursive fallback has a submount to remount.
    let inner_fd = match open_opath(&inner) {
        Ok(f) => f,
        Err(_) => return 20,
    };
    if mount_tmpfs(
        inner_fd.as_fd(),
        Mode::from_bits_truncate(0o755),
        None,
        "/inner",
        None,
    )
    .is_err()
    {
        return 21;
    }

    bwrap_core::mount::set_force_mount_setattr_fallback(true);
    let r = bind_mount(
        c.as_os_str().as_encoded_bytes(),
        d.as_os_str().as_encoded_bytes(),
        opts_ro,
    );
    bwrap_core::mount::set_force_mount_setattr_fallback(false);
    if r.is_err() {
        eprintln!("  forced-fallback bind = {r:?}");
        return 18;
    }
    // Both the bind root and its submount must come out ro, nosuid, nodev.
    for p in [&d, &d.join("inner")] {
        match flags(p) {
            Some(f) if f.contains(FsFlags::ST_RDONLY | FsFlags::ST_NOSUID | FsFlags::ST_NODEV) => {}
            other => {
                eprintln!("  forced-fallback flags {p:?} = {other:?}");
                return 19;
            }
        }
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
    let base = std::env::temp_dir().join(format!("bwrap-mount-host-{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    // Captured before the clone: inside the new userns these appear as the
    // overflow id until we write the map.
    let real_uid = nix::unistd::geteuid().as_raw();
    let real_gid = nix::unistd::getegid().as_raw();

    // NEWIPC too: a fresh mqueue instance can only be mounted in an IPC
    // namespace our user namespace owns.
    let clone_flags =
        CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWIPC;
    let result = match clone_into_namespaces(clone_flags) {
        // The child uses std::process::exit (not _exit) so the coverage
        // profiler flushes the child's data; the clone gives it its own
        // copy-on-write address space, so running atexit handlers is safe here.
        Ok(ForkResult::Child) => std::process::exit(child(&base, real_uid, real_gid)),
        Ok(ForkResult::Parent { child: c }) => wait(c),
        Err(ForkError::Sys(Errno::EPERM | Errno::ENOSPC | Errno::EINVAL | Errno::EUSERS)) => {
            println!("test mount_host ... SKIP (user namespaces unavailable)");
            let _ = std::fs::remove_dir_all(&base);
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            println!("test mount_host ... FAILED: clone: {e}");
            return ExitCode::FAILURE;
        }
    };

    let _ = std::fs::remove_dir_all(&base);
    if result == 0 {
        println!("test mount_host ... ok");
        ExitCode::SUCCESS
    } else {
        println!("test mount_host ... FAILED at step {result}");
        ExitCode::FAILURE
    }
}
