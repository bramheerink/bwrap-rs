//! Process orchestration helpers: exit-status propagation, `--lock-file`
//! locks, and the `--info-fd` / `--json-status-fd` output. Mirrors the
//! corresponding pieces of `bubblewrap.c`.
//!
//! The monitor (`monitor_child`, signalfd + poll) and the pid-1 reaper
//! (`do_init`) are the runtime loops; they land with the orchestration in
//! module 11, where the event/sync/setup fds exist and can be host-tested.
//! This file holds the parts that are self-contained and unit-testable.
//!
//! `monitor_child`/`do_init` convert small kernel values (eventfd payloads that
//! carry exit-code+1, SIGCHLD-derived wait statuses) between integer widths;
//! those fit by construction, so the width/sign lints are allowed file-wide.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl, open};
use nix::libc::{self, c_int};
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sys::prctl::set_pdeathsig;
use nix::sys::signal::{SigSet, SigmaskHow, Signal, sigprocmask};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::stat::Mode;
use nix::unistd::{Pid, read};

use crate::error::{Context, Error, Result};
use crate::seccomp::SeccompPrograms;
use crate::types::SandboxPath;

/// Translate a child's raw wait status into the exit code bwrap reports
/// (`propagate_exit_status`): a normal exit keeps its code; a fatal signal
/// becomes `128 + signal` (bash convention); anything else is 255.
///
/// Decoded with the `W*` macros exactly as C does, so real-time signals
/// (32..=64), which nix's `WaitStatus` cannot represent, map correctly instead
/// of losing the status.
pub fn propagate_exit_status(status: c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        255
    }
}

/// A held `--lock-file` lock: the open fd keeps the `F_RDLCK` until dropped.
#[derive(Debug)]
pub struct LockFile {
    _fd: OwnedFd,
}

/// Take a shared (`F_RDLCK`) lock on `path`, held until the returned
/// [`LockFile`] is dropped (bwrap's `do_init` lock loop). The fd is kept open,
/// as closing it would release the lock.
pub fn take_lock(path: &SandboxPath) -> Result<LockFile> {
    let p = path.as_c_str();
    let fd = open(
        p,
        OFlag::O_RDONLY | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("Unable to open lock file {path}"))?;
    // Whole-file shared lock. F_RDLCK and SEEK_SET are small kernel constants
    // that fit i16 by definition.
    #[allow(clippy::cast_possible_truncation)]
    let flock = libc::flock {
        l_type: libc::F_RDLCK as i16,
        l_whence: libc::SEEK_SET as i16,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    retry_eintr(|| fcntl(&fd, FcntlArg::F_SETLK(&flock)))
        .with_context(|| format!("Unable to lock file {path}"))?;
    Ok(LockFile { _fd: fd })
}

/// Take all the `--lock-file` locks, in order.
pub fn take_locks(paths: &[SandboxPath]) -> Result<Vec<LockFile>> {
    paths.iter().map(take_lock).collect()
}

fn retry_eintr<T>(mut f: impl FnMut() -> nix::Result<T>) -> nix::Result<T> {
    loop {
        match f() {
            Err(Errno::EINTR) => continue,
            other => return other,
        }
    }
}

/// The `{ "exit-code": N }` line bwrap writes to `--json-status-fd` when the
/// child exits (`report_child_exit_status`). Includes the trailing newline.
pub fn exit_code_json(exit_code: i32) -> String {
    format!("{{ \"exit-code\": {exit_code} }}\n")
}

/// Namespace inode ids for the sandbox-info document, in bwrap's fixed
/// `ns_infos` order. The user namespace is deliberately excluded: its id is not
/// valid at the point bwrap reads these (it is unshared later).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NamespaceIds {
    /// cgroup namespace inode (0 = unknown, omitted).
    pub cgroup: u64,
    /// ipc namespace inode.
    pub ipc: u64,
    /// mount namespace inode.
    pub mnt: u64,
    /// net namespace inode.
    pub net: u64,
    /// pid namespace inode.
    pub pid: u64,
    /// uts namespace inode.
    pub uts: u64,
}

/// Which sandbox-info document to build. The two fds use *different* byte
/// layouts (bwrap's two `dump_info` call sites): `--info-fd` is multi-line,
/// `--json-status-fd` is single-line. They differ in head, per-entry indent and
/// closing — keeping them distinct is required by the byte-exact contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoFormat {
    /// `--info-fd`: `"{\n    \"child-pid\": N..."`, indent `"\n    "`, close `"\n}\n"`.
    Info,
    /// `--json-status-fd`: `"{ \"child-pid\": N..."`, indent `" "`, close `" }\n"`.
    JsonStatus,
}

/// Build the `--info-fd` / `--json-status-fd` sandbox-info document — the
/// `child-pid` and each non-zero namespace id — byte-identical to bubblewrap's
/// `dump_info` + `namespace_ids_write`. A zero id is omitted ("we don't have
/// the information").
pub fn sandbox_info_json(format: InfoFormat, child_pid: i32, ns: &NamespaceIds) -> String {
    let (indent, close) = match format {
        InfoFormat::Info => ("\n    ", "\n}\n"),
        InfoFormat::JsonStatus => (" ", " }\n"),
    };
    let mut out = match format {
        InfoFormat::Info => format!("{{\n    \"child-pid\": {child_pid}"),
        InfoFormat::JsonStatus => format!("{{ \"child-pid\": {child_pid}"),
    };
    for (name, id) in [
        ("cgroup", ns.cgroup),
        ("ipc", ns.ipc),
        ("mnt", ns.mnt),
        ("net", ns.net),
        ("pid", ns.pid),
        ("uts", ns.uts),
    ] {
        if id != 0 {
            out.push_str(&format!(",{indent}\"{name}-namespace\": {id}"));
        }
    }
    out.push_str(close);
    out
}

/// Write `data` to `fd` fully (bwrap's `dump_info` / `write_to_fd`). Takes a
/// borrowed fd so the caller keeps ownership.
pub fn write_all(fd: std::os::fd::BorrowedFd<'_>, data: &[u8]) -> Result<()> {
    let mut off = 0;
    while off < data.len() {
        match nix::unistd::write(fd, &data[off..]) {
            Ok(0) => {
                return Err(Error::Sys {
                    message: "write".into(),
                    errno: Errno::EIO,
                });
            }
            Ok(n) => off += n,
            Err(Errno::EINTR) => {}
            Err(e) => {
                return Err(Error::Sys {
                    message: "write".into(),
                    errno: e,
                });
            }
        }
    }
    Ok(())
}

/// Write an info/status document, mapping a write failure to bwrap's `dump_info`
/// message (`Write to info_fd`) regardless of which fd it is, as C does.
pub fn dump_info(fd: std::os::fd::BorrowedFd<'_>, data: &[u8]) -> Result<()> {
    write_all(fd, data).map_err(|e| Error::Sys {
        message: "Write to info_fd".into(),
        errno: e.errno().unwrap_or(Errno::EIO),
    })
}

/// Block `SIGCHLD` and reap any inherited zombies (`block_sigchild`). Must be
/// called before the clone so the later `signalfd` in [`monitor_child`]
/// receives the child's death instead of the default handler.
pub fn block_sigchild() -> Result<()> {
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGCHLD);
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&mask), None).context("sigprocmask")?;
    // Reap any outstanding zombies we may have inherited. Uses the raw wait so a
    // zombie killed by a real-time signal cannot abort the reap with EINVAL.
    while let Ok(Some(_)) = bwrap_sys::process::wait_raw(-1, true) {}
    Ok(())
}

/// Unblock `SIGCHLD` (`unblock_sigchild`), for the sandboxed child before exec.
pub fn unblock_sigchild() -> Result<()> {
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGCHLD);
    sigprocmask(SigmaskHow::SIG_UNBLOCK, Some(&mask), None).context("sigprocmask")?;
    Ok(())
}

/// Bind our lifecycle to the parent's if `die_with_parent` (`--die-with-parent`):
/// `prctl(PR_SET_PDEATHSIG, SIGKILL)` (`handle_die_with_parent`).
pub fn handle_die_with_parent(die_with_parent: bool, expected_parent: Pid) -> Result<()> {
    if die_with_parent {
        set_pdeathsig(Signal::SIGKILL).context("prctl")?;
        // Improvement over bwrap (upstream #700): PR_SET_PDEATHSIG only fires on
        // a *future* parent death. If the parent already died between our fork
        // and this call, the signal was never armed and the process would be
        // orphaned instead of dying. Detect the reparent and emulate the death
        // signal ourselves. In normal operation getppid() == expected_parent and
        // this is a no-op, so the observable (drop-in) behaviour is unchanged.
        if nix::unistd::getppid() != expected_parent {
            let _ = nix::sys::signal::raise(Signal::SIGKILL);
        }
    }
    Ok(())
}

/// When `--json-status-fd` is set, emit `{ "exit-code": N }` once the sandbox
/// has finished setup (`report_child_exit_status`).
///
/// `setup_finished_fd` is the read end of a pipe whose write end the sandbox
/// closes after `exec`: a 1-byte read means setup finished, so the status is
/// reported; 0 (closed before exec) or 2 (closed after) is ignored. The caller
/// owns both fds and closes them (C closes them here; here `OwnedFd` does).
fn report_child_exit_status(
    exitc: i32,
    setup_finished_fd: Option<BorrowedFd<'_>>,
    json_status_fd: Option<BorrowedFd<'_>>,
) -> Result<()> {
    let (Some(setup_fd), Some(json_fd)) = (setup_finished_fd, json_status_fd) else {
        return Ok(());
    };
    let mut data = [0u8; 2];
    let n = loop {
        match read(setup_fd, &mut data) {
            Ok(n) => break n,
            Err(Errno::EINTR) => {}        // TEMP_FAILURE_RETRY
            Err(Errno::EAGAIN) => break 0, // not ready -> no report
            Err(e) => {
                return Err(Error::Sys {
                    message: "read eventfd".into(),
                    errno: e,
                });
            }
        }
    };
    if n != 1 {
        return Ok(());
    }
    // bwrap writes the final exit-code document with exit_on_error=false
    // (bubblewrap.c:471): if the `--json-status-fd` reader closed early, the
    // sandbox's real exit code must still be propagated, not turned into 1.
    let _ = write_all(json_fd, exit_code_json(exitc).as_bytes());
    Ok(())
}

/// Wait for the sandbox's main process and return its exit code (`monitor_child`).
///
/// Runs in the launcher after the clone. It closes every stray fd (keeping the
/// event/json-status/setup fds), then polls a `SIGCHLD` `signalfd` and the
/// `event_fd`. The event_fd (written by pid 1 in [`do_init`]) is read first:
/// if pid 2 dies, pid 1 often dies too, and reading the signalfd first would
/// race and report pid 1's status instead of the real one. `event_fd` must be
/// non-blocking (the launcher creates it `EFD_NONBLOCK`).
///
/// # Caution
///
/// This closes every fd above 2 that is not in the keep-set (`event_fd`,
/// `--json-status-fd`, `setup_finished_fd`). The caller must not retain any
/// other [`OwnedFd`] it will later drop, or that drop would double-close a
/// now-closed number and trip Rust's I/O-safety abort. Release such fds before
/// calling (upstream uses raw ints, where a double close is a harmless EBADF).
pub fn monitor_child(
    event_fd: Option<BorrowedFd<'_>>,
    child_pid: Pid,
    setup_finished_fd: Option<BorrowedFd<'_>>,
    json_status_fd: Option<BorrowedFd<'_>>,
) -> Result<i32> {
    // Local, so the eventfd can be dropped from the poll set if it reaches EOF
    // (a dead pid 1 that wrote nothing) instead of spinning the loop.
    let mut event_fd = event_fd;
    // Close all extra fds in the monitoring process; the child already has the
    // ones it needs. Keep the fds we still use here.
    let mut keep: Vec<RawFd> = Vec::new();
    for fd in [event_fd, json_status_fd, setup_finished_fd]
        .into_iter()
        .flatten()
    {
        keep.push(fd.as_raw_fd());
    }
    // The monitor runs in the launcher, which never pivots, so the host /proc is
    // always reachable; open a handle for the fd walk (bwrap's `proc_fd`).
    let proc_fd = open("/proc", OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty())
        .context("Can't open /proc")?;
    keep.push(proc_fd.as_raw_fd());
    bwrap_sys::process::close_extra_fds(proc_fd.as_fd(), &keep).context("fdwalk")?;

    let mut mask = SigSet::empty();
    mask.add(Signal::SIGCHLD);
    let signal_fd = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
        .context("Can't create signalfd")?;

    loop {
        let mut fds = Vec::with_capacity(2);
        fds.push(PollFd::new(signal_fd.as_fd(), PollFlags::POLLIN));
        if let Some(efd) = event_fd {
            fds.push(PollFd::new(efd, PollFlags::POLLIN));
        }
        match nix::poll::poll(&mut fds, PollTimeout::NONE) {
            Ok(_) => {}
            Err(Errno::EINTR) => continue,
            Err(e) => {
                return Err(Error::Sys {
                    message: "poll".into(),
                    errno: e,
                });
            }
        }

        // Always read the eventfd first: if pid 2 died, pid 1 often dies too,
        // and reading the signalfd first would lose the real exit status.
        if let Some(efd) = event_fd {
            let mut val = [0u8; 8];
            match read(efd, &mut val) {
                Ok(8) => {
                    let exitc = u64::from_ne_bytes(val) as i32 - 1;
                    report_child_exit_status(exitc, setup_finished_fd, json_status_fd)?;
                    return Ok(exitc);
                }
                // EOF: every writer (pid 1) is gone and nothing was written.
                // Drop the fd from the poll set so a dead pid 1 cannot turn the
                // loop into a 100%-CPU spin; the signalfd path reports the status.
                Ok(0) => event_fd = None,
                Ok(_) | Err(Errno::EINTR | Errno::EAGAIN) => {}
                Err(e) => {
                    return Err(Error::Sys {
                        message: "read eventfd".into(),
                        errno: e,
                    });
                }
            }
        }

        // Drain the signalfd so it stops signalling POLLIN; the details are
        // ignored, waitpid below is authoritative.
        match signal_fd.read_signal() {
            Ok(_) | Err(Errno::EINTR | Errno::EAGAIN) => {}
            Err(e) => {
                return Err(Error::Sys {
                    message: "read signalfd".into(),
                    errno: e,
                });
            }
        }

        // Several SIGCHLDs can coalesce into one, so reap all ready children.
        loop {
            match bwrap_sys::process::wait_raw(-1, true) {
                Ok(None) => break, // nothing ready to reap this round
                Ok(Some((pid, status))) => {
                    // We may reap unrelated children (someone forked then
                    // exec'd bwrap); only our sandbox process counts.
                    if pid == child_pid {
                        let exitc = propagate_exit_status(status);
                        report_child_exit_status(exitc, setup_finished_fd, json_status_fd)?;
                        return Ok(exitc);
                    }
                }
                Err(Errno::EINTR) => {}
                Err(Errno::ECHILD) => break, // nothing left to reap
                Err(e) => {
                    // A lost status must never become a silent hang: fail loudly.
                    return Err(Error::Sys {
                        message: "waitpid".into(),
                        errno: e,
                    });
                }
            }
        }
    }
}

/// The sandbox's pid 1 (`do_init`): take the `--lock-file` locks, optionally
/// die with the parent, apply seccomp, then reap every descendant. When the
/// initial sandbox process dies, its exit status + 1 is written to `event_fd`
/// for [`monitor_child`]. Returns the initial process's exit status.
pub fn do_init(
    event_fd: Option<BorrowedFd<'_>>,
    initial_pid: Pid,
    lock_files: &[SandboxPath],
    seccomp: &SeccompPrograms,
    die_with_parent: bool,
) -> Result<i32> {
    // Capture our parent (the launcher) before any work, for the die-with-parent
    // reparent check.
    let parent = nix::unistd::getppid();

    // Hold the locks for our whole lifetime; dropping at return closes the fds,
    // as C does at the end of do_init.
    let _locks = take_locks(lock_files)?;

    handle_die_with_parent(die_with_parent, parent)?;
    seccomp.apply()?;

    let mut initial_exit_status = 1;
    loop {
        match bwrap_sys::process::wait_raw(-1, false) {
            Ok(Some((pid, status))) => {
                if pid == initial_pid {
                    initial_exit_status = propagate_exit_status(status);
                    if let Some(efd) = event_fd {
                        let val = u64::from(initial_exit_status as u32).wrapping_add(1);
                        // Ignore errors: if the parent died and closed event_fd
                        // we must not fail here.
                        let _ = write_all(efd, &val.to_ne_bytes());
                    }
                }
            }
            // Only possible with WNOHANG, which we do not pass; harmless.
            Ok(None) => {}
            Err(Errno::EINTR) => {}
            Err(Errno::ECHILD) => break,
            Err(e) => {
                return Err(Error::Sys {
                    message: "init wait()".into(),
                    errno: e,
                });
            }
        }
    }
    Ok(initial_exit_status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_status_mapping_matches_bwrap() {
        // Raw wait statuses, decoded with the same W* macros as bubblewrap.
        // Normal exit: status is `code << 8`.
        assert_eq!(propagate_exit_status(0), 0);
        assert_eq!(propagate_exit_status(42 << 8), 42);
        // Killed by a signal: status low 7 bits are the signal -> 128 + sig.
        assert_eq!(propagate_exit_status(libc::SIGKILL), 128 + libc::SIGKILL); // 137
        // Real-time signal 34: nix's WaitStatus has no variant for it, but the
        // raw decode must still give 128 + 34 = 162.
        assert_eq!(propagate_exit_status(34), 162);
        // Stopped / unknown (low byte 0x7f): neither exited nor signalled -> 255.
        assert_eq!(propagate_exit_status(0x7f), 255);
    }

    #[test]
    fn exit_code_json_matches_bwrap() {
        assert_eq!(exit_code_json(0), "{ \"exit-code\": 0 }\n");
        assert_eq!(exit_code_json(137), "{ \"exit-code\": 137 }\n");
    }

    #[test]
    fn sandbox_info_json_both_formats() {
        // No namespace ids: just child-pid, each format's head + close.
        let empty = NamespaceIds::default();
        assert_eq!(
            sandbox_info_json(InfoFormat::Info, 1234, &empty),
            "{\n    \"child-pid\": 1234\n}\n"
        );
        assert_eq!(
            sandbox_info_json(InfoFormat::JsonStatus, 1234, &empty),
            "{ \"child-pid\": 1234 }\n"
        );
    }

    #[test]
    fn sandbox_info_json_namespace_ids_in_order_and_skip_zero() {
        // net + pid set, others zero: only those two lines, in ns_infos order.
        let ns = NamespaceIds {
            net: 42,
            pid: 99,
            ..Default::default()
        };
        assert_eq!(
            sandbox_info_json(InfoFormat::Info, 7, &ns),
            "{\n    \"child-pid\": 7,\n    \"net-namespace\": 42,\n    \"pid-namespace\": 99\n}\n"
        );
        assert_eq!(
            sandbox_info_json(InfoFormat::JsonStatus, 7, &ns),
            "{ \"child-pid\": 7, \"net-namespace\": 42, \"pid-namespace\": 99 }\n"
        );
    }

    #[test]
    fn lock_file_takes_and_holds_a_lock() {
        let dir = std::env::temp_dir().join(format!("bwrap-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lock");
        std::fs::write(&path, b"").unwrap();
        let sp = SandboxPath::parse("--lock-file", path.to_str().unwrap()).unwrap();
        let held = take_lock(&sp).expect("take lock");
        // A shared lock can be taken again (read locks are compatible).
        let held2 = take_lock(&sp).expect("second shared lock");
        drop(held);
        drop(held2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_lock_file_errors() {
        let sp = SandboxPath::parse("--lock-file", "/no/such/lock/xyz").unwrap();
        let e = take_lock(&sp).unwrap_err();
        assert!(
            e.to_string()
                .starts_with("Unable to open lock file /no/such/lock/xyz")
        );
    }
}
