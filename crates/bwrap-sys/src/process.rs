//! Process creation: `clone(2)` into new namespaces and plain `fork(2)`.
//!
//! Both are fork-like: the child gets a copy-on-write copy of the address
//! space and continues from the call site. That is only sound if the caller
//! is single-threaded (no other thread can hold a lock that is copied into
//! the child in a locked state), so both functions check the thread count at
//! call time and refuse otherwise. Only the calling thread could spawn a new
//! thread between that check and the syscall, and it is busy executing this
//! function, so the check cannot race.
//!
//! # Caveat for code running in the child
//!
//! A raw `clone` bypasses glibc's `fork()` bookkeeping (atfork handlers,
//! cached thread state). The child should limit itself to plain syscalls and
//! allocation until it `exec`s, and must not create threads. bwrap's sandbox
//! setup does exactly that.

use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{OFlag, openat};
use nix::libc::{self, c_int, c_ulong, pid_t};
use nix::sched::CloneFlags;
use nix::sys::stat::Mode;
use nix::unistd::{ForkResult, Pid};

use crate::thread::guard_thread_count;

/// The namespace flags [`clone_into_namespaces`] accepts.
///
/// Anything else (`CLONE_VM`, `CLONE_THREAD`, `CLONE_SETTLS`, the TID flags,
/// …) requires a stack, a TLS area or shared memory, and is rejected.
pub const NAMESPACE_FLAGS: CloneFlags = CloneFlags::CLONE_NEWNS
    .union(CloneFlags::CLONE_NEWUSER)
    .union(CloneFlags::CLONE_NEWPID)
    .union(CloneFlags::CLONE_NEWNET)
    .union(CloneFlags::CLONE_NEWIPC)
    .union(CloneFlags::CLONE_NEWUTS)
    .union(CloneFlags::CLONE_NEWCGROUP);

/// Why a fork-like call could not be made.
#[derive(Debug)]
pub enum ForkError {
    /// The process has more than one thread, so forking would be unsound.
    MultiThreaded {
        /// Thread count observed.
        threads: usize,
    },
    /// `/proc/self/status` could not be read or parsed.
    ThreadCount(io::Error),
    /// Flags other than [`NAMESPACE_FLAGS`] were passed.
    UnsupportedFlags(CloneFlags),
    /// The syscall itself failed.
    Sys(Errno),
}

impl fmt::Display for ForkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultiThreaded { threads } => {
                write!(
                    f,
                    "refusing to fork a multi-threaded process ({threads} threads)"
                )
            }
            Self::ThreadCount(e) => write!(f, "cannot determine thread count: {e}"),
            Self::UnsupportedFlags(flags) => {
                write!(f, "unsupported clone flags: {:#x}", flags.bits())
            }
            Self::Sys(errno) => f.write_str(&crate::strerror(*errno)),
        }
    }
}

impl std::error::Error for ForkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ThreadCount(e) => Some(e),
            Self::Sys(e) => Some(e),
            Self::MultiThreaded { .. } | Self::UnsupportedFlags(_) => None,
        }
    }
}

impl From<Errno> for ForkError {
    fn from(errno: Errno) -> Self {
        Self::Sys(errno)
    }
}

fn ensure_single_threaded() -> Result<(), ForkError> {
    match guard_thread_count().map_err(ForkError::ThreadCount)? {
        1 => Ok(()),
        threads => Err(ForkError::MultiThreaded { threads }),
    }
}

/// Fork into new namespaces: `clone(SIGCHLD | flags)` with no child stack.
///
/// This is bwrap's `raw_clone()`. `SIGCHLD` is always added, so the parent
/// can reap the child with `waitpid` as with `fork`.
pub fn clone_into_namespaces(flags: CloneFlags) -> Result<ForkResult, ForkError> {
    if !flags.difference(NAMESPACE_FLAGS).is_empty() {
        return Err(ForkError::UnsupportedFlags(flags));
    }
    ensure_single_threaded()?;

    // All allowed flags are below 2^31, so the i32 -> u32 reinterpretation is exact.
    let raw_flags =
        c_ulong::from(flags.bits().cast_unsigned()) | c_ulong::from(libc::SIGCHLD.cast_unsigned());
    let no_stack: c_ulong = 0;
    let unused: c_ulong = 0;

    // On s390 the first two clone() arguments are swapped (CONFIG_CLONE_BACKWARDS2);
    // bwrap's raw_clone() does the same. The arguments after the stack (parent
    // tid, child tid, tls) are only read with CLONE_*TID / CLONE_SETTLS, which
    // NAMESPACE_FLAGS excludes, so their order across architectures does not matter.
    #[cfg(target_arch = "s390x")]
    // SAFETY: Without CLONE_VM and with a NULL stack this behaves like fork(2):
    // the child gets its own copy-on-write address space and returns here on the
    // current stack. We checked above that we are the only thread, so no lock in
    // the copied memory can be held by another thread. No pointers are passed.
    let ret =
        unsafe { libc::syscall(libc::SYS_clone, no_stack, raw_flags, unused, unused, unused) };
    #[cfg(not(target_arch = "s390x"))]
    // SAFETY: see the s390x branch above; identical call with the standard argument order.
    let ret =
        unsafe { libc::syscall(libc::SYS_clone, raw_flags, no_stack, unused, unused, unused) };

    let ret = Errno::result(ret)?;
    to_fork_result(ret)
}

/// `fork(2)`, refused unless the process is single-threaded.
///
/// Used for the intermediate children around `--pidns` and for the pid-1
/// reaper.
pub fn fork_single_threaded() -> Result<ForkResult, ForkError> {
    ensure_single_threaded()?;
    // SAFETY: nix requires that after fork in a multi-threaded process the child
    // only calls async-signal-safe functions. We verified there is exactly one
    // thread, so that restriction does not apply.
    Ok(unsafe { nix::unistd::fork() }?)
}

/// Terminate the calling process immediately with `status` (`_exit(2)`).
///
/// Unlike [`std::process::exit`], this runs no `atexit` handlers and flushes
/// no stdio buffers. That is what a forked or cloned child must use, because
/// those handlers and buffers belong to the parent. nix has no wrapper for it.
//
// nix-upstream-kandidaat: `_exit(c_int) -> !` has no soundness precondition, so
// a nix `pub fn` for it would be genuinely safe and could replace this block.
pub fn exit_immediately(status: i32) -> ! {
    // SAFETY: `_exit` takes a plain integer, touches no memory of ours and
    // never returns. It is async-signal-safe and valid in any process state.
    unsafe { libc::_exit(status) }
}

/// `waitpid(pid, &status, flags)` returning the RAW status integer rather than
/// nix's `WaitStatus`.
///
/// nix decodes the status through `Signal::try_from(WTERMSIG(status))`, which
/// has no enum variant for the real-time signals (32..=64) and so returns
/// `Err(EINVAL)` *after the kernel has already reaped the child* — the status is
/// lost and the caller hangs or dies. bubblewrap decodes the raw status with the
/// `W*` macros (`propagate_exit_status`), so the caller must have the raw value.
///
/// Returns `Ok(None)` when `WNOHANG` was requested and no child had changed
/// state, otherwise `Ok(Some((pid, raw_status)))`.
pub fn wait_raw(pid: pid_t, nohang: bool) -> nix::Result<Option<(Pid, c_int)>> {
    let mut status: c_int = 0;
    let flags = if nohang { libc::WNOHANG } else { 0 };
    // SAFETY: `waitpid` writes the child's status into `status` (a valid local)
    // and touches no other memory of ours; the returned pid/0/-1 is handled below.
    let ret = unsafe { libc::waitpid(pid, &mut status, flags) };
    match Errno::result(ret)? {
        0 => Ok(None),
        child => Ok(Some((Pid::from_raw(child), status))),
    }
}

/// How to change the environment (bwrap's `--clearenv`/`--setenv`/`--unsetenv`),
/// applied in order by [`apply_env`].
#[derive(Debug)]
pub enum EnvOp {
    /// `--clearenv`: drop the entire environment.
    Clear,
    /// `--setenv NAME VALUE`.
    Set(std::ffi::CString, std::ffi::CString),
    /// `--unsetenv NAME`.
    Unset(std::ffi::CString),
}

/// Apply `ops` to the real process environment in order, editing `environ` in
/// place (clearenv/setenv/unsetenv) rather than rebuilding it from a snapshot —
/// so malformed or duplicate inherited entries pass through unchanged and a
/// `--setenv` on a duplicated name behaves like bubblewrap. `execvp`'s `PATH`
/// search and the child's environment both come from this `environ`.
///
/// Refuses unless the process is single-threaded: mutating `environ` while
/// another thread accesses it is a data race — the reason `std::env::set_var`
/// became `unsafe` in edition 2024. bwrap's child is single-threaded by
/// construction (it just cloned/forked from a single-threaded parent and spawns
/// no threads), so this always succeeds there; the check is what makes the
/// function a sound *safe* `pub fn`. Reading the environment stays safe via
/// `std::env::var_os`, so no getenv wrapper is exposed.
pub fn apply_env(ops: &[EnvOp]) -> Result<(), ForkError> {
    ensure_single_threaded()?;
    for op in ops {
        match op {
            EnvOp::Clear => env_clear(),
            EnvOp::Set(name, value) => env_set(name, value),
            EnvOp::Unset(name) => env_unset(name),
        }
    }
    Ok(())
}

pub(crate) fn env_clear() {
    // SAFETY: clears `environ`; apply_env verified single-threadedness first, so
    // nothing races.
    unsafe {
        libc::clearenv();
    }
}

pub(crate) fn env_set(name: &std::ffi::CStr, value: &std::ffi::CStr) {
    // SAFETY: both are valid NUL-terminated C strings borrowed for this call;
    // setenv copies them. Single-threaded (apply_env checked).
    unsafe {
        libc::setenv(name.as_ptr(), value.as_ptr(), 1);
    }
}

pub(crate) fn env_unset(name: &std::ffi::CStr) {
    // SAFETY: a valid NUL-terminated C string; single-threaded (apply_env checked).
    unsafe {
        libc::unsetenv(name.as_ptr());
    }
}

/// Whether the process inherited SIG_IGN for each signal the Rust runtime
/// overrides, captured before the runtime runs (see
/// [`CAPTURE_INHERITED_DISPOSITIONS`]).
///
/// A single bool suffices: bwrap is always reached through `execve`, which resets
/// every caught handler to `SIG_DFL` and preserves only `SIG_IGN`. So at entry
/// the inherited disposition of these signals can only be `SIG_DFL` or `SIG_IGN`
/// — never a custom handler — and restoring it is just "re-ignore if it was
/// ignored, else default". Default (`false`) is C's usual case.
static SIGPIPE_IGNORED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SIGSEGV_IGNORED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SIGBUS_IGNORED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Was `signum` inherited with `SIG_IGN`? Queries via `sigaction` with a null
/// `act`. `None` on failure.
fn inherited_ignored(signum: c_int) -> Option<bool> {
    // SAFETY: an all-zero `sigaction` is a valid value (SIG_DFL, no flags, empty
    // mask); it is overwritten by the query below before being read.
    let mut cur: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: runs single-threaded during ELF startup. A null `act` pointer only
    // reads the current disposition into `cur`; nothing is installed.
    let rc = unsafe { libc::sigaction(signum, std::ptr::null(), &mut cur) };
    (rc == 0).then_some(cur.sa_sigaction == libc::SIG_IGN)
}

/// Install `SIG_IGN` (if `ignored`) or `SIG_DFL` as the disposition of `signum`.
fn install(signum: c_int, ignored: bool) {
    let disp = if ignored {
        libc::SIG_IGN
    } else {
        libc::SIG_DFL
    };
    // SAFETY: called on the single-threaded startup path (first thing in `main`,
    // and again before the clone). `disp` is the `SIG_DFL`/`SIG_IGN` constant;
    // `signal` installs it and touches none of our memory.
    unsafe {
        libc::signal(signum, disp);
    }
}

/// Record whether SIGPIPE/SIGSEGV/SIGBUS were inherited ignored, captured during
/// ELF startup — before `main` and before the Rust runtime overrides them
/// (SIGPIPE → `SIG_IGN`; SIGSEGV/SIGBUS → its stack-overflow handler) — so that
/// [`reset_runtime_signal_state`] can put back what bubblewrap's child inherits.
///
/// bwrap (C) installs no handlers and never touches these signals; the command
/// inherits whatever bwrap was launched with. Since that is only `SIG_DFL` or
/// `SIG_IGN` (see [`SIGPIPE_IGNORED`]) and the runtime clobbers all three, this
/// constructor records the one bit that matters while it still can.
#[used]
#[cfg_attr(
    any(target_os = "linux", target_os = "android"),
    unsafe(link_section = ".init_array")
)]
static CAPTURE_INHERITED_DISPOSITIONS: extern "C" fn() = {
    extern "C" fn capture() {
        if let Some(b) = inherited_ignored(libc::SIGPIPE) {
            SIGPIPE_IGNORED.store(b, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(b) = inherited_ignored(libc::SIGSEGV) {
            SIGSEGV_IGNORED.store(b, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(b) = inherited_ignored(libc::SIGBUS) {
            SIGBUS_IGNORED.store(b, std::sync::atomic::Ordering::Relaxed);
        }
    }
    capture
};

/// Restore SIGPIPE to the disposition the process inherited at startup, undoing
/// the Rust runtime's `SIG_IGN` so the sandbox and the exec'd command see what
/// C's child would. Call it before the clone.
pub fn restore_inherited_sigpipe() {
    install(
        libc::SIGPIPE,
        SIGPIPE_IGNORED.load(std::sync::atomic::Ordering::Relaxed),
    );
}

/// Undo every signal-disposition change the Rust runtime made at startup, so the
/// launcher, the pid-1 reaper and the sandboxed command run with bubblewrap's
/// signal state instead of Rust's. Call it as the very first thing in `main`.
///
/// - SIGPIPE, SIGSEGV and SIGBUS: put back the inherited disposition (`SIG_IGN`
///   if it was ignored, else `SIG_DFL`). C installs no handlers, so this leaves
///   the launcher's `SigCgt` empty like bubblewrap's and lets a crash signal kill
///   it as it kills C, instead of the std handler swallowing the first one.
/// - SIGCHLD: reset to `SIG_DFL` unconditionally, as bubblewrap.c:2905 does
///   ("Reset SIGCHILD to SIG_DFL allowing signalfd working properly if the
///   parent process had set SIGCHLD to SIG_IGN"). A launcher started with
///   SIGCHLD ignored would otherwise never see the child die (the kernel
///   auto-reaps and queues no SIGCHLD), hanging or spinning the monitor, and the
///   ignore would leak into the sandboxed command.
pub fn reset_runtime_signal_state() {
    restore_inherited_sigpipe();
    install(
        libc::SIGSEGV,
        SIGSEGV_IGNORED.load(std::sync::atomic::Ordering::Relaxed),
    );
    install(
        libc::SIGBUS,
        SIGBUS_IGNORED.load(std::sync::atomic::Ordering::Relaxed),
    );
    install(libc::SIGCHLD, false);
}

/// Close every open file descriptor greater than 2 (stdio) that is not in
/// `keep`, by walking the fd directory of `proc` (bwrap's `fdwalk` +
/// `close_extra_fds`).
///
/// `proc` is an `O_PATH` handle to the host `/proc`, opened before any pivot;
/// the directory is listed with `openat(proc, "self/fd")`, never via the
/// `/proc/self/fd` path. This matches bwrap, which threads a single `proc_fd`
/// through, and is required because the sandbox root need not mount `/proc` at
/// all (`--dev` without `--proc`, as glycin does) — a path lookup would then
/// fail right before `exec`.
///
/// Called in the sandboxed child just before `exec` so that no stray host fd
/// leaks in. The fd numbers are collected while the directory is open, then
/// closed after the directory handle is closed; closing an already-closed or
/// invalid number yields `EBADF`, which is ignored, exactly as bwrap does.
pub fn close_extra_fds(proc: BorrowedFd<'_>, keep: &[RawFd]) -> io::Result<()> {
    // Stage 1: opening self/fd is non-fatal — bwrap's fdwalk silently ignores a
    // /proc/self/fd it cannot open (e.g. a root without /proc), rather than
    // treating it as an error.
    let dir_fd = match openat(
        proc.as_fd(),
        "self/fd",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(_) => return Ok(()),
    };
    // Stage 2: fdopendir failure IS surfaced, as the original did. `Dir` owns the
    // fd and its `Drop` does closedir (+ closes the fd).
    let mut dir = Dir::from_fd(dir_fd).map_err(io::Error::from)?;
    let self_fd = dir.as_raw_fd();
    let mut candidates: Vec<RawFd> = Vec::new();
    for entry in dir.iter() {
        let Ok(entry) = entry else { continue };
        if let Ok(n) = entry.file_name().to_str().unwrap_or("").parse::<RawFd>()
            && n > 2
            && n != self_fd
            && !keep.contains(&n)
        {
            candidates.push(n);
        }
    }
    // Close the directory handle before closing the collected numbers (the
    // original closed the DIR* first too). A stale number is a harmless EBADF.
    drop(dir);
    for fd in candidates {
        let _ = nix::unistd::close(fd);
    }
    Ok(())
}

fn to_fork_result(ret: libc::c_long) -> Result<ForkResult, ForkError> {
    if ret == 0 {
        return Ok(ForkResult::Child);
    }
    let pid = pid_t::try_from(ret).map_err(|_| ForkError::Sys(Errno::EOVERFLOW))?;
    Ok(ForkResult::Parent {
        child: Pid::from_raw(pid),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn rejects_non_namespace_flags() {
        let r = clone_into_namespaces(CloneFlags::CLONE_VM | CloneFlags::CLONE_NEWNS);
        assert!(matches!(r, Err(ForkError::UnsupportedFlags(_))));
    }

    #[test]
    fn refuses_when_multithreaded() {
        // libtest already runs us on a worker thread; add one more for certainty.
        let (tx, rx) = mpsc::channel::<()>();
        let helper = std::thread::spawn(move || {
            let _ = rx.recv();
        });

        let fork = fork_single_threaded();
        let clone = clone_into_namespaces(CloneFlags::CLONE_NEWNS);

        drop(tx);
        let _ = helper.join();

        assert!(matches!(fork, Err(ForkError::MultiThreaded { threads }) if threads >= 2));
        assert!(matches!(clone, Err(ForkError::MultiThreaded { threads }) if threads >= 2));
    }

    #[test]
    fn fork_result_mapping() {
        assert!(matches!(to_fork_result(0), Ok(ForkResult::Child)));
        assert!(matches!(
            to_fork_result(42),
            Ok(ForkResult::Parent { child }) if child.as_raw() == 42
        ));
        assert!(matches!(
            to_fork_result(libc::c_long::from(i32::MAX) + 1),
            Err(ForkError::Sys(Errno::EOVERFLOW))
        ));
    }

    #[test]
    fn fork_error_display_texts() {
        assert_eq!(
            ForkError::MultiThreaded { threads: 2 }.to_string(),
            "refusing to fork a multi-threaded process (2 threads)"
        );
        assert_eq!(
            ForkError::ThreadCount(io::Error::other("boom")).to_string(),
            "cannot determine thread count: boom"
        );
        assert_eq!(
            ForkError::UnsupportedFlags(CloneFlags::CLONE_VM).to_string(),
            format!("unsupported clone flags: {:#x}", libc::CLONE_VM)
        );
        assert_eq!(
            ForkError::Sys(Errno::EPERM).to_string(),
            "Operation not permitted"
        );
    }

    #[test]
    fn fork_error_source_chain() {
        use std::error::Error as _;
        assert!(ForkError::MultiThreaded { threads: 2 }.source().is_none());
        assert!(
            ForkError::UnsupportedFlags(CloneFlags::CLONE_VM)
                .source()
                .is_none()
        );
        assert!(ForkError::Sys(Errno::EPERM).source().is_some());
        assert!(
            ForkError::ThreadCount(io::Error::other("x"))
                .source()
                .is_some()
        );
    }

    #[test]
    fn errno_converts_to_sys() {
        assert!(matches!(
            ForkError::from(Errno::ENOMEM),
            ForkError::Sys(Errno::ENOMEM)
        ));
    }

    #[test]
    fn namespace_flags_cover_exactly_the_ns_bits() {
        for f in [
            CloneFlags::CLONE_NEWNS,
            CloneFlags::CLONE_NEWUSER,
            CloneFlags::CLONE_NEWPID,
            CloneFlags::CLONE_NEWNET,
            CloneFlags::CLONE_NEWIPC,
            CloneFlags::CLONE_NEWUTS,
            CloneFlags::CLONE_NEWCGROUP,
        ] {
            assert!(NAMESPACE_FLAGS.contains(f));
        }
        assert!(!NAMESPACE_FLAGS.contains(CloneFlags::CLONE_VM));
        assert!(!NAMESPACE_FLAGS.contains(CloneFlags::CLONE_THREAD));
    }

    #[test]
    fn unsupported_flags_reports_the_flags_passed() {
        let flags = CloneFlags::CLONE_THREAD | CloneFlags::CLONE_NEWNS;
        match clone_into_namespaces(flags) {
            Err(ForkError::UnsupportedFlags(f)) => assert_eq!(f, flags),
            other => panic!("unexpected {other:?}"),
        }
    }
}
