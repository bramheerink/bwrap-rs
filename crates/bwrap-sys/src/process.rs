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
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use nix::errno::Errno;
use nix::libc::{self, c_ulong, pid_t};
use nix::sched::CloneFlags;
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
pub fn exit_immediately(status: i32) -> ! {
    // SAFETY: `_exit` takes a plain integer, touches no memory of ours and
    // never returns. It is async-signal-safe and valid in any process state.
    unsafe { libc::_exit(status) }
}

/// Replace the process environment with `env` (`clearenv` + `setenv` per entry).
///
/// bwrap builds the sandbox environment on the real `environ` and then calls
/// `execvp`, so the command's `PATH` search and the child's environment both
/// come from it. The caller does the same: set the environment here, then
/// `execvp`. (`std::env::set_var` is `unsafe` under edition 2024 and forbidden
/// in the pure-safe crates, so this one wrapper owns the mutation.)
///
/// Sound because the sandbox child is single-threaded at exec time (see the
/// module caveat): no other thread can race on `environ`.
pub fn replace_environ(env: &[(std::ffi::CString, std::ffi::CString)]) {
    // SAFETY: clears `environ`; single-threaded here, so nothing races.
    unsafe { libc::clearenv() };
    for (name, value) in env {
        // SAFETY: both are valid NUL-terminated C strings owned by the caller
        // for this call; setenv copies them. Single-threaded as above.
        unsafe { libc::setenv(name.as_ptr(), value.as_ptr(), 1) };
    }
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
    let mut candidates: Vec<RawFd> = Vec::new();
    // SAFETY: `openat` with a valid directory fd and a static NUL-terminated
    // path. On failure it returns -1 and sets errno, which we surface.
    let dir_fd = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            c"self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if dir_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fdopendir` takes ownership of the freshly opened `dir_fd`; the
    // matching `closedir` below frees the stream and the fd. On failure we close
    // `dir_fd` ourselves and surface errno.
    let dirp = unsafe { libc::fdopendir(dir_fd) };
    if dirp.is_null() {
        let err = io::Error::last_os_error();
        // SAFETY: `dir_fd` is still a valid, unclaimed fd here.
        unsafe { libc::close(dir_fd) };
        return Err(err);
    }
    loop {
        // SAFETY: `dirp` is a valid `DIR*`; `readdir` returns a pointer valid
        // until the next `readdir`/`closedir`, or NULL at end of stream.
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            break;
        }
        // SAFETY: `ent` is a valid `dirent` pointer (checked non-null above);
        // `d_name` is an inline array within it.
        let d_name = unsafe { (*ent).d_name.as_ptr() };
        // SAFETY: `d_name` points at a NUL-terminated C string in that `dirent`.
        let name = unsafe { std::ffi::CStr::from_ptr(d_name) };
        if let Ok(n) = name.to_str().unwrap_or("").parse::<RawFd>()
            && n > 2
            && n != dir_fd
            && !keep.contains(&n)
        {
            candidates.push(n);
        }
    }
    // SAFETY: closes the `DIR*` stream and its underlying `dir_fd`.
    unsafe { libc::closedir(dirp) };
    for fd in candidates {
        // SAFETY: `close` takes an fd number and touches none of our memory. A
        // stale number returns EBADF; we ignore it, as bwrap's fdwalk does.
        unsafe {
            libc::close(fd);
        }
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
