//! Safe wrappers around the Linux syscalls bwrap-rs needs that `nix` does not
//! (safely) provide.
//!
//! This is the **only** crate in the workspace that may contain `unsafe`.
//! Every unsafe block carries a `// SAFETY:` justification, and every public
//! function is safe to call, with one documented exception whose soundness rests
//! on a caller contract the compiler cannot check:
//!
//! - [`process::close_extra_fds`] — must not be called while any `OwnedFd`
//!   outside its keep-set is still live, or that fd's later drop closes a number
//!   this already closed (and perhaps reused): fd confusion, not UB.
//!
//! It is deliberately a safe `fn`, not `unsafe fn`, despite that uncheckable
//! contract. The contract is *process-global* ("no stray live `OwnedFd`"), so no
//! signature can express it; and its two callers (`monitor_child`, the pid-1
//! reaper) live in the `#![forbid(unsafe_code)]` crates — making it `unsafe fn`
//! would either force `unsafe` blocks there (defeating the quarantine that is the
//! project's main assurance) or drag that orchestration down into this thin
//! syscall crate. The keep-set is also legitimately bare `RawFd`s (caller
//! `--sync-fd` numbers this process does not own). So it stays a safe `fn` with
//! this explicit caller contract — the single accepted exception — which the two
//! call sites discharge by releasing (dropping / `into_raw_fd`) every other owned
//! fd before the walk. See each call site's `# Caution`/keep-list comment.
//!
//! The inherited command-line fds (`--bind-fd`, `--info-fd`, …) no longer use a
//! free `borrow_raw`: [`fd::FdTable`] owns their numbers and hands out borrows
//! tied to its own lifetime, so the unsafe `BorrowedFd::borrow_raw` is contained
//! and the lifetime contract is checked by the borrow checker.
//!
//! | Module         | Syscall(s)                                             |
//! |----------------|--------------------------------------------------------|
//! | [`process`]    | `clone(2)` without a stack (fork-like), `fork(2)`     |
//! | [`caps`]       | `capget(2)`, `capset(2)`, `prctl(PR_CAPBSET_*/PR_CAP_AMBIENT)` |
//! | [`seccomp`]    | `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`           |
//! | [`mount_attr`] | `mount_setattr(2)`                                     |
//!
//! Not in here because `nix` already wraps them safely: `unshare`, `setns`,
//! `mount`, `umount2`, `pivot_root`, `openat2`, `sethostname`, `execvp`,
//! `eventfd`, `signalfd`, `prctl(PR_SET_NO_NEW_PRIVS / PR_SET_DUMPABLE /
//! PR_SET_PDEATHSIG / PR_SET_CHILD_SUBREAPER)`.

#[cfg(not(target_os = "linux"))]
compile_error!("bwrap-sys only supports Linux");

pub mod alloc;
pub mod caps;
pub mod fd;
pub mod mount_attr;
pub mod process;
pub mod seccomp;
mod thread;

pub use process::ForkError;

/// The C library's `strerror(errno)` text, as bwrap prints it.
///
/// nix's `Errno::desc()` uses its own table, which differs from glibc for some
/// values (e.g. `ENOMEM` is "Out of memory" there but "Cannot allocate memory"
/// from `strerror`). bwrap's messages come from `strerror`, so use the
/// platform's text via std (which calls `strerror_r`).
pub fn strerror(errno: nix::errno::Errno) -> String {
    let code = errno as i32;
    let full = std::io::Error::from_raw_os_error(code).to_string();
    // std renders "<strerror text> (os error N)"; keep only the text.
    let suffix = format!(" (os error {code})");
    match full.strip_suffix(&suffix) {
        Some(text) => text.to_owned(),
        None => full,
    }
}

#[cfg(test)]
mod tests {
    use super::strerror;
    use nix::errno::Errno;

    #[test]
    fn matches_glibc_strerror_not_nix_table() {
        assert_eq!(strerror(Errno::ENOMEM), "Cannot allocate memory");
        assert_eq!(strerror(Errno::ENOENT), "No such file or directory");
        assert_eq!(strerror(Errno::EPERM), "Operation not permitted");
        assert_eq!(strerror(Errno::EXFULL), "Exchange full");
    }
}
