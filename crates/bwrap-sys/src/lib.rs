//! Safe wrappers around the Linux syscalls bwrap-rs needs that `nix` does not
//! (safely) provide.
//!
//! This is the **only** crate in the workspace that may contain `unsafe`.
//! Every unsafe block carries a `// SAFETY:` justification, and every public
//! function is safe to call, with two documented exceptions whose soundness
//! rests on a caller contract the compiler cannot check (both to be removed by
//! the planned fd-ownership table):
//!
//! - [`fd::borrow_raw`] — the caller chooses the `BorrowedFd` lifetime for an
//!   arbitrary raw fd; it must not outlive the fd.
//! - [`process::close_extra_fds`] — must not be called while any `OwnedFd`
//!   outside its keep-set is still live, or the later drop double-closes.
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
