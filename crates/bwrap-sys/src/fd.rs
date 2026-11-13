//! Caller-supplied file descriptors: tracking their ownership so each inherited
//! number has one owner, can be borrowed soundly, and is closed exactly once.
//!
//! `bwrap-core`/`bwrap-cli` are `#![forbid(unsafe_code)]`, but fds passed on the
//! command line (`--bind-fd`, `--file`, `--args`, `--seccomp`, `--info-fd`, …)
//! arrive as raw integers inherited from the launcher. [`FdTable`] records which
//! of those numbers are still open, so the upper crates can borrow them through a
//! safe API ([`FdTable::borrow`] → `Option`) and close them exactly once. It is
//! the sole way those crates touch an inherited fd; there is no free
//! `borrow_raw`/`close_raw`, so the `unsafe` [`BorrowedFd::borrow_raw`] is
//! confined here and every borrow handed upward is tied to the table's lifetime.
//!
//! Two record paths, matching how bubblewrap itself treats these fds:
//!
//! - [`claim`](FdTable::claim) verifies the number is open (`F_GETFD`) first and
//!   reports `EBADF` otherwise. Used where C reads the fd during argument parsing
//!   (`--args`, `--seccomp`): a bad or reused number must fail with `EBADF`, and
//!   claiming is what stops a closed number from being re-recorded and closed
//!   again.
//! - [`register`](FdTable::register) records an inherited number without a syscall
//!   check. Used for the runtime fds (`--info-fd`, `--userns`, `--bind-fd`, …),
//!   which bubblewrap also uses without a prior openness check: a bad number
//!   surfaces at the actual `setns`/`read`/`write`, byte-for-byte as in C, rather
//!   than at an earlier gate that C does not have. It is idempotent, so a site
//!   may re-register before borrowing to reproduce C's per-fd-variable reuse (a
//!   second `--file N` reads the now-closed number and fails with `EBADF`).

use std::collections::HashSet;
use std::io;
use std::os::fd::{BorrowedFd, RawFd};

use nix::libc;

/// Ownership record for the raw fds bwrap inherits on its command line.
///
/// It deliberately does **not** hold `OwnedFd`s. Dropping those would close a
/// descriptor aliased as e.g. `--info-fd 1` (i.e. stdout) and would perturb the
/// fd numbering the sandbox sees, breaking the byte-exact contract. Instead the
/// table records which inherited numbers are still open:
///
/// - [`borrow`](Self::borrow) is sound because a number is present only after
///   [`claim`](Self::claim) verified it open, and the table is the sole thing
///   that closes a claimed number ([`close`](Self::close) removes it first), so a
///   present number is still open; the returned [`BorrowedFd`] is tied to `&self`
///   and cannot outlive the table.
/// - a reused or already-closed number borrows as `None`, which callers map to
///   `EBADF` — exactly bubblewrap's behaviour for `--args N … --args N` or a
///   repeated `--bind-fd N`.
///
/// Exactly one table should exist per process (created in `main`); a second
/// table tracking the same numbers would be a caller bug.
#[derive(Debug, Default)]
pub struct FdTable {
    open: HashSet<RawFd>,
}

impl FdTable {
    /// An empty table.
    pub fn new() -> Self {
        Self {
            open: HashSet::new(),
        }
    }

    /// Record an inherited fd number, after checking it is actually open.
    /// Idempotent. A negative or closed number is an `EBADF` error, which the
    /// caller reports exactly as bubblewrap does for a bad descriptor.
    pub fn claim(&mut self, fd: RawFd) -> io::Result<()> {
        if fd < 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        // SAFETY: `F_GETFD` only reads `fd`'s close-on-exec flag; it touches no
        // memory of ours. A return of -1 (with EBADF) means the number is not an
        // open descriptor, which we surface rather than record.
        let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }
        self.open.insert(fd);
        Ok(())
    }

    /// Record an inherited runtime fd number without a syscall check, the way
    /// bubblewrap uses `--info-fd`/`--userns`/`--bind-fd`/… — it never probes
    /// them first, so a bad number must surface at the actual `setns`/`read`/
    /// `write` with that call's errno, not at an earlier gate C does not have.
    /// Idempotent: a site re-registers right before borrowing so that reusing a
    /// now-closed number (a second `--file N`) borrows the stale number and fails
    /// at the syscall with `EBADF`, exactly as C's reuse of the variable does.
    pub fn register(&mut self, fd: RawFd) {
        self.open.insert(fd);
    }

    /// Borrow a claimed, still-open fd, or `None` if it was never claimed or has
    /// since been closed (the caller maps `None` to `EBADF`).
    pub fn borrow(&self, fd: RawFd) -> Option<BorrowedFd<'_>> {
        if self.open.contains(&fd) {
            // SAFETY: `fd` is in `open`, so it was verified open at `claim` and
            // nothing else closes a claimed number (only `close` does, and it
            // removes it from `open` first). The borrow is tied to `&self`, so it
            // cannot outlive the table.
            Some(unsafe { BorrowedFd::borrow_raw(fd) })
        } else {
            None
        }
    }

    /// Whether `fd` is currently a live claimed descriptor.
    pub fn is_open(&self, fd: RawFd) -> bool {
        self.open.contains(&fd)
    }

    /// Close a claimed fd now and forget it, so a later [`borrow`](Self::borrow)
    /// yields `None`. A number that is not (or no longer) claimed is a no-op, so
    /// a double close cannot reach an unrelated descriptor.
    pub fn close(&mut self, fd: RawFd) {
        if self.open.remove(&fd) {
            let _ = nix::unistd::close(fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn claim_rejects_bad_numbers() {
        let mut t = FdTable::new();
        assert_eq!(t.claim(-1).unwrap_err().raw_os_error(), Some(libc::EBADF));
        // A number that is almost certainly not an open descriptor in a test proc.
        assert!(t.claim(9999).is_err());
    }

    #[test]
    fn claim_borrow_close_cycle() {
        let (r, w) = nix::unistd::pipe().expect("pipe");
        let fd = r.as_raw_fd();
        // Hand the read end's number to the table as if it were inherited raw, so
        // the table is its sole closer (mirrors a command-line fd).
        std::mem::forget(r);

        let mut t = FdTable::new();
        assert!(t.borrow(fd).is_none(), "not claimed yet");
        t.claim(fd).expect("fd is open");
        assert!(t.is_open(fd));
        assert!(t.borrow(fd).is_some(), "claimed and open");

        t.close(fd);
        assert!(!t.is_open(fd));
        assert!(t.borrow(fd).is_none(), "closed -> caller sees EBADF");
        // A second close is a harmless no-op (cannot reach an unrelated fd).
        t.close(fd);

        drop(w);
    }

    #[test]
    fn claim_is_idempotent() {
        let (r, w) = nix::unistd::pipe().expect("pipe");
        let fd = r.as_raw_fd();
        std::mem::forget(r);
        let mut t = FdTable::new();
        t.claim(fd).unwrap();
        t.claim(fd).unwrap(); // no error, still one entry
        assert!(t.borrow(fd).is_some());
        t.close(fd);
        drop(w);
    }

    #[test]
    fn register_is_unchecked_and_reregister_after_close() {
        let (r, w) = nix::unistd::pipe().expect("pipe");
        let fd = r.as_raw_fd();
        std::mem::forget(r);
        let mut t = FdTable::new();
        // register records without probing the fd (unlike claim).
        t.register(fd);
        assert!(t.borrow(fd).is_some());
        t.close(fd);
        assert!(t.borrow(fd).is_none(), "closed -> not borrowable");
        // Re-registering a closed number makes it borrowable again, mirroring C
        // reusing the stale fd variable; the borrow then fails at the syscall.
        t.register(fd);
        assert!(t.borrow(fd).is_some(), "re-registered stale number");
        // A number that is almost certainly not open registers all the same
        // (no syscall check); it would only fail when actually used.
        t.register(99999);
        assert!(t.borrow(99999).is_some());
        t.close(fd);
        drop(w);
    }
}
