//! Caller-supplied file descriptors: tracking their ownership so each inherited
//! number has one owner, can be borrowed soundly, and is closed exactly once.
//!
//! `bwrap-core`/`bwrap-cli` are `#![forbid(unsafe_code)]`, but fds passed on the
//! command line (`--bind-fd`, `--file`, `--args`, `--seccomp`, `--info-fd`, …)
//! arrive as raw integers inherited from the launcher. [`FdTable`] records which
//! of those numbers are still open, so the upper crates can borrow them through a
//! safe API ([`FdTable::borrow`] → `Option`) and close them explicitly, instead
//! of the free `borrow_raw`/`close_raw` functions whose safety rests on an
//! unwritten caller contract. The migration to [`FdTable`] is in progress; the
//! two free functions remain until every call site is moved over.

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

/// Borrow a caller-supplied raw fd for the lifetime `'a`.
///
/// The returned [`BorrowedFd`] must not outlive the fd. In bwrap these fds are
/// inherited and stay open throughout sandbox setup, and `bwrap-core` only
/// borrows them transiently within a single setup op, so the borrow is sound.
///
/// Being superseded by [`FdTable`], which makes the lifetime contract checkable.
pub fn borrow_raw<'a>(fd: RawFd) -> BorrowedFd<'a> {
    // SAFETY: the caller guarantees `fd` is an open descriptor that stays open
    // for the whole of `'a` (see the contract above). We never close it here.
    unsafe { BorrowedFd::borrow_raw(fd) }
}

/// Close a caller-supplied raw fd by number, ignoring the result.
///
/// Used to stop caller descriptors (`--info-fd`, `--json-status-fd`, `--sync-fd`)
/// from leaking into the sandboxed process, mirroring bwrap's explicit `close`
/// calls. The fd is a plain integer owned by the process, not an `OwnedFd`; a
/// bad or already-closed number simply yields `EBADF`, which is ignored.
///
/// Safe: `nix::unistd::close` wraps the same `close(2)` with no unsafe at the
/// call site; the result (including `EBADF`) is deliberately discarded. Being
/// superseded by [`FdTable::close`].
pub fn close_raw(fd: RawFd) {
    let _ = nix::unistd::close(fd);
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
}
