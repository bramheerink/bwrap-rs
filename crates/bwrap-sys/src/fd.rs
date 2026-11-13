//! Borrowing caller-supplied raw file descriptors.
//!
//! `bwrap-core` is `forbid(unsafe)`, but fds passed on the command line
//! (`--bind-fd`, `--file`, `--bind-data`, `--ro-bind-data`, …) arrive as raw
//! integers inherited from the launcher. Turning one into a [`BorrowedFd`] is an
//! `unsafe` operation, so it lives here.

use std::os::fd::{BorrowedFd, RawFd};

/// Borrow a caller-supplied raw fd for the lifetime `'a`.
///
/// The returned [`BorrowedFd`] must not outlive the fd. In bwrap these fds are
/// inherited and stay open throughout sandbox setup, and `bwrap-core` only
/// borrows them transiently within a single setup op, so the borrow is sound.
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
/// call site; the result (including `EBADF`) is deliberately discarded.
pub fn close_raw(fd: RawFd) {
    let _ = nix::unistd::close(fd);
}
