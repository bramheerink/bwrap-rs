//! Caller-supplied file descriptors: one owner per inherited number, borrows
//! that are only handed out for a descriptor verified open, and exactly one
//! close.
//!
//! `bwrap-core`/`bwrap-cli` are `#![forbid(unsafe_code)]`, but fds passed on the
//! command line (`--bind-fd`, `--file`, `--args`, `--seccomp`, `--info-fd`, …)
//! arrive as raw integers inherited from the launcher. [`FdTable`] is the sole
//! way those crates touch such a number; the `unsafe` [`BorrowedFd::borrow_raw`]
//! is confined to [`FdTable::live`].
//!
//! # Life of an inherited number
//!
//! 1. **Adoption.** While the process has opened no descriptor of its own, each
//!    number named on the command line is [adopted](FdTable::adopt). A number
//!    that is open at that moment becomes *live*; one that is closed becomes
//!    *dead* immediately.
//! 2. **Seal.** [`FdTable::seal`] ends adoption, before the first internal
//!    descriptor is opened. From then on a number the caller left closed can
//!    never be confused with an internal descriptor that happens to land on it.
//! 3. **Use.** [`FdTable::live`] borrows a live number. A dead or unknown number
//!    is an explicit `EBADF`, which callers route through the same error path
//!    the failing syscall would have taken, so bubblewrap's message is kept.
//! 4. **Close.** [`FdTable::close`] closes a live number once and marks it dead.
//!    A consumed descriptor stays consumed, even if the kernel later reuses the
//!    number for something else.

use std::collections::HashSet;
use std::os::fd::{BorrowedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

use nix::errno::Errno;
use nix::libc;

/// Whether an [`FdTable`] currently exists in this process.
static TABLE_EXISTS: AtomicBool = AtomicBool::new(false);

/// Whether `fd` names an open descriptor right now.
fn is_open(fd: RawFd) -> bool {
    // SAFETY: `F_GETFD` only reads the descriptor's flags and touches no memory
    // of ours. Any integer is a valid argument; a bad one yields -1/EBADF.
    fd >= 0 && unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1
}

/// Ownership record for the raw fds bwrap inherits on its command line.
///
/// It deliberately does **not** hold `OwnedFd`s. Dropping those would close a
/// descriptor aliased as e.g. `--info-fd 1` (i.e. stdout) and would perturb the
/// fd numbering the sandbox sees, breaking the drop-in contract.
///
/// # Ownership contract
///
/// Adopting a number claims it, like `OwnedFd::from_raw_fd` does. The compiler
/// cannot check that nothing else owns that number, so the API narrows the
/// window instead: only one table can exist ([`acquire`](Self::acquire)), and
/// adoption ends at [`seal`](Self::seal), which `bwrap-core` calls before it
/// opens any descriptor of its own. The one remaining obligation on the caller
/// is to adopt only numbers inherited from the launcher.
#[derive(Debug)]
pub struct FdTable {
    /// Adopted, verified open, and not yet closed through this table.
    open: HashSet<RawFd>,
    /// Closed at adoption or consumed since. Never becomes live again.
    dead: HashSet<RawFd>,
    /// Set by [`seal`](Self::seal); further adoption is ignored.
    sealed: bool,
}

impl FdTable {
    /// The process's fd table, or `None` while another one exists. Two tables
    /// tracking the same numbers could each close them.
    pub fn acquire() -> Option<Self> {
        if TABLE_EXISTS.swap(true, Ordering::AcqRel) {
            return None;
        }
        Some(Self {
            open: HashSet::new(),
            dead: HashSet::new(),
            sealed: false,
        })
    }

    /// Take ownership of an inherited number, recording whether it is open now.
    /// Idempotent. Ignored after [`seal`](Self::seal), and for a number that is
    /// already dead, so a consumed descriptor cannot be revived.
    pub fn adopt(&mut self, fd: RawFd) {
        if self.sealed || self.open.contains(&fd) || self.dead.contains(&fd) {
            return;
        }
        if is_open(fd) {
            self.open.insert(fd);
        } else {
            self.dead.insert(fd);
        }
    }

    /// End adoption. Must be called before the process opens descriptors of its
    /// own that could land on a number the caller left closed.
    pub fn seal(&mut self) {
        self.sealed = true;
    }

    /// Borrow a live descriptor, or `EBADF` if it was closed at adoption, has
    /// been consumed, was never adopted, or is no longer open.
    pub fn live(&self, fd: RawFd) -> Result<BorrowedFd<'_>, Errno> {
        if !self.open.contains(&fd) || !is_open(fd) {
            return Err(Errno::EBADF);
        }
        // SAFETY: `fd` is non-negative (only an open number enters `open`) and
        // open as just checked. The table owns the number, and closing it through
        // the table needs `&mut self`, which the returned borrow of `&self` rules
        // out for as long as the `BorrowedFd` exists.
        Ok(unsafe { BorrowedFd::borrow_raw(fd) })
    }

    /// Whether [`live`](Self::live) would currently succeed for `fd`.
    pub fn is_live(&self, fd: RawFd) -> bool {
        self.live(fd).is_ok()
    }

    /// Close a live descriptor once and mark it dead. Any other number is a
    /// no-op, so a double close cannot reach an unrelated descriptor.
    pub fn close(&mut self, fd: RawFd) {
        if self.open.remove(&fd) {
            self.dead.insert(fd);
            let _ = nix::unistd::close(fd);
        }
    }
}

impl Drop for FdTable {
    fn drop(&mut self) {
        TABLE_EXISTS.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    /// These tests open and `close(2)` raw, process-global fd *numbers*, and only
    /// one table may exist at a time. Serialize them (no extra dependency) so they
    /// never overlap. Poison is recovered since a failing test would otherwise
    /// wedge the rest.
    static FD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn fd_guard() -> std::sync::MutexGuard<'static, ()> {
        FD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn table() -> FdTable {
        FdTable::acquire().expect("no other table exists")
    }

    /// Numbers well above anything the kernel hands out to tests running in
    /// parallel, which always receive the lowest free number.
    const TEST_FD_BASE: RawFd = 700;

    /// Duplicate `src` onto the lowest free number at or above `min`.
    fn dup_at_or_above(src: &impl AsRawFd, min: RawFd) -> RawFd {
        // SAFETY: `F_DUPFD_CLOEXEC` reads no memory of ours and returns a new fd.
        let fd = unsafe { libc::fcntl(src.as_raw_fd(), libc::F_DUPFD_CLOEXEC, min) };
        assert!(fd >= min, "F_DUPFD_CLOEXEC failed");
        fd
    }

    /// An open read end whose number the test hands to the table, plus the write
    /// end that keeps the pipe alive.
    fn inherited() -> (RawFd, std::os::fd::OwnedFd) {
        let (r, w) = nix::unistd::pipe().expect("pipe");
        (dup_at_or_above(&r, TEST_FD_BASE), w)
    }

    /// Put an unrelated descriptor on the just-freed number `fd`.
    fn occupy(fd: RawFd) -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        let (r, w) = nix::unistd::pipe().expect("pipe");
        assert_eq!(dup_at_or_above(&r, fd), fd, "test needs the number reused");
        (r, w)
    }

    #[test]
    fn only_one_table_exists_at_a_time() {
        let _serialize = fd_guard();
        let first = table();
        assert!(FdTable::acquire().is_none());
        drop(first);
        assert!(FdTable::acquire().is_some());
    }

    #[test]
    fn negative_and_closed_numbers_never_borrow() {
        let _serialize = fd_guard();
        let mut t = table();
        t.adopt(-1);
        t.adopt(9999);
        assert_eq!(t.live(-1).unwrap_err(), Errno::EBADF);
        assert_eq!(t.live(9999).unwrap_err(), Errno::EBADF);
        // Closing a number that was never live is a no-op.
        t.close(-1);
        t.close(9999);
    }

    #[test]
    fn unadopted_number_does_not_borrow_even_if_open() {
        let _serialize = fd_guard();
        let t = table();
        let (r, _w) = nix::unistd::pipe().expect("pipe");
        assert_eq!(t.live(r.as_raw_fd()).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn adopt_borrow_close_cycle() {
        let _serialize = fd_guard();
        let (fd, _w) = inherited();
        let mut t = table();
        t.adopt(fd);
        t.adopt(fd); // idempotent
        assert_eq!(t.live(fd).expect("live").as_raw_fd(), fd);
        assert!(t.is_live(fd));

        t.close(fd);
        assert!(!is_open(fd), "the table really closed it");
        assert_eq!(t.live(fd).unwrap_err(), Errno::EBADF);
        // A second close cannot reach an unrelated descriptor.
        t.close(fd);
    }

    #[test]
    fn consumed_number_stays_dead_when_the_kernel_reuses_it() {
        let _serialize = fd_guard();
        let (fd, _w) = inherited();
        let mut t = table();
        t.adopt(fd);
        t.close(fd);

        // An unrelated descriptor now occupies the consumed number.
        let _unrelated = occupy(fd);
        t.adopt(fd);
        assert_eq!(t.live(fd).unwrap_err(), Errno::EBADF);
        t.close(fd);
        assert!(is_open(fd), "the unrelated descriptor must survive");
        nix::unistd::close(fd).expect("close");
    }

    #[test]
    fn number_closed_at_adoption_is_not_confused_with_a_later_descriptor() {
        let _serialize = fd_guard();
        let (fd, _w) = inherited();
        nix::unistd::close(fd).expect("close");
        let mut t = table();
        t.adopt(fd); // the caller left this number closed
        t.seal();

        let _internal = occupy(fd);
        assert_eq!(t.live(fd).unwrap_err(), Errno::EBADF);
        t.close(fd);
        assert!(is_open(fd), "an internal descriptor must survive");
        nix::unistd::close(fd).expect("close");
    }

    #[test]
    fn adoption_ends_at_seal() {
        let _serialize = fd_guard();
        let (r, _w) = nix::unistd::pipe().expect("pipe");
        let mut t = table();
        t.seal();
        t.adopt(r.as_raw_fd());
        assert_eq!(t.live(r.as_raw_fd()).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn descriptor_closed_behind_the_tables_back_is_not_borrowed() {
        let _serialize = fd_guard();
        let (fd, _w) = inherited();
        let mut t = table();
        t.adopt(fd);
        nix::unistd::close(fd).expect("close");
        assert_eq!(t.live(fd).unwrap_err(), Errno::EBADF);
    }
}
