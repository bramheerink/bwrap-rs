//! Opt-in setup profiler — built only with the `profile` cargo feature.
//!
//! The default (drop-in) build compiles the no-op stubs at the bottom of this
//! file, so `BWRAP_RS_PROFILE` has no effect and the binary stays byte-identical
//! to bubblewrap. Built with `--features profile`, setting
//! `BWRAP_RS_PROFILE=<path>` makes each timed [`span`] append one
//! `phase=<label> dur_us=<n> pid=<n>` line to that file when it ends, so you can
//! see where the port spends its setup time.
//!
//! The destination is an *fd* opened before the clone (like bwrap's `--info-fd`),
//! so spans recorded in the sandbox child still reach it after the `pivot_root`,
//! where a path would be unreachable. Writes are best-effort and never touch
//! stdout/stderr, so profiling can never change the sandbox output.

#[cfg(feature = "profile")]
mod imp {
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::time::Instant;

    /// The open profile fd, or `-1` when disabled. An `i32` so the clone child
    /// reads the inherited fd number without any shared allocation.
    static FD: AtomicI32 = AtomicI32::new(-1);
    /// Keeps the fd open for the process lifetime (closed on exec via `O_CLOEXEC`).
    static HANDLE: OnceLock<Option<OwnedFd>> = OnceLock::new();

    /// Open the profile log named by `BWRAP_RS_PROFILE`, once, before the clone
    /// so the sandbox child inherits the fd. A no-op when the variable is
    /// unset/empty or the path cannot be opened.
    pub fn init() {
        HANDLE.get_or_init(|| {
            let path = std::env::var_os("BWRAP_RS_PROFILE").filter(|p| !p.is_empty())?;
            // O_NONBLOCK so a FIFO with no reader fails with ENXIO instead of
            // blocking the launcher forever; O_NOFOLLOW so a symlinked path is not
            // followed; O_NOCTTY for good measure. std opens with O_CLOEXEC
            // already. On a regular file O_NONBLOCK is a no-op for the writes.
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW | nix::libc::O_NOCTTY)
                .open(path)
                .ok()?;
            let owned = OwnedFd::from(file);
            FD.store(owned.as_raw_fd(), Ordering::Relaxed);
            Some(owned)
        });
    }

    /// Start a timed span that records its duration when dropped. The label is
    /// `'static` so a span never allocates.
    #[must_use]
    pub fn span(label: &'static str) -> Span {
        Span {
            label,
            start: Instant::now(),
        }
    }

    /// A running span (see [`span`]); records its elapsed time on drop.
    #[derive(Debug)]
    pub struct Span {
        label: &'static str,
        start: Instant,
    }

    impl Drop for Span {
        fn drop(&mut self) {
            let fd = FD.load(Ordering::Relaxed);
            if fd < 0 {
                return;
            }
            let line = format!(
                "phase={} dur_us={} pid={}\n",
                self.label,
                self.start.elapsed().as_micros(),
                std::process::id()
            );
            // Best-effort: a profiling write must never change observable output.
            let _ = nix::unistd::write(bwrap_sys::fd::borrow_raw(fd), line.as_bytes());
        }
    }
}

#[cfg(not(feature = "profile"))]
mod imp {
    /// No-op: the profiler is not built into the default drop-in binary, so
    /// `BWRAP_RS_PROFILE` is ignored entirely.
    pub fn init() {}

    /// No-op span; the profiler is not built into the default drop-in binary.
    #[must_use]
    pub fn span(_label: &'static str) -> Span {
        Span
    }

    /// A zero-cost placeholder span (see [`span`]).
    #[derive(Debug)]
    pub struct Span;

    // An explicit (empty) Drop so callers can end a span early with `drop(sp)`
    // without clippy's `drop_non_drop` firing on the no-op build.
    impl Drop for Span {
        fn drop(&mut self) {}
    }
}

pub use imp::{Span, init, span};
