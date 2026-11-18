//! Thread-count check that makes fork-like syscalls sound.

use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The most recent thread count read from the trusted host `/proc`; 0 until the
/// first successful read.
static LAST_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Set by [`seal_thread_count`]: `/proc` can no longer be trusted, so the guard
/// answers from [`LAST_COUNT`].
static SEALED: AtomicBool = AtomicBool::new(false);

/// Number of threads in the calling process, from `/proc/self/status`.
pub(crate) fn thread_count() -> io::Result<usize> {
    let status = fs::read_to_string("/proc/self/status")?;
    parse_thread_count(&status)
}

/// Thread count for the single-thread guard.
///
/// Until [`seal_thread_count`] runs, every call measures the live count, so a
/// thread started after an earlier check is seen. A failed read is an error: an
/// older measurement says nothing about the threads running now.
///
/// After the seal the last measurement is returned without touching any path. A
/// planted `proc/self/status` inside the sandbox (rootfs tarballs, `--file …
/// /proc/self/status`, test fixtures) must not be able to decide whether the
/// pid-1 fork is allowed. This relies on the sealing process starting no thread
/// afterwards, which is the documented contract of [`seal_thread_count`].
pub(crate) fn guard_thread_count() -> io::Result<usize> {
    let last = LAST_COUNT.load(Ordering::Relaxed);
    if SEALED.load(Ordering::Relaxed) && last != 0 {
        return Ok(last);
    }
    let n = thread_count()?;
    LAST_COUNT.store(n, Ordering::Relaxed);
    Ok(n)
}

/// Take a final thread count from the host `/proc` and stop consulting `/proc`.
///
/// Call this in the sandbox child immediately before the mount namespace is
/// rearranged. The caller promises not to start a thread afterwards: from here
/// on the single-thread guard can no longer observe one.
pub(crate) fn seal_thread_count() {
    // Without a fresh measurement nothing is recorded, so the guard keeps measuring
    // live rather than trusting an older count.
    LAST_COUNT.store(thread_count().unwrap_or(0), Ordering::Relaxed);
    SEALED.store(true, Ordering::Relaxed);
}

fn parse_thread_count(status: &str) -> io::Result<usize> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "no \"Threads:\" line in /proc/self/status",
            )
        })?;
    value
        .trim()
        .parse::<usize>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_threads_line() {
        let status = "Name:\tbwrap\nUmask:\t0022\nThreads:\t1\nSigQ:\t0/1\n";
        assert_eq!(parse_thread_count(status).ok(), Some(1));
    }

    #[test]
    fn missing_line_is_error() {
        assert!(parse_thread_count("Name:\tbwrap\n").is_err());
    }

    #[test]
    fn garbage_is_error() {
        assert!(parse_thread_count("Threads:\tlots\n").is_err());
    }

    #[test]
    fn live_count_is_positive() {
        assert!(thread_count().is_ok_and(|n| n >= 1));
    }

    #[test]
    fn guard_reports_live_count_and_records_it() {
        let n = guard_thread_count().expect("/proc readable");
        assert!(n >= 1);
        assert_ne!(LAST_COUNT.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn parse_picks_threads_line_with_spaces() {
        assert_eq!(parse_thread_count("Threads:   17  \n").ok(), Some(17));
        let e = parse_thread_count("Threads:\t-1\n").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let e = parse_thread_count("").unwrap_err();
        assert!(e.to_string().contains("Threads:"));
    }
}
