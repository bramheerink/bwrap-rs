//! Thread-count check that makes fork-like syscalls sound.

use std::fs;
use std::io;
use std::sync::OnceLock;

/// The first thread count seen while `/proc` was readable (normally in the
/// parent, before `pivot_root`). Used only to answer the guard when `/proc`
/// has since disappeared.
static PRIMED_COUNT: OnceLock<usize> = OnceLock::new();

/// Number of threads in the calling process, from `/proc/self/status`.
pub(crate) fn thread_count() -> io::Result<usize> {
    let status = fs::read_to_string("/proc/self/status")?;
    parse_thread_count(&status)
}

/// Thread count for the single-thread guard, independent of the sandbox's
/// `/proc` once primed.
///
/// The first call runs in the parent, before any `pivot_root`, while
/// `/proc/self/status` is still the real host procfs; it reads the count and
/// remembers it in [`PRIMED_COUNT`]. Every later call — in particular the pid-1
/// fork, which happens *after* the pivot (`--unshare-pid`, `--lock-file`,
/// `--sync-fd`) — returns that primed value without touching the path again.
///
/// This is sound because bwrap-rs spawns no threads after startup, so the count
/// cannot have changed; and it removes any dependency on the new root's
/// `/proc/self/status`. A planted or stale `proc/self/status` inside the sandbox
/// (rootfs tarballs, `--file … /proc/self/status`, test fixtures), or an
/// unrelated read error such as `EMFILE` at the fd limit, must not be able to
/// decide whether the fork is allowed. bubblewrap has no such dependency.
pub(crate) fn guard_thread_count() -> io::Result<usize> {
    if let Some(&n) = PRIMED_COUNT.get() {
        return Ok(n);
    }
    let n = thread_count()?;
    let _ = PRIMED_COUNT.set(n);
    Ok(n)
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
    fn guard_reports_live_count_and_primes() {
        let n = guard_thread_count().expect("/proc readable");
        assert!(n >= 1);
        assert!(PRIMED_COUNT.get().is_some());
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
