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

/// Thread count for the single-thread guard, resilient to `/proc` being gone
/// after `pivot_root` (where the pid-1 fork happens).
///
/// Reads `/proc/self/status` and remembers the first success. Only when the
/// failure means `/proc` itself is unreachable (`ENOENT`/`ENOTDIR`) does it
/// fall back to that primed value — bwrap-rs never spawns threads after
/// startup, so the earlier count is still valid. Any other error (`EMFILE`,
/// `ENOMEM`, parse failure, …) is propagated rather than silently trusting a
/// stale count.
pub(crate) fn guard_thread_count() -> io::Result<usize> {
    match thread_count() {
        Ok(n) => {
            let _ = PRIMED_COUNT.set(n);
            Ok(n)
        }
        Err(e) if proc_gone(&e) => PRIMED_COUNT.get().copied().ok_or(e),
        Err(e) => Err(e),
    }
}

/// Whether the error means `/proc` is not mounted/reachable (not a transient
/// resource error).
fn proc_gone(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::NotFound) || e.raw_os_error() == Some(nix::libc::ENOTDIR)
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
    fn proc_gone_only_for_missing_proc() {
        assert!(proc_gone(&io::Error::from(io::ErrorKind::NotFound)));
        assert!(proc_gone(&io::Error::from_raw_os_error(nix::libc::ENOTDIR)));
        assert!(!proc_gone(&io::Error::from_raw_os_error(nix::libc::EMFILE)));
        assert!(!proc_gone(&io::Error::from(io::ErrorKind::InvalidData)));
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
