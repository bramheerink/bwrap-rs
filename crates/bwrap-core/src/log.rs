//! Stderr line formatting, mirroring bubblewrap's `bwrap_logv`.
//!
//! bwrap keeps a process-global `bwrap_level_prefix` flag, set the moment
//! `--level-prefix` is parsed, and every `warn()`/`die()` line is prefixed with
//! `<N>` (the syslog severity) when it is on. The flag is global precisely
//! because it is ordering-sensitive within argument parsing: a warning emitted
//! before `--level-prefix` is seen has no prefix, one after does. We replicate
//! that with a single atomic, set via the parser's host and consulted by every
//! place that writes `bwrap: …` to stderr.

use std::sync::atomic::{AtomicBool, Ordering};

static LEVEL_PREFIX: AtomicBool = AtomicBool::new(false);

const LOG_ERR: u8 = 3;
const LOG_WARNING: u8 = 4;

/// Enable or disable the `<N>` severity prefix (bwrap's `--level-prefix`).
pub fn set_level_prefix(on: bool) {
    LEVEL_PREFIX.store(on, Ordering::Relaxed);
}

/// Whether the severity prefix is currently enabled.
pub fn level_prefix() -> bool {
    LEVEL_PREFIX.load(Ordering::Relaxed)
}

fn line(severity: u8, msg: &str) -> String {
    if level_prefix() {
        format!("<{severity}>bwrap: {msg}")
    } else {
        format!("bwrap: {msg}")
    }
}

/// A `bwrap: …` error line (`LOG_ERR`), with a `<3>` prefix under `--level-prefix`.
pub fn error_line(msg: &str) -> String {
    line(LOG_ERR, msg)
}

/// A `bwrap: …` warning line (`LOG_WARNING`), with a `<4>` prefix under
/// `--level-prefix`.
pub fn warning_line(msg: &str) -> String {
    line(LOG_WARNING, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_toggles_severity_token() {
        // This test owns the global for its duration (run serially via the lock
        // below is unnecessary: no other test reads the flag).
        set_level_prefix(false);
        assert_eq!(error_line("boom"), "bwrap: boom");
        assert_eq!(warning_line("careful"), "bwrap: careful");
        set_level_prefix(true);
        assert_eq!(error_line("boom"), "<3>bwrap: boom");
        assert_eq!(warning_line("careful"), "<4>bwrap: careful");
        set_level_prefix(false);
    }
}
