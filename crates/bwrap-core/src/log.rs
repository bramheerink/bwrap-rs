//! Stderr line formatting, mirroring bubblewrap's `bwrap_logv`.
//!
//! bwrap keeps a process-global `bwrap_level_prefix` flag, set the moment
//! `--level-prefix` is parsed, and every `warn()`/`die()` line is prefixed with
//! `<N>` (the syslog severity) when it is on. The flag is global precisely
//! because it is ordering-sensitive within argument parsing: a warning emitted
//! before `--level-prefix` is seen has no prefix, one after does. We replicate
//! that with a single atomic, set via the parser's host and consulted by every
//! place that writes `bwrap: …` to stderr.

use std::io::Write;
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

/// Write a preformatted line to stderr, swallowing any write error.
///
/// bwrap's `die()`/`warn()` write with `vfprintf` and ignore the result: a
/// failed write (stderr redirected to a full disk, a closed pipe, …) must not
/// change the exit status. Rust's `eprintln!` instead *panics* when the write
/// fails, and with `panic = "abort"` that panic becomes `SIGABRT` (exit 134) —
/// diverging from bwrap's plain exit 1. Every `bwrap: …` diagnostic goes through
/// this helper (and [`emit_out`]) so the byte-exact exit-code contract holds
/// even when the output cannot be written.
pub fn emit_err(line: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// Write raw text to stderr with no added newline, swallowing write errors
/// (the full-usage dump bwrap prints to stderr on the "no command" error).
pub fn emit_err_raw(text: &str) {
    let _ = write!(std::io::stderr().lock(), "{text}");
}

/// Write a line to stdout, swallowing write errors (`--version`, the assumed
/// kernel line). See [`emit_err`] for why the failure is ignored.
pub fn emit_out(line: &str) {
    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

/// Write raw text to stdout with no added newline, swallowing write errors
/// (the `--help` usage dump).
pub fn emit_out_raw(text: &str) {
    let _ = write!(std::io::stdout().lock(), "{text}");
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
