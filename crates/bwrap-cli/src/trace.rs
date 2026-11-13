//! Opt-in invocation logger.
//!
//! Enabled by the `BWRAP_RS_LOG` environment variable, or, when that is unset,
//! by the root-owned file `/etc/bwrap-rs-log` whose first line is the log path.
//! The file fallback makes logging independent of session-environment
//! propagation — every caller logs, however it was launched (flatpak, glycin,
//! Claude Code's own sandbox), which an env var alone cannot guarantee.
//!
//! When neither is set the logger is a no-op (at most one failed `open`), so the
//! binary stays a byte-exact drop-in for bwrap. Nothing is ever written to
//! stdout/stderr, so logging can never change the sandbox's observable output.
//!
//! Note: those callers' argv can contain secrets such as proxy credentials.
//! Point the log at a private, mode-0600 file and do not share it.

use std::ffi::{OsStr, OsString};

/// Log the full invocation (argv), shell-quoted so a captured line can be
/// replayed. Uses the raw `OsString` argv so non-UTF-8 arguments are still
/// recorded (lossily), unlike the parse path which rejects them.
pub(crate) fn invocation(argv: &[OsString]) {
    let Some(path) = log_path() else {
        return;
    };
    let mut line = format!(
        "t={} pid={} bwrap-rs {} argv:",
        now(),
        std::process::id(),
        env!("CARGO_PKG_VERSION"),
    );
    for a in argv {
        line.push(' ');
        line.push_str(&sh_quote(&a.to_string_lossy()));
    }
    line.push('\n');
    append(&path, &line);
}

/// Log how an invocation ended (`exit=N`, or `err=…`), keyed by pid so it pairs
/// with the matching `argv:` line.
pub(crate) fn outcome(outcome: &str) {
    let Some(path) = log_path() else {
        return;
    };
    append(
        &path,
        &format!("t={} pid={} {outcome}\n", now(), std::process::id()),
    );
}

/// Resolve where to write the log, or `None` to disable it. `BWRAP_RS_LOG`
/// (non-empty) wins; otherwise the first line of `/etc/bwrap-rs-log`, if present.
///
/// Hardening: the log records argv, which may contain secrets.
/// - When running as root (euid 0) `BWRAP_RS_LOG` is ignored, so an inherited
///   env var cannot redirect a privileged invocation's log to an attacker path.
/// - `/etc/bwrap-rs-log` is honoured only when it is a regular file owned by
///   root and not group/world-writable, so an unprivileged user cannot point the
///   log by editing (or symlinking) it.
fn log_path() -> Option<OsString> {
    let is_root = nix::unistd::geteuid().is_root();
    if !is_root
        && let Some(p) = std::env::var_os("BWRAP_RS_LOG")
        && !p.is_empty()
    {
        return Some(p);
    }
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::symlink_metadata("/etc/bwrap-rs-log").ok()?;
    if !meta.is_file() || meta.uid() != 0 || (meta.mode() & 0o022) != 0 {
        return None;
    }
    let contents = std::fs::read_to_string("/etc/bwrap-rs-log").ok()?;
    let line = contents.lines().next().unwrap_or("").trim();
    (!line.is_empty()).then(|| OsString::from(line))
}

/// Append one line to `path`. Best-effort: any error (unwritable path, full
/// disk) is ignored. Opened mode-0600 and `O_NOFOLLOW` so the (secret-bearing)
/// log is private and a symlink at the target cannot redirect the write.
fn append(path: &OsStr, record: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
    {
        let _ = f.write_all(record.as_bytes());
    }
}

/// Seconds since the Unix epoch, for a cheap, dependency-free timestamp.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Minimal POSIX shell quoting: pass a token of safe characters through as-is,
/// otherwise single-quote it (with `'` escaped as `'\''`).
fn sh_quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./:=@%+,-".contains(&b));
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}
