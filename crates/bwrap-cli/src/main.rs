//! The `bwrap` binary: collect argv, parse it, dispatch the outcome, resolve
//! the configuration, and run the sandbox. The heavy lifting lives in the
//! library and in `bwrap-core`; this file is the thin, `forbid(unsafe)` shell.

#![forbid(unsafe_code)]

use std::os::fd::RawFd;
use std::process::ExitCode;

use bwrap_cli::usage::{VERSION, usage};
use bwrap_cli::{Outcome, ParseHost, parse};
use bwrap_core::Error;
use bwrap_core::run::run;
use bwrap_core::types::Config;
use bwrap_core::userns::SystemUsernsProbe;
use nix::errno::Errno;

/// Read an fd to EOF (bwrap's `load_file_data`), returning the raw errno on
/// failure so each caller can attach its own message. Does not close the fd.
fn read_fd_fully(fd: RawFd) -> Result<Vec<u8>, Errno> {
    let bf = bwrap_sys::fd::borrow_raw(fd);
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match nix::unistd::read(bf, &mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e),
        }
    }
}

/// The real parser host: reads `--args`/`--add-seccomp-fd` fds and prints
/// warnings to stderr.
struct Host;

impl ParseHost for Host {
    fn read_args(&mut self, fd: RawFd) -> Result<Vec<u8>, Error> {
        read_fd_fully(fd).map_err(|e| Error::Sys {
            message: "Can't read --args data".into(),
            errno: e,
        })
    }

    fn read_seccomp_fd(&mut self, fd: RawFd) -> Result<Vec<u8>, Error> {
        // bwrap's seccomp_program_new reads the whole fd and closes it. Close it
        // regardless of the read result so the descriptor cannot leak into the
        // sandbox.
        let r = read_fd_fully(fd);
        bwrap_sys::fd::close_raw(fd);
        r.map_err(|e| Error::Sys {
            message: "Can't read seccomp data".into(),
            errno: e,
        })
    }

    fn warn(&mut self, msg: &str) {
        eprintln!("{}", bwrap_core::log::warning_line(msg));
    }

    fn set_level_prefix(&mut self, on: bool) {
        bwrap_core::log::set_level_prefix(on);
    }
}

fn main() -> ExitCode {
    // Collect argv without panicking on non-UTF-8 (which `std::env::args()`
    // would). Full byte-faithful handling of non-UTF-8 paths needs a bytes-based
    // parser (a module-3 rework); until then, fail cleanly instead of aborting.
    let argv_os: Vec<std::ffi::OsString> = std::env::args_os().collect();
    // Optional, env-gated invocation log (`BWRAP_RS_LOG`). A no-op when the
    // variable is unset or empty, so the drop-in behaviour and output stay
    // byte-identical to bwrap. Logged first, from the raw argv, so even
    // invocations we then reject (e.g. non-UTF-8 argv) are still captured.
    trace_invocation(&argv_os);
    let argv0 = argv_os
        .first()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "bwrap".to_string());
    let args: Vec<String> = match argv_os
        .iter()
        .skip(1)
        .cloned()
        .map(std::ffi::OsString::into_string)
        .collect()
    {
        Ok(v) => v,
        Err(_) => {
            trace_outcome("err=non-utf8-argv");
            eprintln!("bwrap: non-UTF-8 arguments are not yet supported by this build");
            return ExitCode::FAILURE;
        }
    };

    let mut host = Host;
    let config = match parse(&args, &mut host) {
        Ok(Outcome::Run(cfg)) => *cfg,
        Ok(Outcome::Help) => {
            print!("{}", usage(&argv0));
            return ExitCode::SUCCESS;
        }
        Ok(Outcome::Version) => {
            println!("{VERSION}");
            return ExitCode::SUCCESS;
        }
        Ok(Outcome::PrintAssumedKernel) => {
            println!("0.0.0");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            trace_outcome(&format!("err={e}"));
            eprintln!("{}", bwrap_core::log::error_line(&e.to_string()));
            return ExitCode::FAILURE;
        }
    };

    match launch(config) {
        Ok(code) => {
            trace_outcome(&format!("exit={code}"));
            ExitCode::from(u8::try_from(code).unwrap_or(255))
        }
        // bwrap prints the full usage to stderr for the "no command" error.
        Err(Error::Usage) => {
            trace_outcome("err=usage");
            eprint!("{}", usage(&argv0));
            ExitCode::FAILURE
        }
        Err(e) => {
            trace_outcome(&format!("err={e}"));
            eprintln!("{}", bwrap_core::log::error_line(&e.to_string()));
            ExitCode::FAILURE
        }
    }
}

/// Resolve where to write the invocation log, or `None` to disable it.
///
/// `BWRAP_RS_LOG` (non-empty) wins; otherwise the first line of the root-owned
/// file `/etc/bwrap-rs-log`, if present, is used. The file fallback makes
/// logging independent of session-environment propagation — every caller logs,
/// however it was launched (flatpak, glycin, Claude Code's own sandbox) — which
/// an env var alone cannot guarantee. When the variable is unset and the file
/// is absent, the binary stays a byte-exact drop-in: at most one failed `open`,
/// which changes no observable output.
///
/// Note: those callers' argv can contain secrets such as proxy credentials.
/// Point the log at a private, mode-0600 file and do not share it.
fn log_path() -> Option<std::ffi::OsString> {
    if let Some(p) = std::env::var_os("BWRAP_RS_LOG")
        && !p.is_empty()
    {
        return Some(p);
    }
    let contents = std::fs::read_to_string("/etc/bwrap-rs-log").ok()?;
    let line = contents.lines().next().unwrap_or("").trim();
    (!line.is_empty()).then(|| std::ffi::OsString::from(line))
}

/// Append one line to `path`. Best-effort: any error (unwritable path, full
/// disk) is ignored, and nothing is ever written to stdout/stderr, so logging
/// can never change the sandbox's observable output.
fn trace(path: &std::ffi::OsStr, record: &str) {
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = f.write_all(record.as_bytes());
    }
}

/// Seconds since the Unix epoch, for a cheap, dependency-free timestamp.
fn trace_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Log the full invocation (argv), shell-quoted so a captured line can be
/// replayed. Uses the raw `OsString` argv so non-UTF-8 arguments are still
/// recorded (lossily), unlike the parse path which rejects them.
fn trace_invocation(argv: &[std::ffi::OsString]) {
    let Some(path) = log_path() else {
        return;
    };
    let mut line = format!("t={} pid={} argv:", trace_now(), std::process::id());
    for a in argv {
        line.push(' ');
        line.push_str(&sh_quote(&a.to_string_lossy()));
    }
    line.push('\n');
    trace(&path, &line);
}

/// Log how an invocation ended (`exit=N`, or `err=…`), keyed by pid so it pairs
/// with the matching `argv:` line.
fn trace_outcome(outcome: &str) {
    let Some(path) = log_path() else {
        return;
    };
    trace(
        &path,
        &format!("t={} pid={} {outcome}\n", trace_now(), std::process::id()),
    );
}

/// Minimal POSIX shell quoting: pass through a token of safe characters as-is,
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

fn launch(config: Config) -> Result<i32, Error> {
    let real_uid = nix::unistd::getuid().as_raw();
    let real_gid = nix::unistd::getgid().as_raw();
    let resolved = config.resolve(real_uid, real_gid, &SystemUsernsProbe)?;
    run(&config, &resolved, real_uid, real_gid)
}
