//! The `bwrap` binary: collect argv, parse it, dispatch the outcome, resolve
//! the configuration, and run the sandbox. The heavy lifting lives in the
//! library and in `bwrap-core`; this file is the thin, `forbid(unsafe)` shell.

#![forbid(unsafe_code)]

mod trace;

/// Build identity embedded in the binary so a deployed `/usr/bin/bwrap` (which,
/// by design, prints the same `--version` as the C tool) can still be identified
/// as the port and traced to a build: `strings -a bwrap | grep '^bwrap-rs '`.
/// `#[used]` keeps it through dead-code elimination and `strip = true`; it never
/// touches the CLI surface, so `--version` stays byte-identical.
#[used]
static BWRAP_RS_BUILD_ID: &str = concat!("\0bwrap-rs ", env!("CARGO_PKG_VERSION"), "\0");

/// The git commit the binary was built from, when the release build sets
/// `BWRAP_RS_GIT_SHA`; otherwise a stable placeholder. Kept greppable alongside
/// [`BWRAP_RS_BUILD_ID`].
#[used]
static BWRAP_RS_GIT_SHA: &str = match option_env!("BWRAP_RS_GIT_SHA") {
    Some(sha) => sha,
    None => "bwrap-rs-git: unknown",
};

use std::os::fd::RawFd;
use std::process::ExitCode;

use bwrap_cli::usage::{VERSION, usage};
use bwrap_cli::{Outcome, ParseHost, parse};
use bwrap_core::Error;
use bwrap_core::run::run;
use bwrap_core::types::Config;
use bwrap_core::userns::SystemUsernsProbe;
use nix::errno::Errno;

/// The real parser host: reads `--args`/`--add-seccomp-fd` fds through the
/// process fd table and prints warnings to stderr.
struct Host<'a> {
    fds: &'a mut bwrap_sys::fd::FdTable,
}

impl Host<'_> {
    /// Claim, borrow and read a caller fd to EOF (bwrap's `load_file_data`),
    /// returning the raw errno on failure. A bad or already-closed number is
    /// `EBADF`, so a reused `--args N … --args N` fails on the second read
    /// exactly as bubblewrap does.
    fn read_caller_fd(&mut self, fd: RawFd) -> Result<Vec<u8>, Errno> {
        self.fds.claim(fd).map_err(|_| Errno::EBADF)?;
        let bf = self.fds.borrow(fd).ok_or(Errno::EBADF)?;
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
}

impl ParseHost for Host<'_> {
    fn read_args(&mut self, fd: RawFd) -> Result<Vec<u8>, Error> {
        // bwrap closes the --args fd right after reading (bubblewrap.c:1815), so
        // it never leaks into the sandbox and a repeated `--args N N` re-read
        // fails with EBADF as in C. Close it regardless of the read result.
        let r = self.read_caller_fd(fd);
        self.fds.close(fd);
        r.map_err(|e| Error::Sys {
            message: "Can't read --args data".into(),
            errno: e,
        })
    }

    fn read_seccomp_fd(&mut self, fd: RawFd) -> Result<Vec<u8>, Error> {
        // bwrap's seccomp_program_new reads the whole fd and closes it. Close it
        // regardless of the read result so the descriptor cannot leak into the
        // sandbox.
        let r = self.read_caller_fd(fd);
        self.fds.close(fd);
        r.map_err(|e| Error::Sys {
            message: "Can't read seccomp data".into(),
            errno: e,
        })
    }

    fn warn(&mut self, msg: &str) {
        bwrap_core::log::emit_err(&bwrap_core::log::warning_line(msg));
    }

    fn set_level_prefix(&mut self, on: bool) {
        bwrap_core::log::set_level_prefix(on);
    }
}

fn main() -> ExitCode {
    // Undo the Rust runtime's startup signal changes before anything else, so
    // every exit path (including --help/--version/parse errors) and the sandbox
    // run with bubblewrap's signal state: inherited SIGPIPE/SIGSEGV/SIGBUS and
    // SIGCHLD reset to SIG_DFL. Must be first — the early-return paths below
    // would otherwise still carry the runtime's SIGPIPE = SIG_IGN.
    bwrap_sys::process::reset_runtime_signal_state();
    // Collect argv without panicking on non-UTF-8 (which `std::env::args()`
    // would). Full byte-faithful handling of non-UTF-8 paths needs a bytes-based
    // parser (a module-3 rework); until then, fail cleanly instead of aborting.
    let argv_os: Vec<std::ffi::OsString> = std::env::args_os().collect();
    // Optional, env-gated invocation log (`BWRAP_RS_LOG`). A no-op when the
    // variable is unset or empty, so the drop-in behaviour and output stay
    // byte-identical to bwrap. Logged first, from the raw argv, so even
    // invocations we then reject (e.g. non-UTF-8 argv) are still captured.
    trace::invocation(&argv_os);
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
            trace::outcome("err=non-utf8-argv");
            bwrap_core::log::emit_err(
                "bwrap: non-UTF-8 arguments are not yet supported by this build",
            );
            return ExitCode::FAILURE;
        }
    };

    // The process's fd table; the Host claims the --args/--add-seccomp-fd
    // descriptors through it (owns them for their read, closes them after).
    let mut fds = bwrap_sys::fd::FdTable::new();
    let mut host = Host { fds: &mut fds };
    let config = match parse(&args, &mut host) {
        Ok(Outcome::Run(cfg)) => *cfg,
        Ok(Outcome::Help) => {
            bwrap_core::log::emit_out_raw(&usage(&argv0));
            return ExitCode::SUCCESS;
        }
        Ok(Outcome::Version) => {
            bwrap_core::log::emit_out(VERSION);
            return ExitCode::SUCCESS;
        }
        Ok(Outcome::PrintAssumedKernel) => {
            bwrap_core::log::emit_out("0.0.0");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            trace::outcome(&format!("err={e}"));
            bwrap_core::log::emit_err(&bwrap_core::log::error_line(&e.to_string()));
            return ExitCode::FAILURE;
        }
    };

    match launch(config, &mut fds) {
        Ok(code) => {
            trace::outcome(&format!("exit={code}"));
            ExitCode::from(u8::try_from(code).unwrap_or(255))
        }
        // bwrap prints the full usage to stderr for the "no command" error.
        Err(Error::Usage) => {
            trace::outcome("err=usage");
            bwrap_core::log::emit_err_raw(&usage(&argv0));
            ExitCode::FAILURE
        }
        Err(e) => {
            trace::outcome(&format!("err={e}"));
            bwrap_core::log::emit_err(&bwrap_core::log::error_line(&e.to_string()));
            ExitCode::FAILURE
        }
    }
}

fn launch(config: Config, fds: &mut bwrap_sys::fd::FdTable) -> Result<i32, Error> {
    let real_uid = nix::unistd::getuid().as_raw();
    let real_gid = nix::unistd::getgid().as_raw();
    let resolved = config.resolve(real_uid, real_gid, &SystemUsernsProbe)?;
    run(&config, &resolved, real_uid, real_gid, fds)
}
