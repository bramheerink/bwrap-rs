//! The `bwrap` binary: collect argv, parse it, dispatch the outcome, resolve
//! the configuration, and run the sandbox. The heavy lifting lives in the
//! library and in `bwrap-core`; this file is the thin, `forbid(unsafe)` shell.

#![forbid(unsafe_code)]

mod trace;

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
        // bwrap closes the --args fd right after reading (bubblewrap.c:1815), so
        // it never leaks into the sandbox and a repeated `--args N N` re-read
        // fails with EBADF as in C. Close it regardless of the read result.
        let r = read_fd_fully(fd);
        bwrap_sys::fd::close_raw(fd);
        r.map_err(|e| Error::Sys {
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
        bwrap_core::log::emit_err(&bwrap_core::log::warning_line(msg));
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

    let mut host = Host;
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

    match launch(config) {
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

fn launch(config: Config) -> Result<i32, Error> {
    let real_uid = nix::unistd::getuid().as_raw();
    let real_gid = nix::unistd::getgid().as_raw();
    let resolved = config.resolve(real_uid, real_gid, &SystemUsernsProbe)?;
    run(&config, &resolved, real_uid, real_gid)
}
