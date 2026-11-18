//! The `bwrap` binary: collect argv, parse it, dispatch the outcome, resolve
//! the configuration, and run the sandbox. The heavy lifting lives in the
//! library and in `bwrap-core`; this file is the thin, `forbid(unsafe)` shell.

#![forbid(unsafe_code)]

mod trace;

/// On allocation failure, exit 1 with `Out of memory` like bubblewrap's
/// `die_oom`, instead of Rust's default abort (SIGABRT / exit 134 / core dump).
/// Declaring the allocator is safe; its `unsafe` `GlobalAlloc` impl lives in
/// bwrap-sys, so this crate stays `#![forbid(unsafe_code)]`.
#[global_allocator]
static GLOBAL: bwrap_sys::alloc::OomExit = bwrap_sys::alloc::OomExit;

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

use std::ffi::OsStr;
use std::os::fd::RawFd;
use std::process::ExitCode;

use bwrap_cli::usage::{VERSION, usage};
use bwrap_cli::{Outcome, ParseHost, parse};
use bwrap_core::Error;
use bwrap_core::privs::StartupPrivs;
use bwrap_core::run::{ExecutionPlan, run};
use bwrap_core::types::Config;
use bwrap_core::userns::SystemUsernsProbe;
use nix::errno::Errno;

/// The real parser host: reads `--args`/`--add-seccomp-fd` fds through the
/// process fd table and prints warnings to stderr.
struct Host<'a> {
    fds: &'a mut bwrap_sys::fd::FdTable,
}

impl Host<'_> {
    /// Adopt, borrow and read a caller fd to EOF (bwrap's `load_file_data`),
    /// returning the raw errno on failure. A bad or already-closed number is
    /// `EBADF`, so a reused `--args N … --args N` fails on the second read
    /// exactly as bubblewrap does.
    fn read_caller_fd(&mut self, fd: RawFd) -> Result<Vec<u8>, Errno> {
        self.fds.adopt(fd);
        bwrap_core::fs::io::read_to_end(self.fds.live(fd)?)
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

    fn validate_label(&mut self, label: &OsStr) -> Result<(), Error> {
        bwrap_core::selinux::die_unless_label_valid(label)
    }

    fn set_file_label(&mut self, label: &OsStr) -> Result<(), Error> {
        bwrap_core::selinux::label_create_file(Some(label))
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
    // Collect argv as OS strings so arbitrary bytes (e.g. a non-UTF-8 bind path
    // from a Flatpak portal) flow through verbatim to the syscalls, exactly as
    // bubblewrap passes its `char *` argv. The parser matches option names as
    // ASCII and carries path/command/env/argv0/hostname values as bytes.
    let argv_os: Vec<std::ffi::OsString> = std::env::args_os().collect();
    // A lone `--version` works before any privilege handling, as in bwrap, so it
    // also works in a build environment.
    if argv_os.len() == 2 && argv_os[1] == "--version" {
        bwrap_core::log::emit_out(VERSION);
        return ExitCode::SUCCESS;
    }
    // bwrap's startup gate: refuse setuid / file-caps use and set no_new_privs
    // before touching the caller's input in any way, logging included.
    let privs = match StartupPrivs::acquire() {
        Ok(privs) => privs,
        Err(e) => {
            bwrap_core::log::emit_err(&bwrap_core::log::error_line(&e.to_string()));
            return ExitCode::FAILURE;
        }
    };
    // Optional, env-gated invocation log (`BWRAP_RS_LOG`). A no-op when the
    // variable is unset or empty, so the drop-in behaviour and output stay
    // byte-identical to bwrap. Logged from the raw argv.
    trace::invocation(&argv_os);
    // argv[0] is still rendered lossily for the usage line (a non-UTF-8 argv0
    // shows U+FFFD there — the one remaining fidelity gap, DIFFERENCES.md #6).
    let argv0 = argv_os
        .first()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "bwrap".to_string());
    let args: Vec<std::ffi::OsString> = argv_os.into_iter().skip(1).collect();

    // The process's fd table; the Host adopts the --args/--add-seccomp-fd
    // descriptors through it (owns them for their read, closes them after).
    let mut fds = bwrap_sys::fd::FdTable::acquire().expect("main creates the only fd table");
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

    match launch(config, privs, &mut fds) {
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

fn launch(
    config: Config,
    privs: StartupPrivs,
    fds: &mut bwrap_sys::fd::FdTable,
) -> Result<i32, Error> {
    let plan = ExecutionPlan::new(config, privs, &SystemUsernsProbe)?;
    run(&plan, fds)
}
