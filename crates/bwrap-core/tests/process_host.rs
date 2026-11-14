//! Host integration test for module 10: the real parent/pid-1/child process
//! triangle. A launcher runs `monitor_child`; its pid-1 child runs `do_init`,
//! which forks the sandbox "app" (pid 2), reaps it, and reports its exit
//! status back through an event channel. We assert the launcher observes the
//! app's exit code (not pid 1's).
//!
//! `harness = false` + its own `main` (single-threaded for the forks). Needs no
//! namespaces — just forks, a pipe and a signalfd — so it runs anywhere.
#![allow(clippy::unwrap_used)]

use std::os::fd::{AsFd, OwnedFd};
use std::process::ExitCode;

use bwrap_core::process::{block_sigchild, do_init, monitor_child};
use bwrap_core::seccomp::SeccompPrograms;
use bwrap_core::types::SeccompSource;
use bwrap_sys::process::fork_single_threaded;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, pipe};

/// The exit code the sandbox "app" (pid 2) terminates with. `monitor_child`
/// must surface exactly this, proving the event_fd path (do_init's write of
/// `exitstatus + 1`) is read in preference to pid 1's own status.
const APP_CODE: i32 = 42;

fn main() -> ExitCode {
    match run() {
        0 => {
            println!("test process_host ... ok");
            ExitCode::SUCCESS
        }
        code => {
            println!("test process_host ... FAILED at step {code}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> i32 {
    // Event channel pid 1 -> launcher, carrying `exitstatus + 1`. A pipe gives
    // the same 8-byte semantics monitor_child needs from an eventfd.
    let (rd, wr) = match pipe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pipe: {e}");
            return 1;
        }
    };
    // monitor_child expects the event fd to be non-blocking.
    if fcntl(&rd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).is_err() {
        return 2;
    }

    let seccomp = match SeccompPrograms::load(&SeccompSource::None, |_| Ok(Vec::new())) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("seccomp load: {e}");
            return 3;
        }
    };

    // Fork the whole monitored subtree so monitor_child's fd-closing cannot
    // disturb this test process.
    match fork_single_threaded() {
        Ok(ForkResult::Child) => {
            let code = launcher(rd, wr, &seccomp);
            std::process::exit(code);
        }
        Ok(ForkResult::Parent { child }) => {
            drop(rd);
            drop(wr);
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, c)) if c == APP_CODE => 0,
                Ok(WaitStatus::Exited(_, c)) => {
                    eprintln!("launcher returned {c}, expected {APP_CODE}");
                    10
                }
                other => {
                    eprintln!("launcher ended abnormally: {other:?}");
                    11
                }
            }
        }
        Err(e) => {
            eprintln!("fork launcher: {e}");
            4
        }
    }
}

/// Runs as the launcher process: block SIGCHLD, fork pid 1, and monitor it.
fn launcher(rd: OwnedFd, wr: OwnedFd, seccomp: &SeccompPrograms) -> i32 {
    if block_sigchild().is_err() {
        return 30;
    }
    match fork_single_threaded() {
        Ok(ForkResult::Child) => {
            // pid 1 (init): only the write end is needed here.
            drop(rd);
            // fork the app (pid 2), then run do_init.
            let app_pid = match fork_single_threaded() {
                Ok(ForkResult::Child) => std::process::exit(APP_CODE),
                Ok(ForkResult::Parent { child }) => child,
                Err(_) => std::process::exit(31),
            };
            // die_with_parent is false here, so there is no launcher handshake fd.
            match do_init(Some(wr.as_fd()), app_pid, &[], seccomp, false, None) {
                // do_init returns the app's status; exiting with it is a second,
                // independent signal, but the launcher reads the event fd.
                Ok(_) => std::process::exit(0),
                Err(e) => {
                    eprintln!("do_init: {e}");
                    std::process::exit(32);
                }
            }
        }
        Ok(ForkResult::Parent { child: pid1 }) => {
            // Close the write end before monitor_child's fd-walk, so it is not
            // closed out from under its OwnedFd (real bwrap uses raw ints).
            drop(wr);
            // No die_with_parent handshake fd in this synthetic launcher.
            match monitor_child(Some(rd.as_fd()), pid1, None, None, None) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("monitor_child: {e}");
                    33
                }
            }
        }
        Err(_) => 34,
    }
}
