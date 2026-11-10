//! Host integration test for module 9: load a real BPF filter from an fd and
//! apply it, proving the installed filter takes effect.
//!
//! `harness = false` + its own `main` (single-threaded for the fork). Works
//! without any namespace — just a fork and `PR_SET_NO_NEW_PRIVS`.
#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::process::ExitCode;

use bwrap_core::seccomp::SeccompPrograms;
use bwrap_core::types::SeccompSource;
use nix::errno::Errno;
use nix::libc;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, getcwd};

/// Errno the test filter returns for getcwd. Unusual, so a stale errno can't
/// make the check pass by accident.
const FILTER_ERRNO: Errno = Errno::EXFULL;

/// BPF: `getcwd()` -> EXFULL, everything else allowed.
fn deny_getcwd_bpf() -> Vec<u8> {
    fn insn(code: u32, jt: u8, jf: u8, k: u32) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..2].copy_from_slice(&(code as u16).to_ne_bytes());
        b[2] = jt;
        b[3] = jf;
        b[4..8].copy_from_slice(&k.to_ne_bytes());
        b
    }
    let nr = libc::SYS_getcwd as u32;
    let errno = (FILTER_ERRNO as i32) as u32;
    let mut v = Vec::new();
    // A = seccomp_data.nr (offset 0)
    v.extend(insn(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0));
    // if A == SYS_getcwd goto deny else allow
    v.extend(insn(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 1, nr));
    v.extend(insn(
        libc::BPF_RET | libc::BPF_K,
        0,
        0,
        libc::SECCOMP_RET_ERRNO | errno,
    ));
    v.extend(insn(
        libc::BPF_RET | libc::BPF_K,
        0,
        0,
        libc::SECCOMP_RET_ALLOW,
    ));
    v
}

fn child() -> i32 {
    if nix::sys::prctl::set_no_new_privs().is_err() {
        return 1;
    }
    let bpf = deny_getcwd_bpf();
    // Two programs (via --add-seccomp-fd semantics); both installed in order.
    // `Added` carries the parse-time bytes, so no fd is read here.
    let progs = match SeccompPrograms::load(
        &SeccompSource::Added(vec![bpf.clone(), bpf.clone()]),
        |_fd| panic!("Added must not read an fd"),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  load: {e}");
            return 2;
        }
    };
    if progs.len() != 2 {
        return 3;
    }
    if let Err(e) = progs.apply() {
        eprintln!("  apply: {e}");
        return 4;
    }
    // The filter must now be in force.
    match getcwd() {
        Err(e) if e == FILTER_ERRNO => 0,
        other => {
            eprintln!("  getcwd after apply = {other:?}");
            5
        }
    }
}

fn main() -> ExitCode {
    // SAFETY note: fork_single_threaded refuses unless single-threaded, which
    // this harness is.
    let code = match bwrap_sys::process::fork_single_threaded() {
        Ok(ForkResult::Child) => std::process::exit(child()),
        Ok(ForkResult::Parent { child: c }) => wait(c),
        Err(e) => {
            println!("test seccomp_host ... FAILED: fork: {e}");
            return ExitCode::FAILURE;
        }
    };
    if code == 0 {
        println!("test seccomp_host ... ok");
        ExitCode::SUCCESS
    } else {
        println!("test seccomp_host ... FAILED at step {code}");
        ExitCode::FAILURE
    }
}

fn wait(child: Pid) -> i32 {
    match waitpid(child, None) {
        Ok(WaitStatus::Exited(_, code)) => code,
        other => {
            eprintln!("child ended abnormally: {other:?}");
            99
        }
    }
}
