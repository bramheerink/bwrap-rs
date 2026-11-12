//! Host integration test for module 8: bring up loopback in a fresh network
//! namespace and prove it works by binding a UDP socket to 127.0.0.1.
//!
//! `harness = false` + its own `main` (single-threaded for the clone). SKIPs
//! when the kernel refuses the namespaces.
#![allow(clippy::unwrap_used)]

use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::process::ExitCode;

use bwrap_core::net::loopback_setup;
use bwrap_core::userns::{IdMap, MapTarget, OverflowIds};
use bwrap_sys::process::{ForkError, clone_into_namespaces};
use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::sched::CloneFlags;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, SockaddrIn, bind as sock_bind, socket};
use nix::sys::stat::Mode;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid};

fn child(real_uid: u32, real_gid: u32) -> i32 {
    // Complete the user namespace (map to 0) so we hold CAP_NET_ADMIN cleanly.
    let Ok(overflow) = OverflowIds::read() else {
        return 1;
    };
    let Ok(proc_fd) = open(
        Path::new("/proc"),
        OFlag::O_PATH | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) else {
        return 2;
    };
    let idmap = IdMap {
        sandbox_uid: 0,
        parent_uid: real_uid,
        sandbox_gid: 0,
        parent_gid: real_gid,
        overflow,
        map_root: false,
        deny_groups: true,
    };
    if idmap.write(proc_fd.as_fd(), MapTarget::SelfProc).is_err() {
        return 3;
    }

    // The real test: loopback_setup's RTM_NEWADDR + RTM_NEWLINK netlink
    // requests both succeed in the fresh netns.
    if let Err(e) = loopback_setup() {
        eprintln!("  loopback_setup: {e}");
        return 5;
    }

    // And afterwards 127.0.0.1 is bindable (lo up with the address).
    match bind_loopback() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("  bind after setup: {e}");
            6
        }
    }
}

fn bind_loopback() -> nix::Result<()> {
    let s = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;
    let addr = SockaddrIn::new(127, 0, 0, 1, 0);
    sock_bind(s.as_raw_fd(), &addr)
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

fn main() -> ExitCode {
    let real_uid = nix::unistd::geteuid().as_raw();
    let real_gid = nix::unistd::getegid().as_raw();
    let flags = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET;
    let code = match clone_into_namespaces(flags) {
        Ok(ForkResult::Child) => std::process::exit(child(real_uid, real_gid)),
        Ok(ForkResult::Parent { child: c }) => wait(c),
        Err(ForkError::Sys(Errno::EPERM | Errno::ENOSPC | Errno::EINVAL | Errno::EUSERS)) => {
            if std::env::var_os("BWRAP_RS_REQUIRE_USERNS").is_some() {
                println!(
                    "test net_host ... FAILED (BWRAP_RS_REQUIRE_USERNS set but user/net namespaces unavailable)"
                );
                return ExitCode::FAILURE;
            }
            println!("test net_host ... SKIP (user/net namespaces unavailable)");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            println!("test net_host ... FAILED: clone: {e}");
            return ExitCode::FAILURE;
        }
    };
    if code == 0 {
        println!("test net_host ... ok");
        ExitCode::SUCCESS
    } else {
        println!("test net_host ... FAILED at step {code}");
        ExitCode::FAILURE
    }
}
