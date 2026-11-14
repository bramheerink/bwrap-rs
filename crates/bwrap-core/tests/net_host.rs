//! Host integration test for module 8: bring up loopback in a fresh network
//! namespace and prove it works by binding a UDP socket to 127.0.0.1.
//!
//! `harness = false` + its own `main` (single-threaded for the clone). SKIPs
//! when the kernel refuses the namespaces.
#![allow(clippy::unwrap_used)]

use std::os::fd::AsFd;
use std::path::Path;
use std::process::ExitCode;

use bwrap_core::net::loopback_setup;
use bwrap_core::userns::IdMap;
use bwrap_sys::process::{ForkError, clone_into_namespaces};
use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::sched::CloneFlags;
use nix::sys::stat::Mode;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid};

fn child(real_uid: u32, real_gid: u32) -> i32 {
    // Complete the user namespace (map to 0) so we hold CAP_NET_ADMIN cleanly.
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
        deny_groups: true,
    };
    if idmap.write(proc_fd.as_fd()).is_err() {
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

/// Prove loopback is actually UP, not merely that 127.0.0.1 is bindable: `bind`
/// succeeds as soon as the address exists, link up or not, so a bind alone does
/// not catch a regression that assigns the address but never sets `IFF_UP`. Send
/// a datagram to our own bound address and receive it back — that round-trip
/// needs the link up (a down `lo` fails with ENETUNREACH, or the receive would
/// block, so cap it with a short timeout).
fn bind_loopback() -> std::io::Result<()> {
    use std::net::UdpSocket;
    use std::time::Duration;

    let s = UdpSocket::bind("127.0.0.1:0")?;
    let addr = s.local_addr()?;
    s.set_read_timeout(Some(Duration::from_millis(200)))?;
    s.send_to(b"x", addr)?;
    let mut buf = [0u8; 1];
    let (n, _from) = s.recv_from(&mut buf)?;
    if n == 1 && buf[0] == b'x' {
        Ok(())
    } else {
        Err(std::io::Error::other("loopback datagram not echoed"))
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
