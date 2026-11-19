//! Shadow-oracle verification tool (not part of the shipped `bwrap`).
//!
//! Lets anyone check, for themselves, that bwrap-rs decides the *same* sandbox
//! plan the real bubblewrap 0.13.1 would. It parses and resolves an argv with
//! the bwrap-rs library, serialises the resulting plan, then runs a patched C
//! `bwrap` in dry-run mode (`BWRAP_DRYRUN=1`) on the same argv. The C binary
//! parses and validates exactly as upstream, prints the plan it *would* run,
//! and exits before any namespace/mount/exec — so it changes nothing. The two
//! plans are compared and the verdict printed.
//!
//! This is a developer tool: it lives in `examples/`, so a normal
//! `cargo build`/install never includes it and the shipped binary is untouched.
//!
//! Usage:
//!   BWRAP_RS_SHADOW=/path/to/patched-bwrap \
//!     cargo run -q --example shadow_oracle -- <bwrap args...> COMMAND
//!
//! The patched C binary is built from a copy of bubblewrap 0.13.1 with a small,
//! additive, env-gated `dryrun_dump_and_exit()` (see the project's shadow-oracle
//! notes). Without `BWRAP_DRYRUN` that binary behaves identically to stock bwrap.

use std::os::fd::RawFd;
use std::process::{Command, ExitCode};

use bwrap_cli::{Outcome, ParseHost, parse};
use bwrap_core::Error;
use bwrap_core::types::{BindKind, Config, NsPolicy, OnMissing, OverlayUpper, ResolvedConfig, SetupOp};
use bwrap_core::userns::SystemUsernsProbe;
use nix::errno::Errno;

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

/// A parse host that reads `--args`/seccomp fds, like the real binary's.
struct Host;
impl ParseHost for Host {
    fn read_args(&mut self, fd: RawFd) -> Result<Vec<u8>, Error> {
        let r = read_fd_fully(fd);
        bwrap_sys::fd::close_raw(fd);
        r.map_err(|e| Error::Sys { message: "Can't read --args data".into(), errno: e })
    }
    fn read_seccomp_fd(&mut self, fd: RawFd) -> Result<Vec<u8>, Error> {
        let r = read_fd_fully(fd);
        bwrap_sys::fd::close_raw(fd);
        r.map_err(|e| Error::Sys { message: "Can't read seccomp data".into(), errno: e })
    }
    fn warn(&mut self, _msg: &str) {}
    fn set_level_prefix(&mut self, _on: bool) {}
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Dump mode (`BWRAP_RS_DUMP=1`): print bwrap-rs's own resolved plan — the
    // symmetric counterpart to the C oracle's dry-run — and exit. This is how
    // shadow_replay.py obtains our side; the plan comes from the real library
    // parse+resolve, with no sandbox ever run.
    if std::env::var_os("BWRAP_RS_DUMP").is_some_and(|v| !v.is_empty()) {
        return dump_mode(&args);
    }

    let Some(oracle) = std::env::var_os("BWRAP_RS_SHADOW").filter(|v| !v.is_empty()) else {
        eprintln!(
            "shadow_oracle: set BWRAP_RS_SHADOW=<path to a patched bwrap 0.13.1 dry-run oracle>"
        );
        return ExitCode::FAILURE;
    };

    // --args/--add-seccomp-fd read their fds during parsing; those fds cannot be
    // replayed into the separate oracle process, so this tool cannot compare
    // such invocations. (See the note on approach (c) for lifting this.)
    if args.iter().any(|a| a == "--args" || a == "--add-seccomp-fd") {
        println!("SKIP: invocation uses --args/--add-seccomp-fd (fd cannot be replayed)");
        return ExitCode::SUCCESS;
    }

    let mut host = Host;
    let config = match parse(&args, &mut host) {
        Ok(Outcome::Run(cfg)) => *cfg,
        Ok(Outcome::Help) => return say("nothing to compare: --help"),
        Ok(Outcome::Version) => return say("nothing to compare: --version"),
        Ok(Outcome::PrintAssumedKernel) => return say("nothing to compare: --assume-kernel"),
        Err(e) => return compare_error(&oracle, &args, &format!("parse error: {e}")),
    };

    let real_uid = nix::unistd::getuid().as_raw();
    let real_gid = nix::unistd::getgid().as_raw();
    let resolved = match config.resolve(real_uid, real_gid, &SystemUsernsProbe) {
        Ok(r) => r,
        Err(e) => return compare_error(&oracle, &args, &format!("resolve error: {e}")),
    };

    let ours = normalize(&plan(&config, &resolved));

    let theirs = match run_oracle(&oracle, &args) {
        OracleResult::Plan(p) => normalize(&p),
        OracleResult::Early { code, stderr } => {
            println!("MISMATCH: bwrap-rs produced a plan but C exited {code} before its dump");
            if !stderr.is_empty() {
                println!("  C stderr: {stderr}");
            }
            return ExitCode::FAILURE;
        }
        OracleResult::Spawn(e) => {
            eprintln!("shadow_oracle: could not run oracle {oracle:?}: {e}");
            return ExitCode::FAILURE;
        }
    };

    if ours == theirs {
        println!("MATCH ({} plan lines)", ours.len());
        ExitCode::SUCCESS
    } else {
        println!("MISMATCH");
        for line in diff(&ours, &theirs) {
            println!("  {line}");
        }
        ExitCode::FAILURE
    }
}

fn say(msg: &str) -> ExitCode {
    println!("{msg}");
    ExitCode::SUCCESS
}

/// Print bwrap-rs's resolved plan (same format as the C dry-run oracle), or an
/// `__ERROR__ <message>` / `__NOTHING__ <reason>` marker line. Always exits 0 so
/// the caller reads the result uniformly from stdout.
fn dump_mode(args: &[String]) -> ExitCode {
    let mut host = Host;
    let config = match parse(args, &mut host) {
        Ok(Outcome::Run(cfg)) => *cfg,
        Ok(Outcome::Help) => return say("__NOTHING__ --help"),
        Ok(Outcome::Version) => return say("__NOTHING__ --version"),
        Ok(Outcome::PrintAssumedKernel) => return say("__NOTHING__ --assume-kernel"),
        Err(e) => return say(&format!("__ERROR__ {e}")),
    };
    let real_uid = nix::unistd::getuid().as_raw();
    let real_gid = nix::unistd::getgid().as_raw();
    match config.resolve(real_uid, real_gid, &SystemUsernsProbe) {
        Ok(resolved) => {
            print!("{}", plan(&config, &resolved));
            ExitCode::SUCCESS
        }
        Err(e) => say(&format!("__ERROR__ {e}")),
    }
}

/// When bwrap-rs rejects the argv, confirm the C oracle rejects it too.
fn compare_error(oracle: &std::ffi::OsStr, args: &[String], ours: &str) -> ExitCode {
    println!("bwrap-rs: {ours}");
    match run_oracle(oracle, args) {
        OracleResult::Plan(_) => {
            println!("MISMATCH: bwrap-rs errored but C produced a plan");
            ExitCode::FAILURE
        }
        OracleResult::Early { code, stderr } => {
            println!("C also errored (exit {code}): {stderr}");
            println!("(both rejected the invocation; message wording not compared here)");
            ExitCode::SUCCESS
        }
        OracleResult::Spawn(e) => {
            eprintln!("shadow_oracle: could not run oracle: {e}");
            ExitCode::FAILURE
        }
    }
}

enum OracleResult {
    Plan(String),
    Early { code: i32, stderr: String },
    Spawn(std::io::Error),
}

fn run_oracle(oracle: &std::ffi::OsStr, args: &[String]) -> OracleResult {
    match Command::new(oracle)
        .args(args)
        .env("BWRAP_DRYRUN", "1")
        .env_remove("BWRAP_DRYRUN_FD")
        .output()
    {
        Ok(o) if o.status.success() => OracleResult::Plan(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(o) => OracleResult::Early {
            code: o.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&o.stderr).trim_end().to_string(),
        },
        Err(e) => OracleResult::Spawn(e),
    }
}

// --- plan serialisation: must match the C dryrun_dump_and_exit() format ------

fn plan(config: &Config, resolved: &ResolvedConfig) -> String {
    let b = |x: bool| u8::from(x);
    let mut s = String::new();
    s.push_str("bwrap-dryrun v1\n");
    s.push_str(&format!("flag unshare_user={}\n", b(resolved.namespaces.user == NsPolicy::Unshare)));
    s.push_str(&format!("flag unshare_pid={}\n", b(config.unshare_pid)));
    s.push_str(&format!("flag unshare_net={}\n", b(config.unshare_net)));
    s.push_str(&format!("flag unshare_ipc={}\n", b(config.unshare_ipc)));
    s.push_str(&format!("flag unshare_uts={}\n", b(config.unshare_uts)));
    s.push_str(&format!("flag unshare_cgroup={}\n", b(config.unshare_cgroup)));
    s.push_str(&format!("flag unshare_cgroup_try={}\n", b(config.unshare_cgroup_try)));
    s.push_str(&format!("flag disable_userns={}\n", b(config.disable_userns)));
    s.push_str(&format!("flag assert_userns_disabled={}\n", b(config.assert_userns_disabled)));
    s.push_str(&format!("flag as_pid_1={}\n", b(config.as_pid_1)));
    s.push_str(&format!("flag new_session={}\n", b(config.new_session)));
    s.push_str(&format!("flag die_with_parent={}\n", b(config.die_with_parent)));
    s.push_str(&format!("uid {}\n", resolved.sandbox_uid));
    s.push_str(&format!("gid {}\n", resolved.sandbox_gid));
    s.push_str(&format!("hostname {}\n", config.hostname.as_deref().unwrap_or("-")));
    s.push_str(&format!("chdir {}\n", config.chdir.as_deref().unwrap_or("-")));
    s.push_str(&format!("argv0 {}\n", config.argv0.as_deref().unwrap_or("-")));
    for op in &config.ops {
        push_op(&mut s, op);
    }
    s.push_str("end\n");
    s
}

#[allow(clippy::too_many_arguments)]
fn op_line(s: &mut String, name: &str, src: &str, dest: &str, fd: i32, flags: i32, perms: u16, size: u64) {
    s.push_str(&format!(
        "op {name} src={src} dest={dest} fd={fd} flags={flags} perms={perms} size={size}\n"
    ));
}

fn bind_name(kind: BindKind) -> &'static str {
    match kind {
        BindKind::ReadWrite => "BIND_MOUNT",
        BindKind::ReadOnly => "RO_BIND_MOUNT",
        BindKind::Dev => "DEV_BIND_MOUNT",
    }
}

fn push_op(s: &mut String, op: &SetupOp) {
    match op {
        SetupOp::Bind { src, dest, kind, missing } => {
            let flags = if matches!(missing, OnMissing::Skip) { 2 } else { 0 };
            op_line(s, bind_name(*kind), src.as_str(), dest.as_str(), -1, flags, 0, 0);
        }
        SetupOp::BindFd { fd, dest, kind } => {
            let src = format!("/proc/self/fd/{fd}");
            op_line(s, bind_name(*kind), &src, dest.as_str(), *fd, 0, 0, 0);
        }
        SetupOp::Overlay { lower, upper, dest } => {
            match upper {
                OverlayUpper::Persistent { upper: up, work } => {
                    op_line(s, "OVERLAY_MOUNT", up.as_str(), dest.as_str(), -1, 0, 0, 0);
                    op_line(s, "OVERLAY_SRC", work.as_str(), "-", -1, 0, 0, 0);
                }
                OverlayUpper::Tmp => op_line(s, "TMP_OVERLAY_MOUNT", "-", dest.as_str(), -1, 0, 0, 0),
                OverlayUpper::ReadOnly => op_line(s, "RO_OVERLAY_MOUNT", "-", dest.as_str(), -1, 0, 0, 0),
            }
            for l in lower.iter().rev() {
                op_line(s, "OVERLAY_SRC", l.as_str(), "-", -1, 0, 0, 0);
            }
        }
        SetupOp::Proc { dest } => op_line(s, "MOUNT_PROC", "-", dest.as_str(), -1, 0, 0, 0),
        SetupOp::Dev { dest } => op_line(s, "MOUNT_DEV", "-", dest.as_str(), -1, 0, 0, 0),
        SetupOp::Tmpfs { dest, perms, size } => {
            op_line(s, "MOUNT_TMPFS", "-", dest.as_str(), -1, 0, perms.bits(), size.unwrap_or(0));
        }
        SetupOp::Mqueue { dest } => op_line(s, "MOUNT_MQUEUE", "-", dest.as_str(), -1, 0, 0, 0),
        SetupOp::Dir { dest, perms } => op_line(s, "MAKE_DIR", "-", dest.as_str(), -1, 0, perms.bits(), 0),
        SetupOp::File { fd, dest, perms } => op_line(s, "MAKE_FILE", "-", dest.as_str(), *fd, 0, perms.bits(), 0),
        SetupOp::BindData { fd, dest, kind, perms } => {
            let name = if matches!(kind, BindKind::ReadOnly) { "MAKE_RO_BIND_FILE" } else { "MAKE_BIND_FILE" };
            op_line(s, name, "-", dest.as_str(), *fd, 0, perms.bits(), 0);
        }
        SetupOp::Symlink { target, dest } => {
            op_line(s, "MAKE_SYMLINK", target.as_str(), dest.as_str(), -1, 0, 0, 0);
        }
        SetupOp::RemountRo { dest } => op_line(s, "REMOUNT_RO_NO_RECURSIVE", "-", dest.as_str(), -1, 0, 0, 0),
        SetupOp::Chmod { perms, dest } => op_line(s, "CHMOD", "-", dest.as_str(), -1, 1, perms.bits(), 0),
    }
}

/// Comparable lines: trim, drop blanks, and drop C's `SET_HOSTNAME` op (hostname
/// is compared via the header line, since bwrap-rs keeps it as a field).
fn normalize(dump: &str) -> Vec<String> {
    dump.lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        .filter(|l| !l.starts_with("op SET_HOSTNAME"))
        .map(String::from)
        .collect()
}

fn diff(ours: &[String], theirs: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..ours.len().max(theirs.len()) {
        let a = ours.get(i).map(String::as_str).unwrap_or("<none>");
        let t = theirs.get(i).map(String::as_str).unwrap_or("<none>");
        if a != t {
            out.push(format!("[{i}] bwrap-rs={a:?}  C={t:?}"));
        }
    }
    out
}
