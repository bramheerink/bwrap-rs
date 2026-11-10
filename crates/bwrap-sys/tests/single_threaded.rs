//! Tests that need a single-threaded process: clone, fork, seccomp and
//! mount_setattr. Runs without libtest's harness (`harness = false`), so
//! `main` is the only thread.
//!
//! Each test does its real work in a child process and reports through the
//! exit code, so the test runner itself stays untouched by namespaces or
//! seccomp. Tests that need user namespaces report SKIP when the
//! environment forbids them (e.g. nested in another sandbox).

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bwrap_sys::ForkError;
use bwrap_sys::mount_attr::{MountAttrFlags, Recursion, mount_setattr};
use bwrap_sys::process::{clone_into_namespaces, fork_single_threaded};
use bwrap_sys::seccomp::Program;
use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::libc;
use nix::mount::{MsFlags, mount};
use nix::sched::CloneFlags;
use nix::sys::stat::Mode;
use nix::sys::statvfs::{FsFlags, statvfs};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, getcwd};

enum Outcome {
    Pass,
    Skip(String),
    Fail(String),
}

/// Exit codes from children. 0 = pass, anything else names a failed step.
const SKIP_EXIT: i32 = 77;

fn wait_child(child: Pid) -> Result<i32, String> {
    match waitpid(child, None) {
        Ok(WaitStatus::Exited(_, code)) => Ok(code),
        Ok(other) => Err(format!("child ended abnormally: {other:?}")),
        Err(e) => Err(format!("waitpid: {e}")),
    }
}

fn exit_child(code: i32) -> ! {
    // A normal exit, so that atexit handlers run in the child: under
    // `cargo llvm-cov` that is what writes the child's coverage data. Stdout is
    // line-buffered and flushed after every line in the parent, so there is no
    // buffered text to duplicate. (`exit_immediately` is tested separately.)
    std::process::exit(code)
}

fn from_child_code(code: i32, steps: &[&str]) -> Outcome {
    match code {
        0 => Outcome::Pass,
        SKIP_EXIT => Outcome::Skip("user namespaces unavailable in this environment".into()),
        n => {
            let step = usize::try_from(n - 1).ok().and_then(|i| steps.get(i));
            Outcome::Fail(format!(
                "child failed at step {n} ({})",
                step.unwrap_or(&"?")
            ))
        }
    }
}

fn test_fork_works() -> Outcome {
    match fork_single_threaded() {
        Ok(ForkResult::Child) => exit_child(0),
        Ok(ForkResult::Parent { child }) => match wait_child(child) {
            Ok(0) => Outcome::Pass,
            Ok(n) => Outcome::Fail(format!("child exited {n}")),
            Err(e) => Outcome::Fail(e),
        },
        Err(e) => Outcome::Fail(format!("fork: {e}")),
    }
}

fn test_clone_userns() -> Outcome {
    const STEPS: &[&str] = &["user namespace differs from parent's"];
    let parent_ns = std::fs::read_link("/proc/self/ns/user").ok();
    match clone_into_namespaces(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS) {
        Ok(ForkResult::Child) => {
            let child_ns = std::fs::read_link("/proc/self/ns/user").ok();
            exit_child(if child_ns.is_some() && child_ns != parent_ns {
                0
            } else {
                1
            })
        }
        Ok(ForkResult::Parent { child }) => match wait_child(child) {
            Ok(code) => from_child_code(code, STEPS),
            Err(e) => Outcome::Fail(e),
        },
        Err(ForkError::Sys(Errno::EPERM | Errno::ENOSPC | Errno::EINVAL | Errno::EUSERS)) => {
            Outcome::Skip("clone(CLONE_NEWUSER) not permitted here".into())
        }
        Err(e) => Outcome::Fail(format!("clone: {e}")),
    }
}

/// Errno the test filter returns. Deliberately unusual, so a stale errno left
/// over from earlier code can never make the check pass by accident.
const FILTER_ERRNO: Errno = Errno::EXFULL;

/// BPF: `getcwd()` -> EXFULL, everything else allowed.
///
/// `getcwd` rather than e.g. `getppid`: glibc treats `getppid` as unable to
/// fail and never sets errno for it, so a filtered `getppid` cannot be told
/// apart reliably.
fn deny_getcwd_program() -> Program {
    fn insn(code: u32, jt: u8, jf: u8, k: u32) -> [u8; 8] {
        let code = u16::try_from(code).expect("BPF opcode fits u16");
        let mut b = [0u8; 8];
        b[0..2].copy_from_slice(&code.to_ne_bytes());
        b[2] = jt;
        b[3] = jf;
        b[4..8].copy_from_slice(&k.to_ne_bytes());
        b
    }
    let nr = u32::try_from(libc::SYS_getcwd).expect("syscall nr fits u32");
    let errno = u32::try_from(FILTER_ERRNO as i32).expect("errno fits u32");
    let mut bytes = Vec::new();
    // A = seccomp_data.nr (offset 0)
    bytes.extend(insn(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0));
    // if A == SYS_getcwd goto deny else goto allow
    bytes.extend(insn(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 1, nr));
    bytes.extend(insn(
        libc::BPF_RET | libc::BPF_K,
        0,
        0,
        libc::SECCOMP_RET_ERRNO | errno,
    ));
    bytes.extend(insn(
        libc::BPF_RET | libc::BPF_K,
        0,
        0,
        libc::SECCOMP_RET_ALLOW,
    ));
    Program::from_bytes(&bytes).expect("valid framing")
}

fn test_seccomp_install() -> Outcome {
    const STEPS: &[&str] = &[
        "PR_SET_NO_NEW_PRIVS",
        "install filter",
        "getcwd should fail with the filter errno",
        "other syscalls still allowed",
    ];
    let program = deny_getcwd_program();
    match fork_single_threaded() {
        Ok(ForkResult::Child) => {
            if nix::sys::prctl::set_no_new_privs().is_err() {
                exit_child(1);
            }
            if program.install().is_err() {
                exit_child(2);
            }
            Errno::clear();
            match getcwd() {
                Err(e) if e == FILTER_ERRNO => {}
                other => {
                    eprintln!("  getcwd() = {other:?}, expected Err({FILTER_ERRNO:?})");
                    exit_child(3);
                }
            }
            if nix::unistd::getpid().as_raw() <= 0 {
                exit_child(4);
            }
            exit_child(0)
        }
        Ok(ForkResult::Parent { child }) => match wait_child(child) {
            Ok(code) => from_child_code(code, STEPS),
            Err(e) => Outcome::Fail(e),
        },
        Err(e) => Outcome::Fail(format!("fork: {e}")),
    }
}

fn mount_setattr_child(dir: &Path) -> i32 {
    // Keep our mounts from propagating anywhere, as bwrap does.
    if mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_SLAVE | MsFlags::MS_REC,
        None::<&str>,
    )
    .is_err()
    {
        return 1;
    }
    if mount(Some(dir), dir, None::<&str>, MsFlags::MS_BIND, None::<&str>).is_err() {
        return 2;
    }
    let Ok(before) = statvfs(dir) else { return 3 };
    if before.flags().contains(FsFlags::ST_RDONLY) {
        return 3;
    }
    let Ok(fd) = open(dir, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty()) else {
        return 4;
    };
    let set = MountAttrFlags::RDONLY | MountAttrFlags::NOSUID | MountAttrFlags::NODEV;
    match mount_setattr(
        fd.as_fd(),
        Recursion::ThisMountOnly,
        set,
        MountAttrFlags::empty(),
    ) {
        Ok(()) => {}
        Err(Errno::ENOSYS) => return SKIP_EXIT,
        Err(_) => return 5,
    }
    let Ok(after) = statvfs(dir) else { return 6 };
    let want = FsFlags::ST_RDONLY | FsFlags::ST_NOSUID | FsFlags::ST_NODEV;
    if after.flags().contains(want) { 0 } else { 6 }
}

fn test_mount_setattr() -> Outcome {
    const STEPS: &[&str] = &[
        "make / MS_SLAVE|MS_REC",
        "bind mount test dir",
        "statvfs before (must be rw)",
        "open O_PATH",
        "mount_setattr",
        "statvfs after (must be ro,nosuid,nodev)",
    ];
    let dir: PathBuf = std::env::temp_dir().join(format!("bwrap-sys-test-{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Outcome::Fail(format!("create {}: {e}", dir.display()));
    }
    let outcome = match clone_into_namespaces(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS) {
        Ok(ForkResult::Child) => exit_child(mount_setattr_child(&dir)),
        Ok(ForkResult::Parent { child }) => match wait_child(child) {
            Ok(SKIP_EXIT) => Outcome::Skip("mount_setattr not supported (ENOSYS)".into()),
            Ok(code) => from_child_code(code, STEPS),
            Err(e) => Outcome::Fail(e),
        },
        Err(ForkError::Sys(Errno::EPERM | Errno::ENOSPC | Errno::EINVAL | Errno::EUSERS)) => {
            Outcome::Skip("clone(CLONE_NEWUSER) not permitted here".into())
        }
        Err(e) => Outcome::Fail(format!("clone: {e}")),
    };
    let _ = std::fs::remove_dir(&dir);
    outcome
}

/// Run `child` in a fresh user+mount namespace and map its exit code.
fn in_userns(steps: &[&str], child: impl FnOnce() -> i32) -> Outcome {
    match clone_into_namespaces(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS) {
        Ok(ForkResult::Child) => exit_child(child()),
        Ok(ForkResult::Parent { child }) => match wait_child(child) {
            Ok(SKIP_EXIT) => Outcome::Skip("kernel feature not supported (ENOSYS)".into()),
            Ok(code) => from_child_code(code, steps),
            Err(e) => Outcome::Fail(e),
        },
        Err(ForkError::Sys(Errno::EPERM | Errno::ENOSPC | Errno::EINVAL | Errno::EUSERS)) => {
            Outcome::Skip("clone(CLONE_NEWUSER) not permitted here".into())
        }
        Err(e) => Outcome::Fail(format!("clone: {e}")),
    }
}

fn test_clone_many_namespaces() -> Outcome {
    const STEPS: &[&str] = &["uts ns unchanged", "ipc ns unchanged"];
    let uts = std::fs::read_link("/proc/self/ns/uts").ok();
    let ipc = std::fs::read_link("/proc/self/ns/ipc").ok();
    match clone_into_namespaces(
        CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC,
    ) {
        Ok(ForkResult::Child) => {
            if std::fs::read_link("/proc/self/ns/uts").ok() == uts {
                exit_child(1);
            }
            if std::fs::read_link("/proc/self/ns/ipc").ok() == ipc {
                exit_child(2);
            }
            exit_child(0)
        }
        Ok(ForkResult::Parent { child }) => match wait_child(child) {
            Ok(code) => from_child_code(code, STEPS),
            Err(e) => Outcome::Fail(e),
        },
        Err(ForkError::Sys(Errno::EPERM | Errno::ENOSPC | Errno::EINVAL | Errno::EUSERS)) => {
            Outcome::Skip("clone(CLONE_NEWUSER) not permitted here".into())
        }
        Err(e) => Outcome::Fail(format!("clone: {e}")),
    }
}

fn test_fork_exit_status_and_pid() -> Outcome {
    match fork_single_threaded() {
        Ok(ForkResult::Child) => bwrap_sys::process::exit_immediately(42),
        Ok(ForkResult::Parent { child }) => {
            if child.as_raw() <= 0 || child == nix::unistd::getpid() {
                return Outcome::Fail(format!("bad child pid {child}"));
            }
            match wait_child(child) {
                Ok(42) => Outcome::Pass,
                Ok(n) => Outcome::Fail(format!("exit status {n}, wanted 42")),
                Err(e) => Outcome::Fail(e),
            }
        }
        Err(e) => Outcome::Fail(format!("fork: {e}")),
    }
}

fn bad_filter() -> Program {
    // One instruction with an undefined opcode: framing is fine, the kernel
    // must reject it.
    let mut b = [0u8; 8];
    b[0..2].copy_from_slice(&0xffffu16.to_ne_bytes());
    Program::from_bytes(&b).expect("valid framing")
}

fn test_seccomp_install_errors() -> Outcome {
    const STEPS: &[&str] = &[
        "without no_new_privs must be EACCES",
        "bad BPF must be EINVAL",
        "stacked filters: getcwd still denied",
        "stacked filters: install failed",
        "PR_SET_NO_NEW_PRIVS",
    ];
    match fork_single_threaded() {
        Ok(ForkResult::Child) => {
            // Without PR_SET_NO_NEW_PRIVS, installing a filter is refused with
            // EACCES for an unprivileged process. But a process that already has
            // NO_NEW_PRIVS set (e.g. inside an outer sandbox) or CAP_SYS_ADMIN
            // may succeed, so accept Ok too; only a different errno is wrong.
            let r = deny_getcwd_program().install();
            if !matches!(r, Ok(()) | Err(Errno::EACCES)) {
                eprintln!("  install without nnp = {r:?}");
                exit_child(1);
            }
            if nix::sys::prctl::set_no_new_privs().is_err() {
                exit_child(5);
            }
            let r = bad_filter().install();
            if r != Err(Errno::EINVAL) {
                eprintln!("  bad install = {r:?}");
                exit_child(2);
            }
            // Filters stack: install the same deny filter twice.
            if deny_getcwd_program().install().is_err() || deny_getcwd_program().install().is_err()
            {
                exit_child(4);
            }
            if getcwd() != Err(FILTER_ERRNO) {
                exit_child(3);
            }
            exit_child(0)
        }
        Ok(ForkResult::Parent { child }) => match wait_child(child) {
            Ok(code) => from_child_code(code, STEPS),
            Err(e) => Outcome::Fail(e),
        },
        Err(e) => Outcome::Fail(format!("fork: {e}")),
    }
}

fn setattr_flags(path: &Path) -> Option<FsFlags> {
    statvfs(path).ok().map(|s| s.flags())
}

fn mount_attr_child(dir: &Path) -> i32 {
    let sub = dir.join("sub");
    if std::fs::create_dir_all(&sub).is_err() {
        return 1;
    }
    if mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_SLAVE | MsFlags::MS_REC,
        None::<&str>,
    )
    .is_err()
    {
        return 1;
    }
    // Two stacked bind mounts: dir, and sub below it.
    for p in [dir, sub.as_path()] {
        if mount(Some(p), p, None::<&str>, MsFlags::MS_BIND, None::<&str>).is_err() {
            return 2;
        }
    }
    let open_path = |p: &Path| open(p, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty());
    let (Ok(top), Ok(low)) = (open_path(dir), open_path(&sub)) else {
        return 3;
    };

    // ThisMountOnly must not touch the mount below.
    match mount_setattr(
        top.as_fd(),
        Recursion::ThisMountOnly,
        MountAttrFlags::NOEXEC,
        MountAttrFlags::empty(),
    ) {
        Ok(()) => {}
        Err(Errno::ENOSYS) => return SKIP_EXIT,
        Err(_) => return 4,
    }
    let (Some(t), Some(s)) = (setattr_flags(dir), setattr_flags(&sub)) else {
        return 5;
    };
    if !t.contains(FsFlags::ST_NOEXEC) || s.contains(FsFlags::ST_NOEXEC) {
        return 5;
    }

    // Recursive must reach the submount too.
    if mount_setattr(
        top.as_fd(),
        Recursion::Recursive,
        MountAttrFlags::RDONLY | MountAttrFlags::NODEV,
        MountAttrFlags::empty(),
    )
    .is_err()
    {
        return 6;
    }
    let Some(s) = setattr_flags(&sub) else {
        return 7;
    };
    if !s.contains(FsFlags::ST_RDONLY | FsFlags::ST_NODEV) || s.contains(FsFlags::ST_NOEXEC) {
        return 7;
    }

    // `clear` removes an attribute again.
    if mount_setattr(
        low.as_fd(),
        Recursion::ThisMountOnly,
        MountAttrFlags::empty(),
        MountAttrFlags::RDONLY,
    )
    .is_err()
    {
        return 8;
    }
    match setattr_flags(&sub) {
        Some(f) if !f.contains(FsFlags::ST_RDONLY) && f.contains(FsFlags::ST_NODEV) => {}
        _ => return 8,
    }
    0
}

fn test_mount_setattr_combos() -> Outcome {
    const STEPS: &[&str] = &[
        "setup",
        "bind mounts",
        "open O_PATH",
        "noexec on top",
        "ThisMountOnly leaked / not applied",
        "recursive call",
        "recursive did not reach submount",
        "clear ro",
    ];
    let dir: PathBuf = std::env::temp_dir().join(format!("bwrap-sys-attr-{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Outcome::Fail(format!("create {}: {e}", dir.display()));
    }
    let outcome = in_userns(STEPS, || mount_attr_child(&dir));
    let _ = std::fs::remove_dir_all(&dir);
    outcome
}

fn test_mount_setattr_non_mountpoint() -> Outcome {
    in_userns(&["non-mount-root accepted"], || {
        let Ok(fd) = open("/proc/self/ns", OFlag::O_PATH, Mode::empty()) else {
            return 1;
        };
        match mount_setattr(
            fd.as_fd(),
            Recursion::ThisMountOnly,
            MountAttrFlags::RDONLY,
            MountAttrFlags::empty(),
        ) {
            Err(Errno::EINVAL) => 0,
            Err(Errno::ENOSYS) => SKIP_EXIT,
            _ => 1,
        }
    })
}

type Test = (&'static str, fn() -> Outcome);

fn main() -> ExitCode {
    let tests: &[Test] = &[
        ("fork_single_threaded", test_fork_works),
        ("clone_into_namespaces(NEWUSER|NEWNS)", test_clone_userns),
        ("seccomp::Program::install", test_seccomp_install),
        ("mount_setattr ro,nosuid,nodev", test_mount_setattr),
        ("clone with many namespaces", test_clone_many_namespaces),
        ("fork exit status and pid", test_fork_exit_status_and_pid),
        (
            "seccomp install errors and stacking",
            test_seccomp_install_errors,
        ),
        (
            "mount_setattr recursion and clear",
            test_mount_setattr_combos,
        ),
        (
            "mount_setattr on non-mountpoint",
            test_mount_setattr_non_mountpoint,
        ),
    ];
    let mut failed = 0;
    for (name, test) in tests {
        match test() {
            Outcome::Pass => println!("test {name} ... ok"),
            Outcome::Skip(why) => println!("test {name} ... SKIP ({why})"),
            Outcome::Fail(why) => {
                println!("test {name} ... FAILED: {why}");
                failed += 1;
            }
        }
    }
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
