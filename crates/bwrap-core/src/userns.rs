//! User-namespace setup: overflow ids, the uid/gid maps, `setgroups=deny`,
//! and disabling further user namespaces.
//!
//! Mirrors bwrap's `read_overflowids`, `write_uid_gid_map`, the
//! `--unshare-user-try` probe and the `--disable-userns` sysctl write. All of
//! this is Linux kernel API, not distro-specific; the probes exist precisely
//! so the same binary behaves correctly on Debian, RHEL, etc.

use std::fs;
use std::os::fd::{AsFd, BorrowedFd};

use nix::errno::Errno;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;

use crate::error::{Context, Error, Result};
use crate::types::UsernsProbe;

/// The kernel overflow uid/gid, used as the unmapped identity in a map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverflowIds {
    /// `/proc/sys/kernel/overflowuid`.
    pub uid: u32,
    /// `/proc/sys/kernel/overflowgid`.
    pub gid: u32,
}

impl OverflowIds {
    /// Read and parse the overflow ids (bwrap's `read_overflowids`).
    ///
    /// A value of 0 is rejected, matching bwrap: 0 means the file could not be
    /// parsed, and mapping to uid 0 would be wrong.
    pub fn read() -> Result<Self> {
        Ok(Self {
            uid: read_overflow("/proc/sys/kernel/overflowuid")?,
            gid: read_overflow("/proc/sys/kernel/overflowgid")?,
        })
    }
}

fn read_overflow(path: &'static str) -> Result<u32> {
    let data = fs::read_to_string(path).with_context(|| format!("Can't read {path}"))?;
    // bwrap uses strtol, which stops at the trailing newline.
    match data.trim().parse::<u32>() {
        Ok(v) if v != 0 => Ok(v),
        _ => Err(Error::invalid(format!("Can't parse {path}"))),
    }
}

/// The identity mapping to install into a user namespace.
#[derive(Debug, Clone, Copy)]
pub struct IdMap {
    /// uid inside the sandbox.
    pub sandbox_uid: u32,
    /// uid outside (the real uid).
    pub parent_uid: u32,
    /// gid inside the sandbox.
    pub sandbox_gid: u32,
    /// gid outside (the real gid).
    pub parent_gid: u32,
    /// Write `setgroups=deny` before the gid map.
    pub deny_groups: bool,
}

impl IdMap {
    /// The `uid_map` file contents (pure; bwrap's `uid_map` branch).
    pub fn uid_map_string(&self) -> String {
        single_map(self.sandbox_uid, self.parent_uid)
    }

    /// The `gid_map` file contents (pure; bwrap's `gid_map` branch).
    pub fn gid_map_string(&self) -> String {
        single_map(self.sandbox_gid, self.parent_gid)
    }

    /// Write our own maps under `/proc/self`, in the security-critical order
    /// **uid_map → setgroups=deny → gid_map** (bwrap's `write_uid_gid_map`).
    ///
    /// `setgroups` must be denied before the gid map is written, or an
    /// unprivileged user could use the gid map to gain group privileges. A
    /// missing `setgroups` file (kernel < 3.19, CVE-2014-8989) is tolerated.
    ///
    /// `proc_fd` is an `O_PATH` fd to `/proc` (bwrap keeps one open across the
    /// pivot so these writes still resolve afterwards). bwrap's only reachable
    /// callers write `self` (`pid == -1`); the port does too, so there is no
    /// target parameter.
    pub fn write(&self, proc_fd: BorrowedFd<'_>) -> Result<()> {
        let dir_fd = openat(proc_fd, "self", OFlag::O_PATH, Mode::empty())
            .context("open /proc/self failed")?;

        write_proc_file(dir_fd.as_fd(), "uid_map", self.uid_map_string().as_bytes())
            .context("setting up uid map")?;

        if self.deny_groups {
            match write_proc_file(dir_fd.as_fd(), "setgroups", b"deny\n") {
                Ok(()) => {}
                // No setgroups file: kernel < 3.19. Tolerated, as bwrap does.
                Err(Errno::ENOENT) => {}
                Err(e) => {
                    return Err(Error::Sys {
                        message: "error writing to setgroups".into(),
                        errno: e,
                    });
                }
            }
        }

        write_proc_file(dir_fd.as_fd(), "gid_map", self.gid_map_string().as_bytes())
            .context("setting up gid map")?;
        Ok(())
    }
}

/// A one-line `inside outside 1` id map (bwrap's single-entry `uid_map`/`gid_map`;
/// the `map_root` overflow-entry variant had no reachable caller and was removed).
fn single_map(inside: u32, outside: u32) -> String {
    format!("{inside} {outside} 1\n")
}

fn write_proc_file(dir_fd: BorrowedFd<'_>, name: &str, data: &[u8]) -> nix::Result<()> {
    // bwrap's write_file_at opens O_RDWR | O_CLOEXEC.
    let fd = openat(
        dir_fd,
        name,
        OFlag::O_RDWR | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    crate::fs::io::write_all(fd.as_fd(), data)
}

/// Disable the creation of further user namespaces by writing `1` to
/// `/proc/sys/user/max_user_namespaces` (bwrap's `--disable-userns`).
///
/// Written relative to `proc_fd` so it resolves after the pivot. Must be done
/// before the nested userns is entered.
pub fn disable_user_namespaces(proc_fd: BorrowedFd<'_>) -> Result<()> {
    let fd = openat(
        proc_fd,
        "sys/user/max_user_namespaces",
        OFlag::O_WRONLY,
        Mode::empty(),
    )
    .context("cannot open /proc/sys/user/max_user_namespaces")?;
    crate::fs::io::write_all(fd.as_fd(), b"1").map_err(|errno| Error::Sys {
        message: "sysctl user.max_user_namespaces = 1".into(),
        errno,
    })
}

/// Reads `/proc` and `/sys` to answer the `--unshare-user-try` probe
/// (bwrap's checks in `main()`). The logic is kernel/distro-neutral.
#[derive(Debug, Default)]
pub struct SystemUsernsProbe;

impl UsernsProbe for SystemUsernsProbe {
    fn user_ns_supported(&self) -> bool {
        // bwrap: stat("/proc/self/ns/user") == 0.
        fs::metadata("/proc/self/ns/user").is_ok()
    }

    fn cgroup_ns_supported(&self) -> bool {
        // bwrap: stat("/proc/self/ns/cgroup") == 0.
        fs::metadata("/proc/self/ns/cgroup").is_ok()
    }

    fn unprivileged_userns_disabled(&self) -> bool {
        // RHEL7 module parameter: 'N' means disabled.
        if let Ok(s) = fs::read_to_string("/sys/module/user_namespace/parameters/enable")
            && s.starts_with('N')
        {
            return true;
        }
        // max_user_namespaces == 0 means disabled (Debian and others).
        if let Ok(s) = fs::read_to_string("/proc/sys/user/max_user_namespaces")
            && s.trim() == "0"
        {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_real_overflow_ids() {
        let ids = OverflowIds::read().expect("overflow ids readable on Linux");
        assert!(ids.uid != 0 && ids.gid != 0);
    }

    #[test]
    fn single_line_map() {
        let m = IdMap {
            sandbox_uid: 1000,
            parent_uid: 1001,
            sandbox_gid: 2000,
            parent_gid: 2001,
            deny_groups: true,
        };
        assert_eq!(m.uid_map_string(), "1000 1001 1\n");
        assert_eq!(m.gid_map_string(), "2000 2001 1\n");
    }

    #[test]
    fn probe_reports_userns_supported_on_this_host() {
        // This host has user namespaces (we run the sandbox on it).
        assert!(SystemUsernsProbe.user_ns_supported());
    }

    use std::os::fd::OwnedFd;
    use std::path::{Path, PathBuf};

    fn fake_proc(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bwrap-userns-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn open_dir(p: &Path) -> OwnedFd {
        nix::fcntl::open(
            p,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn id_map(deny_groups: bool) -> IdMap {
        IdMap {
            sandbox_uid: 1000,
            parent_uid: 1001,
            sandbox_gid: 2000,
            parent_gid: 2001,
            deny_groups,
        }
    }

    #[test]
    fn write_fills_all_three_files_in_a_fake_proc() {
        let proc = fake_proc("write");
        let me = proc.join("self");
        fs::create_dir_all(&me).unwrap();
        for f in ["uid_map", "gid_map", "setgroups"] {
            fs::write(me.join(f), b"").unwrap();
        }
        let fd = open_dir(&proc);
        id_map(true).write(fd.as_fd()).unwrap();
        assert_eq!(
            fs::read_to_string(me.join("uid_map")).unwrap(),
            "1000 1001 1\n"
        );
        assert_eq!(
            fs::read_to_string(me.join("gid_map")).unwrap(),
            "2000 2001 1\n"
        );
        assert_eq!(fs::read_to_string(me.join("setgroups")).unwrap(), "deny\n");
        let _ = fs::remove_dir_all(&proc);
    }

    #[test]
    fn write_skips_setgroups_when_allowed() {
        let proc = fake_proc("allow");
        let me = proc.join("self");
        fs::create_dir_all(&me).unwrap();
        fs::write(me.join("uid_map"), b"").unwrap();
        fs::write(me.join("gid_map"), b"").unwrap();
        fs::write(me.join("setgroups"), b"allow\n").unwrap();
        let fd = open_dir(&proc);
        id_map(false).write(fd.as_fd()).unwrap();
        assert_eq!(
            fs::read_to_string(me.join("uid_map")).unwrap(),
            "1000 1001 1\n"
        );
        // deny_groups == false: setgroups is left alone.
        assert_eq!(fs::read_to_string(me.join("setgroups")).unwrap(), "allow\n");
        let _ = fs::remove_dir_all(&proc);
    }

    #[test]
    fn missing_setgroups_file_is_tolerated() {
        let proc = fake_proc("nosetgroups");
        let me = proc.join("self");
        fs::create_dir_all(&me).unwrap();
        fs::write(me.join("uid_map"), b"").unwrap();
        fs::write(me.join("gid_map"), b"").unwrap();
        let fd = open_dir(&proc);
        id_map(true).write(fd.as_fd()).unwrap();
        assert_eq!(
            fs::read_to_string(me.join("gid_map")).unwrap(),
            "2000 2001 1\n"
        );
        let _ = fs::remove_dir_all(&proc);
    }

    #[test]
    fn write_errors_carry_bwrap_messages() {
        let proc = fake_proc("errors");
        let fd = open_dir(&proc);
        // No /proc/self at all.
        let e = id_map(true).write(fd.as_fd()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "open /proc/self failed: No such file or directory"
        );

        // uid_map missing: fails before touching setgroups or gid_map.
        let me = proc.join("self");
        fs::create_dir_all(&me).unwrap();
        fs::write(me.join("setgroups"), b"").unwrap();
        fs::write(me.join("gid_map"), b"").unwrap();
        let e = id_map(true).write(fd.as_fd()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "setting up uid map: No such file or directory"
        );
        assert_eq!(e.errno(), Some(Errno::ENOENT));
        assert_eq!(fs::read(me.join("setgroups")).unwrap(), b"");
        assert_eq!(fs::read(me.join("gid_map")).unwrap(), b"");

        // gid_map missing: uid map and setgroups were written first.
        fs::write(me.join("uid_map"), b"").unwrap();
        fs::remove_file(me.join("gid_map")).unwrap();
        let e = id_map(true).write(fd.as_fd()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "setting up gid map: No such file or directory"
        );
        assert_eq!(
            fs::read_to_string(me.join("uid_map")).unwrap(),
            "1000 1001 1\n"
        );
        assert_eq!(fs::read_to_string(me.join("setgroups")).unwrap(), "deny\n");
        let _ = fs::remove_dir_all(&proc);
    }

    #[test]
    fn setgroups_error_other_than_enoent_is_fatal() {
        let proc = fake_proc("sgerr");
        let me = proc.join("self");
        fs::create_dir_all(me.join("setgroups")).unwrap(); // a directory: EISDIR
        fs::write(me.join("uid_map"), b"").unwrap();
        fs::write(me.join("gid_map"), b"").unwrap();
        let fd = open_dir(&proc);
        let e = id_map(true).write(fd.as_fd()).unwrap_err();
        assert_eq!(e.to_string(), "error writing to setgroups: Is a directory");
        // gid_map must not have been written.
        assert_eq!(fs::read(me.join("gid_map")).unwrap(), b"");
        let _ = fs::remove_dir_all(&proc);
    }

    #[test]
    fn disable_userns_writes_one_to_the_sysctl() {
        let proc = fake_proc("sysctl");
        let dir = proc.join("sys/user");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("max_user_namespaces"), b"9\n").unwrap();
        let fd = open_dir(&proc);
        disable_user_namespaces(fd.as_fd()).unwrap();
        // O_WRONLY without O_TRUNC: "1" overwrites the first byte.
        assert_eq!(fs::read(dir.join("max_user_namespaces")).unwrap(), b"1\n");
        let _ = fs::remove_dir_all(&proc);
    }

    #[test]
    fn disable_userns_reports_open_failure() {
        let proc = fake_proc("sysctl-missing");
        let fd = open_dir(&proc);
        let e = disable_user_namespaces(fd.as_fd()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "cannot open /proc/sys/user/max_user_namespaces: No such file or directory"
        );
        let _ = fs::remove_dir_all(&proc);
    }

    #[test]
    fn disable_userns_reports_write_failure() {
        // /dev/full accepts the open and fails every write with ENOSPC.
        let proc = fake_proc("sysctl-full");
        let dir = proc.join("sys/user");
        fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink("/dev/full", dir.join("max_user_namespaces")).unwrap();
        let fd = open_dir(&proc);
        let e = disable_user_namespaces(fd.as_fd()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "sysctl user.max_user_namespaces = 1: No space left on device"
        );
        assert_eq!(e.errno(), Some(Errno::ENOSPC));
        let _ = fs::remove_dir_all(&proc);
    }

    #[test]
    fn write_proc_file_write_failure_is_returned() {
        let proc = fake_proc("full");
        std::os::unix::fs::symlink("/dev/full", proc.join("uid_map")).unwrap();
        let fd = open_dir(&proc);
        assert_eq!(
            write_proc_file(fd.as_fd(), "uid_map", b"x"),
            Err(Errno::ENOSPC)
        );
        let _ = fs::remove_dir_all(&proc);
    }

    #[test]
    fn probe_unprivileged_disabled_matches_files() {
        // Recompute the answer from the same two files, independently.
        let rhel = fs::read_to_string("/sys/module/user_namespace/parameters/enable")
            .is_ok_and(|s| s.starts_with('N'));
        let zero =
            fs::read_to_string("/proc/sys/user/max_user_namespaces").is_ok_and(|s| s.trim() == "0");
        assert_eq!(
            SystemUsernsProbe.unprivileged_userns_disabled(),
            rhel || zero
        );
    }
}
