//! SELinux labelling (`--exec-label`, `--file-label`, `context=` mount option).
//!
//! bubblewrap uses libselinux (`is_selinux_enabled`, `security_check_context`,
//! `setexeccon`, `setfscreatecon`, `label_mount`). To stay a pure Rust port
//! (std + nix only, no `unsafe`), these are reimplemented against the same
//! kernel interfaces libselinux uses: the `selinuxfs` mount (`/sys/fs/selinux`)
//! and the process attribute files (`/proc/self/attr/*`).
//!
//! Whether SELinux is enabled is a property of the host kernel, not of the
//! filesystem the sandbox happens to see. It is detected once, before the mount
//! namespace is rearranged, and that answer holds for the rest of the process
//! (libselinux likewise initialises this state at load time).

use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;

use nix::errno::Errno;

use crate::error::{Error, Result};

const SELINUX_FS: &str = "/sys/fs/selinux";

/// Append `context="LABEL"` to a mount options string (bwrap's `label_mount`).
/// Pure: `mount_label` present adds the `context=` clause (quoted), otherwise
/// the options pass through unchanged. `None`/`None` yields `None`.
pub fn label_mount(opt: Option<&str>, mount_label: Option<&str>) -> Option<String> {
    match (mount_label, opt) {
        (Some(label), Some(opt)) => Some(format!("{opt},context=\"{label}\"")),
        (Some(label), None) => Some(format!("context=\"{label}\"")),
        (None, Some(opt)) => Some(opt.to_string()),
        (None, None) => None,
    }
}

/// Whether SELinux is enabled on the host (libselinux's `is_selinux_enabled`).
///
/// The first call detects it and every later call returns that answer, so it must
/// first run before the sandbox's root is built. [`crate::run::ExecutionPlan`]
/// guarantees that for any configuration carrying a label.
pub fn is_selinux_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(detect_selinux)
}

/// True iff a `selinuxfs` filesystem is mounted, found by scanning
/// `/proc/self/mountinfo`, which is how libselinux finds the mountpoint.
fn detect_selinux() -> bool {
    match std::fs::read("/proc/self/mountinfo") {
        // The fstype is the field just after the " - " separator on each line.
        Ok(data) => data
            .split(|&b| b == b'\n')
            .any(|line| find_fstype(line) == Some(b"selinuxfs".as_slice())),
        Err(_) => false,
    }
}

/// Extract the filesystem type from one `/proc/self/mountinfo` line: the token
/// immediately after the ` - ` separator.
fn find_fstype(line: &[u8]) -> Option<&[u8]> {
    // Find the " - " separator, then take the next whitespace-delimited token.
    let sep = line.windows(3).position(|w| w == b" - ")?;
    let rest = &line[sep + 3..];
    let start = rest.iter().position(|&b| b != b' ')?;
    let rest = &rest[start..];
    let end = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Decision core of `die_unless_label_valid`, split out for testing: with
/// SELinux disabled, labelling is unsupported (bwrap's `die`, no errno); with it
/// enabled, an invalid context errors with the errno (`die_with_error`, so the
/// text gains `: <strerror>`). Returns bwrap's exact messages.
fn label_error(enabled: bool, check: std::result::Result<(), Errno>, label: &OsStr) -> Result<()> {
    if !enabled {
        return Err(Error::invalid("labeling not supported on this system"));
    }
    check.map_err(|errno| Error::Sys {
        message: format!("invalid label {}", label.to_string_lossy()).into(),
        errno,
    })
}

/// Validate a label the way bwrap's `die_unless_label_valid` does: error if
/// SELinux is off ("labeling not supported on this system") or the context is
/// invalid ("invalid label <label>: <strerror>").
pub fn die_unless_label_valid(label: &OsStr) -> Result<()> {
    let enabled = is_selinux_enabled();
    let check = if enabled {
        check_context(label)
    } else {
        Ok(())
    };
    label_error(enabled, check, label)
}

/// libselinux's `security_check_context`: a context is valid iff it can be
/// written to `/sys/fs/selinux/context`; the errno on failure is reported.
fn check_context(label: &OsStr) -> std::result::Result<(), Errno> {
    write_attr(&format!("{SELINUX_FS}/context"), label.as_bytes())
}

/// A requested label is applied or the launch fails: it is never skipped. The
/// parser already refuses labels on a system without SELinux, so this only fires
/// for a configuration that bypassed that validation.
fn require_labeling(enabled: bool) -> Result<()> {
    if enabled {
        Ok(())
    } else {
        Err(Error::invalid("labeling not supported on this system"))
    }
}

/// Set the exec context for the next `execve` (bwrap's `label_exec` /
/// libselinux `setexeccon`): write the label to `/proc/self/attr/exec`. A no-op
/// only when no label was requested.
pub fn label_exec(label: Option<&OsStr>) -> Result<()> {
    let Some(label) = label else { return Ok(()) };
    require_labeling(is_selinux_enabled())?;
    write_attr("/proc/self/attr/exec", label.as_bytes()).map_err(|errno| Error::Sys {
        message: format!("label_exec {}", label.to_string_lossy()).into(),
        errno,
    })
}

/// Set the file-creation context (bwrap's `label_create_file` / libselinux
/// `setfscreatecon`): write the label to `/proc/self/attr/fscreate`. A no-op
/// only when no label was requested.
pub fn label_create_file(label: Option<&OsStr>) -> Result<()> {
    let Some(label) = label else { return Ok(()) };
    require_labeling(is_selinux_enabled())?;
    write_attr("/proc/self/attr/fscreate", label.as_bytes()).map_err(|errno| Error::Sys {
        message: format!("label_create_file {}", label.to_string_lossy()).into(),
        errno,
    })
}

/// Write a context string to a SELinux attribute/selinuxfs file, returning the
/// errno on failure.
fn write_attr(path: &str, value: &[u8]) -> std::result::Result<(), nix::errno::Errno> {
    use nix::errno::Errno;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| Errno::from_raw(e.raw_os_error().unwrap_or(0)))?;
    // libselinux writes the context with its trailing NUL (`strlen + 1`). We
    // must do the same: an empty label then becomes a lone `\0`, which the
    // kernel rejects with EINVAL ("invalid label : Invalid argument"), matching
    // C — whereas writing zero bytes would be silently accepted.
    let mut buf = Vec::with_capacity(value.len() + 1);
    buf.extend_from_slice(value);
    buf.push(0);
    f.write_all(&buf)
        .map_err(|e| Errno::from_raw(e.raw_os_error().unwrap_or(0)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_mount_builds_context_clause() {
        assert_eq!(label_mount(None, None), None);
        assert_eq!(
            label_mount(Some("mode=0755"), None).as_deref(),
            Some("mode=0755")
        );
        assert_eq!(
            label_mount(None, Some("system_u:object_r:tmp_t:s0")).as_deref(),
            Some("context=\"system_u:object_r:tmp_t:s0\"")
        );
        assert_eq!(
            label_mount(Some("mode=0755"), Some("system_u:object_r:tmp_t:s0")).as_deref(),
            Some("mode=0755,context=\"system_u:object_r:tmp_t:s0\"")
        );
    }

    #[test]
    fn label_error_texts_match_bwrap() {
        assert!(label_error(true, Ok(()), OsStr::new("x")).is_ok());
        assert_eq!(
            label_error(false, Ok(()), OsStr::new("x"))
                .unwrap_err()
                .to_string(),
            "labeling not supported on this system"
        );
        // die_with_error appends ": <strerror>"; EINVAL is "Invalid argument".
        assert_eq!(
            label_error(true, Err(Errno::EINVAL), OsStr::new("sys_u:obj_r:t:s0"))
                .unwrap_err()
                .to_string(),
            "invalid label sys_u:obj_r:t:s0: Invalid argument"
        );
    }

    #[test]
    fn requested_label_is_never_skipped() {
        assert!(require_labeling(true).is_ok());
        assert_eq!(
            require_labeling(false).unwrap_err().to_string(),
            "labeling not supported on this system"
        );
    }

    #[test]
    fn no_label_requested_is_a_no_op() {
        assert!(label_exec(None).is_ok());
        assert!(label_create_file(None).is_ok());
    }

    #[test]
    fn enabled_state_is_stable_across_calls() {
        assert_eq!(is_selinux_enabled(), is_selinux_enabled());
    }

    #[test]
    fn find_fstype_parses_mountinfo_line() {
        let line = b"36 35 0:33 / /sys/fs/selinux rw,relatime shared:9 - selinuxfs selinuxfs rw";
        assert_eq!(find_fstype(line), Some(b"selinuxfs".as_slice()));
        let tmpfs = b"24 30 0:22 / /dev/shm rw,nosuid shared:4 - tmpfs tmpfs rw";
        assert_eq!(find_fstype(tmpfs), Some(b"tmpfs".as_slice()));
        assert_eq!(find_fstype(b"garbage with no separator"), None);
    }
}
