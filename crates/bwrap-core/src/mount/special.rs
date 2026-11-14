//! Self-contained mount primitives: tmpfs, mqueue, and non-recursive
//! remount-read-only. Mirror bubblewrap's `setup_op_tmpfs_mount`, the
//! `SETUP_MOUNT_MQUEUE` case and `SETUP_REMOUNT_RO_NO_RECURSIVE`.
//!
//! `--proc` and `--dev` live with the `setup_newroot` executor (module 11),
//! because they bind their sources from `/oldroot` and reopen the destination
//! from `/newroot` — state that only exists after the pivot.

use std::ffi::CString;
use std::os::fd::BorrowedFd;

use nix::mount::{MsFlags, mount};
use nix::sys::stat::Mode;

use super::bind::{BindResult, bind_mount_fd};
use super::flags::BindOptions;
use crate::error::{Error, MountContext, Result};
use crate::fs::open::proc_self_fd;

/// `MAX_TMPFS_BYTES`: `SIZE_MAX >> 1` on the 64-bit targets we support. Public so
/// the CLI parser rejects an over-large `--size` with the same limit this mount
/// layer enforces (one source of truth; they must not drift).
pub const MAX_TMPFS_BYTES: u64 = u64::MAX >> 1;

fn dest_path(dest: BorrowedFd<'_>) -> CString {
    // /proc/self/fd/N — ASCII, never contains NUL.
    CString::new(proc_self_fd(dest)).expect("fd path is NUL-free")
}

/// C `printf("%#o")`: octal with a forced leading `0`, except `0` itself stays
/// `"0"`. (Rust's `{:#o}` would produce a `0o` prefix, which the kernel would
/// reject in the mount options.)
fn octal_hash(v: u16) -> String {
    if v == 0 {
        "0".to_string()
    } else {
        format!("0{v:o}")
    }
}

/// Mount a tmpfs on `dest` with `perms` and optional `size`
/// (`setup_op_tmpfs_mount`). Always `MS_NOSUID | MS_NODEV`. `dest_display` is
/// the sandbox-relative path used in the error message.
pub fn mount_tmpfs(
    dest: BorrowedFd<'_>,
    perms: Mode,
    size: Option<u64>,
    dest_display: &str,
    file_label: Option<&str>,
) -> Result<()> {
    if let Some(s) = size
        && s > MAX_TMPFS_BYTES
    {
        return Err(Error::invalid(format!(
            "Specified tmpfs size too large ({s} > {MAX_TMPFS_BYTES})"
        )));
    }
    // perms is a Mode; take its low bits for the %#o rendering.
    let mode_bits = u16::try_from(perms.bits() & 0o7777).unwrap_or(0);
    let data = match size {
        Some(s) => format!("mode={},size={s}", octal_hash(mode_bits)),
        None => format!("mode={}", octal_hash(mode_bits)),
    };
    // Fold in the SELinux file label as a `context="…"` option (bwrap's
    // label_mount); without `--file-label` the options are unchanged.
    let data = crate::selinux::label_mount(Some(&data), file_label).unwrap_or(data);
    let data = CString::new(data).map_err(|_| Error::invalid("tmpfs options contain a NUL"))?;
    mount(
        Some(c"tmpfs"),
        dest_path(dest).as_c_str(),
        Some(c"tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(data.as_c_str()),
    )
    .with_mount_context(|| format!("Can't mount tmpfs on {dest_display}"))
}

/// Mount a POSIX message-queue fs on `dest` (`SETUP_MOUNT_MQUEUE`).
/// `dest_display` is the sandbox-relative path used in the error message.
pub fn mount_mqueue(dest: BorrowedFd<'_>, dest_display: &str) -> Result<()> {
    mount(
        Some(c"mqueue"),
        dest_path(dest).as_c_str(),
        Some(c"mqueue"),
        MsFlags::empty(),
        None::<&std::ffi::CStr>,
    )
    .with_mount_context(|| format!("Can't mount mqueue on {dest_display}"))
}

/// Remount the existing mount at `dest` read-only, non-recursively
/// (`SETUP_REMOUNT_RO_NO_RECURSIVE`): re-apply `ro,nosuid,nodev` to that one
/// mount with no source bind. The executor prepends `Can't remount readonly on
/// <dest>:` to the returned [`BindError`], matching bwrap.
pub fn remount_ro(dest: BorrowedFd<'_>) -> BindResult {
    bind_mount_fd(
        None,
        dest,
        BindOptions {
            readonly: true,
            devices: false,
            recursive: false,
            fail_open: false,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octal_hash_matches_printf_hash_o() {
        assert_eq!(octal_hash(0), "0");
        assert_eq!(octal_hash(0o755), "0755");
        assert_eq!(octal_hash(0o700), "0700");
        assert_eq!(octal_hash(0o4755), "04755");
    }

    #[test]
    fn tmpfs_size_limit_is_enforced() {
        // A plain fd (stdin) is enough to reach the size check before mount.
        use std::os::fd::AsFd;
        let e = mount_tmpfs(
            std::io::stdin().as_fd(),
            Mode::from_bits_truncate(0o755),
            Some(u64::MAX),
            "/tmp",
            None,
        )
        .unwrap_err();
        assert!(e.to_string().starts_with("Specified tmpfs size too large"));
    }
}
