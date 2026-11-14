// SPDX-License-Identifier: LGPL-2.0-or-later
// Ported from bubblewrap, Copyright (C) 2016 Alexander Larsson and contributors.
//! Bind mounts with `ro`/`nodev`/`nosuid` attributes, via `mount_setattr`
//! (Linux 5.12+) or the `/proc/self/mountinfo` + `MS_REMOUNT` fallback.
//!
//! Faithful port of bubblewrap's `bind_mount` / `bind_mount_fd` /
//! `mount_setattr_setup` / `mount_setattr_fallback` (`bind-mount.c`), including
//! the `bind_mount_result` error strings. The failing operation, path and
//! errno are preserved in [`BindError`]; the `setup_newroot` executor prepends
//! the caller's `Can't bind mount X on Y:` prefix, exactly as bwrap's
//! `die_with_bind_result` does.

use std::ffi::CString;
use std::fmt;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, Ordering};

use bwrap_sys::mount_attr::{MountAttrFlags, Recursion, mount_setattr};
use nix::errno::Errno;
use nix::fcntl::{OFlag, open, readlink};
use nix::mount::{MsFlags, mount};
use nix::sys::stat::Mode;

use super::flags::{BindOptions, remount_added_flags};
use super::mountinfo::parse_mountinfo;

/// Which bind step failed (bwrap's `bind_mount_result`). The `Display` of
/// [`BindError`] renders the matching `bind_mount_result_to_string` text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindErrorKind {
    /// `mount(2)` of the bind itself failed.
    Mount,
    /// `readlink(/proc/self/fd/N)` on the destination failed.
    ReadlinkDestProcFd,
    /// The destination was not found in the mount table (fallback).
    FindDestMount,
    /// Remounting the destination with the right flags failed (fallback).
    RemountDest,
    /// Remounting a submount failed (fallback).
    RemountSubmount,
    /// Opening the destination `O_PATH` fd failed.
    OpenFd,
    /// `mount_setattr(2)` failed.
    MountSetattr,
}

/// A bind-mount failure: the step, the path involved, and the errno. Renders
/// bwrap's `bind_mount_result_to_string` text (plus the errno, except for
/// `FindDestMount`, which upstream prints with `want_errno = false`).
#[derive(Debug)]
pub struct BindError {
    /// Which step failed.
    pub kind: BindErrorKind,
    /// The path bwrap would name in the message (may be a `/proc/self/fd/N`).
    pub failing_path: Option<Vec<u8>>,
    /// The errno, if the step set one.
    pub errno: Option<Errno>,
}

impl BindError {
    fn new(kind: BindErrorKind, path: &[u8], errno: Errno) -> Self {
        Self {
            kind,
            failing_path: Some(path.to_vec()),
            errno: Some(errno),
        }
    }

    /// The errno behind this failure, if any.
    pub fn errno(&self) -> Option<Errno> {
        self.errno
    }

    /// bwrap's `want_errno`: false only for `FindDestMount`.
    fn wants_errno(&self) -> bool {
        self.kind != BindErrorKind::FindDestMount
    }

    /// bwrap uses `mount_strerror` for the mount/remount failures, plain
    /// `strerror` otherwise.
    fn errno_text(&self, errno: Errno) -> String {
        match self.kind {
            BindErrorKind::Mount | BindErrorKind::RemountDest | BindErrorKind::RemountSubmount => {
                crate::error::mount_strerror(errno)
            }
            _ => bwrap_sys::strerror(errno),
        }
    }
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = self
            .failing_path
            .as_deref()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .unwrap_or_default();
        let s = match self.kind {
            BindErrorKind::Mount => "Unable to mount source on destination".to_string(),
            BindErrorKind::ReadlinkDestProcFd => {
                format!("readlink(/proc/self/fd/N) for \"{path}\"")
            }
            BindErrorKind::FindDestMount => format!("Unable to find \"{path}\" in mount table"),
            BindErrorKind::RemountDest => {
                format!("Unable to remount destination \"{path}\" with correct flags")
            }
            BindErrorKind::RemountSubmount => {
                format!("Unable to apply mount flags: remount \"{path}\"")
            }
            BindErrorKind::OpenFd => format!("Unable to open destination O_PATH fd \"{path}\""),
            BindErrorKind::MountSetattr => format!("mount_setattr() failed at \"{path}\""),
        };
        f.write_str(&s)?;
        if self.wants_errno()
            && let Some(e) = self.errno
        {
            write!(f, ": {}", self.errno_text(e))?;
        }
        Ok(())
    }
}

impl std::error::Error for BindError {}

/// Result of a bind-layer operation.
pub type BindResult = std::result::Result<(), BindError>;

fn proc_fd_path(fd: BorrowedFd<'_>) -> CString {
    // Always valid (ASCII), never contains NUL.
    CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).expect("fd path is NUL-free")
}

/// Open `path` with `O_PATH | O_CLOEXEC`, mapping failure (incl. a NUL byte,
/// which a real C string can never contain) to an `OpenFd` error.
fn open_opath(path: &[u8]) -> std::result::Result<OwnedFd, BindError> {
    let c = CString::new(path)
        .map_err(|_| BindError::new(BindErrorKind::OpenFd, path, Errno::EINVAL))?;
    open(
        c.as_c_str(),
        OFlag::O_PATH | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| BindError::new(BindErrorKind::OpenFd, path, e))
}

/// Bind-mount `src` onto `dest` (both host paths), then apply the attributes
/// in `opts`. Opens both with `O_PATH` first, like bwrap's `bind_mount`. Part of
/// the library bind API (the `bwrap` binary opens its own fds and uses
/// [`bind_mount_fd`]).
pub fn bind_mount(src: &[u8], dest: &[u8], opts: BindOptions) -> BindResult {
    let dest_fd = open_opath(dest)?;
    let src_fd = open_opath(src)?;
    bind_mount_fd(Some(src_fd.as_fd()), dest_fd.as_fd(), opts)
}

/// As [`bind_mount`] but from already-open `O_PATH` fds. `src` is `None` to
/// only re-apply attributes to an existing mount at `dest` (bwrap's
/// `src_fd == -1`).
pub fn bind_mount_fd(
    src: Option<BorrowedFd<'_>>,
    dest: BorrowedFd<'_>,
    opts: BindOptions,
) -> BindResult {
    let dest_proc = proc_fd_path(dest);

    let resolved_dest = readlink(dest_proc.as_c_str())
        .map_err(|e| BindError::new(BindErrorKind::ReadlinkDestProcFd, dest_proc.as_bytes(), e))?;
    let resolved_dest = resolved_dest.as_bytes().to_vec();

    if let Some(src) = src {
        let src_proc = proc_fd_path(src);
        let mut flags = MsFlags::MS_SILENT | MsFlags::MS_BIND;
        if opts.recursive {
            flags |= MsFlags::MS_REC;
        }
        mount(
            Some(src_proc.as_c_str()),
            dest_proc.as_c_str(),
            None::<&std::ffi::CStr>,
            flags,
            None::<&std::ffi::CStr>,
        )
        .map_err(|e| BindError::new(BindErrorKind::Mount, &resolved_dest, e))?;
    }

    apply_attributes(&resolved_dest, opts)
}

/// Apply `ro`/`nodev`/`nosuid` to the bind at `resolved_dest`, via
/// `mount_setattr`, falling back to the mountinfo walk on `ENOSYS` (cached) or
/// when the fallback is forced.
fn apply_attributes(resolved_dest: &[u8], opts: BindOptions) -> BindResult {
    let mut set = MountAttrFlags::NOSUID;
    if !opts.devices {
        set |= MountAttrFlags::NODEV;
    }
    if opts.readonly {
        set |= MountAttrFlags::RDONLY;
    }
    let recursion = if opts.recursive {
        Recursion::Recursive
    } else {
        Recursion::ThisMountOnly
    };

    // Once mount_setattr is known unsupported, or when forced, go to the walk.
    if FORCE_FALLBACK.load(Ordering::Relaxed) || !MOUNT_ATTR_SUPPORTED.load(Ordering::Relaxed) {
        return mount_setattr_fallback(resolved_dest, opts);
    }

    // Reopen the destination after the mount (bwrap reopens here too).
    let dest_fd = open_opath(resolved_dest)?;

    match mount_setattr(dest_fd.as_fd(), recursion, set, MountAttrFlags::empty()) {
        Ok(()) => Ok(()),
        Err(Errno::ENOSYS) => {
            MOUNT_ATTR_SUPPORTED.store(false, Ordering::Relaxed);
            mount_setattr_fallback(resolved_dest, opts)
        }
        Err(e) => Err(BindError::new(
            BindErrorKind::MountSetattr,
            resolved_dest,
            e,
        )),
    }
}

/// Pre-5.12 fallback (bwrap's `mount_setattr_fallback`): read the mount table
/// under `resolved_dest` and `MS_REMOUNT` the root (if its flags change) and,
/// if recursive, each submount.
fn mount_setattr_fallback(resolved_dest: &[u8], opts: BindOptions) -> BindResult {
    let added = remount_added_flags(opts);
    let tab = parse_mountinfo(resolved_dest)
        .map_err(|_| BindError::new(BindErrorKind::FindDestMount, resolved_dest, Errno::EINVAL))?;
    let Some(root) = tab.first() else {
        return Err(BindError::new(
            BindErrorKind::FindDestMount,
            resolved_dest,
            Errno::EINVAL,
        ));
    };

    // Remount the root only if its flags actually change (bwrap's guard).
    let new = root.options | added;
    if new != root.options {
        remount_raw(resolved_dest, new)
            .map_err(|e| BindError::new(BindErrorKind::RemountDest, resolved_dest, e))?;
    }

    if opts.recursive {
        for sub in &tab[1..] {
            let new = sub.options | added;
            if new == sub.options {
                continue;
            }
            match remount_raw(&sub.mountpoint, new) {
                Ok(()) => {}
                // A mountpoint we can't read, we can't remount — safe to skip.
                Err(Errno::EACCES) => {}
                Err(e) => {
                    if opts.fail_open {
                        // --not-a-security-boundary: warn and keep going, exactly
                        // as bwrap's warn() does (bind-mount.c:545).
                        crate::log::emit_err(&crate::log::warning_line(&format!(
                            "Can't remount {} submount ({}), ignoring error",
                            String::from_utf8_lossy(&sub.mountpoint),
                            bwrap_sys::strerror(e),
                        )));
                        continue;
                    }
                    return Err(BindError::new(
                        BindErrorKind::RemountSubmount,
                        &sub.mountpoint,
                        e,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn remount_raw(path: &[u8], new_flags: MsFlags) -> std::result::Result<(), Errno> {
    let target = CString::new(path).map_err(|_| Errno::EINVAL)?;
    mount(
        Some(c"none"),
        target.as_c_str(),
        None::<&std::ffi::CStr>,
        MsFlags::MS_SILENT | MsFlags::MS_BIND | MsFlags::MS_REMOUNT | new_flags,
        None::<&std::ffi::CStr>,
    )
}

/// Whether `mount_setattr` is still believed to work (bwrap's static
/// `mount_attr_supported`); set false on the first `ENOSYS`.
static MOUNT_ATTR_SUPPORTED: AtomicBool = AtomicBool::new(true);
/// Mirrors bwrap's `opt_force_mount_setattr_fallback`: force the pre-5.12 remount
/// fallback. Wired from the parsed config in [`crate::run`] (and set directly by
/// the mount host tests).
static FORCE_FALLBACK: AtomicBool = AtomicBool::new(false);

/// Force (or unforce) the pre-5.12 `mount_setattr` fallback path, for
/// `--debug-opt=force-mount-setattr-fallback`.
pub fn set_force_mount_setattr_fallback(force: bool) {
    FORCE_FALLBACK.store(force, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    const RW: BindOptions = BindOptions {
        readonly: false,
        devices: false,
        recursive: true,
        fail_open: false,
    };

    #[test]
    fn open_failures_carry_kind_path_and_text() {
        // Missing destination (opened first): OpenFd on the dest.
        let e = bind_mount(b"/usr", b"/no/such/dest/xyz", RW).unwrap_err();
        assert_eq!(e.kind, BindErrorKind::OpenFd);
        assert_eq!(e.failing_path.as_deref(), Some(&b"/no/such/dest/xyz"[..]));
        assert_eq!(
            e.to_string(),
            "Unable to open destination O_PATH fd \"/no/such/dest/xyz\": No such file or directory"
        );
        // Missing source, existing dest: OpenFd on the src.
        let e = bind_mount(b"/no/such/src/xyz", b"/tmp", RW).unwrap_err();
        assert_eq!(e.failing_path.as_deref(), Some(&b"/no/such/src/xyz"[..]));
    }

    #[test]
    fn nul_in_path_is_open_fd_einval() {
        let e = bind_mount(b"/a\0b", b"/tmp", RW).unwrap_err();
        assert_eq!(e.kind, BindErrorKind::OpenFd);
        assert_eq!(e.errno, Some(Errno::EINVAL));
    }

    #[test]
    fn display_texts_match_upstream() {
        let p = b"/d".to_vec();
        let cases = [
            (
                BindErrorKind::Mount,
                "Unable to mount source on destination: No such file or directory",
            ),
            (
                BindErrorKind::ReadlinkDestProcFd,
                "readlink(/proc/self/fd/N) for \"/d\": No such file or directory",
            ),
            (
                BindErrorKind::RemountDest,
                "Unable to remount destination \"/d\" with correct flags: No such file or directory",
            ),
            (
                BindErrorKind::RemountSubmount,
                "Unable to apply mount flags: remount \"/d\": No such file or directory",
            ),
            (
                BindErrorKind::MountSetattr,
                "mount_setattr() failed at \"/d\": No such file or directory",
            ),
        ];
        for (kind, want) in cases {
            let e = BindError {
                kind,
                failing_path: Some(p.clone()),
                errno: Some(Errno::ENOENT),
            };
            assert_eq!(e.to_string(), want, "{kind:?}");
        }
        // FindDestMount has want_errno = false: no errno suffix.
        let e = BindError {
            kind: BindErrorKind::FindDestMount,
            failing_path: Some(p),
            errno: Some(Errno::EINVAL),
        };
        assert_eq!(e.to_string(), "Unable to find \"/d\" in mount table");
    }

    #[test]
    fn force_fallback_toggle_roundtrips() {
        set_force_mount_setattr_fallback(true);
        assert!(FORCE_FALLBACK.load(Ordering::Relaxed));
        set_force_mount_setattr_fallback(false);
        assert!(!FORCE_FALLBACK.load(Ordering::Relaxed));
    }
}
