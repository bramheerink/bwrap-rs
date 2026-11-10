//! `safe_open`: open a path confined to a root, never escaping it.
//!
//! Mirrors bwrap's `safe_openat`. The fast path is `openat2` with
//! `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS` (Linux 5.6+); on older kernels, or
//! when `openat2` reports `ENOSYS`/`EINVAL`/`EPERM`, it falls back to resolving
//! with [`chroot_realpath`] and then `openat`, with a `/proc/self/fd` readlink
//! check that the result is really under the root.

use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, Ordering};

use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat, openat2, readlink};
use nix::sys::stat::Mode;
use nix::unistd::dup;

use super::resolve::chroot_realpath;

fn cstr(bytes: &[u8]) -> nix::Result<CString> {
    CString::new(bytes).map_err(|_| Errno::EINVAL)
}

fn is_root(rootfs: &[u8]) -> bool {
    rootfs == b"/"
}

/// Open `path` resolved within `rootfs`, relative to the already-open
/// `dirfd` (which must refer to `rootfs` itself). Never escapes `rootfs`.
pub fn safe_open(
    dirfd: BorrowedFd<'_>,
    rootfs: &[u8],
    path: &[u8],
    flags: OFlag,
    mode: Mode,
) -> nix::Result<OwnedFd> {
    if path.is_empty() {
        // Opening the root itself: open `rootfs` directly.
        let fd = open(cstr(rootfs)?.as_c_str(), flags, mode)?;
        // Skip the readlink check for "/" (after pivot_root it can only be the
        // container root, and the /proc link may not be reachable yet).
        if !is_root(rootfs) {
            check_fd_is_path(fd.as_fd(), rootfs)?;
        }
        return Ok(fd);
    }

    // Skip openat2 entirely once it is known unsupported, or when the
    // `--debug-opt=force-openat-fallback` test hook is set.
    if OPENAT2_SUPPORTED.load(Ordering::Relaxed) && !FORCE_FALLBACK.load(Ordering::Relaxed) {
        let how = OpenHow::new()
            .flags(flags)
            .mode(mode)
            .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS);
        let cpath = cstr(path)?;
        loop {
            match openat2(dirfd, cpath.as_c_str(), how) {
                Ok(fd) => return Ok(fd),
                Err(Errno::EINTR | Errno::EAGAIN) => continue,
                Err(Errno::ENOSYS) => {
                    OPENAT2_SUPPORTED.store(false, Ordering::Relaxed);
                    break;
                }
                // openat2 refusing these flags: fall back for this call only.
                Err(Errno::EINVAL | Errno::EPERM) => break,
                Err(e) => return Err(e),
            }
        }
    }
    safe_open_fallback(dirfd, rootfs, path, flags, mode)
}

/// Whether `openat2` is still believed to work (bwrap's `static
/// openat2_supported`); set false on the first `ENOSYS`.
static OPENAT2_SUPPORTED: AtomicBool = AtomicBool::new(true);
/// Mirrors bwrap's `opt_force_openat_fallback`: force the `chroot_realpath`
/// resolver path. Wired from the parsed config in [`crate::run`] (and set
/// directly by the resolver-agreement tests).
static FORCE_FALLBACK: AtomicBool = AtomicBool::new(false);

/// Force (or unforce) the `chroot_realpath` fallback path, for
/// `--debug-opt=force-openat-fallback`. Set from the parsed config at startup.
pub fn set_force_openat_fallback(force: bool) {
    FORCE_FALLBACK.store(force, Ordering::Relaxed);
}

/// readlink(/proc/self/fd/N) must equal `path` exactly (bwrap's
/// `check_fd_is_path`).
fn check_fd_is_path(fd: BorrowedFd<'_>, path: &[u8]) -> nix::Result<()> {
    let link = readlink_fd(fd)?;
    if link.as_bytes() == path {
        Ok(())
    } else {
        Err(Errno::ENOTDIR)
    }
}

/// readlink(/proc/self/fd/N) must be strictly under `rootfs` — longer than it
/// and with a `/` right after (bwrap's `check_fd_under_path`). For a `rootfs`
/// of "/" (or empty) there is nothing to verify.
fn check_fd_under_path(fd: BorrowedFd<'_>, rootfs: &[u8]) -> nix::Result<()> {
    if rootfs.is_empty() || is_root(rootfs) {
        return Ok(());
    }
    let link = readlink_fd(fd)?;
    let link = link.as_bytes();
    let n = rootfs.len();
    if link.len() > n && &link[..n] == rootfs && link[n] == b'/' {
        Ok(())
    } else {
        Err(Errno::ENOTDIR)
    }
}

fn readlink_fd(fd: BorrowedFd<'_>) -> nix::Result<std::ffi::OsString> {
    let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    readlink(proc_path.as_str())
}

/// Pre-5.6 fallback (bwrap's `safe_openat_fallback`): resolve with
/// [`chroot_realpath`], then `openat` relative to `dirfd`, then verify the
/// result is under `rootfs`.
fn safe_open_fallback(
    dirfd: BorrowedFd<'_>,
    rootfs: &[u8],
    path: &[u8],
    flags: OFlag,
    mode: Mode,
) -> nix::Result<OwnedFd> {
    // With O_NOFOLLOW, resolve only the parent so chroot_realpath does not
    // follow a symlink in the last component (openat handles it instead).
    let (resolve_target, last_component): (&[u8], Option<&[u8]>) =
        if flags.contains(OFlag::O_NOFOLLOW) {
            match path.iter().rposition(|&c| c == b'/') {
                None => (b"", Some(path)),
                Some(i) if i + 1 < path.len() => (&path[..i], Some(&path[i + 1..])),
                // A trailing '/' forces the symlink to be followed anyway.
                Some(_) => (path, None),
            }
        } else {
            (path, None)
        };

    let resolved = chroot_realpath(rootfs, resolve_target).map_err(from_io)?;

    // Drop the rootfs prefix if it is really there, then leading slashes.
    let mut rel: &[u8] = &resolved;
    if !rootfs.is_empty()
        && !is_root(rootfs)
        && rel.len() >= rootfs.len()
        && &rel[..rootfs.len()] == rootfs
    {
        rel = &rel[rootfs.len()..];
    }
    while rel.first() == Some(&b'/') {
        rel = &rel[1..];
    }

    // Re-attach the un-resolved last component, if any.
    let mut relbuf: Vec<u8> = rel.to_vec();
    if let Some(last) = last_component {
        if !relbuf.is_empty() {
            relbuf.push(b'/');
        }
        relbuf.extend_from_slice(last);
    }

    // Empty means the root itself: dup the dirfd.
    if relbuf.is_empty() {
        return dup(dirfd);
    }

    let fd = openat(dirfd, cstr(&relbuf)?.as_c_str(), flags, mode)?;
    check_fd_under_path(fd.as_fd(), rootfs)?;
    Ok(fd)
}

fn from_io(e: std::io::Error) -> Errno {
    match e.raw_os_error() {
        Some(code) => Errno::from_raw(code),
        // std rejects interior NULs before any syscall; the C code can't see
        // them at all (NUL-terminated strings), so EINVAL is what openat2 says.
        None if e.kind() == std::io::ErrorKind::InvalidInput => Errno::EINVAL,
        None => Errno::EIO,
    }
}

/// Convenience for the common "open a path inside a root directory" case
/// (bwrap's `openat_in_root`): open `root` fresh with `O_PATH`, then
/// [`safe_open`] relative to it.
pub fn open_in_root(root: &[u8], path: &[u8], flags: OFlag) -> nix::Result<OwnedFd> {
    let root_fd = open(
        cstr(root)?.as_c_str(),
        OFlag::O_PATH | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    safe_open(root_fd.as_fd(), root, path, flags, Mode::empty())
}

/// Format an fd as its `/proc/self/fd` path — exposed for callers that need
/// the magic path (e.g. the `/proc` source special-case in setup).
pub fn proc_self_fd(fd: BorrowedFd<'_>) -> String {
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::fs::symlink;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bwrap-safeopen-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn opens_a_file_within_root_via_openat2() {
        let root = tmpdir("ok");
        std::fs::write(root.join("f"), b"hi").unwrap();
        let root_b = root.as_os_str().as_bytes();
        let fd = open_in_root(root_b, b"f", OFlag::O_RDONLY).expect("open f");
        drop(fd);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn symlink_escape_is_confined() {
        // A symlink pointing outside the root must resolve back inside it, so
        // opening "escape/passwd" cannot reach the host's /etc.
        let root = tmpdir("escape");
        symlink("../../../../etc", root.join("escape")).unwrap();
        let root_b = root.as_os_str().as_bytes();
        // RESOLVE_IN_ROOT confines the symlink; /etc/hostname inside the root
        // does not exist, so this fails with ENOENT rather than opening the
        // host file.
        let r = open_in_root(root_b, b"escape/hostname", OFlag::O_RDONLY);
        assert!(matches!(r, Err(Errno::ENOENT)), "got {r:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fallback_resolver_confines_symlink_escape() {
        // Force the fallback path by resolving with chroot_realpath directly:
        // the escaping symlink must stay within the root.
        let root = tmpdir("fallback");
        symlink("../../../../etc", root.join("escape")).unwrap();
        let root_b = root.as_os_str().as_bytes();
        let resolved = chroot_realpath(root_b, b"escape").unwrap();
        assert!(
            resolved.starts_with(root_b),
            "escaped: {:?}",
            OsStr::from_bytes(&resolved)
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
