// SPDX-License-Identifier: LGPL-2.1-or-later
// Ported from bubblewrap's chroot_realpath.c, itself based on realpath.c
// Copyright (C) 1993 Rick Sladkey; chroot adaptation 2005 Dan Howell,
// 2019-2020 Giuseppe Scrivano. The original grant is LGPL-2.1-or-later.
//! `chroot_realpath`: resolve a path as if `chroot` were `/`, following
//! symlinks but never escaping `chroot`.
//!
//! A faithful port of bubblewrap's `chroot_realpath.c` (itself from the
//! util-linux / Al Viro lineage). It is the heart of the pre-5.6 fallback used
//! when `openat2(RESOLVE_IN_ROOT)` is unavailable, so a bug here is a sandbox
//! escape on old kernels. Correctness is pinned by a differential test
//! (`tests/chroot_realpath_oracle.rs`) that compiles the original C and
//! compares outputs over many paths and symlink layouts.
//!
//! Like the C version it calls `readlink` on the accumulating resolved path,
//! so it touches the real filesystem; it is not pure.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;

/// bwrap's `MAX_READLINKS`: symlink-depth limit before `ELOOP`.
const MAX_READLINKS: u32 = 32;

/// `PATH_MAX` as the C uses it for its length guards.
const PATH_MAX: usize = 4096;

/// Resolve `path` within `chroot`, returning the resolved *host* path
/// (including the `chroot` prefix), matching `chroot_realpath(chroot, path)`.
///
/// When `chroot` is empty or `/`, the path is returned unchanged (no
/// confinement), as in the C. A nonexistent component is not an error: the
/// unresolved remainder is appended and returned (the caller's `openat` then
/// deals with it).
pub fn chroot_realpath(chroot: &[u8], path: &[u8]) -> io::Result<Vec<u8>> {
    // chroot unset or "/": return the path unchanged.
    if chroot.is_empty() || chroot == b"/" {
        if path.len() >= PATH_MAX {
            return Err(enametoolong());
        }
        return Ok(path.to_vec());
    }
    // Same length guard the C applies up front.
    if chroot.len() + path.len() >= PATH_MAX - 3 {
        return Err(enametoolong());
    }

    // got = chroot followed by a single '/'. The C does NOT strip trailing
    // slashes here (its strip loop sees the NUL terminator and never runs), so
    // chroot "/r/" yields "/r//". root marks the index of the appended '/'.
    let mut got: Vec<u8> = chroot.to_vec();
    let root = got.len();
    got.push(b'/');

    // The path being resolved; symlinks rewrite it, so own it.
    let mut path: Vec<u8> = path.to_vec();
    let mut pi = 0usize;
    let mut readlinks = 0u32;

    while pi < path.len() {
        // Skip stray '/'.
        if path[pi] == b'/' {
            pi += 1;
            continue;
        }
        // "." — ignore.
        if path[pi] == b'.' && matches!(path.get(pi + 1), None | Some(b'/')) {
            pi += 1;
            continue;
        }
        // ".." — back up one component, but never above the root.
        if path[pi] == b'.'
            && path.get(pi + 1) == Some(&b'.')
            && matches!(path.get(pi + 2), None | Some(b'/'))
        {
            pi += 2;
            if got.len() == root + 1 {
                continue; // already at root
            }
            // C: while ((--new_path)[-1] != '/');
            let mut cur = got.len();
            loop {
                cur -= 1;
                if got[cur - 1] == b'/' {
                    break;
                }
            }
            got.truncate(cur);
            continue;
        }

        // Copy the next component.
        while pi < path.len() && path[pi] != b'/' {
            got.push(path[pi]);
            pi += 1;
        }
        let last_component = pi >= path.len();

        // Is the component so far a symlink?
        if readlinks > MAX_READLINKS {
            return Err(io::Error::from_raw_os_error(libc_eloop()));
        }
        readlinks += 1;

        match std::fs::read_link(OsStr::from_bytes(&got)) {
            Ok(target) => {
                let link = target.as_os_str().as_bytes();
                if link.first() == Some(&b'/') {
                    // Absolute symlink: restart from the root.
                    got.truncate(root);
                    got.push(b'/');
                } else {
                    // Relative symlink: back up over this component, keeping the
                    // separator. C: while (*(--new_path) != '/'); new_path++;
                    let mut cur = got.len();
                    loop {
                        cur -= 1;
                        if got[cur] == b'/' {
                            break;
                        }
                    }
                    got.truncate(cur + 1);
                }
                // Same length guard the C applies before inserting the target.
                if path[pi..].len() + link.len() >= PATH_MAX - 2 {
                    return Err(enametoolong());
                }
                // New path to resolve: symlink target + the unresolved remainder.
                let mut newp = link.to_vec();
                newp.extend_from_slice(&path[pi..]);
                path = newp;
                pi = 0;
            }
            Err(e) => match e.raw_os_error() {
                // Component does not exist: return what we have + the remainder.
                Some(code) if code == libc_enoent() => {
                    let mut out = got;
                    let rest = &path[pi..];
                    if !rest.is_empty() && rest.first() != Some(&b'/') {
                        out.push(b'/');
                    }
                    out.extend_from_slice(rest);
                    return Ok(out);
                }
                // EINVAL: exists but is not a symlink — keep it.
                Some(code) if code == libc_einval() => {}
                // Anything else is a real error.
                _ => return Err(e),
            },
        }

        // Separate from the next component (unless this was the last).
        if !last_component {
            got.push(b'/');
        }
    }

    // Drop a trailing slash, but never a lone "/" (C: `new_path != got_path + 1`
    // — that is buffer length 1, not the chroot root). Since `chroot` is
    // non-empty and not "/" here, the buffer is always longer than 1.
    if got.len() > 1 && got.last() == Some(&b'/') {
        got.pop();
    }
    Ok(got)
}

fn enametoolong() -> io::Error {
    io::Error::from_raw_os_error(nix::errno::Errno::ENAMETOOLONG as i32)
}
fn libc_enoent() -> i32 {
    nix::errno::Errno::ENOENT as i32
}
fn libc_einval() -> i32 {
    nix::errno::Errno::EINVAL as i32
}
fn libc_eloop() -> i32 {
    nix::errno::Errno::ELOOP as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(chroot: &str, path: &str) -> String {
        String::from_utf8(chroot_realpath(chroot.as_bytes(), path.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn no_confinement_for_root_chroot() {
        assert_eq!(rp("/", "/a/b"), "/a/b");
        assert_eq!(rp("", "/a/b"), "/a/b");
    }

    // Note: resolution stops at the first component that does not exist and
    // appends the raw remainder (verified against the C oracle). So `..` and
    // extra slashes past a missing component are NOT normalised. These
    // expectations match the oracle, not intuition.

    #[test]
    fn stops_at_first_missing_component() {
        // "a" does not exist under this root, so the remainder is appended raw.
        assert_eq!(rp("/nonexistent-root", "a/b/c"), "/nonexistent-root/a/b/c");
        assert_eq!(
            rp("/nonexistent-root", "/a//b/./c"),
            "/nonexistent-root/a//b/./c"
        );
        assert_eq!(
            rp("/nonexistent-root", "a/../b"),
            "/nonexistent-root/a/../b"
        );
        assert_eq!(rp("/nonexistent-root", "a/"), "/nonexistent-root/a/");
    }

    #[test]
    fn leading_dotdot_is_consumed_before_any_component() {
        // ".." is handled lexically until the first real component, and cannot
        // climb above the root.
        assert_eq!(
            rp("/nonexistent-root", "../../../etc"),
            "/nonexistent-root/etc"
        );
    }
}
