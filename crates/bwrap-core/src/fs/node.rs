//! Creating directory and file nodes in the new root (bwrap's `ensure_node_at`
//! and `ensure_newroot_parents_at`).

use std::ffi::CString;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use nix::errno::Errno;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, mkdirat};

use super::open::open_in_root;

/// The kind of node to ensure exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// A directory.
    Dir,
    /// A regular file.
    File,
}

fn cstr(bytes: &[u8]) -> nix::Result<CString> {
    CString::new(bytes).map_err(|_| Errno::EINVAL)
}

/// Ensure a node named `name` exists under `parent_fd`, returning an
/// `O_PATH | O_NOFOLLOW` fd to it (bwrap's `ensure_node_at`, non-writable case).
///
/// A directory is `mkdirat`'d (tolerating `EEXIST`); a file is created with
/// `O_CREAT | O_EXCL` (tolerating `EEXIST`). The returned fd never follows a
/// final symlink. `perms` defaults to 0755 for a dir and 0444 for a file,
/// matching bwrap.
pub fn ensure_node_at(
    parent_fd: BorrowedFd<'_>,
    name: &[u8],
    node_type: NodeType,
    perms: Option<Mode>,
) -> nix::Result<OwnedFd> {
    let name = cstr(name)?;
    match node_type {
        NodeType::Dir => {
            let mode = perms.unwrap_or_else(|| Mode::from_bits_truncate(0o755));
            match mkdirat(parent_fd, name.as_c_str(), mode) {
                Ok(()) => {}
                Err(Errno::EEXIST) => {}
                Err(e) => return Err(e),
            }
        }
        NodeType::File => {
            let mode = perms.unwrap_or_else(|| Mode::from_bits_truncate(0o444));
            let flags = OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_EXCL
                | OFlag::O_NOFOLLOW
                | OFlag::O_NOCTTY
                | OFlag::O_CLOEXEC;
            match openat(parent_fd, name.as_c_str(), flags, mode) {
                Ok(_) => {}              // created
                Err(Errno::EEXIST) => {} // already there
                Err(e) => return Err(e),
            }
        }
    }
    // Return an O_PATH no-follow handle to the (new or existing) node.
    openat(
        parent_fd,
        name.as_c_str(),
        OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
}

/// Create (truncating) a file node and return a writable (`O_WRONLY`) handle —
/// bwrap's `ensure_node_at` with `return_writable = true`, used by `--file` to
/// copy data into the new node. Unlike the non-writable case there is no
/// `O_EXCL`/`EEXIST` tolerance: `O_CREAT | O_TRUNC` always yields a fresh,
/// empty, writable file. `perms` defaults to 0444 like bwrap.
pub fn ensure_file_writable_at(
    parent_fd: BorrowedFd<'_>,
    name: &[u8],
    perms: Option<Mode>,
) -> nix::Result<OwnedFd> {
    let name = cstr(name)?;
    let mode = perms.unwrap_or_else(|| Mode::from_bits_truncate(0o444));
    openat(
        parent_fd,
        name.as_c_str(),
        OFlag::O_WRONLY
            | OFlag::O_CREAT
            | OFlag::O_TRUNC
            | OFlag::O_NOFOLLOW
            | OFlag::O_NOCTTY
            | OFlag::O_CLOEXEC,
        mode,
    )
}

/// Create the parent directories of `path` within `/newroot`, returning an
/// `O_PATH` fd to the deepest parent and the last path component
/// (bwrap's `ensure_newroot_parents_at`). Ignores leading/trailing slashes.
///
/// Each parent is `mkdirat`'d with `mode` (tolerating `EEXIST`). The last
/// component is NOT created — the caller does that (e.g. a mount point or a
/// node). When `path` has no non-slash components, the parent is `/newroot`
/// itself and the last component is ".".
pub fn ensure_newroot_parents(path: &[u8], mode: Mode) -> nix::Result<(OwnedFd, Vec<u8>)> {
    let newroot = b"/newroot";
    let mut parent_fd = open_in_root(
        newroot,
        b"/",
        OFlag::O_DIRECTORY | OFlag::O_PATH | OFlag::O_CLOEXEC,
    )?;

    // Split into components, skipping empty ones (collapses repeated slashes).
    let components: Vec<&[u8]> = path
        .split(|&c| c == b'/')
        .filter(|c| !c.is_empty())
        .collect();
    if components.is_empty() {
        return Ok((parent_fd, b".".to_vec()));
    }

    // Everything but the last component is a directory to create/descend.
    let mut prefix: Vec<u8> = Vec::new();
    for comp in &components[..components.len() - 1] {
        match mkdirat(parent_fd.as_fd(), *comp, mode) {
            Ok(()) => {}
            Err(Errno::EEXIST) => {}
            Err(e) => return Err(e),
        }
        if !prefix.is_empty() {
            prefix.push(b'/');
        }
        prefix.extend_from_slice(comp);
        // Re-open the descended directory from the root (an old O_PATH fd would
        // not pick up a mount placed on top of it), as bwrap does.
        parent_fd = open_in_root(
            newroot,
            &prefix,
            OFlag::O_DIRECTORY | OFlag::O_PATH | OFlag::O_CLOEXEC,
        )?;
    }

    let last = components[components.len() - 1].to_vec();
    Ok((parent_fd, last))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bwrap-node-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn ensure_dir_creates_and_is_idempotent() {
        let base = tmpdir("dir");
        let parent = nix::fcntl::open(
            base.as_os_str(),
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        ensure_node_at(parent.as_fd(), b"d", NodeType::Dir, None).expect("create");
        // Second call must tolerate EEXIST.
        ensure_node_at(parent.as_fd(), b"d", NodeType::Dir, None).expect("idempotent");
        assert!(base.join("d").is_dir());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn ensure_file_creates_and_is_idempotent() {
        let base = tmpdir("file");
        let parent = nix::fcntl::open(
            base.as_os_str(),
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        ensure_node_at(parent.as_fd(), b"f", NodeType::File, None).expect("create");
        ensure_node_at(parent.as_fd(), b"f", NodeType::File, None).expect("idempotent");
        assert!(base.join("f").is_file());
        let _ = std::fs::remove_dir_all(&base);
    }

    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// umask is process-wide; tests that clear it must not overlap.
    static UMASK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn open_dir(p: &std::path::Path) -> OwnedFd {
        nix::fcntl::open(
            p,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    #[test]
    fn default_permissions_follow_bwrap() {
        let base = tmpdir("defperm");
        let parent = open_dir(&base);
        let _g = UMASK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let old = nix::sys::stat::umask(Mode::empty());
        ensure_node_at(parent.as_fd(), b"d", NodeType::Dir, None).unwrap();
        ensure_node_at(parent.as_fd(), b"f", NodeType::File, None).unwrap();
        nix::sys::stat::umask(old);
        let mode = |n: &str| {
            std::fs::metadata(base.join(n))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode("d"), 0o755);
        assert_eq!(mode("f"), 0o444);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn explicit_permissions_are_used() {
        let base = tmpdir("perm");
        let parent = open_dir(&base);
        let _g = UMASK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let old = nix::sys::stat::umask(Mode::empty());
        ensure_node_at(
            parent.as_fd(),
            b"d",
            NodeType::Dir,
            Some(Mode::from_bits_truncate(0o700)),
        )
        .unwrap();
        ensure_node_at(
            parent.as_fd(),
            b"f",
            NodeType::File,
            Some(Mode::from_bits_truncate(0o640)),
        )
        .unwrap();
        nix::sys::stat::umask(old);
        let mode = |n: &str| {
            std::fs::metadata(base.join(n))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode("d"), 0o700);
        assert_eq!(mode("f"), 0o640);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn existing_nodes_are_kept_untouched() {
        let base = tmpdir("exist");
        std::fs::write(base.join("f"), b"data").unwrap();
        std::fs::set_permissions(base.join("f"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let parent = open_dir(&base);
        let fd = ensure_node_at(parent.as_fd(), b"f", NodeType::File, None).unwrap();
        // Content and mode of the existing file stay as they were.
        assert_eq!(std::fs::read(base.join("f")).unwrap(), b"data");
        assert_eq!(
            std::fs::metadata(base.join("f"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            nix::sys::stat::fstat(fd.as_fd()).unwrap().st_ino,
            std::fs::metadata(base.join("f")).unwrap().ino()
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn kind_mismatch_is_tolerated_like_eexist() {
        // bwrap ignores EEXIST without checking the type; the caller's later
        // mount reports the real problem.
        let base = tmpdir("mismatch");
        std::fs::write(base.join("file"), b"").unwrap();
        std::fs::create_dir(base.join("dir")).unwrap();
        let parent = open_dir(&base);
        ensure_node_at(parent.as_fd(), b"file", NodeType::Dir, None).expect("dir over file");
        ensure_node_at(parent.as_fd(), b"dir", NodeType::File, None).expect("file over dir");
        assert!(base.join("file").is_file());
        assert!(base.join("dir").is_dir());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn returned_fd_does_not_follow_a_final_symlink() {
        let base = tmpdir("nofollow");
        std::os::unix::fs::symlink("target", base.join("ln")).unwrap();
        let parent = open_dir(&base);
        for kind in [NodeType::Dir, NodeType::File] {
            let fd = ensure_node_at(parent.as_fd(), b"ln", kind, None).unwrap();
            let st = nix::sys::stat::fstat(fd.as_fd()).unwrap();
            assert_eq!(
                st.st_mode & nix::libc::S_IFMT,
                nix::libc::S_IFLNK,
                "{kind:?}"
            );
        }
        // Nothing was created behind the link.
        assert!(!base.join("target").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn errors_are_reported() {
        let base = tmpdir("err");
        std::fs::write(base.join("file"), b"").unwrap();
        let parent = open_dir(&base);
        // Name with an embedded NUL.
        for kind in [NodeType::Dir, NodeType::File] {
            assert_eq!(
                ensure_node_at(parent.as_fd(), b"a\0b", kind, None).unwrap_err(),
                Errno::EINVAL
            );
        }
        // Parent that is not a directory.
        let file_fd = nix::fcntl::open(
            base.join("file").as_path(),
            OFlag::O_PATH | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert_eq!(
            ensure_node_at(file_fd.as_fd(), b"x", NodeType::Dir, None).unwrap_err(),
            Errno::ENOTDIR
        );
        assert_eq!(
            ensure_node_at(file_fd.as_fd(), b"x", NodeType::File, None).unwrap_err(),
            Errno::ENOTDIR
        );
        // Missing intermediate component in the name.
        assert_eq!(
            ensure_node_at(parent.as_fd(), b"no/such", NodeType::Dir, None).unwrap_err(),
            Errno::ENOENT
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn newroot_parents_without_a_newroot_fails() {
        // Outside a sandbox setup there is no /newroot (the namespace test
        // covers the success path).
        if std::path::Path::new("/newroot").exists() {
            return;
        }
        assert_eq!(
            ensure_newroot_parents(b"/a/b", Mode::from_bits_truncate(0o755)).unwrap_err(),
            Errno::ENOENT
        );
    }
}
