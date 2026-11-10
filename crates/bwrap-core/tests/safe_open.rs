//! `safe_open` / `open_in_root`, exercised through both resolvers: the
//! `openat2(RESOLVE_IN_ROOT)` fast path and the `chroot_realpath` fallback
//! (forced with `set_force_openat_fallback`). Both must agree on every case
//! below, because the fallback exists only for kernels without `openat2`.
//!
//! The force switch is process-global, so every scenario takes `LOCK`.
#![allow(clippy::unwrap_used)]

use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use bwrap_core::fs::{open_in_root, proc_self_fd, safe_open, set_force_openat_fallback};
use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::sys::stat::{Mode, fstat};

static LOCK: Mutex<()> = Mutex::new(());

/// Runs `scenario` once per resolver, resetting the switch afterwards even on panic.
fn both_resolvers(tag: &str, scenario: impl Fn(&Path, bool)) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            set_force_openat_fallback(false);
        }
    }
    let _guard = LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _reset = Reset;
    let root = fixture(tag);
    for fallback in [false, true] {
        set_force_openat_fallback(fallback);
        scenario(&root, fallback);
    }
    let _ = std::fs::remove_dir_all(&root);
}

fn fixture(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("bwrap-safe-open-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("d")).unwrap();
    std::fs::write(root.join("f"), b"top").unwrap();
    std::fs::write(root.join("d/g"), b"inner").unwrap();
    symlink("/d", root.join("abs")).unwrap();
    symlink("d/g", root.join("rel")).unwrap();
    symlink("../../../../../../etc", root.join("up")).unwrap();
    symlink("loop", root.join("loop")).unwrap();
    root
}

fn rb(root: &Path) -> &[u8] {
    root.as_os_str().as_bytes()
}

fn read_all(fd: OwnedFd) -> String {
    let mut s = String::new();
    std::fs::File::from(fd).read_to_string(&mut s).unwrap();
    s
}

fn ro() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_CLOEXEC
}

#[test]
fn opens_plain_and_nested_files() {
    both_resolvers("plain", |root, fb| {
        let r = rb(root);
        assert_eq!(
            read_all(open_in_root(r, b"f", ro()).unwrap()),
            "top",
            "fb={fb}"
        );
        assert_eq!(
            read_all(open_in_root(r, b"d/g", ro()).unwrap()),
            "inner",
            "fb={fb}"
        );
        // A leading slash is relative to the root, not the host.
        assert_eq!(
            read_all(open_in_root(r, b"/d/g", ro()).unwrap()),
            "inner",
            "fb={fb}"
        );
        assert_eq!(
            read_all(open_in_root(r, b"d/../f", ro()).unwrap()),
            "top",
            "fb={fb}"
        );
        assert_eq!(
            read_all(open_in_root(r, b"d//./g", ro()).unwrap()),
            "inner",
            "fb={fb}"
        );
    });
}

#[test]
fn symlinks_resolve_inside_the_root() {
    both_resolvers("links", |root, fb| {
        let r = rb(root);
        // Absolute link "/d" means <root>/d, not the host's /d.
        assert_eq!(
            read_all(open_in_root(r, b"abs/g", ro()).unwrap()),
            "inner",
            "fb={fb}"
        );
        assert_eq!(
            read_all(open_in_root(r, b"rel", ro()).unwrap()),
            "inner",
            "fb={fb}"
        );
        // Too many "..": stays at the root, so /etc/hostname is looked up in
        // <root>/etc and is absent, instead of reaching the host's file.
        assert_eq!(
            open_in_root(r, b"up/hostname", ro()).unwrap_err(),
            Errno::ENOENT,
            "fb={fb}"
        );
        assert_eq!(
            open_in_root(r, b"../../../f", ro()).map(read_all),
            Ok("top".into()),
            "fb={fb}"
        );
        assert_eq!(
            open_in_root(r, b"loop", ro()).unwrap_err(),
            Errno::ELOOP,
            "fb={fb}"
        );
    });
}

#[test]
fn nofollow_does_not_follow_the_last_component() {
    both_resolvers("nofollow", |root, fb| {
        let r = rb(root);
        let nf = ro() | OFlag::O_NOFOLLOW;
        assert_eq!(
            open_in_root(r, b"rel", nf).unwrap_err(),
            Errno::ELOOP,
            "fb={fb}"
        );
        assert_eq!(
            open_in_root(r, b"abs", nf).unwrap_err(),
            Errno::ELOOP,
            "fb={fb}"
        );
        // O_PATH|O_NOFOLLOW yields a handle on the link itself.
        let fd = open_in_root(r, b"rel", OFlag::O_PATH | OFlag::O_NOFOLLOW).unwrap();
        let st = fstat(fd.as_fd()).unwrap();
        assert_eq!(st.st_mode & libc_ifmt(), libc_iflnk(), "fb={fb}");
        // Intermediate links are still followed.
        assert_eq!(
            read_all(open_in_root(r, b"abs/g", nf).unwrap()),
            "inner",
            "fb={fb}"
        );
        // A trailing slash forces the link to be followed.
        let fd = open_in_root(r, b"abs/", nf | OFlag::O_DIRECTORY).unwrap();
        let want = std::fs::metadata(root.join("d")).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fstat(fd.as_fd()).unwrap().st_ino, want.ino(), "fb={fb}");
        // Plain file with NOFOLLOW works and in a subdirectory too.
        assert_eq!(
            read_all(open_in_root(r, b"d/g", nf).unwrap()),
            "inner",
            "fb={fb}"
        );
        assert_eq!(
            read_all(open_in_root(r, b"f", nf).unwrap()),
            "top",
            "fb={fb}"
        );
    });
}

fn libc_ifmt() -> u32 {
    nix::libc::S_IFMT
}
fn libc_iflnk() -> u32 {
    nix::libc::S_IFLNK
}

#[test]
fn missing_and_invalid_paths() {
    both_resolvers("errors", |root, fb| {
        let r = rb(root);
        assert_eq!(
            open_in_root(r, b"nope", ro()).unwrap_err(),
            Errno::ENOENT,
            "fb={fb}"
        );
        assert_eq!(
            open_in_root(r, b"d/nope/x", ro()).unwrap_err(),
            Errno::ENOENT,
            "fb={fb}"
        );
        assert_eq!(
            open_in_root(r, b"f/x", ro()).unwrap_err(),
            Errno::ENOTDIR,
            "fb={fb}"
        );
        assert_eq!(
            open_in_root(r, b"a\0b", ro()).unwrap_err(),
            Errno::EINVAL,
            "fb={fb}"
        );
        let long = vec![b'a'; 5000];
        assert_eq!(
            open_in_root(r, &long, ro()).unwrap_err(),
            Errno::ENAMETOOLONG,
            "fb={fb}"
        );
        // A nonexistent root cannot even be opened.
        assert_eq!(
            open_in_root(b"/nonexistent-bwrap-root", b"f", ro()).unwrap_err(),
            Errno::ENOENT,
            "fb={fb}"
        );
        assert_eq!(
            open_in_root(b"a\0b", b"f", ro()).unwrap_err(),
            Errno::EINVAL,
            "fb={fb}"
        );
    });
}

#[test]
fn root_itself_and_dot() {
    both_resolvers("rootself", |root, fb| {
        let r = rb(root);
        let want = std::fs::metadata(root).unwrap();
        use std::os::unix::fs::MetadataExt;
        let dir_flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
        for p in [&b""[..], b".", b"/", b"d/..", b"//"] {
            let fd = open_in_root(r, p, dir_flags).unwrap();
            assert_eq!(
                fstat(fd.as_fd()).unwrap().st_ino,
                want.ino(),
                "path {:?} fb={fb}",
                String::from_utf8_lossy(p)
            );
        }
        // Opening the root with a non-directory expectation fails.
        assert_eq!(
            open_in_root(r, b"", OFlag::O_RDWR).unwrap_err(),
            Errno::EISDIR,
            "fb={fb}"
        );
    });
}

#[test]
fn rootfs_spelled_through_a_symlink_is_rejected_by_the_fd_check() {
    // The readlink(/proc/self/fd) check compares against the rootfs string
    // verbatim, so a root named through a symlink does not match the fd's
    // real path. The empty-path case is always checked; the fallback also
    // checks every opened file.
    both_resolvers("rootlink", |root, fb| {
        let link = root.with_extension("lnk");
        let _ = std::fs::remove_file(&link);
        symlink(root, &link).unwrap();
        let lb = link.as_os_str().as_bytes();
        let dir_flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY;
        assert_eq!(
            open_in_root(lb, b"", dir_flags).unwrap_err(),
            Errno::ENOTDIR,
            "fb={fb}"
        );
        let r = open_in_root(lb, b"f", ro());
        if fb {
            assert_eq!(r.unwrap_err(), Errno::ENOTDIR);
        } else {
            assert_eq!(read_all(r.unwrap()), "top");
        }
        let _ = std::fs::remove_file(&link);
    });
}

#[test]
fn slash_root_is_unconfined_and_unchecked() {
    both_resolvers("slashroot", |_root, fb| {
        let fd = open_in_root(b"/", b"proc/self/status", ro()).unwrap();
        assert!(read_all(fd).contains("Name:"), "fb={fb}");
        let fd = open_in_root(b"/", b"", OFlag::O_RDONLY | OFlag::O_DIRECTORY).unwrap();
        drop(fd);
        let st = open_in_root(b"/", b"nonexistent-xyz", ro());
        assert_eq!(st.unwrap_err(), Errno::ENOENT, "fb={fb}");
    });
}

#[test]
fn safe_open_applies_mode_when_creating() {
    both_resolvers("create", |root, fb| {
        let dirfd = open(root, OFlag::O_PATH | OFlag::O_DIRECTORY, Mode::empty()).unwrap();
        let name = format!("new-{fb}");
        let flags = OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC;
        let fd = safe_open(
            dirfd.as_fd(),
            rb(root),
            name.as_bytes(),
            flags,
            Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        drop(fd);
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::metadata(root.join(&name)).unwrap().permissions();
        assert_eq!(perm.mode() & 0o777, 0o600, "fb={fb}");
        // O_EXCL on the second attempt.
        let again = safe_open(
            dirfd.as_fd(),
            rb(root),
            name.as_bytes(),
            flags,
            Mode::empty(),
        );
        assert_eq!(again.unwrap_err(), Errno::EEXIST, "fb={fb}");
    });
}

#[test]
fn proc_self_fd_names_the_descriptor() {
    let fd = open("/", OFlag::O_PATH, Mode::empty()).unwrap();
    let p = proc_self_fd(fd.as_fd());
    assert!(p.starts_with("/proc/self/fd/"));
    use std::os::fd::AsRawFd;
    assert_eq!(p, format!("/proc/self/fd/{}", fd.as_raw_fd()));
    assert_eq!(std::fs::read_link(&p).unwrap(), Path::new("/"));
}
