//! Differential test: the Rust `chroot_realpath` port must agree with the
//! original C (`tests/oracle/chroot_realpath_oracle.c`, a verbatim copy of
//! bubblewrap's function) over many paths against real symlink layouts.
//!
//! The C oracle is compiled with `cc` at test time. If `cc` is missing the
//! test skips (prints a notice) rather than failing.
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use bwrap_core::fs::chroot_realpath;

/// Compile the oracle; return its binary path, or None if `cc` is unavailable.
fn build_oracle(out_dir: &Path) -> Option<PathBuf> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/chroot_realpath_oracle.c");
    let bin = out_dir.join("chroot_realpath_oracle");
    let status = Command::new("cc")
        .arg("-O2")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status();
    match status {
        Ok(s) if s.success() => Some(bin),
        Ok(s) => panic!("cc failed to build the oracle: {s}"),
        Err(e) => {
            eprintln!("SKIP: cc not available to build the oracle ({e})");
            None
        }
    }
}

/// Run the oracle; return its line ("OK:<path>" or "ERR:<errno>").
fn oracle(bin: &Path, chroot: &[u8], path: &str) -> String {
    let out = Command::new(bin)
        .arg(OsStr::from_bytes(chroot))
        .arg(path)
        .output()
        .expect("run oracle");
    assert!(out.status.success(), "oracle exited: {:?}", out.status);
    String::from_utf8(out.stdout)
        .expect("oracle utf8")
        .trim_end()
        .to_string()
}

/// Run the Rust port; format like the oracle.
fn rust(chroot: &[u8], path: &str) -> String {
    match chroot_realpath(chroot, path.as_bytes()) {
        Ok(bytes) => format!("OK:{}", OsStr::from_bytes(&bytes).to_string_lossy()),
        Err(e) => format!("ERR:{}", e.raw_os_error().unwrap_or(-1)),
    }
}

/// Build a rich symlink layout under `root`.
fn make_layout(root: &Path) {
    let mk = |rel: &str| std::fs::create_dir_all(root.join(rel)).unwrap();
    let touch = |rel: &str| std::fs::write(root.join(rel), b"x").unwrap();
    mk("dir/sub");
    touch("dir/file");
    touch("dir/sub/deep");
    // relative symlink to a sibling dir
    symlink("sub", root.join("dir/rel")).unwrap();
    // relative symlink up and over
    symlink("../dir/file", root.join("dir/sub/up")).unwrap();
    // absolute symlink (interpreted within the chroot)
    symlink("/dir/file", root.join("abs")).unwrap();
    // symlink that tries to escape the root
    symlink("../../../../etc/passwd", root.join("escape")).unwrap();
    // dangling symlink
    symlink("nowhere", root.join("dangling")).unwrap();
    // symlink loop
    symlink("loopb", root.join("loopa")).unwrap();
    symlink("loopa", root.join("loopb")).unwrap();
    // chain of symlinks
    symlink("dir", root.join("c1")).unwrap();
    symlink("c1", root.join("c2")).unwrap();
    symlink("/abs", root.join("absindirect")).unwrap();
}

const CASES: &[&str] = &[
    "",
    "/",
    "dir",
    "dir/",
    "/dir/file",
    "dir/sub/deep",
    "dir/rel/deep",
    "dir/sub/up",
    "abs",
    "absindirect",
    "escape",
    "escape/x",
    "dangling",
    "dangling/more",
    "loopa",
    "c2/file",
    "../../../etc",
    "dir/../dir/file",
    "dir/./sub/./deep",
    "dir//sub///deep",
    "nonexistent/a/b",
    "dir/missing/../file",
    ".",
    "..",
    "dir/..",
    "dir/sub/../../abs",
];

#[test]
fn rust_matches_c_oracle() {
    let tmp = std::env::temp_dir().join(format!("bwrap-cr-oracle-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let Some(bin) = build_oracle(&tmp) else {
        return; // cc unavailable
    };
    let root = tmp.join("root");
    std::fs::create_dir_all(&root).unwrap();
    make_layout(&root);
    // A 40-deep relative symlink chain to probe the MAX_READLINKS (32) boundary.
    for i in 0..40 {
        symlink(format!("chain{}", i + 1), root.join(format!("chain{i}"))).unwrap();
    }
    std::fs::write(root.join("chain40"), b"x").unwrap();

    let root_b = root.as_os_str().as_bytes();
    let mut mismatches = Vec::new();

    // The fixed battery against the normal (no trailing slash) chroot.
    let cmp = |chroot: &[u8], path: &str, mm: &mut Vec<String>| {
        let o = oracle(&bin, chroot, path);
        let r = rust(chroot, path);
        if o != r {
            mm.push(format!(
                "chroot {:?} path {path:?}: oracle={o:?} rust={r:?}",
                OsStr::from_bytes(chroot)
            ));
        }
    };
    for case in CASES {
        cmp(root_b, case, &mut mismatches);
    }

    // Finding 1 regression guard: trailing-slash and bare "/"/"" chroots, and
    // paths with trailing slashes through symlinks.
    let trailing: Vec<u8> = [root_b, b"/"].concat();
    let double: Vec<u8> = [root_b, b"//"].concat();
    for chroot in [root_b, trailing.as_slice(), double.as_slice(), b"/", b""] {
        for path in ["", "/", "dir", "dir/", "abs", "abs/", "rel/", "dir/sub/"] {
            cmp(chroot, path, &mut mismatches);
        }
    }
    // MAX_READLINKS boundary and a very long path (ENAMETOOLONG).
    cmp(root_b, "chain0", &mut mismatches);
    cmp(root_b, "chain9", &mut mismatches);
    cmp(root_b, &"a/".repeat(4000), &mut mismatches);

    // Fuzz: random paths built from a component alphabet that stresses the
    // symlinks, `..`, `.` and repeated slashes in the layout above.
    let parts = [
        "dir",
        "sub",
        "deep",
        "file",
        "rel",
        "up",
        "abs",
        "escape",
        "dangling",
        "loopa",
        "c1",
        "c2",
        "..",
        ".",
        "x",
        "absindirect",
    ];
    let mut rng: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = |n: usize| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        (rng as usize) % n
    };
    for _ in 0..3000 {
        let len = 1 + next(5);
        let mut p = String::new();
        for i in 0..len {
            if i > 0 {
                p.push_str(if next(4) == 0 { "//" } else { "/" });
            }
            p.push_str(parts[next(parts.len())]);
        }
        // Sometimes end in a slash (exercises the symlink/trailing-slash path).
        if next(3) == 0 {
            p.push('/');
        }
        cmp(root_b, &p, &mut mismatches);
    }

    let _ = std::fs::remove_dir_all(&tmp);
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
