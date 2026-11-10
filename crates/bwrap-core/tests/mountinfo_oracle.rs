//! Differential test: the Rust `parse_mountinfo_text` must agree with the
//! original C (`tests/oracle/mountinfo_oracle.c`, verbatim `parse_mountinfo`
//! plus helpers) over many randomly generated mountinfo documents. This pins
//! the fiddly, security-relevant tree/covered-mount logic the same way the
//! chroot_realpath oracle pins path resolution.
//!
//! The oracle is compiled with `cc` at test time; if `cc` is missing the test
//! skips.
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use bwrap_core::mount::parse_mountinfo_text;

fn build_oracle(out_dir: &Path) -> Option<PathBuf> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/mountinfo_oracle.c");
    let bin = out_dir.join("mountinfo_oracle");
    match Command::new("cc")
        .arg("-O2")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
    {
        Ok(s) if s.success() => Some(bin),
        Ok(s) => panic!("cc failed to build the mountinfo oracle: {s}"),
        Err(e) => {
            eprintln!("SKIP: cc not available ({e})");
            None
        }
    }
}

/// Oracle output: one "<mountpoint> <flags>" line per entry.
fn oracle(bin: &Path, file: &Path, root: &str) -> String {
    let out = Command::new(bin)
        .arg(file)
        .arg(root)
        .output()
        .expect("run oracle");
    assert!(out.status.success(), "oracle exited: {:?}", out.status);
    String::from_utf8(out.stdout)
        .expect("utf8")
        .trim_end()
        .to_string()
}

/// Rust output in the same format.
fn rust(text: &[u8], root: &str) -> String {
    let tab = parse_mountinfo_text(text, root.as_bytes()).expect("parse");
    tab.iter()
        .map(|e| {
            format!(
                "{} {}",
                String::from_utf8_lossy(&e.mountpoint),
                e.options.bits()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn rust_matches_c_oracle() {
    let tmp = std::env::temp_dir().join(format!("bwrap-mi-oracle-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let Some(bin) = build_oracle(&tmp) else {
        return;
    };

    // Mountpoint pool with duplicates and nesting, to trigger covered mounts,
    // overmounts and sibling dedup.
    let points = [
        "/",
        "/root",
        "/root",
        "/root/a",
        "/root/a",
        "/root/a/b",
        "/root/b",
        "/root/a/b/c",
        "/root/a/b/c",
        "/other",
        "/root/x",
        "/root/x/y",
        // Near-prefix names: must NOT be treated as under /root or /root/a.
        "/rootx",
        "/root/ab",
        "/roo",
        // A mountpoint with an escaped space (\040), to exercise unescape.
        "/root/a\\040b",
    ];
    let opts = [
        "rw",
        "ro",
        "nosuid",
        "nodev",
        "noexec",
        "relatime",
        "noatime",
        "nodiratime",
        // Options bwrap does not decode — must be ignored, not error.
        "seclabel",
        "size=4k",
    ];

    let mut rng: u64 = 0xda3e_39cb_94b9_5bdb;
    let mut next = |n: usize| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        (rng as usize) % n
    };

    let file = tmp.join("mi.txt");
    let mut mismatches = Vec::new();
    for iter in 0..4000 {
        let nlines = 1 + next(12);
        let mut text = String::new();
        // Non-monotonic, unique id values (real mountinfo ids are not ordered
        // and a parent id can exceed its child's). The parent is always an
        // *earlier-generated* node, which keeps the mount graph acyclic (as a
        // real tree is) while the id numbers are shuffled.
        let mut ids: Vec<usize> = Vec::with_capacity(nlines);
        for i in 0..nlines {
            let id = loop {
                let cand = 1 + next(200);
                if !ids.contains(&cand) {
                    break cand;
                }
            };
            ids.push(id);
            let parent = if i == 0 { 0 } else { ids[next(i)] };
            let mp = points[next(points.len())];
            let nopt = 1 + next(3);
            let mut o = Vec::new();
            for _ in 0..nopt {
                o.push(opts[next(opts.len())]);
            }
            // Sometimes include optional fields (shared:N master:M) before "-";
            // bwrap stops at the vfs-options field and must ignore them.
            let optional = if next(2) == 0 {
                format!("shared:{} master:{} ", next(9) + 1, next(9) + 1)
            } else {
                String::new()
            };
            text.push_str(&format!(
                "{id} {parent} 0:{id} / {mp} {} {optional}- tmpfs tmpfs rw\n",
                o.join(",")
            ));
        }
        std::fs::File::create(&file)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();

        let root = ["/root", "/root/a", "/", "/other", "/rootx", "/root/a b"][next(6)];
        let o = oracle(&bin, &file, root);
        let r = rust(text.as_bytes(), root);
        if o != r {
            mismatches.push(format!(
                "iter {iter} root {root}:\n--in--\n{text}--oracle--\n{o}\n--rust--\n{r}"
            ));
            if mismatches.len() >= 5 {
                break;
            }
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n\n")
    );
}
