// SPDX-License-Identifier: LGPL-2.0-or-later
// Ported from bubblewrap, Copyright (C) 2016 Alexander Larsson and contributors.
//! Parsing `/proc/self/mountinfo` into the mount subtree under a given mount
//! point, for the pre-5.12 `mount_setattr` fallback.
//!
//! A faithful port of bubblewrap's `parse_mountinfo` and helpers in
//! `bind-mount.c`. The tree-building (covered/overmounted dedup) is as fiddly
//! and security-relevant as `chroot_realpath`, so [`parse_mountinfo_text`] is
//! pure and pinned by a differential test against the compiled C
//! (`tests/mountinfo_oracle.rs`).

use std::collections::HashMap;
use std::io;

use nix::mount::MsFlags;

use super::flags::decode_mountoptions;

/// One entry of the resolved mount table: a mountpoint and its decoded flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    /// Mountpoint path (unescaped).
    pub mountpoint: Vec<u8>,
    /// Decoded vfs options (`ro`/`nosuid`/`nodev`/…).
    pub options: MsFlags,
}

/// `has_path_prefix(str, prefix)` — true if `prefix` is a path-component
/// prefix of `str`, ignoring repeated and trailing slashes.
pub fn has_path_prefix(mut s: &[u8], mut prefix: &[u8]) -> bool {
    loop {
        while s.first() == Some(&b'/') {
            s = &s[1..];
        }
        while prefix.first() == Some(&b'/') {
            prefix = &prefix[1..];
        }
        if prefix.is_empty() {
            return true;
        }
        while !prefix.is_empty() && prefix[0] != b'/' {
            if s.first() != Some(&prefix[0]) {
                return false;
            }
            s = &s[1..];
            prefix = &prefix[1..];
        }
        if s.first() != Some(&b'/') && !s.is_empty() {
            return false;
        }
    }
}

/// `path_equal(a, b)` — true if the two paths have the same components,
/// ignoring repeated and trailing slashes.
pub fn path_equal(mut a: &[u8], mut b: &[u8]) -> bool {
    loop {
        while a.first() == Some(&b'/') {
            a = &a[1..];
        }
        while b.first() == Some(&b'/') {
            b = &b[1..];
        }
        if a.is_empty() || b.is_empty() {
            return a.is_empty() && b.is_empty();
        }
        while !a.is_empty() && a[0] != b'/' {
            if b.first() != Some(&a[0]) {
                return false;
            }
            a = &a[1..];
            b = &b[1..];
        }
        if b.first() != Some(&b'/') && !b.is_empty() {
            return false;
        }
    }
}

/// Unescape a mountinfo field: `\ooo` octal escapes become their byte
/// (bwrap's `unescape_inline`).
fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        if field[i] == b'\\' && i + 3 < field.len() {
            let d = |c: u8| (c.wrapping_sub(b'0')) & 0x7;
            out.push((d(field[i + 1]) << 6) | (d(field[i + 2]) << 3) | d(field[i + 3]));
            i += 4;
        } else {
            out.push(field[i]);
            i += 1;
        }
    }
    out
}

struct Line {
    id: i64,
    parent_id: i64,
    mountpoint: Vec<u8>,
    options: Vec<u8>,
    covered: bool,
    first_child: Option<usize>,
    next_sibling: Option<usize>,
}

/// Where the sibling-list write cursor points (bwrap's `to_sibling`
/// pointer-to-pointer).
enum Slot {
    ParentFirst(usize),
    SiblingNext(usize),
}

/// Parse mountinfo `text`, returning the mount subtree rooted at `root_mount`
/// (root first, then its submounts, with over-mounted entries dropped), in the
/// same DFS order as bwrap's `collect_mounts`. Empty if `root_mount` is not a
/// mountpoint.
pub fn parse_mountinfo_text(text: &[u8], root_mount: &[u8]) -> io::Result<Vec<MountEntry>> {
    let mut lines: Vec<Line> = Vec::new();
    for raw in text.split(|&c| c == b'\n') {
        if raw.is_empty() {
            continue;
        }
        let fields: Vec<&[u8]> = raw.split(|&c| c == b' ').collect();
        // 0:id 1:parent 2:maj:min 3:mountroot 4:mountpoint 5:options ...
        if fields.len() < 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad mountinfo line",
            ));
        }
        let parse_int = |b: &[u8]| -> io::Result<i64> {
            std::str::from_utf8(b)
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad mountinfo id"))
        };
        lines.push(Line {
            id: parse_int(fields[0])?,
            parent_id: parse_int(fields[1])?,
            mountpoint: unescape(fields[4]),
            options: fields[5].to_vec(),
            covered: false,
            first_child: None,
            next_sibling: None,
        });
    }

    // Find the root line. bwrap assigns `root = i` on every match, so the LAST
    // matching line wins (an over-mount of the root supersedes earlier ones).
    let mut root = None;
    for (i, l) in lines.iter().enumerate() {
        if path_equal(&l.mountpoint, root_mount) {
            root = Some(i);
        }
    }
    let Some(root) = root else {
        return Ok(Vec::new());
    };

    let by_id: HashMap<i64, usize> = lines.iter().enumerate().map(|(i, l)| (l.id, i)).collect();

    for this in 0..lines.len() {
        if !has_path_prefix(&lines[this].mountpoint, root_mount) {
            continue;
        }
        let Some(&parent) = by_id.get(&lines[this].parent_id) else {
            continue;
        };
        if lines[parent].mountpoint == lines[this].mountpoint {
            lines[parent].covered = true;
        }

        let mut covered = false;
        let mut to_sibling = Slot::ParentFirst(parent);
        let mut sibling = lines[parent].first_child;
        while let Some(sib) = sibling {
            // this covered by an existing sibling (sibling is a prefix of this)?
            if has_path_prefix(&lines[this].mountpoint, &lines[sib].mountpoint) {
                covered = true;
                break;
            }
            let next = lines[sib].next_sibling;
            // this covers the sibling (this is a prefix of sibling): drop sibling.
            if has_path_prefix(&lines[sib].mountpoint, &lines[this].mountpoint) {
                set_slot(&mut lines, &to_sibling, next);
                // to_sibling not advanced (splice)
            } else {
                to_sibling = Slot::SiblingNext(sib);
            }
            sibling = next;
        }
        if covered {
            continue;
        }
        set_slot(&mut lines, &to_sibling, Some(this));
    }

    // Pre-order DFS collect, root first, skipping covered nodes.
    let mut out = Vec::new();
    // Real mountinfo is an acyclic tree, but to avoid hanging on a malformed
    // /proc we guard against revisiting a node (which bwrap, recursing, would
    // crash on instead).
    let mut visited = vec![false; lines.len()];
    let mut stack = vec![root];
    while let Some(idx) = stack.pop() {
        if visited[idx] {
            continue;
        }
        visited[idx] = true;
        if !lines[idx].covered {
            let opts = std::str::from_utf8(&lines[idx].options)
                .map(decode_mountoptions)
                .unwrap_or_else(|_| MsFlags::empty());
            out.push(MountEntry {
                mountpoint: lines[idx].mountpoint.clone(),
                options: opts,
            });
        }
        // Push children in reverse so they emit in sibling order.
        let mut children = Vec::new();
        let mut c = lines[idx].first_child;
        while let Some(ci) = c {
            children.push(ci);
            c = lines[ci].next_sibling;
        }
        for ci in children.into_iter().rev() {
            stack.push(ci);
        }
    }
    Ok(out)
}

fn set_slot(lines: &mut [Line], slot: &Slot, val: Option<usize>) {
    match *slot {
        Slot::ParentFirst(p) => lines[p].first_child = val,
        Slot::SiblingNext(n) => lines[n].next_sibling = val,
    }
}

/// Read `/proc/self/mountinfo` and parse the subtree under `root_mount`.
pub fn parse_mountinfo(root_mount: &[u8]) -> io::Result<Vec<MountEntry>> {
    let text = std::fs::read("/proc/self/mountinfo")?;
    parse_mountinfo_text(&text, root_mount)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_helpers() {
        assert!(has_path_prefix(b"/foo/bar", b"/foo"));
        assert!(has_path_prefix(b"/foo//bar", b"/foo/"));
        assert!(!has_path_prefix(b"/foobar", b"/foo"));
        assert!(path_equal(b"/foo/bar", b"/foo//bar/"));
        assert!(!path_equal(b"/foo", b"/foo/bar"));
    }

    #[test]
    fn unescape_octal() {
        assert_eq!(unescape(b"a\\040b"), b" a b"[1..].to_vec()); // \040 == space
        assert_eq!(unescape(b"plain"), b"plain".to_vec());
    }

    const SAMPLE: &[u8] = b"\
21 20 0:20 / /root rw,nosuid,nodev - tmpfs tmpfs rw
22 21 0:21 / /root/proc rw,relatime - proc proc rw
23 21 0:22 / /root/sub ro,nosuid - tmpfs tmpfs ro
24 20 0:23 / /other rw - tmpfs tmpfs rw
";

    #[test]
    fn collects_subtree_in_order() {
        let tab = parse_mountinfo_text(SAMPLE, b"/root").unwrap();
        let points: Vec<&[u8]> = tab.iter().map(|e| e.mountpoint.as_slice()).collect();
        assert_eq!(points, vec![&b"/root"[..], b"/root/proc", b"/root/sub"]);
        assert!(
            tab[0]
                .options
                .contains(MsFlags::MS_NOSUID | MsFlags::MS_NODEV)
        );
        assert!(tab[2].options.contains(MsFlags::MS_RDONLY));
    }

    #[test]
    fn missing_root_gives_empty() {
        assert!(parse_mountinfo_text(SAMPLE, b"/nope").unwrap().is_empty());
    }

    #[test]
    fn overmount_covers_parent() {
        // A second mount exactly on /root covers the first.
        let text = b"\
21 20 0:20 / /root rw - tmpfs tmpfs rw
25 21 0:25 / /root ro - tmpfs tmpfs ro
";
        let tab = parse_mountinfo_text(text, b"/root").unwrap();
        // The covered (first) /root is dropped; only the top one remains.
        assert_eq!(tab.len(), 1);
        assert!(tab[0].options.contains(MsFlags::MS_RDONLY));
    }
}
