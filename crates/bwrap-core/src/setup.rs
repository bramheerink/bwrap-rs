// SPDX-License-Identifier: LGPL-2.0-or-later
// Ported from bubblewrap, Copyright (C) 2016 Alexander Larsson and contributors.
//! The new-root setup executor and its op helpers — the port of bubblewrap's
//! `setup_newroot` dispatch. It runs after the root tmpfs and `pivot_root` are
//! prepared, consuming the resolved `SetupOp` list to build the sandbox
//! filesystem under `/newroot`, reading sources from `/oldroot`.
//!
//! This file (slice 2) provides the executor-level helpers: the caller-prefixed
//! bind wrappers (`setup_op_bind_mount`/`_fd`) and `reopen_in_newroot`. The full
//! `setup_newroot` dispatch is assembled on top of these.

use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use bwrap_sys::fd::FdTable;

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, openat, readlinkat};
use nix::mount::{MsFlags, mount};
use nix::sys::stat::{FchmodatFlags, Mode as NixMode, SFlag, fchmod, fchmodat, fstat, mkdirat};
use nix::unistd::{AccessFlags, faccessat, symlinkat};

use crate::error::{Context, Error, MountContext, Result};
use crate::fs::{
    NodeType, copy_file_data, ensure_file_writable_at, ensure_newroot_parents, ensure_node_at,
    file_type, open_in_root, proc_self_fd,
};
use crate::mount::BindOptions;
use crate::mount::bind::{BindError, bind_mount_fd};
use crate::mount::special::{mount_mqueue, mount_tmpfs, remount_ro};
use crate::types::op::{BindKind, Mode, OnMissing, OverlayUpper, SetupOp};

/// Lossy display of a path for an error message (bwrap prints the raw bytes;
/// sandbox paths are effectively always UTF-8).
fn disp(bytes: &[u8]) -> Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

/// Format a mode the way C's `%#o` does: a leading `0`, except `0` itself prints
/// as `"0"` (not `"00"`). Rust's `{:#o}` would print `0o700`, which diverges
/// from bubblewrap's `die_with_error ("Can't chmod %#o ...")`.
fn c_alt_octal(mode: u16) -> String {
    if mode == 0 {
        "0".into()
    } else {
        format!("0{mode:o}")
    }
}

/// Compose a bind failure the way bwrap's `die_with_bind_result` prints it:
/// `"<prefix>: <result-string>[: <errno>]"`. The [`BindError`] `Display` already
/// renders the result string and the errno suffix (with bwrap's `want_errno`
/// and `mount_strerror`/`strerror` rules), so the prefix is simply prepended.
fn bind_failure(prefix: String, e: &BindError) -> Error {
    Error::invalid(format!("{prefix}: {e}"))
}

/// Bind-mount an already-open source fd onto an open destination fd
/// (`setup_op_bind_mount_fd`). Always recursive — otherwise the sandbox could
/// reach files that are covered by submounts on the host. On failure the
/// message is `"Can't bind mount <src> on <dest>: …"`.
pub fn setup_op_bind_mount_fd(
    mut opts: BindOptions,
    src_fd: BorrowedFd<'_>,
    src_display: &[u8],
    dest_fd: BorrowedFd<'_>,
    dest_display: &[u8],
) -> Result<()> {
    opts.recursive = true;
    bind_mount_fd(Some(src_fd), dest_fd, opts).map_err(|e| {
        bind_failure(
            format!(
                "Can't bind mount {} on {}",
                disp(src_display),
                disp(dest_display)
            ),
            &e,
        )
    })
}

/// Open a source path under `/oldroot` and bind-mount it onto `dest_fd`
/// (`setup_op_bind_mount`). On a missing source the message is
/// `"Can't open source <src>: …"`.
pub fn setup_op_bind_mount(
    opts: BindOptions,
    src: &[u8],
    dest_fd: BorrowedFd<'_>,
    dest_display: &[u8],
) -> Result<()> {
    let src_fd = open_in_root(b"/oldroot", src, OFlag::O_PATH)
        .with_context(|| format!("Can't open source {}", disp(src)))?;
    setup_op_bind_mount_fd(opts, src_fd.as_fd(), src, dest_fd, dest_display)
}

/// Reopen a destination path under `/newroot` after mounting on it
/// (`reopen_newroot_fd`): the pre-mount fd points at the now-hidden underlying
/// node, so a fresh `O_PATH | O_NOFOLLOW` open is needed to see the mount.
pub fn reopen_in_newroot(dest: &[u8]) -> Result<OwnedFd> {
    open_in_root(b"/newroot", dest, OFlag::O_PATH | OFlag::O_NOFOLLOW)
        .with_context(|| format!("Can't reopen {}", disp(dest)))
}

/// Runtime context the executor needs beyond the `SetupOp` list.
#[derive(Debug, Clone, Default)]
pub struct NewrootCtx {
    /// A new pid namespace is being created (`--unshare-pid`).
    pub unshare_pid: bool,
    /// A `--pidns` fd was supplied (join an existing pid namespace).
    pub have_pidns_fd: bool,
    /// `--not-a-security-boundary`: bind mounts may fail-open on submounts.
    pub not_a_security_boundary: bool,
    /// Host tty device path when stdout is a tty, for `/dev/console`.
    pub host_tty_dev: Option<Vec<u8>>,
    /// `--file-label`: SELinux context folded into tmpfs mount options.
    pub file_label: Option<String>,
}

fn cpath(bytes: &[u8]) -> Result<CString> {
    CString::new(bytes).map_err(|_| Error::invalid("path contains a NUL byte"))
}

fn nixmode(m: Mode) -> NixMode {
    NixMode::from_bits_truncate(u32::from(m.bits()))
}

/// bwrap's `parent_mode`: 0755, but when a node's own mode denies group or other
/// access, deny the parents the matching execute/search bits too, so the node
/// cannot be reached around its own permissions (least astonishment).
fn parent_mode(perms: Option<Mode>) -> u32 {
    let mut m = 0o755u32;
    if let Some(p) = perms {
        let b = u32::from(p.bits());
        if b & 0o070 == 0 {
            m &= !0o050;
        }
        if b & 0o007 == 0 {
            m &= !0o005;
        }
    }
    m
}

/// Map a `BindKind` (and `--not-a-security-boundary`) to [`BindOptions`].
/// `recursive` is left false here; the bind wrappers force it on.
fn bind_opts(kind: BindKind, not_a_security_boundary: bool) -> BindOptions {
    BindOptions {
        readonly: matches!(kind, BindKind::ReadOnly),
        devices: matches!(kind, BindKind::Dev),
        fail_open: not_a_security_boundary,
        ..BindOptions::default()
    }
}

/// The writable-layer part of an overlay, independent of fds (for testing the
/// options string).
enum OverlayOpt {
    Persistent { upper: String, work: String },
    Tmp { idx: usize },
    ReadOnly,
}

/// Build the overlayfs mount `data` string, byte-identical to bwrap's
/// `strappendf` sequence: optional `upperdir=…,workdir=…,`, then
/// `lowerdir=<l1:l2:…>,userxattr`.
fn overlay_options(upper: &OverlayOpt, lowers: &[String]) -> String {
    let mut s = String::new();
    match upper {
        OverlayOpt::Persistent { upper, work } => {
            s.push_str(&format!("upperdir={upper},workdir={work},"));
        }
        OverlayOpt::Tmp { idx } => {
            s.push_str(&format!(
                "upperdir=/tmp-overlay-upper-{idx},workdir=/tmp-overlay-work-{idx},"
            ));
        }
        OverlayOpt::ReadOnly => {}
    }
    s.push_str("lowerdir=");
    s.push_str(&lowers.join(":"));
    s.push_str(",userxattr");
    s
}

/// Open a source path under `/oldroot` for a bind mount (`O_PATH`). `/proc`
/// sources are opened directly (magic links). Returns `Ok(None)` when the
/// source is missing and `allow_notexist` is set (the `--bind-try` variants).
fn open_source(src: &[u8], allow_notexist: bool) -> Result<Option<OwnedFd>> {
    // Component-aware `/proc` prefix test (bwrap's `has_path_prefix(source,
    // "/proc")`): a `/proc` source is opened directly, since the in-root resolver
    // rejects its magic symlinks (e.g. `/proc/self/ns/user`). Must ignore leading
    // and repeated slashes, so `//proc/self/ns/user` is handled too — the single
    // correct copy of the check lives in `mountinfo`.
    let r = if crate::mount::mountinfo::has_path_prefix(src, b"/proc") {
        let mut p = b"/oldroot".to_vec();
        p.extend_from_slice(src);
        nix::fcntl::open(
            cpath(&p)?.as_c_str(),
            OFlag::O_PATH | OFlag::O_CLOEXEC,
            NixMode::empty(),
        )
    } else {
        open_in_root(b"/oldroot", src, OFlag::O_PATH)
    };
    match r {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::ENOENT) if allow_notexist => Ok(None),
        Err(e) => Err(Error::Sys {
            message: format!("Can't open source {}", disp(src)).into(),
            errno: e,
        }),
    }
}

/// What kind of destination node a setup op needs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DestKind {
    /// No base node (symlink): only the parents are created.
    None,
    /// The node must already exist; open it `O_PATH | O_NOFOLLOW` (no create).
    Existing,
    /// A directory node.
    Dir,
    /// A regular file node; `writable` returns an `O_WRONLY` handle.
    File { writable: bool },
}

/// Create the destination's parents and (per `kind`) its base node, returning
/// the parent fd, the last path component, and the base-node fd. Mirrors the
/// dest-creation block of bwrap's `setup_newroot`, including the mount-type
/// symlink refusal and the dir/file type checks.
fn make_dest(
    dest: &[u8],
    perms_for_parent: Option<Mode>,
    kind: DestKind,
    node_perms: Option<Mode>,
    is_mount: bool,
) -> Result<(OwnedFd, Vec<u8>, Option<OwnedFd>)> {
    let (parent_fd, name) = ensure_newroot_parents(
        dest,
        NixMode::from_bits_truncate(parent_mode(perms_for_parent)),
    )
    .with_context(|| format!("Can't mkdir parents for {}", disp(dest)))?;

    let dest_fd = match kind {
        DestKind::None => None,
        DestKind::Existing => Some(
            openat(
                parent_fd.as_fd(),
                cpath(&name)?.as_c_str(),
                OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                NixMode::empty(),
            )
            .with_context(|| format!("Can't create file {}", disp(dest)))?,
        ),
        DestKind::Dir => Some(
            ensure_node_at(
                parent_fd.as_fd(),
                &name,
                NodeType::Dir,
                node_perms.map(nixmode),
            )
            .with_context(|| format!("Can't create file {}", disp(dest)))?,
        ),
        DestKind::File { writable: false } => Some(
            ensure_node_at(
                parent_fd.as_fd(),
                &name,
                NodeType::File,
                node_perms.map(nixmode),
            )
            .with_context(|| format!("Can't create file {}", disp(dest)))?,
        ),
        DestKind::File { writable: true } => Some(
            ensure_file_writable_at(parent_fd.as_fd(), &name, node_perms.map(nixmode))
                .with_context(|| format!("Can't create file {}", disp(dest)))?,
        ),
    };

    if let Some(fd) = &dest_fd {
        let mode = file_type(fd.as_fd())
            .with_context(|| format!("Can't get type of dest {}", disp(dest)))?;
        if is_mount && mode == SFlag::S_IFLNK {
            return Err(Error::invalid(format!(
                "Can't mount on symlink destination {}",
                disp(dest)
            )));
        }
        match kind {
            DestKind::Dir if mode != SFlag::S_IFDIR => {
                return Err(Error::invalid(format!(
                    "Destination is not a directory {}",
                    disp(dest)
                )));
            }
            DestKind::File { .. } if mode == SFlag::S_IFDIR => {
                return Err(Error::invalid(format!(
                    "Destination is not a file {}",
                    disp(dest)
                )));
            }
            _ => {}
        }
    }
    Ok((parent_fd, name, dest_fd))
}

/// Execute the resolved setup ops against the prepared `/newroot` (bwrap's
/// `setup_newroot`). Sources are read from `/oldroot`. Must run after the root
/// tmpfs and `pivot_root` are in place.
/// A stable `'static` profiler label per setup-op kind.
fn op_label(op: &SetupOp) -> &'static str {
    match op {
        SetupOp::Bind { .. } => "op.bind",
        SetupOp::BindFd { .. } => "op.bind_fd",
        SetupOp::Overlay { .. } => "op.overlay",
        SetupOp::Proc { .. } => "op.proc",
        SetupOp::Dev { .. } => "op.dev",
        SetupOp::Tmpfs { .. } => "op.tmpfs",
        SetupOp::Mqueue { .. } => "op.mqueue",
        SetupOp::Dir { .. } => "op.dir",
        SetupOp::File { .. } => "op.file",
        SetupOp::BindData { .. } => "op.bind_data",
        SetupOp::Symlink { .. } => "op.symlink",
        SetupOp::RemountRo { .. } => "op.remount_ro",
        SetupOp::Chmod { .. } => "op.chmod",
    }
}

pub fn setup_newroot(ops: &[SetupOp], ctx: &NewrootCtx, fds: &mut FdTable) -> Result<()> {
    let mut tmp_overlay_idx = 0usize;

    for op in ops {
        // Per-op timing for the profiler (BWRAP_RS_PROFILE); no-op when off.
        let _sp = crate::profile::span(op_label(op));
        match op {
            SetupOp::Bind {
                src,
                dest,
                kind,
                missing,
            } => {
                let src_b = src.as_c_str().to_bytes();
                let Some(source_fd) = open_source(src_b, *missing == OnMissing::Skip)? else {
                    continue;
                };
                let src_mode = match file_type(source_fd.as_fd()) {
                    Ok(m) => m,
                    Err(Errno::ENOENT) if *missing == OnMissing::Skip => continue,
                    Err(e) => {
                        return Err(Error::Sys {
                            message: format!("Can't get type of source {}", disp(src_b)).into(),
                            errno: e,
                        });
                    }
                };
                let dest_b = dest.as_c_str().to_bytes();
                let kind_node = if src_mode == SFlag::S_IFDIR {
                    DestKind::Dir
                } else {
                    DestKind::File { writable: false }
                };
                let (_p, _n, dest_fd) = make_dest(dest_b, None, kind_node, None, true)?;
                let dest_fd = dest_fd.expect("bind dest is created");
                setup_op_bind_mount_fd(
                    bind_opts(*kind, ctx.not_a_security_boundary),
                    source_fd.as_fd(),
                    src_b,
                    dest_fd.as_fd(),
                    dest_b,
                )?;
            }

            SetupOp::BindFd { fd, dest, kind } => {
                fds.register(*fd);
                let src_fd = fds.borrow(*fd).expect("bind-fd src just registered");
                // Resolve the caller's fd to its real path (bwrap resolves the
                // `/proc/self/fd/N` source to the realpath), then bind that path
                // from the old root like a normal source — binding the magic link
                // directly gives EINVAL. The race check below (inode compare)
                // guards the TOCTOU this re-resolution opens, as bwrap's does.
                let proc_path = proc_self_fd(src_fd);
                let real = nix::fcntl::readlink(proc_path.as_str())
                    .with_context(|| format!("Can't read link {proc_path}"))?;
                let real_bytes = real.as_bytes();
                let src_opath = open_in_root(b"/oldroot", real_bytes, OFlag::O_PATH)
                    .with_context(|| format!("Can't open source {}", disp(real_bytes)))?;
                let src_mode = file_type(src_opath.as_fd())
                    .with_context(|| format!("Can't get type of source {}", disp(real_bytes)))?;
                let dest_b = dest.as_c_str().to_bytes();
                let kind_node = if src_mode == SFlag::S_IFDIR {
                    DestKind::Dir
                } else {
                    DestKind::File { writable: false }
                };
                let (_p, _n, dest_fd) = make_dest(dest_b, None, kind_node, None, true)?;
                let dest_fd = dest_fd.expect("bind-fd dest is created");
                setup_op_bind_mount_fd(
                    bind_opts(*kind, ctx.not_a_security_boundary),
                    src_opath.as_fd(),
                    real_bytes,
                    dest_fd.as_fd(),
                    dest_b,
                )?;
                // bind-fd race check: the mounted target must be the same inode
                // as the caller's fd, or the path was swapped under us.
                let mounted = reopen_in_newroot(dest_b)?;
                let fd_st = fstat(src_fd).with_context(|| format!("Can't stat fd {fd}"))?;
                let mount_st = fstat(mounted.as_fd())
                    .with_context(|| format!("Can't stat mount at {}", disp(dest_b)))?;
                if fd_st.st_ino != mount_st.st_ino || fd_st.st_dev != mount_st.st_dev {
                    return Err(Error::invalid("Race condition binding dirfd"));
                }
                // Close the caller's fd after the op (bubblewrap.c:1571) so a
                // reused --bind-fd/--ro-bind-fd fd fails instead of binding twice.
                fds.close(*fd);
            }

            SetupOp::Overlay { lower, upper, dest } => {
                let dest_b = dest.as_c_str().to_bytes();
                let (_p, _n, dest_fd) = make_dest(dest_b, None, DestKind::Dir, None, true)?;
                let dest_fd = dest_fd.expect("overlay dest is created");

                // Keep every layer fd open while we build the options and mount.
                let mut layer_fds: Vec<OwnedFd> = Vec::new();
                let upper_opt = match upper {
                    OverlayUpper::Persistent { upper, work } => {
                        let u =
                            open_in_root(b"/oldroot", upper.as_c_str().to_bytes(), OFlag::O_PATH)
                                .with_context(|| {
                                format!(
                                    "Can't open overlay upperdir {}",
                                    disp(upper.as_c_str().to_bytes())
                                )
                            })?;
                        let w =
                            open_in_root(b"/oldroot", work.as_c_str().to_bytes(), OFlag::O_PATH)
                                .with_context(|| {
                                    format!(
                                        "Can't open overlay workdir {}",
                                        disp(work.as_c_str().to_bytes())
                                    )
                                })?;
                        let uo = OverlayOpt::Persistent {
                            upper: proc_self_fd(u.as_fd()),
                            work: proc_self_fd(w.as_fd()),
                        };
                        layer_fds.push(u);
                        layer_fds.push(w);
                        uo
                    }
                    OverlayUpper::Tmp => {
                        let o = OverlayOpt::Tmp {
                            idx: tmp_overlay_idx,
                        };
                        tmp_overlay_idx += 1;
                        o
                    }
                    OverlayUpper::ReadOnly => OverlayOpt::ReadOnly,
                };

                // `lower` is in command-line (bottom-to-top) order; overlayfs
                // wants lowerdir top-to-bottom, so the last --overlay-src comes
                // first. Reverse to match bwrap's make_setup_overlay_src_ops.
                let mut lowers = Vec::with_capacity(lower.len());
                for l in lower.iter().rev() {
                    let lf = open_in_root(b"/oldroot", l.as_c_str().to_bytes(), OFlag::O_PATH)
                        .with_context(|| {
                            format!(
                                "Can't open overlay source {}",
                                disp(l.as_c_str().to_bytes())
                            )
                        })?;
                    lowers.push(proc_self_fd(lf.as_fd()));
                    layer_fds.push(lf);
                }

                let options = overlay_options(&upper_opt, &lowers);
                let dest_path = cpath(proc_self_fd(dest_fd.as_fd()).as_bytes())?;
                let r = mount(
                    Some(c"overlay"),
                    dest_path.as_c_str(),
                    Some(c"overlay"),
                    MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                    Some(cpath(options.as_bytes())?.as_c_str()),
                );
                drop(layer_fds);
                if let Err(e) = r {
                    // bubblewrap prints the destination as `(null)` here: its
                    // error path has advanced `op` past the overlay op onto a
                    // SETUP_OVERLAY_SRC entry (whose `dest` is NULL) before
                    // formatting `op->dest` (bubblewrap.c:1359-1363). Match that
                    // byte-for-byte rather than printing the real destination.
                    if e == Errno::ELOOP {
                        return Err(Error::invalid(format!(
                            "Can't make overlay mount on (null) with options {options}: Overlay directories may not overlap"
                        )));
                    }
                    return Err(Error::Mount {
                        message: format!(
                            "Can't make overlay mount on (null) with options {options}"
                        )
                        .into(),
                        errno: e,
                    });
                }
            }

            SetupOp::Proc { dest } => {
                let dest_b = dest.as_c_str().to_bytes();
                let (_p, _n, dest_fd) = make_dest(dest_b, None, DestKind::Dir, None, true)?;
                let dest_fd = dest_fd.expect("proc dest is created");
                if ctx.unshare_pid || ctx.have_pidns_fd {
                    let dp = cpath(proc_self_fd(dest_fd.as_fd()).as_bytes())?;
                    mount(
                        Some(c"proc"),
                        dp.as_c_str(),
                        Some(c"proc"),
                        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
                        None::<&std::ffi::CStr>,
                    )
                    .with_mount_context(|| format!("Can't mount proc on {}", disp(dest_b)))?;
                } else {
                    setup_op_bind_mount(BindOptions::default(), b"/proc", dest_fd.as_fd(), dest_b)?;
                }
                let dest_fd = reopen_in_newroot(dest_b)?;
                cover_proc_dirs(dest_fd.as_fd(), dest_b)?;
            }

            SetupOp::Dev { dest } => {
                let dest_b = dest.as_c_str().to_bytes();
                let (_p, _n, dest_fd) = make_dest(dest_b, None, DestKind::Dir, None, true)?;
                let dest_fd = dest_fd.expect("dev dest is created");
                mount_tmpfs(
                    dest_fd.as_fd(),
                    nixmode(Mode::from_bits(0o755)),
                    None,
                    &disp(dest_b),
                    ctx.file_label.as_deref(),
                )?;
                let dest_fd = reopen_in_newroot(dest_b)?;
                setup_dev(dest_fd.as_fd(), dest_b, ctx)?;
            }

            SetupOp::Tmpfs { dest, perms, size } => {
                let dest_b = dest.as_c_str().to_bytes();
                let (_p, _n, dest_fd) = make_dest(dest_b, Some(*perms), DestKind::Dir, None, true)?;
                let dest_fd = dest_fd.expect("tmpfs dest is created");
                mount_tmpfs(
                    dest_fd.as_fd(),
                    nixmode(*perms),
                    *size,
                    &disp(dest_b),
                    ctx.file_label.as_deref(),
                )?;
            }

            SetupOp::Mqueue { dest } => {
                let dest_b = dest.as_c_str().to_bytes();
                let (_p, _n, dest_fd) = make_dest(dest_b, None, DestKind::Dir, None, true)?;
                let dest_fd = dest_fd.expect("mqueue dest is created");
                mount_mqueue(dest_fd.as_fd(), &disp(dest_b))?;
            }

            SetupOp::Dir { dest, perms } => {
                let dest_b = dest.as_c_str().to_bytes();
                // The directory node itself is created by make_dest.
                make_dest(dest_b, Some(*perms), DestKind::Dir, Some(*perms), false)?;
            }

            SetupOp::File { fd, dest, perms } => {
                let dest_b = dest.as_c_str().to_bytes();
                let (_p, _n, dest_fd) = make_dest(
                    dest_b,
                    Some(*perms),
                    DestKind::File { writable: true },
                    Some(*perms),
                    false,
                )?;
                let dest_fd = dest_fd.expect("file dest is created");
                fds.register(*fd);
                let src = fds.borrow(*fd).expect("file src just registered");
                copy_file_data(src, dest_fd.as_fd())
                    .with_context(|| format!("Can't write data to file {}", disp(dest_b)))?;
                // bwrap closes the data fd after copying (bubblewrap.c:1306), so a
                // reused `--file N … --file N` re-reads a closed fd and fails with
                // EBADF, instead of silently producing an empty second file.
                fds.close(*fd);
            }

            SetupOp::BindData {
                fd,
                dest,
                kind,
                perms,
            } => {
                let dest_b = dest.as_c_str().to_bytes();
                let (_p, _n, dest_fd) = make_dest(
                    dest_b,
                    Some(*perms),
                    DestKind::File { writable: false },
                    None,
                    true,
                )?;
                let dest_fd = dest_fd.expect("bind-data dest is created");
                // Write the data to a temp file in the root tmpfs, bind it, then
                // unlink so the sandbox can never reach the backing file. The
                // unlink is AFTER the bind: binding a deleted /proc/self/fd path
                // fails with ENOENT.
                let (tmp, name) = bind_data_tmpfile(*perms, *fd, dest_b, fds)?;
                setup_op_bind_mount_fd(
                    bind_opts(*kind, ctx.not_a_security_boundary),
                    tmp.as_fd(),
                    b"tmpfile",
                    dest_fd.as_fd(),
                    dest_b,
                )?;
                let _ = nix::unistd::unlink(cpath(name.as_bytes())?.as_c_str());
            }

            SetupOp::Symlink { target, dest } => {
                let dest_b = dest.as_c_str().to_bytes();
                let (parent_fd, name, _d) = make_dest(dest_b, None, DestKind::None, None, false)?;
                make_symlink(
                    parent_fd.as_fd(),
                    &name,
                    target.as_c_str().to_bytes(),
                    dest_b,
                )?;
            }

            SetupOp::RemountRo { dest } => {
                let dest_b = dest.as_c_str().to_bytes();
                let (_p, _n, dest_fd) = make_dest(dest_b, None, DestKind::Existing, None, true)?;
                let dest_fd = dest_fd.expect("remount-ro dest exists");
                remount_ro(dest_fd.as_fd()).map_err(|e| {
                    bind_failure(format!("Can't remount readonly on {}", disp(dest_b)), &e)
                })?;
            }

            SetupOp::Chmod { perms, dest } => {
                // NO_CREATE_DEST: open the existing path and chmod it.
                let dest_b = dest.as_c_str().to_bytes();
                let dest_fd = open_in_root(b"/newroot", dest_b, OFlag::O_PATH | OFlag::O_NOFOLLOW)
                    .with_context(|| format!("Can't open {}", disp(dest_b)))?;
                let dp = cpath(proc_self_fd(dest_fd.as_fd()).as_bytes())?;
                fchmodat(
                    dest_fd.as_fd(),
                    dp.as_c_str(),
                    nixmode(*perms),
                    FchmodatFlags::FollowSymlink,
                )
                .with_context(|| {
                    format!("Can't chmod {} {}", c_alt_octal(perms.bits()), disp(dest_b))
                })?;
            }
        }
    }
    Ok(())
}

/// bwrap captures `old_cwd` with glibc's `get_current_dir_name()`, which returns
/// `$PWD` when it is an absolute path that names the current directory (same
/// dev/ino, no `.`/`..` components) and falls back to `getcwd()` otherwise. That
/// keeps a *logical* cwd reached through a symlink (bash's `$PWD`) for the
/// sandbox cwd and `PWD`, where a plain `getcwd()` would substitute the physical
/// path — an observable difference for `pwd`/`$PWD` inside the sandbox.
fn get_current_dir_name() -> nix::Result<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    if let Some(pwd) = std::env::var_os("PWD") {
        let b = pwd.as_bytes();
        let has_dot_component = b.windows(3).any(|w| w == b"/./")
            || b.windows(4).any(|w| w == b"/../")
            || b.ends_with(b"/.")
            || b.ends_with(b"/..");
        if b.first() == Some(&b'/') && !has_dot_component {
            let pwd_path = std::path::Path::new(&pwd);
            if let (Ok(at_pwd), Ok(at_dot)) = (
                nix::sys::stat::stat(pwd_path),
                nix::sys::stat::stat(std::path::Path::new(".")),
            ) && at_pwd.st_dev == at_dot.st_dev
                && at_pwd.st_ino == at_dot.st_ino
            {
                return Ok(std::path::PathBuf::from(&pwd));
            }
        }
    }
    nix::unistd::getcwd()
}

/// Build the sandbox root and run the setup (the `pivot_root` dance in bwrap's
/// `main`): mount a tmpfs at `/tmp`, carve `newroot`/`oldroot` and any
/// `--tmp-overlay` dirs, `pivot_root` into it, bind `/proc` so `/proc/self/fd`
/// works during setup, run [`setup_newroot`], then detach the old root with a
/// second pivot so `/newroot` becomes `/`.
///
/// Returns the pre-pivot working directory (bwrap's `old_cwd`), used later as a
/// default sandbox cwd, or `None` when the launcher's cwd no longer exists —
/// bwrap treats that as a NULL `old_cwd` and falls back to `$HOME` then `/`.
/// Must run in the sandbox's own mount namespace.
pub fn pivot_into_newroot(
    ops: &[SetupOp],
    ctx: &NewrootCtx,
    fds: &mut FdTable,
) -> Result<Option<std::path::PathBuf>> {
    use nix::mount::{MntFlags, umount2};
    use nix::unistd::{chdir, fchdir, mkdir, pivot_root};

    const BASE: &str = "/tmp";
    let dir_mode = NixMode::from_bits_truncate(0o755);

    // Mark the tree slave: we still receive mounts from the real root but never
    // propagate ours back to it. Required before pivot_root.
    mount(
        None::<&CStr>,
        c"/",
        None::<&CStr>,
        MsFlags::MS_SILENT | MsFlags::MS_SLAVE | MsFlags::MS_REC,
        None::<&CStr>,
    )
    .with_mount_context(|| "Failed to make / slave".to_string())?;

    // Root tmpfs we will pivot into.
    mount(
        Some(c"tmpfs"),
        BASE,
        Some(c"tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
        None::<&CStr>,
    )
    .with_mount_context(|| "Failed to mount tmpfs".to_string())?;

    // CWD during the whole setup; old/new root reached via "oldroot"/"newroot".
    // glibc's get_current_dir_name() returns NULL when the cwd has been removed;
    // bwrap ignores that and lets the later chdir fall back to $HOME then /. A
    // failed lookup is therefore None here, not a fatal error.
    let old_cwd = get_current_dir_name().ok();
    chdir(BASE).context("chdir base_path")?;

    mkdir("newroot", dir_mode).context("Creating newroot failed")?;
    mount(
        Some(c"newroot"),
        c"newroot",
        None::<&CStr>,
        MsFlags::MS_SILENT | MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&CStr>,
    )
    .with_mount_context(|| "setting up newroot bind".to_string())?;
    mkdir("oldroot", dir_mode).context("Creating oldroot failed")?;

    let tmp_overlays = ops
        .iter()
        .filter(|o| {
            matches!(
                o,
                SetupOp::Overlay {
                    upper: OverlayUpper::Tmp,
                    ..
                }
            )
        })
        .count();
    for i in 0..tmp_overlays {
        mkdir(format!("tmp-overlay-upper-{i}").as_str(), dir_mode)
            .context("Creating --tmp-overlay upperdir failed")?;
        mkdir(format!("tmp-overlay-work-{i}").as_str(), dir_mode)
            .context("Creating --tmp-overlay workdir failed")?;
    }

    pivot_root(BASE, "oldroot").context("pivot_root")?;
    chdir("/").context("chdir / (base path)")?;

    // Bind /proc so the /proc/self/fd/N paths used by fd-based mounts resolve.
    mkdir("proc", dir_mode).context("Creating proc failed")?;
    mount(
        Some(c"oldroot/proc"),
        c"proc",
        None::<&CStr>,
        MsFlags::MS_SILENT | MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&CStr>,
    )
    .with_mount_context(|| "mounting proc".to_string())?;

    setup_newroot(ops, ctx, fds)?;

    // The old root must be rprivate or unmounts would propagate to the parent.
    mount(
        Some(c"oldroot"),
        c"oldroot",
        None::<&CStr>,
        MsFlags::MS_SILENT | MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&CStr>,
    )
    .with_mount_context(|| "Failed to make old root rprivate".to_string())?;
    umount2("oldroot", MntFlags::MNT_DETACH).context("unmount old root")?;

    // Second pivot: make /newroot the real root and drop the old one.
    let oldrootfd = nix::fcntl::open(c"/", OFlag::O_DIRECTORY | OFlag::O_RDONLY, NixMode::empty())
        .context("can't open /")?;
    chdir("/newroot").context("chdir /newroot")?;
    pivot_root(".", ".").context("pivot_root(/newroot)")?;
    fchdir(oldrootfd.as_fd()).context("fchdir to oldroot")?;
    umount2(".", MntFlags::MNT_DETACH).context("umount old root")?;
    chdir("/").context("chdir /")?;

    Ok(old_cwd)
}

/// Cover the writable legacy `/proc` subdirs by bind-mounting each read-only on
/// itself, when accessible (bwrap's `cover_proc_dirs` loop).
fn cover_proc_dirs(dest_fd: BorrowedFd<'_>, dest_display: &[u8]) -> Result<()> {
    for name in [b"sys".as_slice(), b"sysrq-trigger", b"irq", b"bus"] {
        let cname = cpath(name)?;
        match faccessat(
            dest_fd,
            cname.as_c_str(),
            AccessFlags::W_OK,
            AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(Errno::EACCES | Errno::ENOENT | Errno::EROFS) => continue,
            Err(e) => {
                return Err(Error::Sys {
                    message: format!("Can't access {}/{}", disp(dest_display), disp(name)).into(),
                    errno: e,
                });
            }
        }
        let subdir = openat(
            dest_fd,
            cname.as_c_str(),
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            NixMode::empty(),
        )
        .with_context(|| format!("Can't open {}/{}", disp(dest_display), disp(name)))?;
        let ro = BindOptions {
            readonly: true,
            ..BindOptions::default()
        };
        setup_op_bind_mount_fd(ro, subdir.as_fd(), name, subdir.as_fd(), name)?;
    }
    Ok(())
}

/// Populate a freshly-mounted `/dev` tmpfs (bwrap's `SETUP_MOUNT_DEV` body):
/// device nodes, stdio symlinks, `shm`/`pts`, devpts, ptmx, and `/dev/console`.
fn setup_dev(dest_fd: BorrowedFd<'_>, dest_display: &[u8], ctx: &NewrootCtx) -> Result<()> {
    for dev in [
        b"null".as_slice(),
        b"zero",
        b"full",
        b"random",
        b"urandom",
        b"tty",
    ] {
        let node = ensure_node_at(
            dest_fd,
            dev,
            NodeType::File,
            Some(NixMode::from_bits_truncate(0o444)),
        )
        .with_context(|| format!("Can't create file {}/{}", disp(dest_display), disp(dev)))?;
        let mut src = b"/dev/".to_vec();
        src.extend_from_slice(dev);
        let devices = BindOptions {
            devices: true,
            ..BindOptions::default()
        };
        setup_op_bind_mount(devices, &src, node.as_fd(), dev)?;
    }

    for (i, name) in [b"stdin".as_slice(), b"stdout", b"stderr"]
        .iter()
        .enumerate()
    {
        let target = format!("/proc/self/fd/{i}");
        symlinkat(
            cpath(target.as_bytes())?.as_c_str(),
            dest_fd,
            cpath(name)?.as_c_str(),
        )
        .with_context(|| format!("Can't create symlink {}/{}", disp(dest_display), disp(name)))?;
    }
    symlinkat(c"/proc/self/fd", dest_fd, c"fd")
        .with_context(|| format!("Can't create symlink {}/fd", disp(dest_display)))?;
    symlinkat(c"/proc/kcore", dest_fd, c"core")
        .with_context(|| format!("Can't create symlink {}/core", disp(dest_display)))?;

    mkdirat(dest_fd, c"shm", NixMode::from_bits_truncate(0o755))
        .with_context(|| format!("Can't create {}/shm", disp(dest_display)))?;
    mkdirat(dest_fd, c"pts", NixMode::from_bits_truncate(0o755))
        .with_context(|| format!("Can't create {}/pts", disp(dest_display)))?;

    let pts = openat(
        dest_fd,
        c"pts",
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        NixMode::empty(),
    )
    .with_context(|| format!("Can't open {}/pts", disp(dest_display)))?;
    let pts_path = cpath(proc_self_fd(pts.as_fd()).as_bytes())?;
    mount(
        Some(c"devpts"),
        pts_path.as_c_str(),
        Some(c"devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some(c"newinstance,ptmxmode=0666,mode=620"),
    )
    .with_mount_context(|| format!("Can't mount devpts on {}/pts", disp(dest_display)))?;

    symlinkat(c"pts/ptmx", dest_fd, c"ptmx")
        .with_context(|| format!("Can't make symlink at {}/ptmx", disp(dest_display)))?;

    if let Some(tty) = &ctx.host_tty_dev
        && !tty.is_empty()
    {
        let console = ensure_node_at(
            dest_fd,
            b"console",
            NodeType::File,
            Some(NixMode::from_bits_truncate(0o444)),
        )
        .with_context(|| format!("creating {}/console", disp(dest_display)))?;
        let devices = BindOptions {
            devices: true,
            ..BindOptions::default()
        };
        setup_op_bind_mount(devices, tty, console.as_fd(), b"console")?;
    }
    Ok(())
}

/// Write the `--bind-data` fd into a temp file in the root tmpfs with `perms`,
/// bind it, and unlink the backing file (bwrap's `SETUP_MAKE_BIND_FILE`).
fn bind_data_tmpfile(
    perms: Mode,
    fd: std::os::fd::RawFd,
    dest_display: &[u8],
    fds: &mut FdTable,
) -> Result<(OwnedFd, String)> {
    // A fresh, exclusively-created file in the root tmpfs ("/" is the new tmpfs
    // root at this point in setup). The caller binds it and THEN unlinks the
    // name (unlinking before the bind would make the /proc/self/fd source a
    // deleted path, which mount(2) rejects with ENOENT).
    let name = format!("/bindfile-{}-{}", std::process::id(), fd);
    let tmp = nix::fcntl::open(
        cpath(name.as_bytes())?.as_c_str(),
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC,
        NixMode::from_bits_truncate(0o600),
    )
    .with_context(|| format!("Can't create tmpfile for {}", disp(dest_display)))?;
    fchmod(tmp.as_fd(), nixmode(perms)).with_context(|| {
        format!(
            "Can't set mode {} on file to be used for {}",
            c_alt_octal(perms.bits()),
            disp(dest_display)
        )
    })?;
    fds.register(fd);
    let src = fds.borrow(fd).expect("bind-data src just registered");
    copy_file_data(src, tmp.as_fd())
        .with_context(|| format!("Can't write data to file {}", disp(dest_display)))?;
    // Close the data fd after copying (bubblewrap.c:1547) so a reused
    // --bind-data/--ro-bind-data fd fails with EBADF like bubblewrap.
    fds.close(fd);
    Ok((tmp, name))
}

/// Create a symlink, tolerating an identical existing one (bwrap's
/// `SETUP_MAKE_SYMLINK` case): an existing non-symlink, or a symlink to a
/// different target, is an error with bwrap's exact text.
fn make_symlink(
    parent_fd: BorrowedFd<'_>,
    name: &[u8],
    target: &[u8],
    dest_display: &[u8],
) -> Result<()> {
    let cname = cpath(name)?;
    let ctarget = cpath(target)?;
    match symlinkat(ctarget.as_c_str(), parent_fd, cname.as_c_str()) {
        Ok(()) => Ok(()),
        Err(Errno::EEXIST) => match readlinkat(parent_fd, cname.as_c_str()) {
            Ok(existing) if existing.as_bytes() == target => Ok(()),
            Ok(existing) => Err(Error::invalid(format!(
                "Can't make symlink at {}: existing destination is {}",
                disp(dest_display),
                existing.to_string_lossy()
            ))),
            Err(Errno::EINVAL) => Err(Error::invalid(format!(
                "Can't make symlink at {}: destination exists and is not a symlink",
                disp(dest_display)
            ))),
            Err(e) => Err(Error::Sys {
                message: format!(
                    "Can't make symlink at {}: destination exists, and cannot read symlink target",
                    disp(dest_display)
                )
                .into(),
                errno: e,
            }),
        },
        Err(e) => Err(Error::Sys {
            message: format!("Can't make symlink at {}", disp(dest_display)).into(),
            errno: e,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount::bind::{BindError, BindErrorKind};
    use nix::errno::Errno;

    fn err(kind: BindErrorKind, path: &str, errno: Option<Errno>) -> BindError {
        BindError {
            kind,
            failing_path: Some(path.as_bytes().to_vec()),
            errno,
        }
    }

    #[test]
    fn bind_failure_prepends_prefix_and_keeps_errno() {
        // OpenFd uses plain strerror; glibc ENOENT text is stable.
        let e = err(BindErrorKind::OpenFd, "/b", Some(Errno::ENOENT));
        let msg = bind_failure("Can't bind mount /a on /b".into(), &e).to_string();
        assert_eq!(
            msg,
            "Can't bind mount /a on /b: Unable to open destination O_PATH fd \"/b\": No such file or directory"
        );
    }

    #[test]
    fn bind_failure_find_dest_mount_has_no_errno() {
        // FindDestMount is bwrap's want_errno = false case: no trailing errno.
        let e = err(BindErrorKind::FindDestMount, "/b", Some(Errno::ENOENT));
        let msg = bind_failure("Can't remount readonly on /b".into(), &e).to_string();
        assert_eq!(
            msg,
            "Can't remount readonly on /b: Unable to find \"/b\" in mount table"
        );
    }

    #[test]
    fn bind_failure_mount_uses_mount_strerror() {
        // Mount uses mount_strerror; the message starts with the fixed text.
        let e = err(BindErrorKind::Mount, "/b", Some(Errno::EACCES));
        let msg = bind_failure("Can't bind mount /a on /b".into(), &e).to_string();
        assert!(
            msg.starts_with("Can't bind mount /a on /b: Unable to mount source on destination: "),
            "got: {msg}"
        );
    }

    #[test]
    fn parent_mode_least_astonishment() {
        // No perms: plain 0755.
        assert_eq!(parent_mode(None), 0o755);
        // Group+other accessible: unchanged.
        assert_eq!(parent_mode(Some(Mode::from_bits(0o755))), 0o755);
        // No group access: drop group search (0050) from parents.
        assert_eq!(parent_mode(Some(Mode::from_bits(0o700))), 0o700);
        // No other access: drop other search (0005).
        assert_eq!(parent_mode(Some(Mode::from_bits(0o750))), 0o750);
        // 0640: group has read (0o040 != 0) so group bits stay; other is 0, so
        // only the other-search bit is dropped -> 0750 (matches bwrap).
        assert_eq!(parent_mode(Some(Mode::from_bits(0o640))), 0o750);
    }

    #[test]
    fn bind_opts_maps_kinds() {
        assert!(!bind_opts(BindKind::ReadWrite, false).readonly);
        assert!(!bind_opts(BindKind::ReadWrite, false).devices);
        assert!(bind_opts(BindKind::ReadOnly, false).readonly);
        assert!(bind_opts(BindKind::Dev, false).devices);
        assert!(bind_opts(BindKind::ReadWrite, true).fail_open);
        assert!(!bind_opts(BindKind::ReadWrite, false).fail_open);
    }

    #[test]
    fn proc_prefix_check_is_component_aware() {
        use crate::mount::mountinfo::has_path_prefix;
        let is_proc = |p: &[u8]| has_path_prefix(p, b"/proc");
        assert!(is_proc(b"/proc"));
        assert!(is_proc(b"/proc/self/ns/user"));
        // Leading/repeated slashes are a /proc path too (bwrap's has_path_prefix),
        // the regression from the old `== "/proc" || starts_with("/proc/")` check.
        assert!(is_proc(b"//proc/self/ns/user"));
        assert!(is_proc(b"//proc/self"));
        assert!(is_proc(b"proc/self"));
        assert!(!is_proc(b"/process"));
        assert!(!is_proc(b"/procfs"));
        assert!(!is_proc(b"/var/proc"));
    }

    #[test]
    fn overlay_options_match_bwrap() {
        // Read-only: no upper/work, just the lowerdir list + userxattr.
        assert_eq!(
            overlay_options(
                &OverlayOpt::ReadOnly,
                &["/proc/self/fd/5".into(), "/proc/self/fd/6".into()]
            ),
            "lowerdir=/proc/self/fd/5:/proc/self/fd/6,userxattr"
        );
        // Persistent upper+work prefix.
        assert_eq!(
            overlay_options(
                &OverlayOpt::Persistent {
                    upper: "/proc/self/fd/3".into(),
                    work: "/proc/self/fd/4".into()
                },
                &["/proc/self/fd/5".into()]
            ),
            "upperdir=/proc/self/fd/3,workdir=/proc/self/fd/4,lowerdir=/proc/self/fd/5,userxattr"
        );
        // Tmp overlay uses the indexed well-known paths.
        assert_eq!(
            overlay_options(&OverlayOpt::Tmp { idx: 2 }, &["/proc/self/fd/5".into()]),
            "upperdir=/tmp-overlay-upper-2,workdir=/tmp-overlay-work-2,lowerdir=/proc/self/fd/5,userxattr"
        );
    }
}
