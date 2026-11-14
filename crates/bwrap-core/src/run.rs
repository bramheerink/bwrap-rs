//! Top-level sandbox orchestration: the port of bubblewrap's `main()` from the
//! clone onwards. Wires the clone, the parent/child handshake, the uid/gid map,
//! `pivot_into_newroot`, privilege dropping, the environment, the optional pid-1
//! reaper, seccomp and the final `exec`.
//!
//! This covers the common unprivileged path and the already-root (rpm-ostree)
//! path, as well as the descriptor-driven modes — `--userns`/`--userns2`/
//! `--pidns`/`--userns-block-fd`/`--block-fd`, the second-level user namespace
//! for `--disable-userns`/remapped ids — and the SELinux `--exec-label`/
//! `--file-label` labelling.

use std::ffi::CString;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::sched::CloneFlags;
use nix::sys::stat::{Mode as NixMode, fstat};
use std::os::fd::AsRawFd;

use nix::unistd::{Pid, chdir, execvp, read, setsid};

use bwrap_sys::fd::FdTable;

use crate::caps::{drop_bounding_set, set_ambient};
use crate::error::{Context, Error, Result};
use crate::privs::{acquire_privs, drop_privs, switch_to_user_with_privs};
use crate::process::{
    NamespaceIds, block_sigchild, do_init, handle_die_with_parent, monitor_child, unblock_sigchild,
    write_all,
};
use crate::seccomp::SeccompPrograms;
use crate::setup::{NewrootCtx, pivot_into_newroot};
use crate::types::caps::CapOp;
use crate::types::config::NsPolicy;
use crate::types::op::{OnMissing, OverlayUpper};
use crate::types::{CapSet, Config, HostPath, ResolvedConfig, SetupOp};
use crate::userns::{IdMap, MapTarget, OverflowIds};

/// Run the sandbox described by `config` (already resolved into `resolved`).
/// Returns the exit code to propagate. `real_uid`/`real_gid` are the launcher's.
/// `fds` is the process fd-ownership table, already holding the `--args`/
/// `--seccomp` descriptors read at parse time; the inherited runtime fds are
/// registered here and every borrow/close of them goes through it.
pub fn run(
    config: &Config,
    resolved: &ResolvedConfig,
    real_uid: u32,
    real_gid: u32,
    fds: &mut FdTable,
) -> Result<i32> {
    // Wire the `--debug-opt=force-*-fallback` toggles from the parsed config into
    // the resolver and the mount engine (bwrap's global `opt_force_*`). Set before
    // the clone so the sandbox child inherits the choice. SELinux label validation
    // and the `--file-label` fscreate context are done at parse time, as bwrap
    // does, not here (the fscreate context is inherited across the clone).
    crate::fs::set_force_openat_fallback(config.force_openat_fallback);
    crate::mount::set_force_mount_setattr_fallback(config.force_mount_setattr_fallback);

    // The Rust runtime forces SIGPIPE to SIG_IGN at startup; bwrap (C) never
    // touches SIGPIPE, so its child inherits whatever disposition bwrap was
    // launched with. Restore that inherited disposition before the clone so the
    // sandbox and the exec'd command match C — including when a parent passed
    // SIG_IGN through (e.g. a CI runner), not just the usual SIG_DFL case.
    bwrap_sys::process::restore_inherited_sigpipe();

    // Open the optional profile log (BWRAP_RS_PROFILE) before the clone so the
    // sandbox child inherits the fd. A no-op when the variable is unset.
    crate::profile::init();

    // Record every inherited runtime caller fd in the ownership table before the
    // clone, so both the launcher and the sandbox child — which closes some of
    // them with no preceding borrow — operate on owned numbers rather than bare
    // integers. Each use site re-registers idempotently to mirror bubblewrap's
    // per-fd-variable reuse (a second `--file N` reads the now-closed number and
    // fails with EBADF), and every close goes through the table so a number is
    // closed exactly once.
    for &fd in config
        .userns_fd
        .iter()
        .chain(config.userns2_fd.iter())
        .chain(config.pidns_fd.iter())
        .chain(config.userns_block_fd.iter())
        .chain(config.info_fd.iter())
        .chain(config.json_status_fd.iter())
        .chain(config.block_fd.iter())
        .chain(config.sync_fds.iter())
    {
        fds.register(fd);
    }
    if let crate::types::SeccompSource::Single(fd) = &config.seccomp {
        fds.register(*fd);
    }
    for op in &config.ops {
        match op {
            SetupOp::File { fd, .. }
            | SetupOp::BindData { fd, .. }
            | SetupOp::BindFd { fd, .. } => fds.register(*fd),
            _ => {}
        }
    }

    // The process that invoked bwrap, captured before the clone, for the
    // launcher's die-with-parent reparent check (#700).
    let invoker = nix::unistd::getppid();

    // acquire_privs: seed the requested caps (effective as root, else empty),
    // then fold in --cap-add/--cap-drop.
    let is_root = real_uid == 0;
    let requested = CapOp::fold(acquire_privs()?, &config.cap_ops);
    let cap_used = config.cap_add_or_drop_used;

    // Never gain privileges through a later exec. Set before the clone so the
    // sandbox inherits it; the whole capability model AND `--seccomp` (which
    // installs a filter with no caps) depend on it.
    nix::sys::prctl::set_no_new_privs().context("prctl(PR_SET_NO_NEW_PRIVS) failed")?;

    // Join a custom user namespace before the clone, which gives us privileges
    // in it (it must be a descendant of ours). `--unshare-user` is mutually
    // exclusive with this, so the clone below won't also make a new userns.
    if let Some(fd) = config.userns_fd {
        fds.register(fd);
        let bf = fds.borrow(fd).expect("userns_fd just registered");
        nix::sched::setns(bf, CloneFlags::CLONE_NEWUSER).map_err(|e| {
            if e == Errno::EINVAL {
                Error::invalid(
                    "Joining the specified user namespace failed, it might not be a descendant of the current user namespace.",
                )
            } else {
                Error::Sys { message: "Joining specified user namespace failed".into(), errno: e }
            }
        })?;
    }

    let ns = &resolved.namespaces;
    // With `--pidns` the pid namespace is joined (and optionally re-unshared) in
    // the child via setns/unshare, so the clone itself must not create one.
    let mut clone_flags = clone_flags(ns);
    if config.pidns_fd.is_some() {
        clone_flags.remove(CloneFlags::CLONE_NEWPID);
    }
    let host_tty = host_tty_dev();

    // `--pidns`: become a subreaper so we can reap the real (grand)child, and set
    // up the socket that carries its pid-namespace-translated pid back to us.
    if config.pidns_fd.is_some() {
        nix::sys::prctl::set_child_subreaper(true).context("prctl(PR_SET_CHILD_SUBREAPER)")?;
    }
    let pid_sockets = if config.pidns_fd.is_some() {
        Some(create_pid_socketpair()?)
    } else {
        None
    };

    // Handshake and lifecycle fds (8-byte payloads, like bwrap's eventfds). The
    // launcher->child "go" channel is a socketpair, not a pipe, so the launcher
    // can signal with MSG_NOSIGNAL (see parent()) without risking SIGPIPE, while
    // a stream socket still gives the child EOF if the launcher dies (see child()).
    let (cw_r, cw_w) = child_wait_pair()?; // launcher -> child: "maps ready, go"
    // The event pipe (pid-1 -> monitor: exit status + 1) exists ONLY when there
    // is a pid-namespace init to report through it, exactly as bwrap creates its
    // eventfd only for `opt_unshare_pid && !opt_as_pid_1`. In every other case
    // the monitor learns the exit status from waitpid via its signalfd; polling
    // an event fd whose only writer is the exec'd child's CLOEXEC copy (which
    // closes on exec) would spin forever on POLLHUP/EOF and peg a CPU core.
    let event_pipe = if ns.pid == NsPolicy::Unshare && !config.as_pid_1 {
        let (r, w) = pipe_pair()?;
        set_nonblocking(r.as_fd())?; // monitor reads the event fd non-blocking
        Some((r, w))
    } else {
        None
    };
    let setup_pipe = match config.json_status_fd {
        Some(_) => Some(pipe_pair()?),
        None => None,
    };

    block_sigchild()?;

    match bwrap_sys::process::clone_into_namespaces(clone_flags) {
        Ok(nix::unistd::ForkResult::Child) => {
            // Child keeps: cw_r (wait), ev_w (do_init, if any), setup write end.
            drop(cw_w);
            let ev_w = event_pipe.map(|(r, w)| {
                drop(r);
                w
            });
            let setup_w = setup_pipe.map(|(r, w)| {
                drop(r);
                w
            });
            // `--pidns`: enter the target pid namespace (and optionally a nested
            // new one), then report the real pid back to the launcher. After the
            // intermediate forks, only the final sandbox process continues here.
            if let Some((s0, s1)) = pid_sockets {
                if let Some(fd) = config.pidns_fd {
                    fds.register(fd);
                    let bf = fds.borrow(fd).expect("pidns_fd just registered");
                    nix::sched::setns(bf, CloneFlags::CLONE_NEWPID)
                        .map_err(|e| Error::Sys {
                            message: "Setting pidns failed".into(),
                            errno: e,
                        })
                        .unwrap_or_else(die_in_child);
                    fork_intermediate().unwrap_or_else(die_in_child);
                    if resolved.namespaces.pid == NsPolicy::Unshare {
                        nix::sched::unshare(CloneFlags::CLONE_NEWPID)
                            .map_err(|e| Error::Sys {
                                message: "unshare pid ns".into(),
                                errno: e,
                            })
                            .unwrap_or_else(die_in_child);
                        fork_intermediate().unwrap_or_else(die_in_child);
                    }
                }
                drop(s0);
                send_pid(s1.as_fd()).unwrap_or_else(die_in_child);
                drop(s1);
            }
            let code = child(
                config, resolved, real_uid, real_gid, requested, cap_used, is_root, &host_tty,
                cw_r, ev_w, setup_w, fds,
            );
            match code {
                Ok(c) => bwrap_sys::process::exit_immediately(c),
                Err(e) => {
                    crate::log::emit_err(&crate::log::error_line(&e.to_string()));
                    bwrap_sys::process::exit_immediately(1);
                }
            }
        }
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            // Launcher keeps: cw_w (signal), ev_r (monitor, if any), setup read end.
            drop(cw_r);
            let ev_r = event_pipe.map(|(r, w)| {
                drop(w);
                r
            });
            let setup_r = setup_pipe.map(|(r, w)| {
                drop(w);
                r
            });
            // `--pidns`: our direct child is an intermediate that exits; the real
            // sandbox pid (translated into our pid namespace) arrives on the
            // socket, and the subreaper lets us reap the reparented grandchild.
            let child = match pid_sockets {
                Some((s0, s1)) => {
                    drop(s1);
                    let real = read_pid(s0.as_fd())?;
                    drop(s0);
                    real
                }
                None => child,
            };
            parent(
                config, resolved, child, invoker, cap_used, is_root, cw_w, ev_r, setup_r, fds,
            )
        }
        Err(e) => Err(clone_error(
            resolved.namespaces.user == NsPolicy::Unshare,
            e,
        )),
    }
}

/// The launcher side after the clone: read namespace ids, drop all privileges,
/// emit `--info-fd`/`--json-status-fd`, release the child, and monitor it.
#[expect(
    clippy::too_many_arguments,
    reason = "launcher-side orchestration threads the config, resolved ids and several fds; a ChildCtx struct is a tracked post-1.0 cleanup"
)]
fn parent(
    config: &Config,
    resolved: &ResolvedConfig,
    child: Pid,
    invoker: Pid,
    cap_used: bool,
    is_root: bool,
    cw_w: OwnedFd,
    ev_r: Option<OwnedFd>,
    setup_r: Option<OwnedFd>,
    fds: &mut FdTable,
) -> Result<i32> {
    let ns_ids = namespace_ids_read(child, &resolved.namespaces)?;
    // Optionally join a second user namespace (bwrap's `--userns2`).
    if let Some(fd) = config.userns2_fd {
        fds.register(fd);
        let bf = fds.borrow(fd).expect("userns2_fd just registered");
        nix::sched::setns(bf, CloneFlags::CLONE_NEWUSER).context("Setting userns2 failed")?;
    }
    // The launcher needs no privileges.
    drop_privs(None, cap_used, is_root)?;
    // The launcher binds its lifecycle to whoever invoked bwrap.
    handle_die_with_parent(config.die_with_parent, invoker)?;

    if let Some(fd) = config.info_fd {
        let doc = crate::process::sandbox_info_json(
            crate::process::InfoFormat::Info,
            child.as_raw(),
            &ns_ids,
        );
        fds.register(fd);
        let bf = fds.borrow(fd).expect("info_fd just registered");
        crate::process::dump_info(bf, doc.as_bytes())?;
        // bwrap closes --info-fd here, right after writing and before the
        // --userns-block-fd wait, so a helper that reads the info pipe to EOF
        // before releasing the block fd does not deadlock.
        fds.close(fd);
    }
    if let Some(fd) = config.json_status_fd {
        let doc = crate::process::sandbox_info_json(
            crate::process::InfoFormat::JsonStatus,
            child.as_raw(),
            &ns_ids,
        );
        // Re-register: if `--json-status-fd` aliased `--info-fd`, the close above
        // removed the number, and C writes json to that same (now closed) number
        // and fails at the write — so borrow the stale number to reproduce it.
        fds.register(fd);
        let bf = fds.borrow(fd).expect("json_status_fd just registered");
        crate::process::dump_info(bf, doc.as_bytes())?;
    }

    // With `--userns-block-fd`, an external process writes the child's maps and
    // signals us here (it learned the child pid from `--info-fd`). Wait for it.
    if let Some(fd) = config.userns_block_fd {
        fds.register(fd);
        let bf = fds.borrow(fd).expect("userns_block_fd just registered");
        let mut b = [0u8; 1];
        let _ = read(bf, &mut b);
        fds.close(fd);
    }

    // Let the child proceed now that its maps are set up. Ignore the result,
    // exactly as bwrap does (bubblewrap.c:3181, "Ignore res, if e.g. the child
    // died"): if the child is already gone the send fails, but we must still fall
    // through to monitor_child to reap it and report its real exit status —
    // instead of dying here (e.g. SIGPIPE/exit 141) and losing that status.
    // MSG_NOSIGNAL keeps this one send from raising SIGPIPE; the launcher's own
    // --info-fd/--json-status-fd writes keep C's SIG_DFL behaviour.
    let _ = nix::sys::socket::send(
        cw_w.as_raw_fd(),
        &1u64.to_ne_bytes(),
        nix::sys::socket::MsgFlags::MSG_NOSIGNAL,
    );
    drop(cw_w);

    let json = if let Some(fd) = config.json_status_fd {
        fds.register(fd);
        fds.borrow(fd)
    } else {
        None
    };
    monitor_child(
        ev_r.as_ref().map(AsFd::as_fd),
        child,
        setup_r.as_ref().map(AsFd::as_fd),
        json,
    )
}

/// The sandbox side after the clone: wait for the launcher, switch user, write
/// maps, build the new root, drop privileges, set up the environment, optionally
/// become pid-1's reaper, then `exec`.
#[expect(
    clippy::too_many_arguments,
    reason = "sandbox-side orchestration threads the config, resolved ids and several fds; a ChildCtx struct is a tracked post-1.0 cleanup"
)]
fn child(
    config: &Config,
    resolved: &ResolvedConfig,
    real_uid: u32,
    real_gid: u32,
    requested: CapSet,
    cap_used: bool,
    is_root: bool,
    host_tty: &Option<Vec<u8>>,
    cw_r: OwnedFd,
    ev_w: Option<OwnedFd>,
    setup_w: Option<OwnedFd>,
    fds: &mut FdTable,
) -> Result<i32> {
    let ns = &resolved.namespaces;
    let unshare_user = ns.user == NsPolicy::Unshare;

    // The caller's status fds must not leak into the sandbox (bwrap closes them
    // in the child right after the clone). Our copies are a separate fd table
    // after the clone, so closing them here does not affect the launcher. The
    // numbers were registered before the clone, so the table closes them once
    // (an alias of the same number is already gone and closing is a no-op).
    if let Some(fd) = config.info_fd {
        fds.close(fd);
    }
    if let Some(fd) = config.json_status_fd {
        fds.close(fd);
    }

    // Wait for the launcher to finish its setup. A full 8-byte read is "go".
    // Anything else — EOF (the launcher died before signalling) or an error —
    // means the launcher is gone: exit without printing and without running the
    // command, so a failed or aborted launch never leaves an unmonitored sandbox
    // process behind (e.g. a `?` error in parent(), or the launcher killed while
    // waiting on --userns-block-fd). This is stricter than bubblewrap, whose
    // eventfd child would block forever instead; recorded in DIFFERENCES.md.
    let mut buf = [0u8; 8];
    let mut got = 0;
    let launcher_ready = loop {
        match read(cw_r.as_fd(), &mut buf[got..]) {
            Ok(0) => break false, // EOF: the launcher is gone
            Ok(n) => {
                got += n;
                if got == buf.len() {
                    break true;
                }
            }
            Err(Errno::EINTR) => {}
            Err(_) => break false,
        }
    };
    if !launcher_ready {
        bwrap_sys::process::exit_immediately(1);
    }
    drop(cw_r);
    // The launcher is alive here (it just signalled us), so this is the valid
    // parent for die-with-parent.
    let mut exec_parent = nix::unistd::getppid();

    let sp = crate::profile::span("child.switch_user");
    switch_to_user_with_privs(
        unshare_user,
        config.userns_fd.is_some(),
        requested,
        real_uid,
        resolved.sandbox_uid,
        real_gid,
        resolved.sandbox_gid,
    )?;
    drop(sp);

    if ns.net == NsPolicy::Unshare {
        crate::net::loopback_setup()?;
    }

    // `--hostname` is no longer set here: each occurrence is a `SetupOp::SetHostname`
    // run in command-line order inside `setup_newroot` (bwrap's
    // `SETUP_SET_HOSTNAME`), so an invalid earlier value fails where bwrap fails.

    // Open a single O_PATH handle to the host /proc and read the kernel
    // overflow ids up front, before any pivot — exactly as bwrap does. Both are
    // needed again after the pivot (to write the second-level uid/gid map and,
    // with --disable-userns, to lock userns), but the sandbox root may not mount
    // /proc at all: `--dev` without `--proc` (as GNOME's glycin image loaders
    // do) leaves no /proc behind. Reading or reopening /proc late would then
    // fail and abort the sandbox. The O_PATH fd keeps the host procfs reachable
    // via openat() across the pivot; every tests had `--proc /proc`, which is
    // why this path went unseen.
    let proc_fd = open("/proc", OFlag::O_PATH | OFlag::O_CLOEXEC, NixMode::empty())
        .context("Can't open /proc")?;
    let overflow = OverflowIds::read()?;

    // `--dev` mounts devpts, which needs the mounter to be root in the user
    // namespace. In that case we first map the real id to 0, then (after the
    // pivot) create a second user namespace mapping 0 back to the sandbox id.
    let needs_devpts = config.ops.iter().any(|o| matches!(o, SetupOp::Dev { .. }));
    let (ns_uid, ns_gid) = if needs_devpts {
        (0, 0)
    } else {
        (resolved.sandbox_uid, resolved.sandbox_gid)
    };

    // Unprivileged: write our own uid/gid map inside the new user namespace.
    // With `--userns-block-fd` an external process writes the maps instead.
    if unshare_user && config.userns_block_fd.is_none() {
        let idmap = IdMap {
            sandbox_uid: ns_uid,
            parent_uid: real_uid,
            sandbox_gid: ns_gid,
            parent_gid: real_gid,
            overflow,
            map_root: false,
            deny_groups: true,
        };
        idmap.write(proc_fd.as_fd(), MapTarget::SelfProc)?;
    }

    let old_umask = nix::sys::stat::umask(NixMode::empty());

    let ctx = NewrootCtx {
        unshare_pid: ns.pid == NsPolicy::Unshare,
        have_pidns_fd: config.pidns_fd.is_some(),
        not_a_security_boundary: config.not_a_security_boundary,
        host_tty_dev: host_tty.clone(),
        file_label: config.file_label.clone(),
    };
    // Resolve symlinks in the op sources against the real root before pivoting
    // (and fail early on a missing source with the right message).
    let resolved_ops = resolve_symlinks_in_ops(&config.ops)?;
    let sp = crate::profile::span("child.setup_newroot");
    let old_cwd = pivot_into_newroot(&resolved_ops, &ctx, fds)?;
    drop(sp);

    // Close the op source fds now that setup has consumed them, so the exec'd
    // sandbox never inherits them (bwrap's `close_ops_fd`, called right after
    // `setup_newroot`). Every op has been applied by the pivot above, and the
    // oldroot teardown it also performed does not touch these fds, so closing
    // here is equivalent to bwrap's placement. Without this, a launcher fd
    // passed to `--file`/`--bind-data`/`--bind-fd` would leak into the sandbox.
    // `setup_newroot` already closed each op's data fd through the table as it
    // applied the op (so a reused `--file N` fails with EBADF), so these closes
    // are now no-ops on the table; they remain as a defensive backstop matching
    // bwrap's `close_ops_fd` placement.
    for op in &config.ops {
        match op {
            SetupOp::File { fd, .. }
            | SetupOp::BindData { fd, .. }
            | SetupOp::BindFd { fd, .. } => fds.close(*fd),
            _ => {}
        }
    }

    // Optionally join a second user namespace (bwrap's `--userns2`), after the
    // pivot, as the sandbox side does.
    if let Some(fd) = config.userns2_fd {
        fds.register(fd);
        let bf = fds.borrow(fd).expect("userns2_fd just registered");
        nix::sched::setns(bf, CloneFlags::CLONE_NEWUSER).context("Setting userns2 failed")?;
    }

    // Second-level user namespace: map back to the sandbox uid/gid after the
    // devpts root trick, and/or lock out further userns creation for
    // --disable-userns (so the sandbox cannot undo the restriction).
    if unshare_user
        && config.userns_block_fd.is_none()
        && (ns_uid != resolved.sandbox_uid
            || ns_gid != resolved.sandbox_gid
            || config.disable_userns)
    {
        if config.disable_userns {
            crate::userns::disable_user_namespaces(proc_fd.as_fd())?;
        }
        nix::sched::unshare(CloneFlags::CLONE_NEWUSER).context("unshare user ns")?;
        // The new userns restored the bounding set; clear it again (keeping the
        // requested caps), as bwrap's drop_cap_bounding_set(false) does.
        drop_bounding_set(requested)?;
        IdMap {
            sandbox_uid: resolved.sandbox_uid,
            parent_uid: ns_uid,
            sandbox_gid: resolved.sandbox_gid,
            parent_gid: ns_gid,
            overflow,
            map_root: false,
            deny_groups: false,
        }
        .write(proc_fd.as_fd(), MapTarget::SelfProc)?;
    }

    if config.disable_userns || config.assert_userns_disabled {
        // Verify we really can no longer create a user namespace.
        if nix::sched::unshare(CloneFlags::CLONE_NEWUSER).is_ok() {
            return Err(Error::invalid(
                "creation of new user namespaces was not disabled as requested",
            ));
        }
    }

    // All privileged ops done; keep only the requested caps.
    drop_privs(Some(requested), cap_used, is_root)?;

    // `--block-fd`: wait for an external process to let us continue.
    if let Some(fd) = config.block_fd {
        fds.register(fd);
        let bf = fds.borrow(fd).expect("block_fd just registered");
        let mut b = [0u8; 1];
        let _ = read(bf, &mut b);
        fds.close(fd);
    }

    // Load seccomp now (reads the fds), apply just before exec. The single
    // `--seccomp FD` is read through the table (bwrap's `seccomp_program_new`
    // reads the fd and closes it before the pid-1 fork, so it cannot leak into
    // the sandbox); `--add-seccomp-fd` programs were already read at parse time.
    let sp = crate::profile::span("child.seccomp_load");
    let seccomp = SeccompPrograms::load(&config.seccomp, |fd| read_all_fd(fd, fds))?;
    drop(sp);

    nix::sys::stat::umask(old_umask);

    // Environment, then cwd, then PWD (bwrap's order), applied in place to the
    // real environ exactly as C does (clearenv/setenv/unsetenv), never rebuilt
    // from a snapshot — so malformed/duplicate inherited entries pass through
    // unchanged and a `--setenv` on a duplicated name behaves like bubblewrap.
    apply_env_ops(&config.env_ops)?;
    let new_cwd = compute_cwd(config, old_cwd.as_deref())?;
    // PWD is set after the cwd is known (bwrap sets it last), so it is a separate
    // single op routed through the same gated apply_env. The NUL case cannot
    // occur for a path, so skip defensively rather than panicking.
    if let Ok(pwd) = CString::new(new_cwd.clone()) {
        env_apply(&[bwrap_sys::process::EnvOp::Set(
            CString::new("PWD").expect("PWD has no NUL"),
            pwd,
        )])?;
    }

    if config.new_session {
        setsid().context("setsid")?;
    }

    // pid-1 reaper when there is no single exec to own the namespace.
    let unshare_pid = ns.pid == NsPolicy::Unshare;
    if !config.as_pid_1
        && (unshare_pid || !config.lock_files.is_empty() || !config.sync_fds.is_empty())
    {
        match bwrap_sys::process::fork_single_threaded() {
            Ok(nix::unistd::ForkResult::Parent { child: app }) => {
                drop_privs(None, cap_used, is_root)?;
                // Release the setup-finished write end (owned) before the fd
                // walk closes its number, or its later drop would double-close
                // (see the module-10 close_extra_fds caveat). pid 2 keeps its
                // own copy for the exec-side write.
                drop(setup_w);
                let mut keep: Vec<std::os::fd::RawFd> = Vec::new();
                if let Some(efd) = &ev_w {
                    keep.push(efd.as_fd().as_raw_fd());
                }
                keep.extend(config.sync_fds.iter().copied());
                // Keep the /proc handle out of the walk (it is reading through
                // it, and a later double close would abort), then close it right
                // after: bwrap closes proc_fd in pid 1 too, so the sandbox keeps
                // no descriptor pointing at the host /proc.
                keep.push(proc_fd.as_raw_fd());
                bwrap_sys::process::close_extra_fds(proc_fd.as_fd(), &keep).context("fdwalk")?;
                drop(proc_fd);
                return do_init(
                    ev_w.as_ref().map(AsFd::as_fd),
                    app,
                    &config.lock_files,
                    &seccomp,
                    config.die_with_parent,
                );
            }
            Ok(nix::unistd::ForkResult::Child) => {
                // pid 2: our parent is now pid 1, not the launcher.
                exec_parent = nix::unistd::getppid();
            }
            Err(e) => return Err(Error::invalid(format!("Can't fork for pid 1: {e}"))),
        }
    }

    // Final child: exec the command. Close the caller's --sync-fd(s) unless
    // --as-pid-1 (bwrap leaks them only in the --as-pid-1 case), so the
    // sandboxed command never inherits them.
    if !config.as_pid_1 {
        for &fd in &config.sync_fds {
            fds.close(fd);
        }
    }

    unblock_sigchild()?;
    handle_die_with_parent(config.die_with_parent, exec_parent)?;
    // Apply the SELinux exec context (bwrap's label_exec) before exec.
    if let Err(e) = crate::selinux::label_exec(config.exec_label.as_deref()) {
        let errno = e.errno().unwrap_or(Errno::EINVAL);
        return Err(Error::Sys {
            message: format!("label_exec {}", config.command[0]).into(),
            errno,
        });
    }
    set_ambient(requested)?;
    seccomp.apply()?;

    // Setup-finished protocol (bwrap): one byte signals "about to exec". On a
    // successful exec the CLOEXEC write end closes, leaving exactly one byte, so
    // the monitor reports the exit code. If exec fails we write a SECOND byte,
    // so the monitor sees two and does NOT report an exit code for a child that
    // never ran.
    if let Some(sf) = &setup_w {
        let _ = write_all(sf.as_fd(), &[0u8]);
    }

    match exec_command(config) {
        // exec_command only returns on failure; on success execvpe replaced us.
        Ok(code) => Ok(code),
        Err(e) => {
            if let Some(sf) = &setup_w {
                let _ = write_all(sf.as_fd(), &[0u8]);
            }
            Err(e)
        }
    }
}

/// Build the `CLONE_*` flag set from the resolved namespace decisions. The mount
/// namespace is always created (the pivot needs it).
fn clone_flags(ns: &crate::types::config::NamespaceConfig) -> CloneFlags {
    let mut f = CloneFlags::CLONE_NEWNS;
    if ns.user == NsPolicy::Unshare {
        f |= CloneFlags::CLONE_NEWUSER;
    }
    if ns.pid == NsPolicy::Unshare {
        f |= CloneFlags::CLONE_NEWPID;
    }
    if ns.net == NsPolicy::Unshare {
        f |= CloneFlags::CLONE_NEWNET;
    }
    if ns.ipc == NsPolicy::Unshare {
        f |= CloneFlags::CLONE_NEWIPC;
    }
    if ns.uts == NsPolicy::Unshare {
        f |= CloneFlags::CLONE_NEWUTS;
    }
    if ns.cgroup == NsPolicy::Unshare {
        f |= CloneFlags::CLONE_NEWCGROUP;
    }
    f
}

/// Map a clone failure to bwrap's exact diagnostics. `unshare_user` is the
/// *resolved* decision (bwrap forces it on for any non-root user before this
/// check), not the raw `--unshare-user` flag, so the user-namespace guidance
/// fires for the common non-root invocation that never passed `--unshare-user`.
fn clone_error(unshare_user: bool, e: bwrap_sys::process::ForkError) -> Error {
    use bwrap_sys::process::ForkError;
    if let ForkError::Sys(errno) = e {
        if unshare_user {
            if errno == Errno::EINVAL {
                return Error::invalid(
                    "Creating new namespace failed, likely because the kernel does not support user namespaces.",
                );
            }
            if errno == Errno::EPERM {
                return Error::invalid(
                    "No permissions to create a new namespace, likely because the kernel does not allow non-privileged user namespaces. On e.g. debian this can be enabled with 'sysctl kernel.unprivileged_userns_clone=1'.",
                );
            }
        }
        if errno == Errno::ENOSPC {
            return Error::invalid(
                "Creating new namespace failed: nesting depth or /proc/sys/user/max_*_namespaces exceeded (ENOSPC)",
            );
        }
        return Error::Sys {
            message: "Creating new namespace failed".into(),
            errno,
        };
    }
    Error::invalid(format!("Creating new namespace failed: {e}"))
}

/// `ttyname(1)` when stdout is a tty, for `/dev/console` (bwrap's `host_tty_dev`).
fn host_tty_dev() -> Option<Vec<u8>> {
    use std::os::fd::AsFd;
    use std::os::unix::ffi::OsStrExt;
    // Borrow the real stdout safely (Stdout: AsFd) instead of fabricating a
    // BorrowedFd<'static> for fd 1 by hand.
    let out = std::io::stdout();
    nix::unistd::ttyname(out.as_fd())
        .ok()
        .map(|p| p.into_os_string().as_bytes().to_vec())
}

/// Read the sandbox process's namespace inode ids (bwrap's `namespace_ids_read`):
/// `stat(/proc/<pid>/ns/<name>).st_ino`, but ONLY for namespaces that were
/// actually unshared (bwrap's `do_unshare` gate). The mount namespace is always
/// unshared; a shared namespace's id stays 0 and is omitted from the output.
fn namespace_ids_read(
    pid: Pid,
    ns: &crate::types::config::NamespaceConfig,
) -> Result<NamespaceIds> {
    let one = |name: &str| -> u64 {
        let path = format!("/proc/{}/ns/{name}", pid.as_raw());
        match open(
            path.as_str(),
            OFlag::O_PATH | OFlag::O_CLOEXEC,
            NixMode::empty(),
        ) {
            Ok(fd) => fstat(fd.as_fd()).map(|st| st.st_ino).unwrap_or(0),
            Err(_) => 0,
        }
    };
    let gated = |unshared: bool, name: &str| if unshared { one(name) } else { 0 };
    Ok(NamespaceIds {
        cgroup: gated(ns.cgroup == NsPolicy::Unshare, "cgroup"),
        ipc: gated(ns.ipc == NsPolicy::Unshare, "ipc"),
        mnt: one("mnt"), // the mount namespace is always unshared
        net: gated(ns.net == NsPolicy::Unshare, "net"),
        pid: gated(ns.pid == NsPolicy::Unshare, "pid"),
        uts: gated(ns.uts == NsPolicy::Unshare, "uts"),
    })
}

/// A close-on-exec pipe returned as `(read, write)` owned fds.
fn pipe_pair() -> Result<(OwnedFd, OwnedFd)> {
    nix::unistd::pipe2(OFlag::O_CLOEXEC).context("pipe2()")
}

/// A close-on-exec `SOCK_STREAM` socketpair for the launcher->child "go"
/// handshake, as `(child_end, launcher_end)`. A stream socket (rather than a
/// pipe) lets the launcher signal with `MSG_NOSIGNAL`, so a send to an
/// already-dead child cannot raise SIGPIPE and kill the launcher before it reaps
/// the child and reports its exit status — while the child still sees EOF if the
/// launcher dies first.
fn child_wait_pair() -> Result<(OwnedFd, OwnedFd)> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
    socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .context("socketpair() for the child handshake")
}

fn set_nonblocking(fd: BorrowedFd<'_>) -> Result<()> {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    fcntl(fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).context("fcntl O_NONBLOCK")?;
    Ok(())
}

/// Canonicalize the source paths of bind/overlay ops against the real root,
/// before the pivot (bwrap's `resolve_symlinks_in_ops`): symlinks in the source
/// are resolved, and a missing source fails early with `Can't find source path
/// X` unless the op is a `-try` variant. Non-source ops pass through unchanged.
fn resolve_symlinks_in_ops(ops: &[SetupOp]) -> Result<Vec<SetupOp>> {
    ops.iter()
        .map(|op| match op {
            SetupOp::Bind {
                src,
                dest,
                kind,
                missing,
            } => Ok(SetupOp::Bind {
                src: resolve_source(src, *missing == OnMissing::Skip)?,
                dest: dest.clone(),
                kind: *kind,
                missing: *missing,
            }),
            SetupOp::Overlay { lower, upper, dest } => {
                // bubblewrap creates the overlay ops as upper (SETUP_OVERLAY_MOUNT),
                // then workdir, then the --overlay-src list, and resolves them in
                // that order — so resolve upper/work BEFORE the lower layers, or
                // the *first* "Can't find source path" names a different directory
                // than bubblewrap when more than one source is missing (#34).
                let upper = match upper {
                    OverlayUpper::Persistent { upper, work } => OverlayUpper::Persistent {
                        upper: resolve_source(upper, false)?,
                        work: resolve_source(work, false)?,
                    },
                    OverlayUpper::Tmp => OverlayUpper::Tmp,
                    OverlayUpper::ReadOnly => OverlayUpper::ReadOnly,
                };
                let lower = lower
                    .iter()
                    .map(|l| resolve_source(l, false))
                    .collect::<Result<Vec<_>>>()?;
                Ok(SetupOp::Overlay {
                    lower,
                    upper,
                    dest: dest.clone(),
                })
            }
            SetupOp::BindFd { fd, .. } => {
                // bwrap stores a bind-fd source as the string "/proc/self/fd/N"
                // and realpaths it here like any other bind source (bubblewrap.c
                // op->source = "/proc/self/fd/%d"), so a bad fd must fail *here*
                // with the same "Can't find source path" message — not later with
                // a readlink-specific one. Validate the magic link now.
                let proc = format!("/proc/self/fd/{fd}");
                std::fs::canonicalize(&proc).map_err(|e| Error::Sys {
                    message: format!("Can't find source path {proc}").into(),
                    errno: Errno::from_raw(e.raw_os_error().unwrap_or(0)),
                })?;
                Ok(op.clone())
            }
            other => Ok(other.clone()),
        })
        .collect()
}

/// `realpath(src)`: resolve symlinks and return the canonical path. A missing
/// path yields `Can't find source path <src>` (with the errno), unless
/// `allow_notexist` (a `-try` variant), which keeps the original.
fn resolve_source(src: &HostPath, allow_notexist: bool) -> Result<HostPath> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::OsStr::from_bytes(src.as_c_str().to_bytes());
    match std::fs::canonicalize(path) {
        Ok(p) => HostPath::parse("--bind", &p.to_string_lossy()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && allow_notexist => Ok(src.clone()),
        Err(e) => Err(Error::Sys {
            message: format!("Can't find source path {}", src.as_str()).into(),
            errno: Errno::from_raw(e.raw_os_error().unwrap_or(0)),
        }),
    }
}

// --- `--pidns` support: pass the real sandbox pid across pid namespaces ---

/// A `SOCK_SEQPACKET` socketpair with `SO_PASSCRED` on the receiving end, so a
/// pid sent as `SCM_CREDENTIALS` is translated by the kernel into the receiver's
/// pid namespace (bwrap's `create_pid_socketpair`).
fn create_pid_socketpair() -> Result<(OwnedFd, OwnedFd)> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, setsockopt, socketpair, sockopt};
    let (a, b) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .context("Can't create intermediate pids socket")?;
    setsockopt(&a, sockopt::PassCred, &true).context("Can't set SO_PASSCRED")?;
    Ok((a, b))
}

/// Print an error the way bwrap's `die` does and exit the sandbox child with 1.
/// Used on the clone-child setup path, where we cannot return a `Result`.
/// Generic in the (never produced) return type so it fits `unwrap_or_else`.
fn die_in_child<T>(e: Error) -> T {
    crate::log::emit_err(&crate::log::error_line(&e.to_string()));
    bwrap_sys::process::exit_immediately(1)
}

/// Fork to actually enter a pid namespace joined/created via setns/unshare (which
/// only affect children). The parent half is not needed and exits (bwrap's
/// `fork_intermediate_child`); only the child returns.
fn fork_intermediate() -> Result<()> {
    match bwrap_sys::process::fork_single_threaded() {
        Ok(nix::unistd::ForkResult::Parent { .. }) => bwrap_sys::process::exit_immediately(0),
        Ok(nix::unistd::ForkResult::Child) => Ok(()),
        Err(e) => Err(Error::invalid(format!("Can't fork for --pidns: {e}"))),
    }
}

/// Send our pid over the socket as `SCM_CREDENTIALS`; the kernel rewrites it to
/// the receiver's pid namespace (bwrap's `send_pid_on_socket`).
fn send_pid(sock: BorrowedFd<'_>) -> Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, UnixCredentials, sendmsg};
    use std::io::IoSlice;
    let cred = UnixCredentials::new();
    let buf = [0u8; 1];
    let iov = [IoSlice::new(&buf)];
    let cmsgs = [ControlMessage::ScmCredentials(&cred)];
    sendmsg::<()>(sock.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)
        .context("Can't send pid")?;
    Ok(())
}

/// Read the sandbox pid from the socket's `SCM_CREDENTIALS` (bwrap's
/// `read_pid_from_socket`).
fn read_pid(sock: BorrowedFd<'_>) -> Result<Pid> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, UnixCredentials, recvmsg};
    use std::io::IoSliceMut;
    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut space = nix::cmsg_space!(UnixCredentials);
    let msg = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut space),
        MsgFlags::empty(),
    )
    .context("Can't read pid from socket")?;
    // The sender (an intermediate that failed before send_pid) closed the socket
    // without writing: an empty datagram, like bwrap's `msg_controllen <= 0`.
    if msg.bytes == 0 {
        return Err(Error::invalid("Unexpected short read from pid socket"));
    }
    for c in msg.cmsgs().map_err(|e| Error::Sys {
        message: "Can't read pid from socket".into(),
        errno: e,
    })? {
        if let ControlMessageOwned::ScmCredentials(cred) = c {
            return Ok(Pid::from_raw(cred.pid()));
        }
    }
    Err(Error::invalid("No pid returned on socket"))
}

/// Read all bytes from a caller fd (for `--seccomp`), then close it through the
/// table. Re-registers first so a stale (reused) number still borrows and fails
/// at the `read` with the same errno as C, rather than at an earlier gate.
fn read_all_fd(fd: std::os::fd::RawFd, fds: &mut FdTable) -> Result<Vec<u8>> {
    fds.register(fd);
    let bf = fds.borrow(fd).expect("seccomp fd just registered");
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let result = loop {
        match read(bf, &mut buf) {
            Ok(0) => break Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(Errno::EINTR) => {}
            Err(e) => {
                break Err(Error::Sys {
                    message: "Can't read seccomp data".into(),
                    errno: e,
                });
            }
        }
    };
    // bwrap's `seccomp_program_new` reads the fd and closes it (before the pid-1
    // fork), so `--seccomp FD` cannot leak into the sandboxed process.
    fds.close(fd);
    result
}

/// Apply the `--clearenv`/`--setenv`/`--unsetenv` operations to the real process
/// environment in order (bwrap's env handling), editing `environ` in place via
/// `clearenv`/`setenv`/`unsetenv` rather than rebuilding it from a snapshot.
///
/// Rebuilding through `std::env::vars_os()` is lossy: entries without `=`, or
/// starting with `=`, are dropped, and duplicate names collapse — none of which
/// a byte-exact drop-in may do to the block it passes on. Editing in place keeps
/// the inherited block verbatim and changes only what the ops name, exactly as
/// bubblewrap does. (`setenv` on a duplicated name updates the first entry and
/// leaves the rest, so the command and `execvp` see what C sees.)
///
/// All mutation funnels through the single gated `bwrap_sys::process::apply_env`
/// (which refuses unless single-threaded), so the primitives are not exposed as
/// safe `pub fn`s that safe multithreaded code could misuse.
fn apply_env_ops(ops: &[crate::types::config::EnvOp]) -> Result<()> {
    use crate::types::config::EnvOp;
    use bwrap_sys::process::EnvOp as SysOp;
    let mut sys_ops: Vec<SysOp> = Vec::with_capacity(ops.len());
    for op in ops {
        match op {
            EnvOp::Clear => sys_ops.push(SysOp::Clear),
            // argv-derived strings are NUL-free, so CString::new succeeds; skip
            // defensively if that ever fails rather than panicking.
            EnvOp::Set { name, value } => {
                if let (Ok(n), Ok(v)) = (
                    CString::new(name.as_bytes()),
                    CString::new(value.as_bytes()),
                ) {
                    sys_ops.push(SysOp::Set(n, v));
                }
            }
            EnvOp::Unset { name } => {
                if let Ok(n) = CString::new(name.as_bytes()) {
                    sys_ops.push(SysOp::Unset(n));
                }
            }
        }
    }
    env_apply(&sys_ops)
}

/// Apply environment ops through the single-threaded-gated syscall wrapper,
/// mapping its refusal to an `Error`. (It can only fail if the process is
/// multi-threaded, which never happens in bwrap's cloned/forked child.)
fn env_apply(ops: &[bwrap_sys::process::EnvOp]) -> Result<()> {
    bwrap_sys::process::apply_env(ops)
        .map_err(|e| Error::invalid(format!("refusing to change the environment: {e}")))
}

/// bwrap's cwd logic: `--chdir`, else the old cwd if reachable, else `$HOME`,
/// else `/`. Returns the resulting cwd (for `PWD`).
fn compute_cwd(config: &Config, old_cwd: Option<&std::path::Path>) -> Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    if let Some(dir) = &config.chdir {
        chdir(dir.as_str()).with_context(|| format!("Can't chdir to {dir}"))?;
        return Ok(dir.as_bytes().to_vec());
    }
    // chdir to the old cwd if we captured one and it is reachable in the sandbox;
    // a NULL/unreachable old cwd falls through to $HOME then / (bwrap's order).
    if let Some(old) = old_cwd
        && chdir(old).is_ok()
    {
        return Ok(old.as_os_str().as_bytes().to_vec());
    }
    // HOME is read from the real environ (after the env ops have been applied),
    // like bwrap's getenv("HOME"). Reading is safe (std::env::var_os), so no
    // getenv wrapper is needed; only the mutation is gated (apply_env).
    if let Some(home) = std::env::var_os("HOME") {
        let home = home.as_bytes();
        if chdir(home).is_ok() {
            return Ok(home.to_vec());
        }
    }
    Ok(b"/".to_vec())
}

/// `execvp` the command with `argv0` applied and the computed environment,
/// exactly as bwrap does.
///
/// The environment is applied to the real `environ` first (in place, by
/// [`apply_env_ops`]), then `execvp` resolves the command and runs it. This
/// matters: `execvp`'s `PATH` search reads the global `environ`,
/// so the sandbox `PATH` must be installed there — not merely passed as an
/// `envp` vector. Using `execvpe` with an `envp` instead looks the command up in
/// bwrap's *own* `PATH`, which is the bug that broke every flatpak launch
/// (`execvp smile: No such file`). Deferring to real `execvp` also gives the
/// `_CS_PATH` default and the ENOEXEC shell fallback for free.
fn exec_command(config: &Config) -> Result<i32> {
    let exec_path = CString::new(config.command[0].as_bytes())
        .map_err(|_| Error::invalid("command contains a NUL byte"))?;
    let mut argv: Vec<CString> = Vec::with_capacity(config.command.len());
    let argv0 = config
        .argv0
        .as_deref()
        .unwrap_or(config.command[0].as_str());
    argv.push(CString::new(argv0.as_bytes()).map_err(|_| Error::invalid("argv0 NUL"))?);
    for a in &config.command[1..] {
        argv.push(CString::new(a.as_bytes()).map_err(|_| Error::invalid("arg NUL"))?);
    }
    // The environment was already applied to the real `environ` in place
    // (apply_env_ops); execvp reads that global environ for the PATH search and
    // passes it to the command.
    match execvp(&exec_path, &argv) {
        Ok(_) => unreachable!("execvp returns only on error"),
        Err(e) => Err(Error::Sys {
            message: format!("execvp {}", config.command[0]).into(),
            errno: e,
        }),
    }
}
