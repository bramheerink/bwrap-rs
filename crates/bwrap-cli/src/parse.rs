//! The argument parser, mirroring `parse_args_recurse` in `bubblewrap.c`.

use std::os::fd::RawFd;

use bwrap_core::cnum::c_strtou64;
use bwrap_core::types::{
    BindKind, CapOp, Capability, Config, EnvOp, HostPath, Mode, OnMissing, OverlayUpper,
    SandboxPath, SeccompSource, SetupOp,
};
use bwrap_core::{Error, Result};

use crate::{Outcome, ParseHost};

/// bwrap's `MAX_ARGS`: the NUL-byte hardening cap on total parsed arguments.
const MAX_ARGS: usize = 9000;

/// `MAX_TMPFS_BYTES`: `SIZE_MAX >> 1`. We target 64-bit, matching the host.
const MAX_TMPFS_BYTES: u64 = u64::MAX >> 1;

/// Parse `args` (the arguments after the program name) into an [`Outcome`].
///
/// `host` supplies the bytes of any `--args` file and receives warnings as
/// they occur.
pub fn parse(args: &[String], host: &mut dyn ParseHost) -> Result<Outcome> {
    let mut p = Parser {
        cfg: Config::default(),
        pending_overlay_src: Vec::new(),
        next_perms: None,
        next_size: None,
        total_parsed: args.len(),
        short_circuit: None,
        host,
    };
    p.run(args, false)?;

    if let Some(outcome) = p.short_circuit {
        return Ok(outcome);
    }
    // Final check, as in bwrap's parse_args(): a dangling --overlay-src.
    if !p.pending_overlay_src.is_empty() {
        return Err(Error::invalid(OVERLAY_SRC_DANGLING));
    }
    Ok(Outcome::Run(Box::new(p.cfg)))
}

const OVERLAY_SRC_DANGLING: &str = "--overlay-src must be followed by another --overlay-src or one of --overlay, --tmp-overlay, or --ro-overlay";

struct Parser<'a> {
    cfg: Config,
    /// Raw `--overlay-src` operand strings, validated only when an overlay op
    /// consumes them (as bwrap does in `make_setup_overlay_src_ops`).
    pending_overlay_src: Vec<String>,
    next_perms: Option<Mode>,
    next_size: Option<u64>,
    total_parsed: usize,
    /// Set when `--help`/`--version`/print-assumed-kernel short-circuits.
    short_circuit: Option<Outcome>,
    host: &'a mut dyn ParseHost,
}

impl Parser<'_> {
    fn warn_only_last(&mut self, name: &str) {
        self.host
            .warn(&format!("Only the last {name} option will take effect"));
    }

    /// Process one argument list. `in_file` is true inside an `--args` file.
    /// Returns `Ok(true)` if a `--` or command start ended the option list.
    fn run(&mut self, args: &[String], in_file: bool) -> Result<bool> {
        if self.total_parsed > MAX_ARGS {
            return Err(Error::invalid(format!(
                "Exceeded maximum number of arguments {MAX_ARGS}"
            )));
        }
        let mut i = 0;
        while i < args.len() {
            if self.short_circuit.is_some() {
                return Ok(true);
            }
            let arg = args[i].as_str();

            // Command boundary. bwrap `break`s here *before* the bottom guards,
            // so a dangling --perms/--size right before the command is ignored.
            // The command is only taken from the top-level argv; a `--` or
            // non-option inside an --args file ends that frame and its
            // remainder is discarded (verified against bwrap).
            if arg == "--" {
                if !in_file {
                    self.cfg.command = args[i + 1..].to_vec();
                }
                return Ok(true);
            }
            if !arg.starts_with('-') {
                // Includes the empty string, as in bwrap (`*arg != '-'`).
                if !in_file {
                    self.cfg.command = args[i..].to_vec();
                }
                return Ok(true);
            }

            // How many extra args this option consumed (beyond `arg` itself).
            let consumed = self.dispatch(arg, &args[i..], in_file)?;
            if self.short_circuit.is_some() {
                return Ok(true);
            }

            // End-of-option guards, exactly as at the bottom of bwrap's loop.
            if !is_modifier(arg) && self.next_perms.is_some() {
                return Err(Error::invalid(
                    "--perms must be followed by an option that creates a file",
                ));
            }
            if !is_modifier(arg) && self.next_size.is_some() {
                return Err(Error::invalid("--size must be followed by --tmpfs"));
            }
            if arg != "--overlay-src" && !self.pending_overlay_src.is_empty() {
                return Err(Error::invalid(OVERLAY_SRC_DANGLING));
            }

            i += 1 + consumed;
        }
        Ok(false)
    }

    /// Dispatch a single option. Returns the number of extra arguments
    /// consumed, or [`STOP`] if the option list ends here (command start).
    fn dispatch(&mut self, arg: &str, rest: &[String], in_file: bool) -> Result<usize> {
        // `rest[0]` is `arg`; operands are rest[1], rest[2], ...
        let need = |n: usize, msg: &str| -> Result<()> {
            if rest.len() <= n {
                Err(Error::invalid(msg.to_string()))
            } else {
                Ok(())
            }
        };

        match arg {
            "--help" => {
                self.short_circuit = Some(Outcome::Help);
                Ok(0)
            }
            "--version" => {
                self.short_circuit = Some(Outcome::Version);
                Ok(0)
            }
            "--args" => {
                if in_file {
                    return Err(Error::invalid("--args not supported in arguments file"));
                }
                need(1, "--args takes an argument")?;
                let fd = parse_fd(&rest[1])?;
                let bytes = self.host.read_args(fd)?;
                let sub = split_nul_args(&bytes);
                self.total_parsed += sub.len();
                if self.total_parsed > MAX_ARGS {
                    return Err(Error::invalid(format!(
                        "Exceeded maximum number of arguments {MAX_ARGS}"
                    )));
                }
                self.run(&sub, true)?;
                Ok(1)
            }
            "--argv0" => {
                need(1, "--argv0 takes one argument")?;
                if self.cfg.argv0.is_some() {
                    return Err(Error::invalid("--argv0 used multiple times"));
                }
                self.cfg.argv0 = Some(rest[1].clone());
                Ok(1)
            }
            "--level-prefix" => {
                // Take effect immediately, so a later parse warning/error is
                // prefixed but an earlier one is not (bwrap's global). The flag
                // lives only in the logger's atomic; there is no Config field.
                self.host.set_level_prefix(true);
                Ok(0)
            }
            "--unshare-all" => {
                self.cfg.unshare_user_try = true;
                self.cfg.unshare_ipc = true;
                self.cfg.unshare_pid = true;
                self.cfg.unshare_uts = true;
                self.cfg.unshare_cgroup_try = true;
                self.cfg.unshare_net = true;
                Ok(0)
            }
            "--unshare-user" => set(&mut self.cfg.unshare_user),
            "--unshare-user-try" => set(&mut self.cfg.unshare_user_try),
            "--unshare-ipc" => set(&mut self.cfg.unshare_ipc),
            "--unshare-pid" => set(&mut self.cfg.unshare_pid),
            "--unshare-net" => set(&mut self.cfg.unshare_net),
            "--unshare-uts" => set(&mut self.cfg.unshare_uts),
            "--unshare-cgroup" => set(&mut self.cfg.unshare_cgroup),
            "--unshare-cgroup-try" => set(&mut self.cfg.unshare_cgroup_try),
            "--share-net" => {
                self.cfg.unshare_net = false;
                Ok(0)
            }
            "--chdir" => {
                need(1, "--chdir takes one argument")?;
                if self.cfg.chdir.is_some() {
                    self.warn_only_last("--chdir");
                }
                self.cfg.chdir = Some(path_arg("--chdir", &rest[1])?);
                Ok(1)
            }
            "--disable-userns" => set(&mut self.cfg.disable_userns),
            "--assert-userns-disabled" => set(&mut self.cfg.assert_userns_disabled),
            "--remount-ro" => {
                need(1, "--remount-ro takes one argument")?;
                self.push(SetupOp::RemountRo {
                    dest: dest("--remount-ro", &rest[1])?,
                });
                Ok(1)
            }
            "--bind" | "--bind-try" => self.bind(arg, rest, BindKind::ReadWrite),
            "--ro-bind" | "--ro-bind-try" => self.bind(arg, rest, BindKind::ReadOnly),
            "--dev-bind" | "--dev-bind-try" => self.bind(arg, rest, BindKind::Dev),
            "--bind-fd" | "--ro-bind-fd" => {
                need(2, "--bind-fd takes two arguments")?;
                let fd = parse_fd(&rest[1])?;
                let kind = if arg == "--ro-bind-fd" {
                    BindKind::ReadOnly
                } else {
                    BindKind::ReadWrite
                };
                self.push(SetupOp::BindFd {
                    fd,
                    dest: dest(arg, &rest[2])?,
                    kind,
                });
                Ok(2)
            }
            "--overlay-src" => {
                // bwrap does no argc check and does not read/validate the
                // operand here; it just records that a source is pending. A
                // trailing `--overlay-src` (no operand) therefore falls through
                // to the dangling-src message at end of parse. The operand is
                // always the next token, whatever it is.
                if rest.len() > 1 {
                    self.pending_overlay_src.push(rest[1].clone());
                    Ok(1)
                } else {
                    // Keep the pending marker so the final guard fires; nothing
                    // consumes it, so the raw (here empty) value is never used.
                    self.pending_overlay_src.push(String::new());
                    Ok(0)
                }
            }
            "--overlay" => {
                need(3, "--overlay takes three arguments")?;
                if self.pending_overlay_src.is_empty() {
                    return Err(Error::invalid(
                        "--overlay requires at least one --overlay-src",
                    ));
                }
                let upper = HostPath::parse("--overlay", &rest[1])?;
                let work = HostPath::parse("--overlay", &rest[2])?;
                let dest = dest("--overlay", &rest[3])?;
                let lower = self.take_overlay_src()?;
                self.push(SetupOp::Overlay {
                    lower,
                    upper: OverlayUpper::Persistent { upper, work },
                    dest,
                });
                Ok(3)
            }
            "--tmp-overlay" => {
                need(1, "--tmp-overlay takes an argument")?;
                if self.pending_overlay_src.is_empty() {
                    return Err(Error::invalid(
                        "--tmp-overlay requires at least one --overlay-src",
                    ));
                }
                let dest = dest("--tmp-overlay", &rest[1])?;
                let lower = self.take_overlay_src()?;
                self.push(SetupOp::Overlay {
                    lower,
                    upper: OverlayUpper::Tmp,
                    dest,
                });
                Ok(1)
            }
            "--ro-overlay" => {
                need(1, "--ro-overlay takes an argument")?;
                if self.pending_overlay_src.len() < 2 {
                    return Err(Error::invalid(
                        "--ro-overlay requires at least two --overlay-src",
                    ));
                }
                let dest = dest("--ro-overlay", &rest[1])?;
                let lower = self.take_overlay_src()?;
                self.push(SetupOp::Overlay {
                    lower,
                    upper: OverlayUpper::ReadOnly,
                    dest,
                });
                Ok(1)
            }
            "--proc" => {
                need(1, "--proc takes an argument")?;
                self.push(SetupOp::Proc {
                    dest: dest("--proc", &rest[1])?,
                });
                Ok(1)
            }
            "--dev" => {
                need(1, "--dev takes an argument")?;
                self.push(SetupOp::Dev {
                    dest: dest("--dev", &rest[1])?,
                });
                Ok(1)
            }
            "--tmpfs" => {
                need(1, "--tmpfs takes an argument")?;
                let dest = dest("--tmpfs", &rest[1])?;
                let perms = self.take_perms(Mode::from_bits(0o755));
                let size = self.next_size.take();
                self.push(SetupOp::Tmpfs { dest, perms, size });
                Ok(1)
            }
            "--mqueue" => {
                need(1, "--mqueue takes an argument")?;
                self.push(SetupOp::Mqueue {
                    dest: dest("--mqueue", &rest[1])?,
                });
                Ok(1)
            }
            "--dir" => {
                need(1, "--dir takes an argument")?;
                let dest = dest("--dir", &rest[1])?;
                let perms = self.take_perms(Mode::from_bits(0o755));
                self.push(SetupOp::Dir { dest, perms });
                Ok(1)
            }
            "--file" => {
                need(2, "--file takes two arguments")?;
                let fd = parse_fd(&rest[1])?;
                let dest = dest("--file", &rest[2])?;
                let perms = self.take_perms(Mode::from_bits(0o666));
                self.push(SetupOp::File { fd, dest, perms });
                Ok(2)
            }
            "--bind-data" => self.bind_data(arg, rest, BindKind::ReadWrite),
            "--ro-bind-data" => self.bind_data(arg, rest, BindKind::ReadOnly),
            "--symlink" => {
                need(2, "--symlink takes two arguments")?;
                let target = HostPath::parse("--symlink", &rest[1])?;
                self.push(SetupOp::Symlink {
                    target,
                    dest: dest("--symlink", &rest[2])?,
                });
                Ok(2)
            }
            "--exec-label" => {
                need(1, "--exec-label takes an argument")?;
                if self.cfg.exec_label.is_some() {
                    self.warn_only_last("--exec-label");
                }
                // bwrap validates the label as it is parsed (before the no-command
                // check and before scanning later arguments).
                bwrap_core::selinux::die_unless_label_valid(&rest[1])?;
                self.cfg.exec_label = Some(rest[1].clone());
                Ok(1)
            }
            "--file-label" => {
                need(1, "--file-label takes an argument")?;
                if self.cfg.file_label.is_some() {
                    self.warn_only_last("--file-label");
                }
                // bwrap validates and installs the fscreate context at parse time;
                // the context is then inherited across the clone. A setfscreatecon
                // failure is reported as C's `--file-label setup failed`.
                bwrap_core::selinux::die_unless_label_valid(&rest[1])?;
                bwrap_core::selinux::label_create_file(Some(&rest[1])).map_err(|e| Error::Sys {
                    message: "--file-label setup failed".into(),
                    errno: e.errno().unwrap_or(nix::errno::Errno::EINVAL),
                })?;
                self.cfg.file_label = Some(rest[1].clone());
                Ok(1)
            }
            "--hostname" => {
                need(1, "--hostname takes an argument")?;
                if self.cfg.hostname.is_some() {
                    self.warn_only_last("--hostname");
                }
                // Keep the last value for the `--unshare-uts` requirement check
                // in `Config::resolve` (bwrap's `opt_sandbox_hostname`), and also
                // append an ordered op for every occurrence (bwrap's
                // `SETUP_SET_HOSTNAME`), so each is applied in command-line order
                // and an invalid earlier one still fails.
                self.cfg.hostname = Some(rest[1].clone());
                self.push(SetupOp::SetHostname {
                    name: rest[1].clone(),
                });
                Ok(1)
            }
            "--clearenv" => {
                self.cfg.env_ops.push(EnvOp::Clear);
                Ok(0)
            }
            "--setenv" => {
                need(2, "--setenv takes two arguments")?;
                // bwrap calls setenv(3) at parse time, which fails (EINVAL) on
                // an empty name or one containing '='; bwrap dies "setenv failed".
                if !is_valid_env_name(&rest[1]) {
                    return Err(Error::invalid("setenv failed"));
                }
                self.cfg.env_ops.push(EnvOp::Set {
                    name: rest[1].clone(),
                    value: rest[2].clone(),
                });
                Ok(2)
            }
            "--unsetenv" => {
                need(1, "--unsetenv takes an argument")?;
                // unsetenv(3) likewise fails on an empty name or one with '='.
                if !is_valid_env_name(&rest[1]) {
                    return Err(Error::invalid("unsetenv failed"));
                }
                self.cfg.env_ops.push(EnvOp::Unset {
                    name: rest[1].clone(),
                });
                Ok(1)
            }
            "--uid" => {
                need(1, "--uid takes an argument")?;
                if self.cfg.sandbox_uid.is_some() {
                    self.warn_only_last("--uid");
                }
                self.cfg.sandbox_uid = Some(parse_id(&rest[1], "uid")?);
                Ok(1)
            }
            "--gid" => {
                need(1, "--gid takes an argument")?;
                if self.cfg.sandbox_gid.is_some() {
                    self.warn_only_last("--gid");
                }
                self.cfg.sandbox_gid = Some(parse_id(&rest[1], "gid")?);
                Ok(1)
            }
            "--lock-file" => {
                need(1, "--lock-file takes an argument")?;
                self.cfg.lock_files.push(dest("--lock-file", &rest[1])?);
                Ok(1)
            }
            "--sync-fd" => {
                need(1, "--sync-fd takes an argument")?;
                self.cfg.sync_fds.push(parse_fd(&rest[1])?);
                Ok(1)
            }
            "--block-fd" => self.single_fd(rest, "--block-fd", |c| &mut c.block_fd),
            "--userns-block-fd" => {
                self.single_fd(rest, "--userns-block-fd", |c| &mut c.userns_block_fd)
            }
            "--info-fd" => self.single_fd(rest, "--info-fd", |c| &mut c.info_fd),
            "--json-status-fd" => {
                self.single_fd(rest, "--json-status-fd", |c| &mut c.json_status_fd)
            }
            "--userns" => self.single_fd(rest, "--userns", |c| &mut c.userns_fd),
            "--userns2" => self.single_fd(rest, "--userns2", |c| &mut c.userns2_fd),
            "--pidns" => self.single_fd(rest, "--pidns", |c| &mut c.pidns_fd),
            "--seccomp" => {
                need(1, "--seccomp takes an argument")?;
                if matches!(self.cfg.seccomp, SeccompSource::Added(_)) {
                    return Err(Error::invalid(
                        "--seccomp cannot be combined with --add-seccomp-fd",
                    ));
                }
                if matches!(self.cfg.seccomp, SeccompSource::Single(_)) {
                    self.warn_only_last("--seccomp");
                }
                self.cfg.seccomp = SeccompSource::Single(parse_fd(&rest[1])?);
                Ok(1)
            }
            "--add-seccomp-fd" => {
                need(1, "--add-seccomp-fd takes an argument")?;
                // bwrap order: combine-check, then parse the fd, then read and
                // validate the program (seccomp_program_new, which owns the fd).
                if matches!(self.cfg.seccomp, SeccompSource::Single(_)) {
                    return Err(Error::invalid(
                        "--add-seccomp-fd cannot be combined with --seccomp",
                    ));
                }
                let fd = parse_fd(&rest[1])?;
                let bytes = self.host.read_seccomp_fd(fd)?;
                // Validate the framing now, as bwrap does at parse time. We keep
                // our stricter checks (reject an empty or oversized program)
                // rather than C's accept-empty + silent u16 length truncation.
                bwrap_sys::seccomp::Program::from_bytes(&bytes)
                    .map_err(|e| Error::invalid(e.to_string()))?;
                match &mut self.cfg.seccomp {
                    SeccompSource::Added(v) => v.push(bytes),
                    other => *other = SeccompSource::Added(vec![bytes]),
                }
                Ok(1)
            }
            "--new-session" => set(&mut self.cfg.new_session),
            "--die-with-parent" => set(&mut self.cfg.die_with_parent),
            "--as-pid-1" => set(&mut self.cfg.as_pid_1),
            "--cap-add" => self.cap(rest, false),
            "--cap-drop" => self.cap(rest, true),
            "--perms" => {
                need(1, "--perms takes an argument")?;
                if self.next_perms.is_some() {
                    return Err(Error::invalid("--perms given twice for the same action"));
                }
                self.next_perms = Some(parse_perms("--perms", &rest[1])?);
                Ok(1)
            }
            "--size" => {
                need(1, "--size takes an argument")?;
                if self.next_size.is_some() {
                    return Err(Error::invalid("--size given twice for the same action"));
                }
                self.next_size = Some(parse_size(&rest[1])?);
                Ok(1)
            }
            "--chmod" => {
                need(2, "--chmod takes two arguments")?;
                let perms = parse_perms("--chmod", &rest[1])?;
                self.push(SetupOp::Chmod {
                    perms,
                    dest: dest("--chmod", &rest[2])?,
                });
                Ok(2)
            }
            "--not-a-security-boundary" => set(&mut self.cfg.not_a_security_boundary),
            _ if arg.starts_with("--debug-opt=") => self.debug_opt(&arg["--debug-opt=".len()..]),
            // `--` and non-options are handled in `run` before dispatch, so any
            // arg reaching here starts with `-` and matched nothing.
            _ => Err(Error::invalid(format!("Unknown option {arg}"))),
        }
    }

    fn bind(&mut self, arg: &str, rest: &[String], kind: BindKind) -> Result<usize> {
        if rest.len() <= 2 {
            return Err(Error::invalid(format!("{arg} takes two arguments")));
        }
        let missing = if arg.ends_with("-try") {
            OnMissing::Skip
        } else {
            OnMissing::Fail
        };
        self.push(SetupOp::Bind {
            src: HostPath::parse(arg, &rest[1])?,
            dest: dest(arg, &rest[2])?,
            kind,
            missing,
        });
        Ok(2)
    }

    fn bind_data(&mut self, arg: &str, rest: &[String], kind: BindKind) -> Result<usize> {
        if rest.len() <= 2 {
            return Err(Error::invalid(format!("{arg} takes two arguments")));
        }
        let fd = parse_fd(&rest[1])?;
        let dest = dest(arg, &rest[2])?;
        let perms = self.take_perms(Mode::from_bits(0o600));
        self.push(SetupOp::BindData {
            fd,
            dest,
            kind,
            perms,
        });
        Ok(2)
    }

    fn cap(&mut self, rest: &[String], drop: bool) -> Result<usize> {
        if rest.len() <= 1 {
            return Err(Error::invalid(format!(
                "--cap-{} takes an argument",
                if drop { "drop" } else { "add" }
            )));
        }
        self.cfg.cap_add_or_drop_used = true;
        let op = if rest[1].eq_ignore_ascii_case("ALL") {
            if drop { CapOp::DropAll } else { CapOp::AddAll }
        } else {
            // libcap's cap_from_name accepts a numeric capability too.
            let cap = Capability::from_arg(&rest[1])?;
            if drop {
                CapOp::Drop(cap)
            } else {
                CapOp::Add(cap)
            }
        };
        self.cfg.cap_ops.push(op);
        Ok(1)
    }

    fn single_fd(
        &mut self,
        rest: &[String],
        name: &str,
        field: fn(&mut Config) -> &mut Option<RawFd>,
    ) -> Result<usize> {
        if rest.len() <= 1 {
            return Err(Error::invalid(format!("{name} takes an argument")));
        }
        // bwrap warns before parsing the fd, so the warning precedes any
        // "Invalid fd" error on stderr.
        if field(&mut self.cfg).is_some() {
            self.warn_only_last(name);
        }
        let fd = parse_fd(&rest[1])?;
        *field(&mut self.cfg) = Some(fd);
        Ok(1)
    }

    fn debug_opt(&mut self, val: &str) -> Result<usize> {
        match val {
            "force-openat-fallback" => {
                self.cfg.force_openat_fallback = true;
                Ok(0)
            }
            "force-mount-setattr-fallback" => {
                self.cfg.force_mount_setattr_fallback = true;
                Ok(0)
            }
            "print-assumed-kernel" => {
                self.short_circuit = Some(Outcome::PrintAssumedKernel);
                Ok(0)
            }
            other => Err(Error::invalid(format!(
                "Unknown --debug-opt value: {other}"
            ))),
        }
    }

    fn take_perms(&mut self, default: Mode) -> Mode {
        self.next_perms.take().unwrap_or(default)
    }

    /// Take the pending `--overlay-src` strings and validate each as a path,
    /// as bwrap's `make_setup_overlay_src_ops` does only when the overlay op
    /// is built (so an empty src errors here, not at `--overlay-src`).
    fn take_overlay_src(&mut self) -> Result<Vec<HostPath>> {
        std::mem::take(&mut self.pending_overlay_src)
            .iter()
            .map(|s| HostPath::parse("--overlay-src", s))
            .collect()
    }

    fn push(&mut self, op: SetupOp) {
        self.cfg.ops.push(op);
    }
}

fn set(flag: &mut bool) -> Result<usize> {
    *flag = true;
    Ok(0)
}

fn is_modifier(arg: &str) -> bool {
    arg == "--perms" || arg == "--size"
}

/// A non-empty path argument (bwrap's `path_argument`).
fn path_arg(option: &str, value: &str) -> Result<String> {
    if value.is_empty() {
        return Err(Error::invalid(format!(
            "{option} does not take an empty path argument"
        )));
    }
    Ok(value.to_string())
}

fn dest(option: &str, value: &str) -> Result<SandboxPath> {
    SandboxPath::parse(option, value)
}

/// An environment variable name that `setenv`/`unsetenv` accept: non-empty and
/// with no `=`.
fn is_valid_env_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('=')
}

/// Parse an fd argument like bwrap: `int fd = strtol(.., 10)`, reject empty,
/// trailing junk, or a negative value, with the message `Invalid fd: <value>`.
///
/// The `strtol` result is a `long` that bwrap stores into an `int`, so the
/// value is narrowed with a wrapping cast to `i32` before the `< 0` check
/// (e.g. `4294967297` wraps to `1`, matching bwrap).
fn parse_fd(value: &str) -> Result<RawFd> {
    // The `as i32` truncation is the whole point: it reproduces C storing a
    // `long` into an `int`.
    #[allow(clippy::cast_possible_truncation)]
    match strtol10(value) {
        Some(n) if (n as i32) >= 0 => Ok(n as i32),
        _ => Err(Error::invalid(format!("Invalid fd: {value}"))),
    }
}

/// Parse `--uid`/`--gid`: `int id = strtol(..)`, reject negative (bwrap's
/// `the_uid < 0`), same `int` narrowing as [`parse_fd`].
fn parse_id(value: &str, which: &str) -> Result<u32> {
    // Intentional C int-narrowing, as in parse_fd; the i32 is then known >= 0.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    match strtol10(value) {
        Some(n) if (n as i32) >= 0 => Ok((n as i32) as u32),
        _ => Err(Error::invalid(format!("Invalid {which}: {value}"))),
    }
}

/// `strtol(value, &end, 10)` with the full-consumption and non-empty checks
/// bwrap applies. Returns the `long` value (saturating on overflow, as
/// `strtol` does with `ERANGE`), or `None` on empty input / no digits /
/// trailing junk. Leading C whitespace and a leading `+`/`-` are accepted.
fn strtol10(value: &str) -> Option<i64> {
    let c = c_strtou64(value, 10);
    // bwrap applies strtol's non-empty and full-consumption checks.
    if c.digits == 0 || c.end != value.len() {
        return None; // no digits, or trailing junk
    }
    // strtol returns LONG_MAX / LONG_MIN on ERANGE: that is a u64 overflow, or a
    // magnitude outside the signed `long` range even when it still fits a u64.
    // bwrap stores the result into an int without checking errno, so a huge
    // positive later narrows to -1 and a huge negative to 0.
    const LONG_MAX_MAG: u64 = i64::MAX as u64; // |LONG_MAX|
    const LONG_MIN_MAG: u64 = LONG_MAX_MAG + 1; // |LONG_MIN|
    if c.overflow || (!c.neg && c.val > LONG_MAX_MAG) || (c.neg && c.val > LONG_MIN_MAG) {
        return Some(if c.neg { i64::MIN } else { i64::MAX });
    }
    if c.neg && c.val == LONG_MIN_MAG {
        return Some(i64::MIN); // the one magnitude that negates but cannot be held positive
    }
    // c.val <= LONG_MAX here, so it fits an i64.
    let mag = i64::try_from(c.val).unwrap_or(i64::MAX);
    Some(if c.neg { -mag } else { mag })
}

/// Parse `--perms`/`--chmod`: octal, `<= 07777`. Error text names `option`.
fn parse_perms(option: &str, value: &str) -> Result<Mode> {
    Mode::parse_octal(option, value)
}

/// Parse `--size`: `strtoull(.., 0)` with bwrap's guards. First char must be a
/// digit (so no sign/whitespace), base auto-detected (`0x`→hex, `0`→octal),
/// fully consumed, non-zero, `<= MAX_TMPFS_BYTES`.
fn parse_size(value: &str) -> Result<u64> {
    let non_zero = "--size takes a non-zero number of bytes";
    // C guards with `isdigit(argv[1][0])`: the first byte must be a digit, which
    // simultaneously rejects leading whitespace and any sign. Keep that guard —
    // the shared scanner would otherwise skip them.
    if value.as_bytes().first().is_none_or(|c| !c.is_ascii_digit()) {
        return Err(Error::invalid(non_zero));
    }
    let c = c_strtou64(value, 0);
    // `strtoull` sets ERANGE on overflow (bwrap's `errno != 0`), bwrap requires
    // full consumption (`*endptr == '\0'`), and the result must be non-zero —
    // all three share the "non-zero number of bytes" message.
    if c.overflow || c.end != value.len() || c.val == 0 {
        return Err(Error::invalid(non_zero));
    }
    if c.val > MAX_TMPFS_BYTES {
        return Err(Error::invalid(format!(
            "--size (for tmpfs) is limited to {MAX_TMPFS_BYTES}"
        )));
    }
    Ok(c.val)
}

/// Split the bytes of an `--args` file into arguments, as bwrap does: NUL is
/// the separator, and `load_file_data` appends a terminating NUL, so a
/// trailing NUL does not create an extra empty argument.
fn split_nul_args(bytes: &[u8]) -> Vec<String> {
    let mut parts: Vec<&[u8]> = bytes.split(|&c| c == 0).collect();
    // A terminating NUL (or the one load_file_data appends) leaves a trailing
    // empty element that is not a real argument.
    if bytes.is_empty() {
        // Empty file: load_file_data records data_len excluding the appended
        // NUL, so bwrap reads zero arguments, not one empty one.
        return Vec::new();
    }
    if bytes.last() == Some(&0) {
        parts.pop();
    }
    // Arguments are char*, so invalid UTF-8 would be lossy; see the UTF-8 note
    // in DESIGN.md open points. For now assume UTF-8 (true for all real callers).
    parts
        .into_iter()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strtol10_matches_c_long_semantics() {
        assert_eq!(strtol10(" \t\x0b5"), Some(5)); // C whitespace, incl. vtab
        assert_eq!(strtol10("+7"), Some(7));
        assert_eq!(strtol10("-2147483648"), Some(-2_147_483_648));
        assert_eq!(strtol10("4294967296"), Some(4_294_967_296));
        assert_eq!(strtol10("9223372036854775807"), Some(i64::MAX));
        assert_eq!(strtol10("-9223372036854775808"), Some(i64::MIN));
        // Out of signed-long range but still within u64: strtol saturates (ERANGE).
        assert_eq!(strtol10("9223372036854775808"), Some(i64::MAX));
        assert_eq!(strtol10("-9223372036854775809"), Some(i64::MIN));
        // Beyond u64 too.
        assert_eq!(strtol10("99999999999999999999999"), Some(i64::MAX));
        assert_eq!(strtol10("-99999999999999999999999"), Some(i64::MIN));
        // Empty, no digits, or trailing junk ('x' is not a base-10 digit).
        assert_eq!(strtol10(""), None);
        assert_eq!(strtol10("5x"), None);
        assert_eq!(strtol10("0x10"), None);
    }

    #[test]
    fn parse_size_matches_c_strtoull_base0() {
        assert_eq!(parse_size("0x10000").unwrap(), 0x10000);
        assert_eq!(parse_size("010").unwrap(), 0o10);
        assert_eq!(parse_size("1").unwrap(), 1);
        // Trailing junk, zero, leading space / sign: all the "non-zero" message.
        for bad in ["1e3", "00", "0x", " 5", "+5", "-5"] {
            let e = parse_size(bad).unwrap_err();
            assert_eq!(
                e.to_string(),
                "--size takes a non-zero number of bytes",
                "{bad:?}"
            );
        }
        // u64::MAX fits strtoull (no ERANGE) but exceeds the tmpfs cap.
        assert!(
            parse_size("18446744073709551615")
                .unwrap_err()
                .to_string()
                .contains("limited to")
        );
        // One past u64::MAX is ERANGE, which bwrap reports as "non-zero".
        assert_eq!(
            parse_size("18446744073709551616").unwrap_err().to_string(),
            "--size takes a non-zero number of bytes"
        );
    }

    /// The three command-line number parsers are built on one scanner
    /// (`c_strtou64`), but keep their own post-checks. This table feeds the same
    /// tricky inputs to all three with independently hand-computed glibc
    /// results, so a drift in the shared scan moves more than one column at once
    /// and is caught here.
    #[test]
    fn the_three_callers_share_one_scanner() {
        struct Row {
            input: &'static str,
            long: Option<i64>,  // strtol10: --uid/--gid/fd (base 10)
            perms: Option<u16>, // Mode::parse_octal: --perms/--chmod (base 8)
            size: Option<u64>,  // parse_size: --size (base 0, isdigit-guarded)
        }
        let rows = [
            Row {
                input: "0",
                long: Some(0),
                perms: Some(0),
                size: None,
            },
            Row {
                input: "10",
                long: Some(10),
                perms: Some(0o10),
                size: Some(10),
            },
            Row {
                input: "0x10",
                long: None,
                perms: None,
                size: Some(0x10),
            },
            Row {
                input: "010",
                long: Some(10),
                perms: Some(0o10),
                size: Some(0o10),
            },
            Row {
                input: " 5",
                long: Some(5),
                perms: Some(5),
                size: None,
            },
            Row {
                input: "5x",
                long: None,
                perms: None,
                size: None,
            },
            Row {
                input: "8",
                long: Some(8),
                perms: None,
                size: Some(8),
            },
        ];
        for r in rows {
            assert_eq!(strtol10(r.input), r.long, "strtol10 {:?}", r.input);
            assert_eq!(
                Mode::parse_octal("--perms", r.input).ok().map(Mode::bits),
                r.perms,
                "parse_octal {:?}",
                r.input
            );
            assert_eq!(parse_size(r.input).ok(), r.size, "parse_size {:?}", r.input);
        }
    }
}
