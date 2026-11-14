//! The parsed sandbox configuration and its validation/resolution.
//!
//! [`Config`] mirrors bwrap's option globals as the CLI parser
//! fills them: raw, before any defaulting. [`Config::resolve`] reproduces the
//! sequence in bwrap's `main()` exactly — the option-compatibility `die()`
//! checks, the forcing of `--unshare-user`, the uid/gid defaulting, and the
//! remaining checks — and yields a [`ResolvedConfig`].
//!
//! Everything here is pure given its inputs (`real_uid`, `real_gid`, and a
//! [`UsernsProbe`]), so it is fully testable without privileges.

use std::ffi::OsString;
use std::os::fd::RawFd;

use super::caps::CapOp;
use super::op::SetupOp;
use super::path::SandboxPath;
use crate::error::{Error, Result};

/// An environment mutation from `--clearenv` / `--setenv` / `--unsetenv`,
/// in command-line order. bwrap applies these to its own environment during
/// parsing; we record them and apply to a copy later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvOp {
    /// `--clearenv`: drop the entire environment.
    Clear,
    /// `--setenv NAME VALUE`.
    Set {
        /// Variable name.
        name: OsString,
        /// Value.
        value: OsString,
    },
    /// `--unsetenv NAME`.
    Unset {
        /// Variable name.
        name: OsString,
    },
}

/// Where seccomp filters come from. `--seccomp` and `--add-seccomp-fd` are
/// mutually exclusive (bwrap rejects the combination).
///
/// The two sources differ in *when* the fd is read, mirroring bubblewrap:
/// `--seccomp` stores the fd and reads it late (just before `exec`), whereas
/// `--add-seccomp-fd` is read and validated at parse time (bwrap's
/// `seccomp_program_new`, which takes ownership of the fd), so a bad fd or
/// malformed program fails during argument parsing.
#[derive(Debug, Default, PartialEq, Eq)]
pub enum SeccompSource {
    /// No seccomp filtering.
    #[default]
    None,
    /// A single `--seccomp FD`, read late.
    Single(RawFd),
    /// One or more `--add-seccomp-fd FD` (repeatable), each already read and
    /// framing-validated at parse time; the raw program bytes are kept here.
    Added(Vec<Vec<u8>>),
}

/// How bwrap should treat one namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsPolicy {
    /// Share the host's namespace (do not unshare).
    Share,
    /// Create a new namespace.
    Unshare,
}

/// The resolved per-namespace decisions.
///
/// This captures only what can be decided from the options alone. Two things
/// are finished at orchestration time (in `run`), not here:
/// - `--pidns FD` (`pidns_fd`): a joined pid namespace suppresses `CLONE_NEWPID`
///   even though `pid` is `Unshare`.
/// - `--unshare-cgroup-try` and the `--unshare-cgroup` kernel-support check are
///   resolved against `/proc/self/ns/cgroup` at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceConfig {
    /// User namespace (after `--unshare-user[-try]` and uid-forcing).
    pub user: NsPolicy,
    /// PID namespace.
    pub pid: NsPolicy,
    /// Network namespace.
    pub net: NsPolicy,
    /// IPC namespace.
    pub ipc: NsPolicy,
    /// UTS namespace.
    pub uts: NsPolicy,
    /// cgroup namespace.
    pub cgroup: NsPolicy,
}

/// Probes bwrap performs on the running system while resolving namespaces.
///
/// Abstracted so resolution can be tested with a fake. The real implementation
/// reads `/proc` and `/sys` (`SystemUsernsProbe`).
pub trait UsernsProbe {
    /// `stat("/proc/self/ns/user") == 0`: the kernel supports user namespaces.
    fn user_ns_supported(&self) -> bool;
    /// For `--unshare-user-try`: whether *unprivileged* user namespaces are
    /// disabled (RHEL7 module param `N`, or `max_user_namespaces` == 0).
    fn unprivileged_userns_disabled(&self) -> bool;
    /// `stat("/proc/self/ns/cgroup") == 0`: the kernel supports cgroup
    /// namespaces. Gates `--unshare-cgroup` (bwrap dies without it) and
    /// `--unshare-cgroup-try` (used only when available).
    fn cgroup_ns_supported(&self) -> bool;
}

/// The parsed options, mirroring bwrap's `opt_*` globals before resolution.
///
/// Fd-valued options are held as raw fd numbers (`Some(n)` == bwrap's `!= -1`);
/// ownership and dup'ing happen later. `None` is bwrap's `-1`.
#[derive(Debug, Default)]
pub struct Config {
    // Namespace requests (the raw flags).
    pub unshare_user: bool,
    pub unshare_user_try: bool,
    pub unshare_pid: bool,
    pub unshare_ipc: bool,
    pub unshare_net: bool,
    pub unshare_uts: bool,
    pub unshare_cgroup: bool,
    pub unshare_cgroup_try: bool,

    // Userns-related fds and flags.
    pub userns_fd: Option<RawFd>,
    pub userns2_fd: Option<RawFd>,
    pub pidns_fd: Option<RawFd>,
    pub disable_userns: bool,
    pub assert_userns_disabled: bool,
    pub userns_block_fd: Option<RawFd>,

    // Identity. `None` is bwrap's (uid_t)-1 sentinel ("not given").
    pub sandbox_uid: Option<u32>,
    pub sandbox_gid: Option<u32>,
    pub hostname: Option<OsString>,

    // Process behaviour.
    pub as_pid_1: bool,
    pub new_session: bool,
    pub die_with_parent: bool,

    // Status fds.
    pub info_fd: Option<RawFd>,
    pub json_status_fd: Option<RawFd>,
    pub block_fd: Option<RawFd>,
    pub sync_fds: Vec<RawFd>,

    // Capability operations, folded onto the runtime base in order.
    pub cap_ops: Vec<CapOp>,
    /// Whether any `--cap-add`/`--cap-drop` was given (bwrap's
    /// `opt_cap_add_or_drop_used`, which gates whether `capset` is called).
    pub cap_add_or_drop_used: bool,

    // Filesystem operations, in command-line order.
    pub ops: Vec<SetupOp>,
    /// `--lock-file` destinations, in order.
    pub lock_files: Vec<SandboxPath>,

    // Environment and process behaviour (CLI-only, not in the validation above).
    /// `--clearenv`/`--setenv`/`--unsetenv`, in order.
    pub env_ops: Vec<EnvOp>,
    /// `--chdir` target (a path inside the sandbox).
    pub chdir: Option<OsString>,
    /// `--argv0` override.
    pub argv0: Option<OsString>,
    /// `--exec-label` (SELinux exec context).
    pub exec_label: Option<OsString>,
    /// `--file-label` (SELinux file context).
    pub file_label: Option<OsString>,
    /// `--not-a-security-boundary`.
    pub not_a_security_boundary: bool,
    /// Seccomp source (`--seccomp` / `--add-seccomp-fd`).
    pub seccomp: SeccompSource,
    /// The command and its arguments (everything after the options).
    pub command: Vec<OsString>,

    // Debug hooks (`--debug-opt=`), used by the upstream test suite.
    /// Force the `openat2` → manual-resolver fallback.
    pub force_openat_fallback: bool,
    /// Force the `mount_setattr` → mountinfo fallback.
    pub force_mount_setattr_fallback: bool,
}

/// The configuration after bwrap's `main()` resolution and checks.
#[derive(Debug)]
pub struct ResolvedConfig {
    /// Resolved namespace decisions.
    pub namespaces: NamespaceConfig,
    /// Sandbox uid (defaulted to the real uid when `--uid` was absent).
    pub sandbox_uid: u32,
    /// Sandbox gid (defaulted to the real gid when `--gid` was absent).
    pub sandbox_gid: u32,
}

impl Config {
    /// Reproduce bwrap's `main()` validation and resolution, in order.
    ///
    /// Returns the first failing check as an [`Error`] whose message matches
    /// bwrap's `die()` text, or the [`ResolvedConfig`] on success.
    pub fn resolve(
        &self,
        real_uid: u32,
        real_gid: u32,
        probe: &dyn UsernsProbe,
    ) -> Result<ResolvedConfig> {
        // --- Checks that run before --unshare-user is forced (main() order) ---
        if self.userns_block_fd.is_some() && !self.unshare_user {
            return Err(Error::invalid("--userns-block-fd requires --unshare-user"));
        }
        if self.userns_block_fd.is_some() && self.info_fd.is_none() {
            return Err(Error::invalid("--userns-block-fd requires --info-fd"));
        }
        if self.userns_fd.is_some() && self.unshare_user {
            return Err(Error::invalid(
                "--userns is not compatible with --unshare-user",
            ));
        }
        if self.userns_fd.is_some() && self.unshare_user_try {
            return Err(Error::invalid(
                "--userns is not compatible with --unshare-user-try",
            ));
        }
        if self.disable_userns && !self.unshare_user {
            return Err(Error::invalid("--disable-userns requires --unshare-user"));
        }
        if self.disable_userns && self.userns_block_fd.is_some() {
            return Err(Error::invalid(
                "--disable-userns is not compatible with --userns-block-fd",
            ));
        }

        // --- Force --unshare-user (main(): "DWIM" for non-root) ---
        let mut unshare_user = self.unshare_user;
        if real_uid != 0 && self.userns_fd.is_none() {
            unshare_user = true;
        }
        // --- --unshare-user-try, gated on kernel support ---
        if self.unshare_user_try
            && probe.user_ns_supported()
            && !probe.unprivileged_userns_disabled()
        {
            unshare_user = true;
        }

        // --- uid/gid defaulting ---
        let sandbox_uid = self.sandbox_uid.unwrap_or(real_uid);
        let sandbox_gid = self.sandbox_gid.unwrap_or(real_gid);

        // --- "No command given" usage error (main()'s second `argc <= 0`) ---
        // It runs after the userns checks, the forcing and the probe, but
        // before the uid/gid/hostname/--as-pid-1/--lock-file checks, so e.g.
        // `--hostname x` with no command is a usage error, not a hostname one.
        if self.command.is_empty() {
            return Err(Error::Usage);
        }

        // --- Checks that run after resolution (main() order) ---
        if !unshare_user && self.userns_fd.is_none() && sandbox_uid != real_uid {
            return Err(Error::invalid(
                "Specifying --uid requires --unshare-user or --userns",
            ));
        }
        if !unshare_user && self.userns_fd.is_none() && sandbox_gid != real_gid {
            return Err(Error::invalid(
                "Specifying --gid requires --unshare-user or --userns",
            ));
        }
        if !self.unshare_uts && self.hostname.is_some() {
            return Err(Error::invalid(
                "Specifying --hostname requires --unshare-uts",
            ));
        }
        if self.as_pid_1 && !self.unshare_pid {
            return Err(Error::invalid(
                "Specifying --as-pid-1 requires --unshare-pid",
            ));
        }
        if self.as_pid_1 && !self.lock_files.is_empty() {
            return Err(Error::invalid(
                "Specifying --as-pid-1 and --lock-file is not permitted",
            ));
        }

        // cgroup namespace (bubblewrap.c:3068-3084): `--unshare-cgroup` requires
        // kernel support — bwrap dies otherwise — while `--unshare-cgroup-try`
        // enables it only when available. Both probe `/proc/self/ns/cgroup`.
        let cgroup_unshare = if self.unshare_cgroup {
            if !probe.cgroup_ns_supported() {
                return Err(Error::invalid(
                    "Cannot create new cgroup namespace because the kernel does not support it",
                ));
            }
            true
        } else {
            self.unshare_cgroup_try && probe.cgroup_ns_supported()
        };

        let ns = |unshare: bool| {
            if unshare {
                NsPolicy::Unshare
            } else {
                NsPolicy::Share
            }
        };
        Ok(ResolvedConfig {
            namespaces: NamespaceConfig {
                user: ns(unshare_user),
                // PID ns is unshared by --unshare-pid; a joined --pidns affects
                // clone flags later but the policy here is "new pid ns wanted".
                pid: ns(self.unshare_pid),
                net: ns(self.unshare_net),
                ipc: ns(self.unshare_ipc),
                uts: ns(self.unshare_uts),
                cgroup: ns(cgroup_unshare),
            },
            sandbox_uid,
            sandbox_gid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Probe that says user namespaces work and are not disabled.
    struct Available;
    impl UsernsProbe for Available {
        fn user_ns_supported(&self) -> bool {
            true
        }
        fn unprivileged_userns_disabled(&self) -> bool {
            false
        }
        fn cgroup_ns_supported(&self) -> bool {
            true
        }
    }

    fn resolve(cfg: &Config, uid: u32) -> Result<ResolvedConfig> {
        cfg.resolve(uid, uid, &Available)
    }

    /// A config with a command, so it passes the "no command" usage gate and
    /// the post-resolution checks are reached.
    fn base() -> Config {
        Config {
            command: vec![OsString::from("true")],
            ..Config::default()
        }
    }

    #[test]
    fn non_root_forces_unshare_user() {
        let r = resolve(&base(), 1000).unwrap();
        assert_eq!(r.namespaces.user, NsPolicy::Unshare);
    }

    #[test]
    fn root_does_not_force_unshare_user() {
        let r = base().resolve(0, 0, &Available).unwrap();
        assert_eq!(r.namespaces.user, NsPolicy::Share);
    }

    #[test]
    fn no_command_is_a_usage_error() {
        let e = base_without_command_resolve();
        assert!(matches!(e, Error::Usage));
    }

    fn base_without_command_resolve() -> Error {
        Config::default()
            .resolve(1000, 1000, &Available)
            .unwrap_err()
    }

    #[test]
    fn no_command_beats_hostname_check() {
        // `--hostname x` with no command is a usage error upstream, not a
        // hostname error (the no-command gate runs first).
        let cfg = Config {
            hostname: Some("box".into()),
            ..Config::default()
        };
        assert!(matches!(
            cfg.resolve(1000, 1000, &Available),
            Err(Error::Usage)
        ));
    }

    #[test]
    fn userns_block_fd_requires_unshare_user() {
        let cfg = Config {
            userns_block_fd: Some(5),
            ..Config::default()
        };
        // real_uid 0 so unshare_user is not forced, exposing the check.
        let e = cfg.resolve(0, 0, &Available).unwrap_err();
        assert_eq!(e.to_string(), "--userns-block-fd requires --unshare-user");
    }

    #[test]
    fn userns_block_fd_requires_info_fd() {
        let cfg = Config {
            unshare_user: true,
            userns_block_fd: Some(5),
            ..Config::default()
        };
        let e = cfg.resolve(0, 0, &Available).unwrap_err();
        assert_eq!(e.to_string(), "--userns-block-fd requires --info-fd");
    }

    #[test]
    fn userns_fd_incompatible_with_unshare_user() {
        let cfg = Config {
            userns_fd: Some(7),
            unshare_user: true,
            ..Config::default()
        };
        let e = cfg.resolve(0, 0, &Available).unwrap_err();
        assert_eq!(
            e.to_string(),
            "--userns is not compatible with --unshare-user"
        );
    }

    #[test]
    fn uid_requires_userns_when_root() {
        // root, no userns, --uid different from real: must fail.
        let cfg = Config {
            sandbox_uid: Some(1000),
            ..base()
        };
        let e = cfg.resolve(0, 0, &Available).unwrap_err();
        assert_eq!(
            e.to_string(),
            "Specifying --uid requires --unshare-user or --userns"
        );
    }

    #[test]
    fn uid_ok_when_userns_present() {
        let cfg = Config {
            sandbox_uid: Some(1000),
            userns_fd: Some(3),
            ..base()
        };
        let r = cfg.resolve(0, 0, &Available).unwrap();
        assert_eq!(r.sandbox_uid, 1000);
    }

    #[test]
    fn hostname_requires_unshare_uts() {
        let cfg = Config {
            hostname: Some("box".into()),
            ..base()
        };
        let e = resolve(&cfg, 1000).unwrap_err();
        assert_eq!(
            e.to_string(),
            "Specifying --hostname requires --unshare-uts"
        );
    }

    #[test]
    fn as_pid_1_requires_unshare_pid() {
        let cfg = Config {
            as_pid_1: true,
            ..base()
        };
        let e = resolve(&cfg, 1000).unwrap_err();
        assert_eq!(
            e.to_string(),
            "Specifying --as-pid-1 requires --unshare-pid"
        );
    }

    #[test]
    fn as_pid_1_and_lock_file_rejected() {
        let cfg = Config {
            as_pid_1: true,
            unshare_pid: true,
            lock_files: vec![SandboxPath::parse("--lock-file", "/l").unwrap()],
            ..base()
        };
        let e = resolve(&cfg, 1000).unwrap_err();
        assert_eq!(
            e.to_string(),
            "Specifying --as-pid-1 and --lock-file is not permitted"
        );
    }

    #[test]
    fn unshare_user_try_honours_probe() {
        struct Disabled;
        impl UsernsProbe for Disabled {
            fn user_ns_supported(&self) -> bool {
                true
            }
            fn unprivileged_userns_disabled(&self) -> bool {
                true
            }
            fn cgroup_ns_supported(&self) -> bool {
                true
            }
        }
        // root + try + disabled => not forced on.
        let cfg = Config {
            unshare_user_try: true,
            ..base()
        };
        let r = cfg.resolve(0, 0, &Disabled).unwrap();
        assert_eq!(r.namespaces.user, NsPolicy::Share);
        // root + try + available => on.
        let r = cfg.resolve(0, 0, &Available).unwrap();
        assert_eq!(r.namespaces.user, NsPolicy::Unshare);
    }

    #[test]
    fn check_order_matches_main() {
        // Both --userns+--unshare-user AND a bad --uid are wrong; bwrap reports
        // the userns one first because it comes earlier in main().
        let cfg = Config {
            userns_fd: Some(3),
            unshare_user: true,
            sandbox_uid: Some(1000),
            ..Config::default()
        };
        let e = cfg.resolve(0, 0, &Available).unwrap_err();
        assert_eq!(
            e.to_string(),
            "--userns is not compatible with --unshare-user"
        );
    }
}
