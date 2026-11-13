//! Golden tests: the parser's text and behaviour must match bubblewrap 0.13.1.
//!
//! The `--help`/`--version` fixtures were captured from `/usr/bin/bwrap`, and
//! the error strings from running it (see UPSTREAM-FINDINGS / DESIGN). Parse
//! errors here are asserted equal to those exact `bwrap: <text>` messages,
//! minus the `bwrap: ` prefix the binary adds.

use std::collections::HashMap;
use std::os::fd::RawFd;

use bwrap_cli::{Outcome, ParseHost, parse, usage};
use bwrap_core::types::{Config, SeccompSource, SetupOp};

/// Test host: maps fd numbers to `--args` bytes and collects warnings.
#[derive(Default)]
struct TestHost {
    files: HashMap<RawFd, Vec<u8>>,
    warnings: Vec<String>,
}
impl ParseHost for TestHost {
    fn read_args(&mut self, fd: RawFd) -> Result<Vec<u8>, bwrap_core::Error> {
        self.files
            .get(&fd)
            .cloned()
            .ok_or_else(|| bwrap_core::Error::invalid(format!("no such test fd {fd}")))
    }
    fn read_seccomp_fd(&mut self, fd: RawFd) -> Result<Vec<u8>, bwrap_core::Error> {
        self.files
            .get(&fd)
            .cloned()
            .ok_or_else(|| bwrap_core::Error::invalid(format!("no such test fd {fd}")))
    }
    fn warn(&mut self, msg: &str) {
        self.warnings.push(msg.to_string());
    }
}

fn words(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_string).collect()
}

fn parse_ok(argv: &str) -> Outcome {
    parse(&words(argv), &mut TestHost::default()).expect("parse should succeed")
}

fn run_cfg(argv: &str) -> Config {
    match parse_ok(argv) {
        Outcome::Run(cfg) => *cfg,
        other => panic!("expected Run, got {other:?}"),
    }
}

fn err(argv: &str) -> String {
    parse(&words(argv), &mut TestHost::default())
        .expect_err("parse should fail")
        .to_string()
}

// ---- help / version -------------------------------------------------------

#[test]
fn version_text_matches_golden() {
    let golden = include_str!("golden/version.txt");
    assert_eq!(format!("{}\n", usage::VERSION), golden);
}

#[test]
fn help_text_matches_golden_for_that_argv0() {
    // The golden was captured as `/usr/bin/bwrap`, so the usage line uses it.
    let golden = include_str!("golden/help.txt");
    assert_eq!(usage::usage("/usr/bin/bwrap"), golden);
}

#[test]
fn help_prints_argv0_verbatim() {
    assert!(usage::usage("./mybw").starts_with("usage: ./mybw [OPTIONS...]"));
    // An empty argv0 is printed verbatim, as C does (it substitutes "bwrap" only
    // for a NULL argv0, which the kernel never delivers). The "bwrap" fallback
    // for a truly missing argv is applied in `main`, not here.
    assert!(usage::usage("").starts_with("usage:  [OPTIONS...]"));
}

#[test]
fn help_and_version_short_circuit() {
    assert!(matches!(parse_ok("--help"), Outcome::Help));
    assert!(matches!(parse_ok("--version"), Outcome::Version));
    // They win even with other (here invalid) options around them.
    assert!(matches!(
        parse_ok("--unshare-pid --help --bogus"),
        Outcome::Help
    ));
}

// ---- error strings (exact bwrap text) -------------------------------------

#[test]
fn error_strings_match_bwrap() {
    assert_eq!(err("--bind /a"), "--bind takes two arguments");
    assert_eq!(err("--bind  /a"), "--bind takes two arguments"); // empty collapses
    assert_eq!(
        err("--perms 0700 --unshare-pid true"),
        "--perms must be followed by an option that creates a file"
    );
    assert_eq!(
        err("--perms 999 --dir /x true"),
        "--perms takes an octal argument <= 07777"
    );
    assert_eq!(
        err("--perms 0700 --perms 0700 --dir /x"),
        "--perms given twice for the same action"
    );
    assert_eq!(
        err("--size 100 --dir /x true"),
        "--size must be followed by --tmpfs"
    );
    assert_eq!(err("--cap-add CAP_NOPE true"), "unknown cap: CAP_NOPE");
    assert_eq!(err("--seccomp abc true"), "Invalid fd: abc");
    assert_eq!(
        err("--chmod 99999 /x true"),
        "--chmod takes an octal argument <= 07777"
    );
    assert_eq!(
        err("--overlay /a /b /c true"),
        "--overlay requires at least one --overlay-src"
    );
    assert_eq!(err("--symlink /a"), "--symlink takes two arguments");
    assert_eq!(
        err("--argv0 x --argv0 y true"),
        "--argv0 used multiple times"
    );
    // `--seccomp` first stores the fd without reading it, so the combine check
    // fires before any fd is touched. (The reverse order reads the fd first and
    // is covered by `add_seccomp_fd_then_seccomp_reads_then_rejects`.)
    assert_eq!(
        err("--seccomp 3 --add-seccomp-fd 4 true"),
        "--add-seccomp-fd cannot be combined with --seccomp"
    );
    assert_eq!(err("--nope"), "Unknown option --nope");
    assert_eq!(
        err("--ro-overlay /d true"),
        "--ro-overlay requires at least two --overlay-src"
    );
}

#[test]
fn empty_path_rejected() {
    // An empty operand becomes a real empty string via the args file.
    let mut r = TestHost::default();
    r.files.insert(7, b"--bind\0\0/dest\0".to_vec());
    let e = parse(&words("--args 7 true"), &mut r)
        .unwrap_err()
        .to_string();
    assert_eq!(e, "--bind does not take an empty path argument");
}

// ---- parse results --------------------------------------------------------

#[test]
fn command_is_everything_after_options() {
    let cfg = run_cfg("--unshare-pid --ro-bind / / -- /bin/sh -c echo hi");
    assert_eq!(cfg.command, vec!["/bin/sh", "-c", "echo", "hi"]);
    assert!(cfg.unshare_pid);
}

#[test]
fn double_dash_lets_command_start_with_dash() {
    let cfg = run_cfg("--unshare-pid -- --weird-cmd arg");
    assert_eq!(cfg.command, vec!["--weird-cmd", "arg"]);
}

#[test]
fn unshare_all_sets_the_try_variants() {
    let cfg = run_cfg("--unshare-all true");
    assert!(cfg.unshare_user_try && cfg.unshare_cgroup_try);
    assert!(cfg.unshare_ipc && cfg.unshare_pid && cfg.unshare_uts && cfg.unshare_net);
    assert!(
        !cfg.unshare_user,
        "--unshare-all uses the -try user variant"
    );
}

#[test]
fn share_net_overrides_unshare_all() {
    let cfg = run_cfg("--unshare-all --share-net true");
    assert!(!cfg.unshare_net);
}

#[test]
fn perms_and_size_modifiers_apply_then_reset() {
    let cfg = run_cfg("--perms 0700 --dir /a --size 4096 --tmpfs /b --dir /c true");
    match &cfg.ops[..] {
        [
            SetupOp::Dir { perms: pa, .. },
            SetupOp::Tmpfs {
                perms: pb, size, ..
            },
            SetupOp::Dir { perms: pc, .. },
        ] => {
            assert_eq!(pa.bits(), 0o700);
            assert_eq!(
                pb.bits(),
                0o755,
                "tmpfs with no --perms uses the 0755 default"
            );
            assert_eq!(*size, Some(4096));
            assert_eq!(
                pc.bits(),
                0o755,
                "the --perms was consumed by the first --dir only"
            );
        }
        other => panic!("unexpected ops: {other:?}"),
    }
}

#[test]
fn default_perms_per_op() {
    let cfg = run_cfg("--dir /a --tmpfs /b --file 3 /c --bind-data 4 /d true");
    match &cfg.ops[..] {
        [
            SetupOp::Dir { perms: d, .. },
            SetupOp::Tmpfs { perms: t, .. },
            SetupOp::File { perms: f, .. },
            SetupOp::BindData { perms: bd, .. },
        ] => {
            assert_eq!(
                (d.bits(), t.bits(), f.bits(), bd.bits()),
                (0o755, 0o755, 0o666, 0o600)
            );
        }
        other => panic!("unexpected ops: {other:?}"),
    }
}

#[test]
fn cap_ops_recorded_in_order() {
    let cfg = run_cfg("--cap-drop ALL --cap-add CAP_NET_ADMIN true");
    assert!(cfg.cap_add_or_drop_used);
    assert_eq!(cfg.cap_ops.len(), 2);
}

#[test]
fn add_seccomp_fd_repeatable() {
    // bwrap reads and validates each --add-seccomp-fd program at parse time, so
    // the fds must carry valid framing; the parsed config keeps the bytes.
    let prog3 = vec![0u8; 8];
    let prog4 = vec![0u8; 16];
    let mut host = TestHost::default();
    host.files.insert(3, prog3.clone());
    host.files.insert(4, prog4.clone());
    let cfg = match parse(
        &words("--add-seccomp-fd 3 --add-seccomp-fd 4 true"),
        &mut host,
    )
    .unwrap()
    {
        Outcome::Run(c) => *c,
        other => panic!("expected Run, got {other:?}"),
    };
    assert_eq!(cfg.seccomp, SeccompSource::Added(vec![prog3, prog4]));
}

#[test]
fn add_seccomp_fd_then_seccomp_reads_then_rejects() {
    // With --add-seccomp-fd first, bwrap reads/validates the fd BEFORE it sees
    // the later --seccomp and rejects the combination (seccomp_program_new runs
    // at parse). So fd 3 must be valid for the combine error to surface.
    let mut host = TestHost::default();
    host.files.insert(3, vec![0u8; 8]);
    let e = parse(&words("--add-seccomp-fd 3 --seccomp 4 true"), &mut host)
        .expect_err("parse should fail")
        .to_string();
    assert_eq!(e, "--seccomp cannot be combined with --add-seccomp-fd");
}

#[test]
fn add_seccomp_fd_bad_data_fails_at_parse() {
    // A program that is not a multiple of 8 fails during parsing (bwrap frames it
    // in seccomp_program_new), not later at apply time.
    let mut host = TestHost::default();
    host.files.insert(3, vec![0u8; 5]);
    let e = parse(&words("--add-seccomp-fd 3 true"), &mut host)
        .expect_err("parse should fail")
        .to_string();
    assert_eq!(e, "Invalid seccomp data, must be multiple of 8");
}

#[test]
fn sync_fd_repeatable() {
    let cfg = run_cfg("--sync-fd 3 --sync-fd 4 true");
    assert_eq!(cfg.sync_fds, vec![3, 4]);
}

#[test]
fn repeated_single_option_warns_keeps_last() {
    let mut host = TestHost::default();
    let outcome = parse(&words("--info-fd 3 --info-fd 5 true"), &mut host).unwrap();
    assert_eq!(
        host.warnings,
        vec!["Only the last --info-fd option will take effect"]
    );
    if let Outcome::Run(cfg) = outcome {
        assert_eq!(cfg.info_fd, Some(5));
    } else {
        panic!("expected Run");
    }
}

#[test]
fn warning_is_emitted_even_when_parsing_then_fails() {
    // bwrap prints the warning, then dies on the later error. The warning must
    // survive the failure (it is emitted immediately, not on success).
    let mut host = TestHost::default();
    let e = parse(&words("--info-fd 3 --info-fd 5 --bogus"), &mut host).unwrap_err();
    assert_eq!(e.to_string(), "Unknown option --bogus");
    assert_eq!(
        host.warnings,
        vec!["Only the last --info-fd option will take effect"]
    );
}

// ---- edge cases verified against the real binary --------------------------

#[test]
fn numeric_capabilities_are_accepted() {
    // libcap's cap_from_name accepts numbers (strtoul base 0).
    for arg in ["21", "0x5", "05", "41", "63"] {
        let cfg = run_cfg(&format!("--cap-add {arg} true"));
        assert_eq!(cfg.cap_ops.len(), 1, "arg {arg}");
    }
    assert_eq!(err("--cap-add 64 true"), "unknown cap: 64");
    assert_eq!(err("--cap-add +5 true"), "unknown cap: +5");
}

#[test]
fn setenv_unsetenv_reject_bad_names() {
    assert_eq!(err("--setenv a=b v true"), "setenv failed");
    assert_eq!(err("--unsetenv a=b true"), "unsetenv failed");
    // A valid name is accepted.
    let cfg = run_cfg("--setenv FOO bar true");
    assert_eq!(cfg.env_ops.len(), 1);
}

#[test]
fn empty_setenv_name_rejected_via_args_file() {
    // The empty name can only be expressed through an --args file.
    let mut r = TestHost::default();
    r.files.insert(4, b"--setenv\0\0val\0true\0".to_vec());
    let e = parse(&words("--args 4"), &mut r).unwrap_err().to_string();
    assert_eq!(e, "setenv failed");
}

#[test]
fn overlay_src_not_followed_by_overlay_gives_dangling_message() {
    // Trailing --overlay-src, and --overlay-src followed by a non-overlay
    // option, both end in the dangling message (matches bwrap).
    assert_eq!(err("--overlay-src /usr"), OVERLAY_DANGLING);
    assert_eq!(
        err("--overlay-src /usr --proc /proc true"),
        OVERLAY_DANGLING
    );
}

const OVERLAY_DANGLING: &str = "--overlay-src must be followed by another --overlay-src or one of --overlay, --tmp-overlay, or --ro-overlay";

#[test]
fn perms_accepts_strtoul_quirks() {
    // strtoul: "-0" is 0; leading whitespace is allowed.
    assert_eq!(run_cfg("--perms -0 --dir /x true").ops.len(), 1);
}

#[test]
fn size_rejects_sign_after_base_prefix() {
    assert_eq!(
        err("--size 0x+5 --tmpfs /x true"),
        "--size takes a non-zero number of bytes"
    );
}

#[test]
fn exercises_the_full_option_surface() {
    // One big invocation touching most option arms, to lock parsing and raise
    // coverage. fds are just numbers here (not opened).
    let cfg = run_cfg(
        "--unshare-user --unshare-ipc --unshare-pid --unshare-net --unshare-uts \
         --unshare-cgroup --unshare-cgroup-try --unshare-user-try \
         --userns 3 --userns2 4 --pidns 5 --disable-userns --assert-userns-disabled \
         --uid 1000 --gid 1000 --hostname box --chdir /work --argv0 sh --new-session \
         --die-with-parent --as-pid-1 --level-prefix --not-a-security-boundary \
         --clearenv --setenv FOO bar --unsetenv BAZ \
         --lock-file /l --sync-fd 6 --sync-fd 7 --block-fd 8 --userns-block-fd 9 \
         --info-fd 10 --json-status-fd 11 \
         --cap-add CAP_NET_ADMIN --cap-drop CAP_SYS_ADMIN \
         --proc /proc --dev /dev --tmpfs /tmp --mqueue /q --dir /d \
         --ro-bind /usr /usr --dev-bind /devhost /devhost --bind-try /maybe /maybe \
         --bind-fd 14 /bf --ro-bind-fd 15 /rbf \
         --perms 0700 --file 16 /f --bind-data 17 /bd --ro-bind-data 18 /rbd \
         --symlink /target /link --remount-ro /usr --chmod 0755 /d \
         --overlay-src /lower --overlay /rw /work /ovl \
         --overlay-src /a --overlay-src /b --ro-overlay /ro \
         --debug-opt=force-openat-fallback --debug-opt=force-mount-setattr-fallback \
         -- /bin/sh -c true",
    );
    assert!(cfg.unshare_user && cfg.unshare_ipc && cfg.unshare_net && cfg.unshare_cgroup);
    assert_eq!(cfg.userns_fd, Some(3));
    assert_eq!(cfg.pidns_fd, Some(5));
    assert!(cfg.disable_userns && cfg.assert_userns_disabled);
    assert_eq!(cfg.sandbox_uid, Some(1000));
    assert_eq!(cfg.hostname.as_deref(), Some("box"));
    assert_eq!(cfg.chdir.as_deref(), Some("/work"));
    assert_eq!(cfg.argv0.as_deref(), Some("sh"));
    // `--level-prefix` has no Config field (its only effect is on the logger's
    // global); that the full parse above accepts it is the coverage here, and
    // its byte-exact output is checked by the conformance `level-prefix` case.
    assert!(cfg.new_session && cfg.die_with_parent && cfg.as_pid_1);
    assert!(
        cfg.not_a_security_boundary
            && cfg.force_openat_fallback
            && cfg.force_mount_setattr_fallback
    );
    assert_eq!(cfg.sync_fds, vec![6, 7]);
    assert_eq!(cfg.block_fd, Some(8));
    assert_eq!(cfg.lock_files.len(), 1);
    assert_eq!(cfg.env_ops.len(), 3);
    assert_eq!(cfg.cap_ops.len(), 2);
    // NB: `--exec-label`/`--file-label` and `--add-seccomp-fd` are NOT exercised
    // here — bwrap reads/validates those at parse time against real resources (the
    // live SELinux policy, an open fd with valid framing), so they belong in the
    // dedicated tests above, not this resource-free parsing sweep.
    assert_eq!(cfg.command, vec!["/bin/sh", "-c", "true"]);
    // Op kinds present, in order, roughly.
    assert!(cfg.ops.iter().any(|o| matches!(o, SetupOp::Proc { .. })));
    assert!(cfg.ops.iter().any(|o| matches!(o, SetupOp::Dev { .. })));
    assert!(cfg.ops.iter().any(|o| matches!(o, SetupOp::Tmpfs { .. })));
    assert!(cfg.ops.iter().any(|o| matches!(o, SetupOp::Mqueue { .. })));
    assert!(cfg.ops.iter().any(|o| matches!(o, SetupOp::Symlink { .. })));
    assert!(cfg.ops.iter().any(|o| matches!(o, SetupOp::Chmod { .. })));
    assert!(
        cfg.ops
            .iter()
            .any(|o| matches!(o, SetupOp::RemountRo { .. }))
    );
    assert_eq!(
        cfg.ops
            .iter()
            .filter(|o| matches!(o, SetupOp::Overlay { .. }))
            .count(),
        2
    );
    assert!(cfg.ops.iter().any(|o| matches!(o, SetupOp::BindFd { .. })));
}

#[test]
fn debug_opt_print_assumed_kernel_and_unknown() {
    assert!(matches!(
        parse_ok("--debug-opt=print-assumed-kernel"),
        Outcome::PrintAssumedKernel
    ));
    assert_eq!(
        err("--debug-opt=bogus true"),
        "Unknown --debug-opt value: bogus"
    );
}

// ---- --args -----------------------------------------------------------------

#[test]
fn args_file_is_parsed_recursively() {
    // Options come from the file; the command must be on the top-level argv.
    // A command inside the file would be discarded (verified against bwrap).
    let mut r = TestHost::default();
    r.files
        .insert(9, b"--unshare-pid\0--ro-bind\0/\0/\0".to_vec());
    let parsed = parse(&words("--args 9 true"), &mut r).unwrap();
    if let Outcome::Run(cfg) = parsed {
        assert!(cfg.unshare_pid);
        assert_eq!(cfg.command, vec!["true"]);
    } else {
        panic!("expected Run");
    }
}

#[test]
fn command_inside_args_file_is_discarded() {
    // bwrap takes the command only from the top level; here it ends up empty.
    let mut r = TestHost::default();
    r.files.insert(9, b"--unshare-pid\0true\0".to_vec());
    let cfg = match parse(&words("--args 9"), &mut r).unwrap() {
        Outcome::Run(cfg) => *cfg,
        other => panic!("expected Run, got {other:?}"),
    };
    assert!(cfg.unshare_pid);
    assert!(cfg.command.is_empty());
}

#[test]
fn args_not_allowed_inside_args_file() {
    let mut r = TestHost::default();
    r.files.insert(9, b"--args\x0010\0".to_vec());
    let e = parse(&words("--args 9"), &mut r).unwrap_err().to_string();
    assert_eq!(e, "--args not supported in arguments file");
}

#[test]
fn overlay_src_across_args_boundary_does_not_crash() {
    // This is upstream F5 (containers/bubblewrap#828): bwrap 0.13.1 segfaults.
    // bwrap-rs builds the overlay cleanly instead.
    let mut r = TestHost::default();
    r.files
        .insert(3, b"--overlay\0/rw\0/work\0/dest\0true\0".to_vec());
    let cfg = match parse(&words("--overlay-src /usr --args 3"), &mut r).unwrap() {
        Outcome::Run(cfg) => *cfg,
        other => panic!("expected Run, got {other:?}"),
    };
    assert!(matches!(cfg.ops[..], [SetupOp::Overlay { .. }]));
    // The `true` lives inside the args file, so it is not the command.
    assert!(cfg.command.is_empty());
}
