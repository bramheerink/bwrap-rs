//! Parser edge cases: duplicate-option warnings, argument-count limits,
//! `--args` file handling, overlay bookkeeping, and the strtol/strtoull
//! number-parsing corner cases. Expected strings were confirmed against
//! `/usr/bin/bwrap` (bubblewrap 0.13.1).

use std::collections::HashMap;
use std::os::fd::RawFd;

use bwrap_cli::{Outcome, ParseHost, parse};
use bwrap_core::types::{BindKind, Config, OverlayUpper, SeccompSource, SetupOp};

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

fn argv(s: &[&str]) -> Vec<std::ffi::OsString> {
    s.iter().map(std::ffi::OsString::from).collect()
}

/// Parse, returning the config and the warnings emitted.
fn ok(a: &[&str]) -> (Config, Vec<String>) {
    let mut host = TestHost::default();
    match parse(&argv(a), &mut host).expect("parse should succeed") {
        Outcome::Run(c) => (*c, host.warnings),
        other => panic!("expected Run, got {other:?}"),
    }
}

/// Parse expecting failure: the error text and the warnings emitted before it.
fn fails(a: &[&str]) -> (String, Vec<String>) {
    let mut host = TestHost::default();
    let e = parse(&argv(a), &mut host).expect_err("parse should fail");
    (e.to_string(), host.warnings)
}

fn err(a: &[&str]) -> String {
    fails(a).0
}

fn only_last(name: &str) -> Vec<String> {
    vec![format!("Only the last {name} option will take effect")]
}

#[test]
fn repeated_single_value_options_warn_and_last_wins() {
    let (c, w) = ok(&["--chdir", "/a", "--chdir", "/b", "true"]);
    assert_eq!(c.chdir.as_deref(), Some(std::ffi::OsStr::new("/b")));
    assert_eq!(w, only_last("--chdir"));

    let (c, w) = ok(&["--uid", "1", "--uid", "2", "true"]);
    assert_eq!(c.sandbox_uid, Some(2));
    assert_eq!(w, only_last("--uid"));

    let (c, w) = ok(&["--gid", "1", "--gid", "2", "true"]);
    assert_eq!(c.sandbox_gid, Some(2));
    assert_eq!(w, only_last("--gid"));

    let (c, w) = ok(&["--hostname", "a", "--hostname", "b", "true"]);
    assert_eq!(c.hostname.as_deref(), Some(std::ffi::OsStr::new("b")));
    assert_eq!(w, only_last("--hostname"));

    // `--exec-label`/`--file-label` last-wins is NOT asserted here: bwrap validates
    // each label against the live SELinux policy at parse time, so a placeholder
    // label like "a" dies ("invalid label a", or "labeling not supported" without
    // SELinux) before last-wins is observable. It is covered — with a host-valid
    // label — by the oracle-anchored differential tests instead.

    let (c, w) = ok(&["--seccomp", "5", "--seccomp", "6", "true"]);
    assert_eq!(c.seccomp, SeccompSource::Single(6));
    assert_eq!(w, only_last("--seccomp"));
}

#[test]
fn repeated_fd_options_warn_before_validating_the_fd() {
    let (c, w) = ok(&["--userns", "3", "--userns", "4", "true"]);
    assert_eq!((c.userns_fd, w), (Some(4), only_last("--userns")));
    let (c, w) = ok(&["--userns2", "3", "--userns2", "4", "true"]);
    assert_eq!((c.userns2_fd, w), (Some(4), only_last("--userns2")));
    let (c, w) = ok(&["--pidns", "3", "--pidns", "4", "true"]);
    assert_eq!((c.pidns_fd, w), (Some(4), only_last("--pidns")));
    // The warning is emitted even though the second value is then rejected.
    let (e, w) = fails(&["--pidns", "3", "--pidns", "x", "true"]);
    assert_eq!(e, "Invalid fd: x");
    assert_eq!(w, only_last("--pidns"));
}

#[test]
fn missing_operand_messages() {
    for (opt, msg) in [
        ("--chdir", "--chdir takes one argument"),
        ("--uid", "--uid takes an argument"),
        ("--gid", "--gid takes an argument"),
        ("--hostname", "--hostname takes an argument"),
        ("--exec-label", "--exec-label takes an argument"),
        ("--seccomp", "--seccomp takes an argument"),
        ("--userns", "--userns takes an argument"),
        ("--userns2", "--userns2 takes an argument"),
        ("--pidns", "--pidns takes an argument"),
        ("--cap-add", "--cap-add takes an argument"),
        ("--cap-drop", "--cap-drop takes an argument"),
        ("--size", "--size takes an argument"),
        ("--perms", "--perms takes an argument"),
        ("--bind-data", "--bind-data takes two arguments"),
        ("--ro-bind-data", "--ro-bind-data takes two arguments"),
    ] {
        assert_eq!(err(&[opt]), msg, "{opt}");
    }
    // bind-data needs two operands, not one.
    assert_eq!(
        err(&["--bind-data", "3"]),
        "--bind-data takes two arguments"
    );
}

#[test]
fn empty_path_operands_are_rejected() {
    assert_eq!(
        err(&["--chdir", "", "true"]),
        "--chdir does not take an empty path argument"
    );
    assert_eq!(
        err(&["--overlay-src", "/a", "--tmp-overlay", "", "true"]),
        "--tmp-overlay does not take an empty path argument"
    );
}

#[test]
fn uid_gid_follow_strtol_int_narrowing() {
    // 2^32 + 1 wraps to 1 when stored in an int, like bwrap.
    let (c, _) = ok(&["--uid", "4294967297", "true"]);
    assert_eq!(c.sandbox_uid, Some(1));
    let (c, _) = ok(&["--gid", " 7", "true"]);
    assert_eq!(c.sandbox_gid, Some(7), "leading whitespace is accepted");
    let (c, _) = ok(&["--uid", "+9", "true"]);
    assert_eq!(c.sandbox_uid, Some(9));
    let (c, _) = ok(&["--uid", "\u{b}3", "true"]);
    assert_eq!(c.sandbox_uid, Some(3), "vertical tab is C whitespace");
    for bad in ["-1", " 5x", "", "abc", "5 ", "+", "-", " "] {
        assert_eq!(err(&["--uid", bad, "true"]), format!("Invalid uid: {bad}"));
        assert_eq!(err(&["--gid", bad, "true"]), format!("Invalid gid: {bad}"));
    }
}

#[test]
fn strtol_overflow_saturates_then_narrows() {
    // LONG_MAX narrows to -1 as an int: rejected. LONG_MIN narrows to 0.
    assert_eq!(
        err(&["--uid", "99999999999999999999", "true"]),
        "Invalid uid: 99999999999999999999"
    );
    let (c, _) = ok(&["--uid", "-99999999999999999999", "true"]);
    assert_eq!(c.sandbox_uid, Some(0));
    assert_eq!(
        err(&["--userns", "99999999999999999999", "true"]),
        "Invalid fd: 99999999999999999999"
    );
    let (c, _) = ok(&["--userns", "-99999999999999999999", "true"]);
    assert_eq!(c.userns_fd, Some(0));
}

#[test]
fn size_parsing_matches_strtoull_base0() {
    let tmpfs_size = |s: &str| -> Option<u64> {
        let (c, _) = ok(&["--size", s, "--tmpfs", "/x", "true"]);
        match c.ops.as_slice() {
            [SetupOp::Tmpfs { size, .. }] => *size,
            other => panic!("unexpected ops {other:?}"),
        }
    };
    assert_eq!(tmpfs_size("1024"), Some(1024));
    assert_eq!(tmpfs_size("0x10"), Some(16));
    assert_eq!(tmpfs_size("0X1f"), Some(31));
    assert_eq!(tmpfs_size("010"), Some(8), "leading 0 means octal");
    assert_eq!(tmpfs_size("9223372036854775807"), Some(i64::MAX as u64));

    let nonzero = "--size takes a non-zero number of bytes";
    for bad in [
        "0",
        "00",
        "0x0",
        "",
        " 5",
        "-5",
        "+5",
        "abc",
        "5k",
        "0x",
        "0x+5",
        "0x-5",
        "08",
        "99999999999999999999",
    ] {
        assert_eq!(
            err(&["--size", bad, "--tmpfs", "/x", "true"]),
            nonzero,
            "{bad:?}"
        );
    }
    assert_eq!(
        err(&["--size", "9223372036854775808", "--tmpfs", "/x", "true"]),
        "--size (for tmpfs) is limited to 9223372036854775807"
    );
    assert_eq!(
        err(&["--size", "0x10", "--size", "5", "--tmpfs", "/x", "true"]),
        "--size given twice for the same action"
    );
    assert_eq!(
        err(&["--perms", "0755", "--perms", "0700", "--dir", "/x", "true"]),
        "--perms given twice for the same action"
    );
}

#[test]
fn modifiers_apply_to_one_action_only() {
    let (c, _) = ok(&["--perms", "0700", "--dir", "/a", "--dir", "/b", "true"]);
    match c.ops.as_slice() {
        [
            SetupOp::Dir { perms: p1, .. },
            SetupOp::Dir { perms: p2, .. },
        ] => {
            assert_eq!(p1.bits(), 0o700);
            assert_eq!(p2.bits(), 0o755);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn bind_data_validates_fd_and_dest() {
    assert_eq!(err(&["--bind-data", "x", "/a", "true"]), "Invalid fd: x");
    assert_eq!(
        err(&["--ro-bind-data", "3", "", "true"]),
        "--ro-bind-data does not take an empty path argument"
    );
    let (c, _) = ok(&[
        "--perms",
        "0640",
        "--bind-data",
        "5",
        "/a",
        "--ro-bind-data",
        "6",
        "/b",
        "true",
    ]);
    match c.ops.as_slice() {
        [
            SetupOp::BindData {
                fd: 5,
                kind: BindKind::ReadWrite,
                perms: pa,
                ..
            },
            SetupOp::BindData {
                fd: 6,
                kind: BindKind::ReadOnly,
                perms: pb,
                ..
            },
        ] => {
            assert_eq!(pa.bits(), 0o640);
            assert_eq!(pb.bits(), 0o600, "default is 0600 and --perms was consumed");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(c.command, ["true"]);
}

#[test]
fn overlay_rules() {
    assert_eq!(
        err(&["--tmp-overlay", "/a", "true"]),
        "--tmp-overlay requires at least one --overlay-src"
    );
    assert_eq!(
        err(&["--ro-overlay", "/a", "true"]),
        "--ro-overlay requires at least two --overlay-src"
    );
    assert_eq!(
        err(&["--overlay-src", "/b", "--ro-overlay", "/a", "true"]),
        "--ro-overlay requires at least two --overlay-src"
    );
    assert_eq!(
        err(&["--overlay", "/u", "/w", "/d"]),
        "--overlay requires at least one --overlay-src"
    );
    let dangling = "--overlay-src must be followed by another --overlay-src or one of --overlay, --tmp-overlay, or --ro-overlay";
    assert_eq!(err(&["--overlay-src"]), dangling);
    assert_eq!(err(&["--overlay-src", "/a"]), dangling);
    assert_eq!(err(&["--overlay-src", "/a", "true"]), dangling);

    let (c, _) = ok(&[
        "--overlay-src",
        "/l1",
        "--overlay-src",
        "/l2",
        "--tmp-overlay",
        "/t",
        "--overlay-src",
        "/l3",
        "--overlay-src",
        "/l4",
        "--ro-overlay",
        "/r",
        "--overlay-src",
        "/l5",
        "--overlay",
        "/up",
        "/work",
        "/p",
        "true",
    ]);
    match c.ops.as_slice() {
        [
            SetupOp::Overlay {
                lower: l1,
                upper: OverlayUpper::Tmp,
                dest: d1,
            },
            SetupOp::Overlay {
                lower: l2,
                upper: OverlayUpper::ReadOnly,
                dest: d2,
            },
            SetupOp::Overlay {
                lower: l3,
                upper: OverlayUpper::Persistent { upper, work },
                dest: d3,
            },
        ] => {
            let s = |v: &Vec<bwrap_core::types::HostPath>| {
                v.iter().map(ToString::to_string).collect::<Vec<_>>()
            };
            assert_eq!(s(l1), ["/l1", "/l2"]);
            assert_eq!(
                s(l2),
                ["/l3", "/l4"],
                "sources are consumed by each overlay"
            );
            assert_eq!(s(l3), ["/l5"]);
            assert_eq!((&*d1.as_str(), &*d2.as_str(), &*d3.as_str()), ("/t", "/r", "/p"));
            assert_eq!((&*upper.as_str(), &*work.as_str()), ("/up", "/work"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn seccomp_exclusivity() {
    // --add-seccomp-fd first: bwrap reads/validates fd 5 at parse time, then
    // rejects the later --seccomp, so fd 5 must carry a valid program.
    let mut host = TestHost::default();
    host.files.insert(5, vec![0u8; 8]);
    let e = parse(
        &argv(&["--add-seccomp-fd", "5", "--seccomp", "6", "true"]),
        &mut host,
    )
    .expect_err("parse should fail")
    .to_string();
    assert_eq!(e, "--seccomp cannot be combined with --add-seccomp-fd");

    // --seccomp first only stores the fd, so the combine check rejects
    // --add-seccomp-fd before its fd is ever read (no fd 6 needed).
    assert_eq!(
        err(&["--seccomp", "5", "--add-seccomp-fd", "6", "true"]),
        "--add-seccomp-fd cannot be combined with --seccomp"
    );
}

#[test]
fn argument_count_limit() {
    // 9000 is allowed, 9001 is not.
    let many = |n: usize| vec![std::ffi::OsString::from("--unshare-pid"); n];
    let mut host = TestHost::default();
    assert!(parse(&many(9000), &mut host).is_ok());
    let e = parse(&many(9001), &mut host).unwrap_err();
    assert_eq!(e.to_string(), "Exceeded maximum number of arguments 9000");
}

#[test]
fn args_file_handling() {
    let mut host = TestHost::default();
    host.files
        .insert(5, b"--unshare-net\0--hostname\0h\0".to_vec());
    host.files.insert(6, Vec::new());
    host.files.insert(7, b"--args\x005\0".to_vec());
    let mut big = Vec::new();
    for _ in 0..9000 {
        big.extend_from_slice(b"--unshare-pid\0");
    }
    host.files.insert(8, big);

    let a = argv(&["--args", "5", "--unshare-uts", "true"]);
    let Outcome::Run(c) = parse(&a, &mut host).unwrap() else {
        panic!()
    };
    assert!(c.unshare_net && c.unshare_uts);
    assert_eq!(c.hostname.as_deref(), Some(std::ffi::OsStr::new("h")));
    assert_eq!(c.command, ["true"]);

    // An empty file contributes no arguments (not one empty argument).
    let a = argv(&["--args", "6", "--unshare-ipc", "true"]);
    let Outcome::Run(c) = parse(&a, &mut host).unwrap() else {
        panic!()
    };
    assert!(c.unshare_ipc);

    // --args inside an args file is refused.
    let e = parse(&argv(&["--args", "7", "true"]), &mut host).unwrap_err();
    assert_eq!(e.to_string(), "--args not supported in arguments file");

    // The cap counts arguments coming out of files too.
    let e = parse(&argv(&["--args", "8", "true"]), &mut host).unwrap_err();
    assert_eq!(e.to_string(), "Exceeded maximum number of arguments 9000");

    // Missing operand, bad fd, unreadable fd.
    assert_eq!(
        parse(&argv(&["--args"]), &mut host)
            .unwrap_err()
            .to_string(),
        "--args takes an argument"
    );
    assert_eq!(
        parse(&argv(&["--args", "x"]), &mut host)
            .unwrap_err()
            .to_string(),
        "Invalid fd: x"
    );
    assert_eq!(
        parse(&argv(&["--args", "99", "true"]), &mut host)
            .unwrap_err()
            .to_string(),
        "no such test fd 99"
    );
}

#[test]
fn debug_opts() {
    let (c, _) = ok(&[
        "--debug-opt=force-openat-fallback",
        "--debug-opt=force-mount-setattr-fallback",
        "true",
    ]);
    assert!(c.force_openat_fallback && c.force_mount_setattr_fallback);
    let mut host = TestHost::default();
    assert!(matches!(
        parse(&argv(&["--debug-opt=print-assumed-kernel"]), &mut host).unwrap(),
        Outcome::PrintAssumedKernel
    ));
}
