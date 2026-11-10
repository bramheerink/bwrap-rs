//! Module 13 — drop-in acceptance: a differential harness that runs the same
//! invocations through our `bwrap` and the real `/usr/bin/bwrap` 0.13.1 and
//! compares exit code, stdout and stderr, plus a set of security regression
//! checks (the module-11 review findings) that must hold on our binary alone.
//!
//! `harness = false` with its own `main`: it SKIPs when the kernel refuses user
//! namespaces (e.g. inside the build sandbox), and runs real A/B only when the
//! system `bwrap` is exactly 0.13.1 (the drop-in target). Run it OUTSIDE the
//! Bash sandbox so the namespaces actually work.
#![allow(clippy::unwrap_used)]

use std::process::{Command, ExitCode, Output};

/// Our freshly-built binary (Cargo exposes its path to this bin crate's tests).
const OURS: &str = env!("CARGO_BIN_EXE_bwrap");
const REAL: &str = "/usr/bin/bwrap";

/// A minimal read-only sandbox that is the SAME on any usr-merged distribution:
/// bind `/usr` and recreate the usr-merge symlinks, so the command, its loader
/// and its libraries all resolve through `/usr` whether libc lives in
/// `/usr/lib64` (Fedora) or `/usr/lib/<triplet>` (Debian/Ubuntu). Binding
/// `/lib64`+`/bin` only (the old base) broke on Ubuntu, where libc is under
/// `/lib`. The resulting root is deterministic: bin lib lib64 proc sbin usr.
const BASE: &[&str] = &[
    "--unshare-user",
    "--ro-bind",
    "/usr",
    "/usr",
    "--symlink",
    "usr/bin",
    "/bin",
    "--symlink",
    "usr/lib",
    "/lib",
    "--symlink",
    "usr/lib64",
    "/lib64",
    "--symlink",
    "usr/sbin",
    "/sbin",
    "--proc",
    "/proc",
];

fn run(bin: &str, args: &[&str]) -> Output {
    Command::new(bin).args(args).output().unwrap()
}

/// Run a shell line (for cases that need fd redirection like `--seccomp N N<f`).
fn sh(line: &str) -> Output {
    Command::new("/bin/sh")
        .arg("-c")
        .arg(line)
        .output()
        .unwrap()
}

fn base_with(extra: &[&str]) -> Vec<String> {
    BASE.iter()
        .chain(extra.iter())
        .map(|s| s.to_string())
        .collect()
}

/// Is the system bwrap exactly the drop-in target (0.13.1)?
fn real_is_target() -> bool {
    match Command::new(REAL).arg("--version").output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim() == "bubblewrap 0.13.1",
        Err(_) => false,
    }
}

type Check = (
    &'static str,
    Box<dyn Fn(bool) -> std::result::Result<(), String>>,
);

fn main() -> ExitCode {
    // Probe: can we create a user namespace at all?
    let probe = run(
        OURS,
        &base_with(&["/bin/true"])
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let stderr = String::from_utf8_lossy(&probe.stderr);
    // The base above is distro-agnostic, so the usual reason it can't run here
    // is that user namespaces are restricted (the build sandbox, or Ubuntu's
    // AppArmor userns limit). Either way, if the base can't even run `/bin/true`,
    // skip rather than fail. (Mirrors `tests/conformance.sh`, which also skips
    // when its base `/bin/true` won't run.)
    if !probe.status.success() {
        let reason = stderr.lines().next().unwrap_or("base sandbox unavailable");
        println!("test differential ... SKIP ({reason})");
        return ExitCode::SUCCESS;
    }

    let have_real = real_is_target();
    let checks = build_checks();

    let mut failures = Vec::new();
    for (name, check) in &checks {
        if let Err(msg) = check(have_real) {
            failures.push(format!("  [{name}] {msg}"));
        }
    }

    let n = checks.len();
    if failures.is_empty() {
        let ab = if have_real {
            "with A/B vs /usr/bin/bwrap 0.13.1"
        } else {
            "ours-only (no 0.13.1 present)"
        };
        println!("test differential ... ok ({n} checks, {ab})");
        ExitCode::SUCCESS
    } else {
        println!("test differential ... FAILED ({}/{n}):", failures.len());
        for f in &failures {
            println!("{f}");
        }
        ExitCode::FAILURE
    }
}

/// Run `args` through ours and (if present) the real bwrap, asserting identical
/// exit/stdout/stderr. When real is absent, assert ours matches `want`.
fn differential(
    args: &[&str],
    want: impl Fn(&Output) -> std::result::Result<(), String>,
    have_real: bool,
) -> std::result::Result<(), String> {
    let o = run(OURS, args);
    want(&o)?;
    if have_real {
        let r = run(REAL, args);
        if o.status.code() != r.status.code() {
            return Err(format!(
                "exit differs: ours={:?} real={:?}",
                o.status.code(),
                r.status.code()
            ));
        }
        if o.stdout != r.stdout {
            return Err(format!(
                "stdout differs:\n  ours={:?}\n  real={:?}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&r.stdout)
            ));
        }
        if o.stderr != r.stderr {
            return Err(format!(
                "stderr differs:\n  ours={:?}\n  real={:?}",
                String::from_utf8_lossy(&o.stderr),
                String::from_utf8_lossy(&r.stderr)
            ));
        }
    }
    Ok(())
}

fn exit_is(o: &Output, code: i32) -> std::result::Result<(), String> {
    if o.status.code() == Some(code) {
        Ok(())
    } else {
        Err(format!(
            "expected exit {code}, got {:?} (stderr: {})",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr)
        ))
    }
}

fn build_checks() -> Vec<Check> {
    let mut v: Vec<Check> = Vec::new();

    // --- Core behaviour, differential vs real when present ---
    v.push((
        "echo",
        Box::new(|real| {
            let args = base_with(&["/bin/echo", "hello"]);
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            differential(
                &a,
                |o| {
                    exit_is(o, 0)?;
                    if o.stdout == b"hello\n" {
                        Ok(())
                    } else {
                        Err(format!("stdout={:?}", String::from_utf8_lossy(&o.stdout)))
                    }
                },
                real,
            )
        }),
    ));

    v.push((
        "false-exit-1",
        Box::new(|real| {
            let args = base_with(&["/bin/false"]);
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            differential(&a, |o| exit_is(o, 1), real)
        }),
    ));

    v.push((
        "sigterm-143",
        Box::new(|real| {
            let args = base_with(&["/bin/sh", "-c", "kill -TERM $$"]);
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            differential(&a, |o| exit_is(o, 143), real)
        }),
    ));

    v.push((
        "isolation-ls-root",
        Box::new(|real| {
            let args = base_with(&["/bin/sh", "-c", "ls /"]);
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            differential(
                &a,
                |o| {
                    exit_is(o, 0)?;
                    let mut got: Vec<&str> = std::str::from_utf8(&o.stdout)
                        .unwrap_or("")
                        .split_whitespace()
                        .collect();
                    got.sort_unstable();
                    if got == ["bin", "lib", "lib64", "proc", "sbin", "usr"] {
                        Ok(())
                    } else {
                        Err(format!("root entries: {got:?}"))
                    }
                },
                real,
            )
        }),
    ));

    // Error grammar: a missing bind source must match C byte-for-byte on stderr
    // (regression for the resolve_symlinks_in_ops "Can't find source path" fix).
    v.push((
        "missing-source-error",
        Box::new(|real| {
            let args = base_with(&["--bind", "/no/such/src", "/x", "/bin/true"]);
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            differential(&a, |o| exit_is(o, 1), real)
        }),
    ));

    // --- Security regressions from the module-11 review (ours-only invariants) ---
    v.push((
        "no-new-privs",
        Box::new(|_| {
            let args = base_with(&["/bin/sh", "-c", "grep NoNewPrivs /proc/self/status"]);
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            let o = run(OURS, &a);
            exit_is(&o, 0)?;
            if String::from_utf8_lossy(&o.stdout).contains("NoNewPrivs:\t1") {
                Ok(())
            } else {
                Err(format!(
                    "NoNewPrivs not 1: {:?}",
                    String::from_utf8_lossy(&o.stdout)
                ))
            }
        }),
    ));

    v.push((
        "info-fd-not-leaked",
        Box::new(|_| {
            // fd 7 (the --info-fd) must not be open in the sandboxed process.
            let base = BASE.join(" ");
            let line =
                format!("{OURS} --info-fd 7 {base} /bin/sh -c 'ls /proc/self/fd/7' 7>/dev/null");
            let o = sh(&line);
            if o.status.code() == Some(0) {
                Err("fd 7 is still open in the sandbox".into())
            } else {
                Ok(())
            }
        }),
    ));

    v.push((
        "sync-fd-not-leaked",
        Box::new(|_| {
            let base = BASE.join(" ");
            let line =
                format!("{OURS} --sync-fd 8 {base} /bin/sh -c 'ls /proc/self/fd/8' 8<>/dev/null");
            let o = sh(&line);
            if o.status.code() == Some(0) {
                Err("fd 8 is still open in the sandbox".into())
            } else {
                Ok(())
            }
        }),
    ));

    v.push((
        "seccomp-allows",
        Box::new(|real| {
            // An 8-byte BPF program: single RET|K with SECCOMP_RET_ALLOW (0x7fff0000).
            let dir = std::env::temp_dir().join(format!("bwrap-diff-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let bpf = dir.join("allow.bpf");
            std::fs::write(&bpf, [0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f]).unwrap();
            let base = BASE.join(" ");
            let line = format!("{OURS} --seccomp 9 {base} /bin/true 9<{}", bpf.display());
            let o = sh(&line);
            let res = exit_is(&o, 0);
            if res.is_ok() && real {
                let rline = format!("{REAL} --seccomp 9 {base} /bin/true 9<{}", bpf.display());
                let r = sh(&rline);
                if r.status.code() != Some(0) {
                    let _ = std::fs::remove_dir_all(&dir);
                    return Err(format!("real bwrap seccomp exit {:?}", r.status.code()));
                }
            }
            let _ = std::fs::remove_dir_all(&dir);
            res
        }),
    ));

    v.push((
        "invalid-exec-label",
        Box::new(|real| {
            // An invalid SELinux label must be rejected identically to C (on a
            // SELinux-enabled host; where SELinux is off, both say "labeling not
            // supported" — still a match).
            let args = base_with(&["--exec-label", "not_a_real_type_t", "/bin/true"]);
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            differential(&a, |o| exit_is(o, 1), real)
        }),
    ));

    v
}
