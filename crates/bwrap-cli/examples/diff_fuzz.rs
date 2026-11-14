//! Generative differential fuzzer against the real bubblewrap 0.13.1.
//!
//! The conformance matrix proves byte-identity for the cases someone wrote; this
//! synthesises argv from the option grammar, runs **both** binaries, and flags
//! any divergence in exit code / stdout / stderr. That is the one class a rewrite
//! introduces that memory-safety cannot catch and byte-exactness catches only if
//! the exact case was written down (cf. the sudo-rs CVE-2025-64517 logic-bug
//! lesson). Out-of-process and seeded, so a finding reprints a reproducer.
//!
//! Run on a host with user namespaces and the real oracle (a slow scheduled
//! campaign, not CI — many invocations do a full sandbox setup):
//!
//! ```text
//! OURS=target/release/bwrap \
//! REAL=~/dev/bwrap-c-0.13.1/build/bwrap \
//!   cargo run --release --example diff_fuzz -- [iterations] [seed]
//! ```
//!
//! Each invocation is wrapped in `timeout` so a hang (e.g. an error path that
//! leaks a child holding stdout) is skipped, not compared. argv are valid UTF-8
//! and stdio stays open. Non-UTF-8 values are now processed verbatim and are
//! byte-identical on the success path (DIFFERENCES.md #6 is down to error-text
//! rendering only); this campaign keeps to UTF-8 so a divergence it reports is
//! not just that documented error-text gap. The closed-stdio reopen
//! (DIFFERENCES.md #9) stays out of scope. Any reported divergence is a genuine
//! finding or a new one to register.
#![forbid(unsafe_code)]

use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};

/// Minimal deterministic PRNG (xorshift64*), so no dependency is added and a run
/// is fully reproducible from its seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next_u64() % (n as u64)).unwrap_or(0)
    }
    fn pick<'a>(&mut self, pool: &[&'a str]) -> &'a str {
        pool[self.below(pool.len())]
    }
}

// Value pools, each spanning the valid / edge / invalid ranges the C parser and
// validators branch on.
// Deliberately excludes 0/1/2: this harness points the sandbox's stdio at
// /dev/null and capture files, so an fd option naming 0/1/2 reads those (a
// harness artifact, and the documented closed-stdio / empty-seccomp divergences
// DIFFERENCES.md #9/#1), not a real bug. 3+ are closed, giving both binaries a
// clean EBADF.
const FD: &[&str] = &["3", "7", "9", "99", "2147483647", "-1", "abc", ""];
const UINT: &[&str] = &[
    "0",
    "1",
    "1000",
    "65534",
    "4294967295",
    "99999999999",
    "-1",
    "0x10",
    "abc",
    "",
];
const OCTAL: &[&str] = &[
    "0", "700", "0755", "1777", "7777", "10000", "8", "0x20", "zzz", "",
];
const CAP: &[&str] = &[
    "CAP_SYS_ADMIN",
    "cap_net_raw",
    "CAP_CHECKPOINT_RESTORE",
    "CAP_BOGUS",
    "21",
    "0",
    "999",
    "ALL",
    "",
];
const PATH: &[&str] = &[
    "/",
    "/usr",
    "/etc",
    "/nonexistent",
    "/tmp",
    "x",
    "..",
    "/a/b",
    "",
];
const STR: &[&str] = &["x", "", "a b", "ZZZ", "sandbox", "box.example"];

/// The argument "shape" of an option: how many values of which pool it takes.
enum Arg {
    None,
    One(&'static [&'static str]),
    Two(&'static [&'static str], &'static [&'static str]),
}

/// A representative slice of bubblewrap's option grammar (the parse / validation
/// surface, where byte-exact divergences overwhelmingly live).
const OPTS: &[(&str, Arg)] = &[
    ("--unshare-all", Arg::None),
    ("--unshare-user", Arg::None),
    ("--unshare-user-try", Arg::None),
    ("--unshare-ipc", Arg::None),
    ("--unshare-pid", Arg::None),
    ("--unshare-net", Arg::None),
    ("--unshare-uts", Arg::None),
    ("--unshare-cgroup", Arg::None),
    ("--unshare-cgroup-try", Arg::None),
    ("--share-net", Arg::None),
    ("--die-with-parent", Arg::None),
    ("--as-pid-1", Arg::None),
    ("--new-session", Arg::None),
    ("--clearenv", Arg::None),
    ("--disable-userns", Arg::None),
    ("--assert-userns-disabled", Arg::None),
    ("--not-a-security-boundary", Arg::None),
    ("--level-prefix", Arg::None),
    ("--hostname", Arg::One(STR)),
    ("--chdir", Arg::One(PATH)),
    ("--uid", Arg::One(UINT)),
    ("--gid", Arg::One(UINT)),
    ("--cap-add", Arg::One(CAP)),
    ("--cap-drop", Arg::One(CAP)),
    ("--seccomp", Arg::One(FD)),
    ("--add-seccomp-fd", Arg::One(FD)),
    // --info-fd / --json-status-fd omitted: their output carries the run's pid and
    // namespace inodes, which differ between any two processes, so they are not a
    // byte-comparable surface here (the conformance matrix checks their format).
    ("--block-fd", Arg::One(FD)),
    ("--userns", Arg::One(FD)),
    ("--userns2", Arg::One(FD)),
    ("--pidns", Arg::One(FD)),
    ("--userns-block-fd", Arg::One(FD)),
    ("--sync-fd", Arg::One(FD)),
    ("--args", Arg::One(FD)),
    ("--argv0", Arg::One(STR)),
    ("--exec-label", Arg::One(STR)),
    ("--file-label", Arg::One(STR)),
    ("--perms", Arg::One(OCTAL)),
    ("--size", Arg::One(UINT)),
    ("--chmod", Arg::Two(OCTAL, PATH)),
    ("--bind", Arg::Two(PATH, PATH)),
    ("--ro-bind", Arg::Two(PATH, PATH)),
    ("--dev-bind", Arg::Two(PATH, PATH)),
    ("--bind-try", Arg::Two(PATH, PATH)),
    ("--bind-fd", Arg::Two(FD, PATH)),
    ("--symlink", Arg::Two(PATH, PATH)),
    ("--dir", Arg::One(PATH)),
    ("--tmpfs", Arg::One(PATH)),
    ("--proc", Arg::One(PATH)),
    ("--dev", Arg::One(PATH)),
    ("--mqueue", Arg::One(PATH)),
    ("--remount-ro", Arg::One(PATH)),
    ("--setenv", Arg::Two(STR, STR)),
    ("--unsetenv", Arg::One(STR)),
    ("--overlay-src", Arg::One(PATH)),
    ("--tmp-overlay", Arg::One(PATH)),
    ("--ro-overlay", Arg::One(PATH)),
    ("--this-is-not-an-option", Arg::None),
];

fn gen_argv(rng: &mut Rng) -> Vec<String> {
    let mut argv = Vec::new();
    let n = 1 + rng.below(8);
    for _ in 0..n {
        let (flag, arg) = &OPTS[rng.below(OPTS.len())];
        argv.push((*flag).to_string());
        match arg {
            Arg::None => {}
            Arg::One(p) => argv.push(rng.pick(p).to_string()),
            Arg::Two(a, b) => {
                argv.push(rng.pick(a).to_string());
                argv.push(rng.pick(b).to_string());
            }
        }
    }
    // 2/3 of the time give a command (so valid invocations reach exec); otherwise
    // leave it off to exercise the no-command usage error.
    match rng.below(3) {
        0 => {}
        1 => argv.push("/enoent-cmd".to_string()),
        _ => {
            argv.push("/bin/true".to_string());
        }
    }
    argv
}

struct Run {
    code: i32,
    out: String,
    err: String,
    timed_out: bool,
}

/// Run `bin argv…` under `timeout`, stdin = /dev/null, with stdout/stderr sent to
/// **files** (not pipes): some error paths fork a child that holds stdout open,
/// which would make a pipe read block past the timeout — a file read does not, so
/// the whole invocation is bounded to the timeout. A `timeout` kill (124) marks
/// `timed_out`. The temp files are truncated and reused each call.
fn run(bin: &str, argv: &[String], outp: &Path, errp: &Path) -> Run {
    let skip = || Run {
        code: -1,
        out: String::new(),
        err: String::new(),
        timed_out: true,
    };
    let (Ok(of), Ok(ef)) = (File::create(outp), File::create(errp)) else {
        return skip();
    };
    let status = Command::new("timeout")
        .arg("-k")
        .arg("1")
        .arg("3")
        .arg(bin)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::from(of))
        .stderr(Stdio::from(ef))
        .status();
    match status {
        Ok(s) => {
            let code = s.code().unwrap_or(-1);
            let read = |p: &Path| {
                String::from_utf8_lossy(&std::fs::read(p).unwrap_or_default()).into_owned()
            };
            Run {
                code,
                out: read(outp),
                err: read(errp),
                timed_out: code == 124,
            }
        }
        Err(_) => skip(),
    }
}

fn main() -> std::process::ExitCode {
    let ours = std::env::var("OURS").unwrap_or_else(|_| "target/release/bwrap".to_string());
    let real = match std::env::var("REAL") {
        Ok(r) => r,
        Err(_) => {
            eprintln!("set REAL to a bubblewrap 0.13.1 binary");
            return std::process::ExitCode::from(2);
        }
    };
    let mut args = std::env::args().skip(1);
    let iters: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(20_000);
    let seed: u64 = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x1234_5678);

    // Normalise the two binary paths (which appear in usage lines) to one token
    // so only genuine differences remain.
    let norm = |s: &str| s.replace(&ours, "BWRAP").replace(&real, "BWRAP");

    let tmp = std::env::temp_dir();
    let (op, ep) = (tmp.join("diff_fuzz.o"), tmp.join("diff_fuzz.e"));
    eprintln!("diff_fuzz: ours={ours} real={real} iters={iters} seed={seed}");

    let mut rng = Rng::new(seed);
    let (mut ran, mut skipped, mut diffs) = (0u64, 0u64, 0u64);
    for i in 0..iters {
        let argv = gen_argv(&mut rng);
        let o = run(&ours, &argv, &op, &ep);
        if o.timed_out {
            skipped += 1;
            continue;
        }
        let r = run(&real, &argv, &op, &ep);
        if r.timed_out {
            skipped += 1;
            continue;
        }
        ran += 1;
        // Report on stderr (unbuffered) so a finding is never lost to stdout
        // block-buffering, and tick progress every 50 iterations.
        if i % 50 == 0 {
            eprintln!("… {i}/{iters} ({ran} compared, {skipped} skipped, {diffs} diffs)");
        }
        if o.code != r.code || norm(&o.out) != norm(&r.out) || norm(&o.err) != norm(&r.err) {
            diffs += 1;
            eprintln!("\n=== DIVERGENCE #{diffs} (seed={seed} iter={i}) ===");
            eprintln!("argv: {argv:?}");
            eprintln!("exit:   ours={} real={}", o.code, r.code);
            if norm(&o.out) != norm(&r.out) {
                eprintln!("stdout: ours=[{}] real=[{}]", norm(&o.out), norm(&r.out));
            }
            if norm(&o.err) != norm(&r.err) {
                eprintln!("stderr: ours=[{}] real=[{}]", norm(&o.err), norm(&r.err));
            }
        }
    }
    eprintln!(
        "\ndiff_fuzz: {ran} compared, {skipped} skipped (timeout/spawn), {diffs} divergences"
    );
    if diffs > 0 {
        std::process::ExitCode::from(1)
    } else {
        std::process::ExitCode::SUCCESS
    }
}
