# Roadmap

Status: pre-1.0, pre-adoption. Priorities are calibrated to that — proportionate
now, not gold-plating. This is a living plan, not a promise.

## North star

**Byte-exact by default; strictly-safer divergences allowed, documented, and
fail-closed.**

Byte-exactness against bubblewrap 0.13.1 is the default behaviour and the test
oracle (the conformance harness dual-runs every option against a from-source
0.13.1 binary and requires byte-identical exit code, stdout and stderr). It is
the project's single strongest asset: an exhaustive, byte-level correctness
proof. But for a *security* tool, byte-exactness is not an unbreakable rule —
where the C's observable behaviour is itself unsafe, the right move is to diverge
and fail closed, and record it in [DIFFERENCES.md](DIFFERENCES.md). This gives us
the compatibility of a drop-in *and* the security posture of a rewrite.

See [THREAT-MODEL.md](THREAT-MODEL.md) for what the project does and does not
protect, and the crucial reminder that memory safety does not prevent logic-level
escapes (TOCTOU, symlink races, fd confusion, seccomp gaps).

## Now

- **Fuzzing the two untrusted-input paths** — the argv/CLI grammar and the
  seccomp-BPF blob. **In place:** `cargo-fuzz` crash/panic targets (`fuzz/`,
  targets `parse` and `seccomp`) run in CI as a short regression smoke; both
  survive millions of iterations without panicking. **Enhancement (later):** make
  the `parse` target *differential* — reuse the byte-exact oracle so a divergence
  (not just a crash) is a finding; this needs an out-of-process compare against
  the C binary, so it belongs in a slower, scheduled campaign rather than the CI
  smoke.
- **Threat model + divergence register** — [THREAT-MODEL.md](THREAT-MODEL.md)
  and [DIFFERENCES.md](DIFFERENCES.md) as the public, versioned record of every
  intentional deviation (fail-closed) vs. deliberately-replicated C quirk.
- **Targeted hardening tests for the real escape classes** — argument injection
  reaching bwrap, terminal-injection (TIOCSTI/TIOCLINUX, `--new-session`), and
  TOCTOU/symlink races on mount/overlay setup. These are logic bugs Rust does
  *not* prevent, so they need explicit negative tests.
- **Supply-chain CI** — `cargo-deny` (advisories/bans/sources) over the tiny
  (single external) dependency tree. Done. `cargo-audit` is redundant with it.
- **Mutation testing** (`cargo-mutants`) — the third leg beside the conformance
  oracle and the fuzzer: it measures whether the *tests* would catch a
  subtly-wrong implementation (oracle = is the behaviour right; fuzzer = does the
  code survive weird input; mutants = would the tests notice if it broke). A
  scoped run on the number parser (`cnum.rs`) already found and closed one real
  gap — an unguarded base-0 `0x` autodetect case. A scoped run on the logic
  modules (`cnum`, `parse`, `types/op`, `caps`, `seccomp`, `usage`) plus the new
  fd-ownership table — run with the full test environment (user namespaces + the
  real oracle) — came back **348 mutants, 0 missed**. Important scope note: that
  leg exercises the *unit/integration* tests, **not** `conformance.sh`'s
  observability. A separate hand-mutation pass against the conformance matrix
  found that several isolation properties can be removed without a case noticing
  (tracked as the test-observability work below); those gaps are real and still
  open. A full run across all modules still belongs on the build box rather than
  CI.

## Later

- **`rustix` measurement spike** — count how many `-sys` unsafe blocks `rustix`
  (I/O-safe syscall wrappers) could remove versus `nix`, and decide whether to
  relax the "one external dependency" rule. Treat one-dependency as a marketing
  virtue, not a security axiom: adding a second minimal-unsafe, heavily-fuzzed
  crate to *reduce net unsafe lines* is a net win. The genuinely irreducible
  unsafe (raw stackless `clone`, `_exit`, raw seccomp install, environ mutation)
  stays quarantined regardless.
- **The fd-ownership table** — **done (PR #47).** `fd::borrow_raw` and
  `close_raw` are gone; a single `fd::FdTable` owns the inherited descriptor
  numbers and hands out borrows tied to its own lifetime, closing each at most
  once, so a use-after-close is no longer representable in the safe crates (a
  guardrail test fails the build if either escape hatch reappears). `apply_env`
  (formerly `replace_environ`) was already honest — it checks single-threadedness
  itself. The one remaining `bwrap-sys` exception, `close_extra_fds`, is an
  irreducible case: its precondition is a process-global invariant no signature
  can express, so it is slated to be expressed as `unsafe` + a documented caller
  invariant rather than refactored (closes most of issue #33).
- **Fuzz-target upstreaming to OSS-Fuzz** — after the fuzz harnesses exist and
  there is adoption traction (being the sandbox behind Flatpak is the "critical
  infrastructure" argument).
- **nix upstreaming** — the safe-wrapper candidates marked
  `// nix-upstream-kandidaat` in the source (`_exit`, the caps prctls,
  `mount_setattr`) could become genuinely-safe `nix` APIs and delete an unsafe
  block each.
- **Architecture / structure review** — *underway.* The read-only design pass
  (structure is itself a safety mechanism) has produced its first findings: the
  fd-ownership table was its concrete #1 output, and the 13 open issues #29–#41
  have been grouped by root cause rather than treated as 13 unrelated bugs. The
  grouping and the safe-path pattern for each class live in the internal design
  notes; the prioritised next items it yields are:
  1. **Test-observability (#35–#37)** — the conformance matrix proves "the
     command ran and printed the same", not "the option delivered its isolation
     property". Make each option's case observe the property itself, and compare
     files rather than command-substitution captures. Highest security value.
  2. **The ordered op-spine (#29, #34, #31)** — settings bubblewrap runs as
     ordered `SETUP_*` ops must be ops here, not hoisted `Config` scalars or
     deferred transforms. `--hostname` is done; overlay source order and the
     cwd/`PWD` env-timing are the rest of the class.
  3. **#32 `--die-with-parent`** — tie the liveness check to the handshake fd
     (which closes on launcher death) instead of a pid that reads as 0 inside a
     new pid namespace.
  4. **#30 OOM**, then the docs/dead-code/dedup/CI hygiene (#38–#41, with the
     real `EIO`→`ENOSPC` fix folded into the dedup).
  Open structural questions still carried: can the privilege roles (userns /
  real-root / setuid-refused) be kept apart by type rather than by branch (#39 is
  the negative case — a removed role's code paths linger)? Which remaining
  invariants can move from discipline into the type system? Small structural
  improvements only where they clearly pay off.

## Informed by sudo-rs (peer rewrite)

A comparison pass against **sudo-rs** (the Rust rewrite of sudo). Its *philosophy*
is largely the inverse of ours — it deliberately drops features and diverges for
safety, where we are byte-exact by mandate — so that part does not transfer. Its
*engineering process* does, and it validates our bets: our `unsafe` quarantine (a
dedicated `bwrap-sys` crate) is stronger than its per-module attributes; our
standing fuzz + mutation legs go beyond its CI; and its hardest-won lesson
(CVE-2025-64517, a pure logic bug the rewrite introduced) is exactly the case for
our differential conformance oracle. Concrete items it yields:

- **CI-gate the divergence register.** Bind every DIFFERENCES.md entry to an
  expected-divergence / xfail conformance case, and add a CI check that (a) no
  un-registered divergence passes silently and (b) no xfail has started matching
  the oracle again without being promoted. sudo-rs enforces exactly this ("all
  ignored tests linked to an issue" / "didn't forget to gate a passing test"); it
  fits a byte-exact port even better than it fits sudo. Highest-value new item.
- **`ResolvedPath` / parse-don't-validate.** sudo-rs's worst audit finding
  (CLN-001, a path-traversal) was a validate-not-parse failure; for a sandbox that
  resolves bind-mount sources/dests, a typed resolved path is the highest-leverage
  type move. (This is the architecture review's open question (b).)
- **Privilege roles apart by type — yes; typestate for syscall ordering — no.**
  sudo-rs uses thin id newtypes and a scoped-closure (not typestate) for its
  *dynamic* euid transitions, and still shipped privilege bugs — so typestate buys
  less than it costs (matches our "ceremony" call, enforce order by statement
  order). But our roles are *static and discrete* (unprivileged-userns / real-root
  / setuid-refused), so type-separating them is cheap and sound where sudo-rs's
  dynamic model could not support it. (#39 is the negative case: a removed role's
  code paths linger.)
- **Two cheap `bwrap-sys` practices to adopt:** a two-reviewer rule on every
  `SAFETY:` comment, and **Miri in CI** over the `bwrap-sys` unit tests.
- **Scope the `rustix` spike on its own merits.** sudo-rs kept raw `libc` because
  it is setuid-root (minimise trusted code); that argument is weaker for an
  *unprivileged* tool, so a safe wrapper that shrinks `bwrap-sys`'s unsafe surface
  is more defensible for us — evaluate it, keep the one-dependency discipline.

## Skip (for now)

- **Reproducible builds** — valuable once a distro ships this, but low marginal
  security value pre-adoption. Revisit on packaging.
- **`cargo-vet`** — more ceremony than a single-dependency project needs now;
  add it if the dependency set grows or a distro asks.

## Release discipline

No release ships until CI is fully green *and* the two untrusted-input paths are
fuzzed. A new alpha (`v0.1.3-alpha`) follows the current merged work once those
hold; tagging `v*` triggers the release job (version==tag check, build with the
embedded git-sha marker, sha256 upload).
