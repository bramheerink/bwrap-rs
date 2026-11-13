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

- **Differential fuzzing of the two untrusted-input paths** — the argv/CLI
  grammar and the seccomp-BPF blob. Reuse the existing byte-exact oracle as the
  comparison target so the harness goes from example-based to coverage-guided
  (`cargo-fuzz` + `arbitrary` for structure-aware argv). Highest-value work: it
  directly de-risks the parser, the exact path where memory safety pays off.
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
  gap — an unguarded base-0 `0x` autodetect case. A full run across all modules
  needs the complete test environment (user namespaces, the real oracle) and
  belongs on the build box rather than CI.

## Later

- **`rustix` measurement spike** — count how many `-sys` unsafe blocks `rustix`
  (I/O-safe syscall wrappers) could remove versus `nix`, and decide whether to
  relax the "one external dependency" rule. Treat one-dependency as a marketing
  virtue, not a security axiom: adding a second minimal-unsafe, heavily-fuzzed
  crate to *reduce net unsafe lines* is a net win. The genuinely irreducible
  unsafe (raw stackless `clone`, `_exit`, raw seccomp install, environ mutation)
  stays quarantined regardless.
- **The fd-ownership table** — replace the unsound `fd::borrow_raw` with a table
  that owns inherited descriptors and hands out table-scoped borrows, consumed by
  `close_extra_fds` so the borrow checker enforces the invariant. Removes the two
  remaining documented exceptions in `bwrap-sys/src/lib.rs`.
- **Fuzz-target upstreaming to OSS-Fuzz** — after the fuzz harnesses exist and
  there is adoption traction (being the sandbox behind Flatpak is the "critical
  infrastructure" argument).
- **nix upstreaming** — the safe-wrapper candidates marked
  `// nix-upstream-kandidaat` in the source (`_exit`, the caps prctls,
  `mount_setattr`) could become genuinely-safe `nix` APIs and delete an unsafe
  block each.
- **Architecture / structure review** — a deliberate, read-only design pass (not
  a rewrite): re-examine the module boundaries and type seams through the lens of
  the threat model, because *structure is itself a safety mechanism*. The
  strongest fixes so far were structural — the unsafe quarantine, the planned
  fd-ownership table, types that make illegal states unrepresentable — not point
  patches. Questions to ask: is `parse → Config → setup` the cleanest
  untrusted-input seam? Can the privilege roles (userns / real-root /
  setuid-refused) be kept apart by type rather than by branch? Which remaining
  invariants can move from discipline into the type system so the compiler
  enforces them? Findings first; small structural improvements only where they
  clearly pay off.

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
