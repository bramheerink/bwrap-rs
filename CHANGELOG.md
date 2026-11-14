# Changelog

All notable changes to bwrap-rs. The project is a byte-exact, drop-in
reimplementation of bubblewrap 0.13.1; every release is verified against a
from-source 0.13.1 binary used as a conformance oracle (byte-identical exit
code, stdout and stderr). Deliberate, fail-closed divergences are recorded in
[DIFFERENCES.md](DIFFERENCES.md).

## [0.1.4-alpha] — 2026-11-14

Architecture-review and hardening milestone. No measurable size or speed cost
over 0.1.3-alpha (the release binary is marginally smaller and startup is
within noise; both sit a few percent above the C original, as before).

### Added
- **Non-UTF-8 argument support.** Arbitrary argument bytes (a non-UTF-8 bind
  path, command, `argv[0]`, hostname or environment value) now flow through the
  parser verbatim to the syscalls, exactly as bubblewrap passes its `char *`.
  The success path is byte-identical to C; only error-message *rendering* of
  non-UTF-8 bytes stays lossy for now (DIFFERENCES.md #6, narrowed from the
  previous outright rejection).
- **Generative differential fuzzer** (`crates/bwrap-cli/examples/diff_fuzz.rs`):
  synthesises argv from the option grammar, runs both binaries, and flags any
  exit/stdout/stderr divergence.
- **Conformance now observes isolation properties, not just equivalence.** New
  cases assert the property each option exists for — `setgroups=deny`, net/uts
  namespace isolation, tmpfs size enforcement, dropped capabilities — so a
  regression that silently removes an isolation fails a case (proven with a
  hand-mutation).
- **SECURITY.md** (private reporting + scope) and a threat-model entry naming
  the user-namespace kernel-amplification surface.

### Changed
- **Ordered setup-op spine.** Settings bubblewrap runs as ordered `SETUP_*` ops
  are ops here too (e.g. `--hostname` → `SetHostname`, overlay source order
  resolved upper/work before lower), not hoisted `Config` scalars.
- **`ResolvedOps` parse-don't-validate gate.** The new-root executor accepts
  only ops whose sources were symlink-resolved against the real root, so running
  un-resolved ops is a compile error.
- **`--die-with-parent` closes the launcher-death race under `--unshare-pid`**
  (where pid 1 sees `getppid() == 0`): the liveness check is tied to the
  handshake socket's EOF (DIFFERENCES.md #2/#7).
- Out-of-memory now exits 1 with `Out of memory` like C's `die_oom`, not
  `SIGABRT`.
- `DIFFERENCES.md` reorganised into three explicit categories (safer divergence
  / equivalent by design / known limitation).

### Fixed
- `EIO`→`ENOSPC` drift in the short-write path; several documentation and
  dead-code issues (removed the setuid-era id-map modes); CI/lint hygiene.

## [0.1.3-alpha]

First tagged alpha: byte-exact parser and sandbox core, the conformance oracle
harness, `cargo-fuzz` targets for the argv and seccomp inputs, mutation testing
on the logic modules, and supply-chain CI.
