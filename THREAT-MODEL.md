# Threat model

`bwrap-rs` is a byte-exact, drop-in reimplementation of bubblewrap 0.13.1. Its
security properties are, by design, **exactly those of bubblewrap** — no more,
no less. This document states what that does and does not buy you, and where the
Rust rewrite actually moves the needle.

## What bwrap is (and is not)

Quoting upstream's own honesty: bubblewrap is *not* a complete, ready-made
sandbox. **The protection level is entirely determined by the arguments passed
to it.** A bwrap invocation with weak arguments is a weak sandbox; `bwrap-rs`
faithfully reproduces that. In particular, bwrap is **not always a security
boundary** — e.g. without `--new-session` (or a seccomp filter) a sandboxed
process can inject input into the controlling terminal (TIOCSTI/TIOCLINUX).
`bwrap-rs` inherits these caveats unchanged.

bwrap is trusted to *build* the sandbox correctly from its arguments. That is the
asset this project protects: the correctness and safety of the sandbox-setup
code itself, on the privilege boundary, before the unprivileged payload runs.

## Attack surface

The code processes untrusted or semi-trusted input on the privilege boundary:

1. **The argument grammar** (`argv`, and `--args FD` NUL-separated args). A
   crafted argument vector reaching bwrap is a real, exploited class — see the
   Flatpak→bubblewrap argument-injection history. This is the primary surface and
   the one where memory safety pays off most.
2. **The seccomp-BPF blob** (`--seccomp`/`--add-seccomp-fd`) — an attacker- or
   caller-supplied byte program parsed and installed into the kernel.
3. **Filesystem setup** — mounts, binds, overlays, symlink resolution and the
   `pivot_root` dance, much of it operating on caller-named paths.
4. **Two privilege roles** the parser feeds into: unprivileged user namespaces
   (the Flatpak path) and real root (rpm-ostree/container builders), plus the
   installed-setuid mode, which must be *refused*.
5. **The kernel surface the namespaces themselves expose.** Creating an
   *unprivileged* user namespace is the enabler for a whole class of kernel
   privilege-escalation bugs (overlayfs copy-up, `fs_context`, and friends) —
   which is why several distributions now gate unprivileged userns behind a
   sysctl or AppArmor. bwrap-rs cannot fix the kernel, and this surface is the
   dominant real-world blast radius for *any* userns sandbox, not the setup code.
   Its job is to not *widen* that surface and to faithfully implement the two
   caller-supplied mitigations that bound it: a **seccomp filter** (restricting
   the syscalls the sandboxed process can reach) and **`--disable-userns`**
   (stopping the sandboxed process from nesting a further user namespace). Both
   are load-bearing for a hardened deployment — Flatpak uses both — so a filter
   that is absent or incomplete, or a missing `--disable-userns`, leaves this
   surface open regardless of how correct bwrap-rs's own setup code is.

## What the Rust rewrite does and does not change

**Removes, structurally:** the C memory-safety bug class (buffer overflows,
use-after-free, uninitialised reads) on the setup and parsing paths. All
`unsafe` is quarantined in one `-sys` crate with mandatory `// SAFETY:`
justifications and lints; the parser and argument handling are
`#![forbid(unsafe_code)]`. This is the core value proposition.

**Does NOT remove:** logic-level sandbox escapes. Memory safety buys *nothing*
against:

- **TOCTOU / symlink races** on setup paths (a path checked then followed
  through an attacker-swapped symlink). This class has bitten *Rust* container
  runtimes too — it is not hypothetical.
- **fd confusion** (the wrong descriptor used for an operation).
- **seccomp-filter gaps** (an incomplete filter the kernel faithfully enforces).
- **argument/parse leniency** that an attacker exploits.

These are **design defects, not language defects**, and are exactly where this
project must keep its guard up. The fd-ownership work (replacing raw borrowed
descriptors with an owned table) and the `--size`/number-parser unification are
examples of extending the same rigor to the logic layer. Filesystem setup
(mount/symlink/overlay) is the next area to harden with explicit race tests.

## Byte-exactness is not a security axiom

Byte-exactness is the default and the *test oracle*, not an unbreakable rule.
Replicating a cosmetic C quirk (e.g. an overlay error that prints `(null)` from
a C use-after-free in the error path) is harmless and documented. But where the
C's observable behaviour is *itself* the vulnerability — a TOCTOU window, a
lenient parse — the right choice is to **diverge and fail closed**, and record
it. See [DIFFERENCES.md](DIFFERENCES.md), which is both the behavioural-divergence
list and the register of deliberate, strictly-safer deviations.

## Honest framing

bubblewrap 0.13.1 is small, mature, widely deployed C that has had years of bug
shake-out. The marginal memory-safety yield from porting such battle-tested code
is lower than from writing new code in Rust. The realistic win here is **future-
proofing the parser against the next bug and providing a maintainable, auditable,
memory-safe base** — proven equivalent to the upstream binary — not a claim that
today's C is riddled with exploitable memory bugs.
