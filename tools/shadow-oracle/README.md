# Shadow-oracle: differential parity verification

A tool for **anyone** to check, for themselves, that `bwrap-rs` decides the
*same* sandbox as the real bubblewrap would — on their own machine, against
their own real-world invocations.

`bwrap-rs` aims to be a byte-exact, drop-in replacement for bubblewrap. We test
that with a behavioural conformance suite (`tests/conformance.sh`) and with
oracle-anchored differential tests in the crates. This tool extends that to
*live* traffic: it takes the invocations a machine actually makes and compares,
one by one, the plan `bwrap-rs` resolves against the plan upstream bubblewrap
would build.

## How it works

Two side-effect-free halves are compared:

1. **bwrap-rs's plan.** Parsing and resolving arguments in `bwrap-rs` is a pure
   function of the argv — no mounts, no namespaces, no `exec`. The
   `shadow_oracle` example (`crates/bwrap-cli/examples/shadow_oracle.rs`) runs
   that function and serialises the resulting plan.

2. **bubblewrap's plan.** A copy of bubblewrap 0.13.1 with one small, additive,
   env-gated change (`apply_dryrun_patch.py`): when `BWRAP_DRYRUN=1`, it parses
   and validates the arguments exactly as upstream does, prints the plan it
   *would* execute, and `exit(0)` **before any namespace/mount/exec setup**.
   With the variable unset it behaves identically to stock bubblewrap.

The two plans are compared line by line. The real sandbox is never run by this
tool, and the C oracle never changes anything on the system — it only ever
*computes* what it would do.

This is deliberately kept **out of the shipped `bwrap` binary**: it is a
verification aid, not a runtime feature, so the drop-in stays byte-identical to
bubblewrap with nothing extra linked in.

## Building the dry-run oracle

You need a pristine bubblewrap 0.13.1 source tree and its build deps
(`meson`, `ninja`, `gcc`, `libcap`, `libselinux`).

```sh
# 1. copy a pristine bubblewrap-0.13.1 source tree
cp -a /path/to/bubblewrap-0.13.1 c-oracle

# 2. apply the additive dry-run patch
python3 -I apply_dryrun_patch.py c-oracle/bubblewrap.c

# 3. build
cd c-oracle && meson setup build && ninja -C build
#    -> build/bwrap   (this is the dry-run oracle)
```

To target a *different* bubblewrap version (e.g. the one your distribution
ships), start from that version's source instead; the patch anchors on code
that is stable across the 0.1x series, and the plan format is version-agnostic.

## Using it

### One-shot: check a single invocation

```sh
cargo build --release --example shadow_oracle -p bwrap-cli

BWRAP_RS_SHADOW=/path/to/c-oracle/build/bwrap \
  cargo run -q --release --example shadow_oracle -- \
    --unshare-all --ro-bind /usr /usr --proc /proc --dev /dev /bin/true
# -> MATCH (N plan lines)   |   MISMATCH + the diff   |   SKIP
```

### Replay a log of real invocations

`bwrap-rs` can log every invocation it serves (opt-in, see the
`BWRAP_RS_LOG` logger). Replay that log through the oracle:

```sh
BWRAP_RS_SHADOW=/path/to/c-oracle/build/bwrap \
  ./shadow_replay.py ~/bwrap-rs.log
```

### Continuous soak

Keep diffing new invocations as they are logged, recording any divergence:

```sh
BWRAP_RS_SHADOW=/path/to/c-oracle/build/bwrap \
  ./shadow_replay.py --follow --results ~/bwrap-rs-shadow.log ~/bwrap-rs.log
```

### Output format

Each genuine divergence is written as one JSON object per line (JSONL): a line
is greppable, and `jq .` expands it to a readable record. Every record carries
the **call** and what **each side** did with it:

```jsonc
{
  "verdict": "MISMATCH",
  "argv": ["--size", "0b10000000000000000", "--tmpfs", "/s", ...],
  "bwrap_rs": { "outcome": "error", "error": "--size takes a non-zero number of bytes" },
  "bwrap_c":  { "outcome": "plan",  "plan": [ ... "op MOUNT_TMPFS ... size=65536", ... ] },
  "diff": [ { "i": 3, "rs": "...", "c": "..." } ]   // present when both sides built a plan
}
```

Review a soak with e.g. `jq -c '{verdict, argv}' ~/bwrap-rs-shadow.log` or expand
one fully with `jq . ~/bwrap-rs-shadow.log`. Both sides are obtained from a
dry-run: `bwrap-rs` via `BWRAP_RS_DUMP=1` on the `shadow_oracle` example, C via
`BWRAP_DRYRUN=1` on the patched oracle.

## Scope and honest limits

- Invocations using `--args`/`--add-seccomp-fd` are **skipped**: those fds are
  read during parsing and cannot be faithfully replayed into a second process.
- Comparison covers the namespace flags, identity (uid/gid), chdir/argv0 and the
  full ordered `SetupOp` list. Environment mutations (`--setenv` etc.) and the
  exact wording of error messages are not part of the plan diff.
- Some divergences are libc artefacts rather than bubblewrap behaviour (e.g.
  `--size 0b…`, a glibc ≥ 2.38 `strtoull` extension). Known, deliberate
  differences are listed in [`../../DIFFERENCES.md`](../../DIFFERENCES.md).

## Why this exists

Trust in a drop-in replacement should be *checkable*, not asserted. A packager
or a distribution evaluating `bwrap-rs` can point this tool at their own version
of bubblewrap and their own workload and get a concrete parity report, rather
than taking our word for it.
