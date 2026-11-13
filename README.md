# bwrap-rs

A port of [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) to Rust.

It aims to be a byte-exact, drop-in replacement for bubblewrap 0.13.1 — the same
command-line surface and behaviour, reimplemented in safe Rust (`std` + the `nix`
crate, with `unsafe` confined to a small syscall crate).

The north star is **byte-exact by default, with strictly-safer divergences
allowed, documented, and fail-closed** — proven against a real bubblewrap 0.13.1
binary used as an oracle. See:

- [THREAT-MODEL.md](THREAT-MODEL.md) — what this does and does not protect, and
  why memory safety does not prevent logic-level sandbox escapes.
- [DIFFERENCES.md](DIFFERENCES.md) — the divergence register: every deliberate
  deviation and every deliberately-replicated C quirk.
- [ROADMAP.md](ROADMAP.md) — priorities (differential fuzzing next), with
  now/later/skip verdicts.

## Build

```sh
cargo build --release    # -> target/release/bwrap
cargo test  --workspace
```

## Credit & license

A port (derivative work) of bubblewrap 0.13.1; all design credit belongs to the
bubblewrap authors. Licensed under [LGPL-2.1-or-later](LICENSE) — compatible with
bubblewrap's own LGPL-2.0-or-later and with the LGPL-2.1-or-later
`chroot_realpath` code it ports. The directly ported source files carry their
upstream copyright and SPDX notices.
