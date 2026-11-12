# bwrap-rs

A port of [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) to Rust.

It aims to be a byte-exact, drop-in replacement for bubblewrap 0.13.1 — the same
command-line surface and behaviour, reimplemented in safe Rust (`std` + the `nix`
crate, with `unsafe` confined to a small syscall crate).

The handful of deliberate behavioural differences are documented in
[DIFFERENCES.md](DIFFERENCES.md).

## Compatibility

Compatibility is defined by bubblewrap *version*, not by distribution: the
target is a byte-exact drop-in for **bubblewrap 0.13.1**, which is the newest
released version — so this port never lags behind, and a distribution's fit only
improves as it updates. The logic is distribution-agnostic (no Fedora-isms;
SELinux is detected at runtime and simply reports "disabled" on AppArmor
systems), and kernel-feature gaps are handled by fallbacks (`openat2` →
`chroot_realpath` below Linux 5.6; a `mount_setattr` fallback).

| bubblewrap version | Fit | Example distributions (at time of writing) |
|---|---|---|
| **0.13.x** | Byte-exact drop-in | Fedora 45 + Rawhide, Arch, openSUSE Tumbleweed, Void, Debian testing/sid, Alpine edge, nixpkgs unstable |
| **0.10–0.12** | Drop-in; differs only where bubblewrap itself changed between those point releases (a few added flags, slightly different usage/error text) | Fedora 44, Debian 13 (trixie), Alpine stable, NixOS stable, Gentoo, openSUSE Leap, Ubuntu 26.04 LTS, CentOS Stream 10 |
| **≤ 0.9** | CLI-backward-compatible (common invocations run), but **not** byte-exact: these versions lack later options and carry older text | Debian stable (bookworm), Ubuntu 24.04 LTS, RHEL/Rocky/Alma 8–9, EPEL 7 |

For live per-distribution versions see
[Repology](https://repology.org/project/bubblewrap/versions).

Notes:

- **Build target.** The release binary is a glibc build. musl distributions
  (Alpine) need a `--target x86_64-unknown-linux-musl` rebuild — no source
  change. Any Linux target supported by Rust and `nix` builds (x86_64,
  aarch64, …).
- **setuid.** Not applicable: bubblewrap 0.13.1 itself refuses setuid use
  (userns-only), and distributions that still rely on a setuid-root `bwrap` are
  by definition on the older (≤ 0.9) versions above.

## Build

```sh
cargo build --release    # -> target/release/bwrap
cargo test  --workspace
```

## Credit & license

An independent reimplementation; all design credit belongs to the bubblewrap
authors. Licensed under [LGPL-2.0-or-later](LICENSE), the same as bubblewrap.
