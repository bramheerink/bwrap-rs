# bwrap-rs

A port of [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) to Rust.

It aims to be a byte-exact, drop-in replacement for bubblewrap 0.13.1 — the same
command-line surface and behaviour, reimplemented in safe Rust (`std` + the `nix`
crate, with `unsafe` confined to a small syscall crate).

The handful of deliberate behavioural differences are documented in
[DIFFERENCES.md](DIFFERENCES.md).

## Build

```sh
cargo build --release    # -> target/release/bwrap
cargo test  --workspace
```

## Credit & license

An independent reimplementation; all design credit belongs to the bubblewrap
authors. Licensed under [LGPL-2.0-or-later](LICENSE), the same as bubblewrap.
