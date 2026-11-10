//! Command-line parsing for bwrap-rs, byte-compatible with bubblewrap's
//! argument grammar (`parse_args_recurse` in `bubblewrap.c`).
//!
//! The parser turns an argument list into a [`bwrap_core::Config`] plus an
//! [`Outcome`]. Its only side effects go through an injected [`ParseHost`]:
//! reading an `--args` file, and emitting warnings. Warnings are emitted
//! immediately (not collected), so — like bwrap — a warning is printed even
//! when parsing then fails with an error. The real host lives with the binary
//! (module 11); tests supply a fake. This keeps the crate `forbid(unsafe)` and
//! fully testable.
//!
//! What this crate does *not* do: the `main()` validation/resolution (that is
//! [`bwrap_core::Config::resolve`]) and the "no command given" usage error,
//! which is interleaved with the resolution checks and therefore belongs to
//! the orchestration layer.

#![forbid(unsafe_code)]

mod parse;
pub mod usage;

use std::os::fd::RawFd;

use bwrap_core::Error;
use bwrap_core::types::Config;

pub use parse::parse;

/// The parser's window onto the outside world: reading `--args` files and
/// emitting warnings. Abstracted so the parser stays pure and testable.
pub trait ParseHost {
    /// Read all bytes from an `--args` fd (bwrap's `load_file_data` + `close`).
    /// The parser then splits them on NUL.
    fn read_args(&mut self, fd: RawFd) -> Result<Vec<u8>, Error>;

    /// Read all bytes from an `--add-seccomp-fd` fd and close it (bwrap's
    /// `load_file_data` + `close` inside `seccomp_program_new`, which takes
    /// ownership of the fd). A read failure is reported as bwrap's
    /// `Can't read seccomp data: <errno>`. Closing it at parse time prevents the
    /// descriptor from leaking into the sandboxed process.
    fn read_seccomp_fd(&mut self, fd: RawFd) -> Result<Vec<u8>, Error>;

    /// Emit a warning (bwrap's `warn()`), e.g. "Only the last --X option will
    /// take effect". Called the moment the condition is hit, before any later
    /// error, so stderr ordering matches bwrap. The binary writes `bwrap: <msg>`
    /// to stderr; a test host may collect them.
    fn warn(&mut self, msg: &str);

    /// Called when `--level-prefix` is parsed, so subsequent warnings/errors get
    /// bwrap's `<N>` syslog-severity prefix. Ordering-sensitive within parsing,
    /// hence a side effect rather than a post-parse config read. Defaults to a
    /// no-op (test hosts that only collect raw warnings need not implement it).
    fn set_level_prefix(&mut self, _on: bool) {}
}

/// What the caller should do after parsing.
#[derive(Debug)]
pub enum Outcome {
    /// Normal: run with this configuration (the command may still be empty;
    /// the caller applies the "no command" usage check in `main()` order).
    Run(Box<Config>),
    /// `--help`: print [`usage::usage`] to stdout and exit 0.
    Help,
    /// `--version`: print [`usage::VERSION`] to stdout and exit 0.
    Version,
    /// `--debug-opt=print-assumed-kernel`: print the assumed kernel and exit 0.
    /// We build with no assumed kernel, so this is `"0.0.0"`.
    PrintAssumedKernel,
}
