//! The bwrap-rs domain model: type-safe translations of bwrap's options.
//!
//! - [`path`]: `HostPath` / `SandboxPath` newtypes (reject empty, like #771).
//! - [`caps`]: `Capability` and the 64-bit `CapSet`.
//! - [`op`]: `Mode` and the `SetupOp` enum (one variant per `--bind`, `--dir`, …).
//! - [`config`]: `Config` (parsed options) and its `main()`-faithful `resolve`.

pub mod caps;
pub mod config;
pub mod op;
pub mod path;

pub use caps::{CapOp, CapSet, Capability};
pub use config::{
    Config, EnvOp, NamespaceConfig, NsPolicy, ResolvedConfig, SeccompSource, UsernsProbe,
};
pub use op::{BindKind, Mode, OnMissing, OverlayUpper, SetupOp};
pub use path::{HostPath, SandboxPath};
