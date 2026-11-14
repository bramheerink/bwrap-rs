//! Filesystem helpers: resolving paths confined to a root, and creating
//! directory/file nodes. Mirrors bwrap's `safe_openat.c`, `chroot_realpath.c`
//! and the `ensure_*` helpers.

pub mod file;
pub mod io;
pub mod node;
pub mod open;
pub mod resolve;

pub use file::{copy_file_data, file_type};
pub use node::{NodeType, ensure_file_writable_at, ensure_newroot_parents, ensure_node_at};
pub use open::{open_in_root, proc_self_fd, safe_open, set_force_openat_fallback};
pub use resolve::chroot_realpath;
