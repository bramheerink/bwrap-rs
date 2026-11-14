//! The mount layer: bind mounts with attributes (`bind`), and the tmpfs, proc,
//! dev, mqueue and overlay mounts used by `setup_newroot` (`special`). Mirrors
//! bubblewrap's `bind-mount.c` and the mounting half of `setup_newroot`.

pub mod bind;
pub mod flags;
pub mod mountinfo;
pub mod special;

pub use bind::{
    BindError, BindErrorKind, BindResult, bind_mount, bind_mount_fd,
    set_force_mount_setattr_fallback,
};
pub use flags::{BindOptions, decode_mountoptions, remount_added_flags};
pub use mountinfo::{MountEntry, parse_mountinfo, parse_mountinfo_text};
pub use special::{mount_mqueue, mount_tmpfs, remount_ro};
