//! `mount_setattr(2)` (Linux 5.12+): change the flags of an existing mount
//! (or a whole mount tree) by file descriptor.
//!
//! bwrap uses it to make bind mounts `ro`/`nodev`/`nosuid`, recursively when
//! requested. On `ENOSYS` the caller falls back to `/proc/self/mountinfo` plus
//! `MS_REMOUNT`, which lives in `bwrap-core`.

use std::ops::{BitOr, BitOrAssign};
use std::os::fd::{AsRawFd, BorrowedFd};

use nix::errno::Errno;
use nix::libc::{self, c_uint, mount_attr};

/// Set of `MOUNT_ATTR_*` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct MountAttrFlags(u64);

impl MountAttrFlags {
    /// `MOUNT_ATTR_RDONLY`
    pub const RDONLY: Self = Self(libc::MOUNT_ATTR_RDONLY);
    /// `MOUNT_ATTR_NOSUID`
    pub const NOSUID: Self = Self(libc::MOUNT_ATTR_NOSUID);
    /// `MOUNT_ATTR_NODEV`
    pub const NODEV: Self = Self(libc::MOUNT_ATTR_NODEV);
    /// `MOUNT_ATTR_NOEXEC`
    pub const NOEXEC: Self = Self(libc::MOUNT_ATTR_NOEXEC);

    /// No flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Raw `MOUNT_ATTR_*` bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// `self | other`, usable in `const` context.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every flag in `other` is also in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for MountAttrFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl BitOrAssign for MountAttrFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = self.union(rhs);
    }
}

/// Whether to apply to one mount or to the whole tree below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recursion {
    /// Only the mount `fd` refers to.
    ThisMountOnly,
    /// That mount and every mount below it (`AT_RECURSIVE`).
    Recursive,
}

/// Set and clear attributes on the mount `fd` refers to
/// (`mount_setattr(fd, "", AT_EMPTY_PATH[|AT_RECURSIVE], …)`).
///
/// `fd` is typically opened with `O_PATH` on the mount point *after* the
/// mount was made. Returns `ENOSYS` on kernels older than 5.12.
//
// nix-upstream-kandidaat: a borrowed fd + plain-data `mount_attr` + fixed size,
// no uncheckable invariant — a safe nix wrapper (in its mount module) would be
// genuinely safe and could replace this block.
pub fn mount_setattr(
    fd: BorrowedFd<'_>,
    recursion: Recursion,
    set: MountAttrFlags,
    clear: MountAttrFlags,
) -> nix::Result<()> {
    let mut at_flags = libc::AT_EMPTY_PATH;
    if recursion == Recursion::Recursive {
        at_flags |= libc::AT_RECURSIVE;
    }
    let mut attr = mount_attr {
        attr_set: set.bits(),
        attr_clr: clear.bits(),
        propagation: 0,
        userns_fd: 0,
    };
    let at_flags: c_uint = at_flags.cast_unsigned();
    // SAFETY: the path is a valid NUL-terminated empty string (with
    // AT_EMPTY_PATH the kernel acts on `fd` itself), `attr` is a valid
    // `struct mount_attr` and we pass its exact size. Both outlive the call;
    // the kernel only reads them. `fd` is a live descriptor, borrowed.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            fd.as_raw_fd(),
            c"".as_ptr(),
            at_flags,
            &raw mut attr,
            std::mem::size_of::<mount_attr>(),
        )
    };
    Errno::result(ret).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_ops() {
        let f = MountAttrFlags::RDONLY | MountAttrFlags::NODEV;
        assert!(f.contains(MountAttrFlags::RDONLY));
        assert!(f.contains(MountAttrFlags::NODEV));
        assert!(!f.contains(MountAttrFlags::NOSUID));
        assert_eq!(MountAttrFlags::empty().bits(), 0);
        let mut g = MountAttrFlags::empty();
        g |= MountAttrFlags::NOSUID;
        assert_eq!(g, MountAttrFlags::NOSUID);
    }

    #[test]
    fn attr_struct_is_ver0_size() {
        assert_eq!(
            std::mem::size_of::<mount_attr>(),
            usize::try_from(libc::MOUNT_ATTR_SIZE_VER0).expect("positive")
        );
    }

    #[test]
    fn bits_match_kernel_constants() {
        assert_eq!(MountAttrFlags::RDONLY.bits(), libc::MOUNT_ATTR_RDONLY);
        assert_eq!(MountAttrFlags::NOSUID.bits(), libc::MOUNT_ATTR_NOSUID);
        assert_eq!(MountAttrFlags::NODEV.bits(), libc::MOUNT_ATTR_NODEV);
        assert_eq!(MountAttrFlags::NOEXEC.bits(), libc::MOUNT_ATTR_NOEXEC);
    }

    #[test]
    fn union_is_const_and_idempotent() {
        const ALL: MountAttrFlags = MountAttrFlags::RDONLY
            .union(MountAttrFlags::NOSUID)
            .union(MountAttrFlags::NODEV)
            .union(MountAttrFlags::NOEXEC);
        assert_eq!(
            ALL.bits(),
            libc::MOUNT_ATTR_RDONLY
                | libc::MOUNT_ATTR_NOSUID
                | libc::MOUNT_ATTR_NODEV
                | libc::MOUNT_ATTR_NOEXEC
        );
        assert_eq!(ALL | ALL, ALL);
        assert!(ALL.contains(MountAttrFlags::empty()));
        assert!(!MountAttrFlags::empty().contains(MountAttrFlags::RDONLY));
        assert_eq!(MountAttrFlags::default(), MountAttrFlags::empty());
    }

    #[test]
    fn non_mount_fd_is_rejected_unprivileged() {
        // A plain directory that is not a mount root: the kernel refuses
        // (EINVAL), or EPERM/ENOSYS where mount_setattr is restricted.
        let fd = nix::fcntl::open(
            "/proc/self/ns",
            nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .unwrap();
        use std::os::fd::AsFd;
        for rec in [Recursion::ThisMountOnly, Recursion::Recursive] {
            let r = mount_setattr(
                fd.as_fd(),
                rec,
                MountAttrFlags::RDONLY,
                MountAttrFlags::empty(),
            );
            assert!(
                matches!(r, Err(Errno::EINVAL | Errno::EPERM | Errno::ENOSYS)),
                "{r:?}"
            );
        }
    }
}
