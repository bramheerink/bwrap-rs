//! Linux capabilities: `capget(2)`/`capset(2)` (v3 ABI) and the bounding and
//! ambient sets via `prctl(2)`.
//!
//! Capabilities are addressed by their raw kernel number here (`CAP_CHOWN` =
//! 0 … `CAP_CHECKPOINT_RESTORE` = 40). The typed `Capability` enum lives in
//! `bwrap-core`.
//!
//! Capability state is per thread. bwrap-rs is single-threaded during setup,
//! so per thread equals per process.

use nix::errno::Errno;
use nix::libc::{self, c_int, c_ulong};

/// `_LINUX_CAPABILITY_VERSION_3` from `<linux/capability.h>`.
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
/// `_LINUX_CAPABILITY_U32S_3`: v3 uses two 32-bit words per set.
const LINUX_CAPABILITY_U32S_3: usize = 2;

/// `struct __user_cap_header_struct`. libc does not export it.
#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: c_int,
}

/// `struct __user_cap_data_struct`. libc does not export it.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// The effective, permitted and inheritable sets of the calling thread,
/// one bit per capability number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapState {
    /// Effective set.
    pub effective: u64,
    /// Permitted set.
    pub permitted: u64,
    /// Inheritable set.
    pub inheritable: u64,
}

fn header() -> CapUserHeader {
    CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0, // 0 = calling thread
    }
}

fn join(lo: u32, hi: u32) -> u64 {
    u64::from(lo) | (u64::from(hi) << 32)
}

fn split(v: u64) -> (u32, u32) {
    // Masking makes the truncation explicit and exact.
    ((v & 0xffff_ffff) as u32, (v >> 32) as u32)
}

/// Read the calling thread's capability sets.
pub fn capget() -> nix::Result<CapState> {
    let mut hdr = header();
    let mut data = [CapUserData::default(); LINUX_CAPABILITY_U32S_3];
    // SAFETY: `hdr` is a valid v3 header and `data` has room for the two
    // `__user_cap_data_struct`s the v3 ABI writes. Both outlive the call.
    let ret = unsafe { libc::syscall(libc::SYS_capget, &raw mut hdr, data.as_mut_ptr()) };
    Errno::result(ret)?;
    Ok(CapState {
        effective: join(data[0].effective, data[1].effective),
        permitted: join(data[0].permitted, data[1].permitted),
        inheritable: join(data[0].inheritable, data[1].inheritable),
    })
}

/// Replace the calling thread's capability sets.
pub fn capset(state: &CapState) -> nix::Result<()> {
    let mut hdr = header();
    let (e_lo, e_hi) = split(state.effective);
    let (p_lo, p_hi) = split(state.permitted);
    let (i_lo, i_hi) = split(state.inheritable);
    let data = [
        CapUserData {
            effective: e_lo,
            permitted: p_lo,
            inheritable: i_lo,
        },
        CapUserData {
            effective: e_hi,
            permitted: p_hi,
            inheritable: i_hi,
        },
    ];
    // SAFETY: `hdr` is a valid v3 header and `data` holds the two
    // `__user_cap_data_struct`s the v3 ABI reads. The kernel may write the
    // preferred version back into `hdr`, which is why it is `mut`.
    let ret = unsafe { libc::syscall(libc::SYS_capset, &raw mut hdr, data.as_ptr()) };
    Errno::result(ret).map(drop)
}

fn prctl(option: c_int, arg2: c_ulong, arg3: c_ulong) -> nix::Result<c_int> {
    let zero: c_ulong = 0;
    // SAFETY: only used for the PR_CAPBSET_* and PR_CAP_AMBIENT options below,
    // which take integer arguments only (no pointers); unused args are 0 as the
    // man page requires.
    let ret = unsafe { libc::prctl(option, arg2, arg3, zero, zero) };
    Errno::result(ret)
}

/// Is `cap` in the bounding set? `EINVAL` if the kernel does not know `cap`.
pub fn bounding_set_contains(cap: u32) -> nix::Result<bool> {
    prctl(libc::PR_CAPBSET_READ, c_ulong::from(cap), 0).map(|r| r == 1)
}

/// Remove `cap` from the bounding set. Needs `CAP_SETPCAP`.
pub fn bounding_set_drop(cap: u32) -> nix::Result<()> {
    prctl(libc::PR_CAPBSET_DROP, c_ulong::from(cap), 0).map(drop)
}

/// Add `cap` to the ambient set. It must already be permitted and inheritable.
pub fn ambient_raise(cap: u32) -> nix::Result<()> {
    let op = c_ulong::from(libc::PR_CAP_AMBIENT_RAISE.cast_unsigned());
    prctl(libc::PR_CAP_AMBIENT, op, c_ulong::from(cap)).map(drop)
}

/// Empty the ambient set.
pub fn ambient_clear_all() -> nix::Result<()> {
    let op = c_ulong::from(libc::PR_CAP_AMBIENT_CLEAR_ALL.cast_unsigned());
    prctl(libc::PR_CAP_AMBIENT, op, 0).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_join_roundtrip() {
        for v in [0, 1, 1 << 31, 1 << 32, 1 << 40, u64::MAX] {
            let (lo, hi) = split(v);
            assert_eq!(join(lo, hi), v);
        }
    }

    #[test]
    fn capget_capset_roundtrip() {
        let state = capget().expect("capget");
        assert_eq!(
            state.effective & !state.permitted,
            0,
            "effective must be subset of permitted"
        );
        // Setting the current state again is always allowed.
        capset(&state).expect("capset with unchanged state");
        assert_eq!(capget().expect("capget"), state);
    }

    #[test]
    fn bounding_read_known_and_unknown() {
        assert!(bounding_set_contains(0).is_ok()); // CAP_CHOWN
        assert_eq!(bounding_set_contains(1000), Err(Errno::EINVAL));
    }

    #[test]
    fn ambient_clear_is_unprivileged() {
        ambient_clear_all().expect("PR_CAP_AMBIENT_CLEAR_ALL");
    }
}
