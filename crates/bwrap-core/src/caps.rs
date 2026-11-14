//! Capability policy: the requested set, the bounding set and the ambient set.
//!
//! This is the policy layer on top of the raw `bwrap_sys::caps` syscalls. It
//! mirrors bwrap's `has_caps`, `prctl_caps`, `drop_cap_bounding_set`,
//! `set_ambient_capabilities` and `drop_all_caps`.
//!
//! Capability state is per thread; bwrap-rs is single-threaded during setup,
//! so per thread equals per process.

use std::sync::OnceLock;

use bwrap_sys::caps::{self, CapState};
use nix::errno::Errno;

use crate::error::{Context, Error, Result};
use crate::types::caps::CAP_LAST_KNOWN;
use crate::types::{CapSet, Capability};

/// Cached result of the `cap_last_cap` probe (constant for a running kernel).
static LAST_CAP: OnceLock<u8> = OnceLock::new();

/// The kernel's highest valid capability number.
///
/// bwrap uses the compile-time `CAP_LAST_CAP`; we probe it at runtime instead
/// so we drop and raise exactly the caps this kernel knows, even one newer than
/// our header table. The probe uses `prctl(PR_CAPBSET_READ, n)` (which returns
/// `EINVAL` past the last cap), so it needs no `/proc` and works after
/// `pivot_root`. The result is cached (it cannot change). Falls back to the
/// table's last entry only if even cap 0 cannot be probed.
pub fn cap_last_cap() -> u8 {
    *LAST_CAP.get_or_init(|| {
        let mut last: Option<u8> = None;
        for n in 0..=63u8 {
            match caps::bounding_set_contains(u32::from(n)) {
                Ok(_) => last = Some(n),
                Err(_) => break, // EINVAL: n is past the last valid cap
            }
        }
        last.unwrap_or(CAP_LAST_KNOWN)
    })
}

/// Whether the calling process holds any permitted capability
/// (bwrap's `has_caps`).
pub fn has_caps() -> Result<bool> {
    let state = caps::capget().context("capget failed")?;
    Ok(state.permitted != 0)
}

/// The initial requested-capability set, before `--cap-add`/`--cap-drop`.
///
/// bwrap's `acquire_privs`: when running as real uid 0, inherit the current
/// effective caps (so `--cap-drop` can pare them down); otherwise none.
pub fn initial_requested(is_root: bool) -> Result<CapSet> {
    if is_root {
        let state = caps::capget().context("capget (for uid == 0) failed")?;
        Ok(CapSet::from_bits(state.effective))
    } else {
        Ok(CapSet::EMPTY)
    }
}

/// Shared core of bwrap's `prctl_caps`: for every capability the kernel knows,
/// raise it in the ambient set if kept (and `do_ambient`), and drop it from
/// the bounding set if not kept (and `do_bounding`).
///
/// `EINVAL` and `EPERM` per capability are ignored, exactly as bwrap does:
/// `PR_SET_NO_NEW_PRIVS` is what actually constrains privileges, and old
/// kernels can spuriously return `EPERM` here.
fn prctl_caps(keep: CapSet, do_bounding: bool, do_ambient: bool) -> Result<()> {
    let last = cap_last_cap();
    for n in 0..=last {
        let cap = Capability::from_number(n)?;
        let kept = keep.contains(cap);

        if kept && do_ambient {
            match caps::ambient_raise(u32::from(n)) {
                Ok(()) => {}
                Err(Errno::EINVAL | Errno::EPERM) => {}
                Err(e) => {
                    return Err(Error::Sys {
                        message: format!("Adding ambient capability {n}").into(),
                        errno: e,
                    });
                }
            }
        }
        if !kept && do_bounding {
            match caps::bounding_set_drop(u32::from(n)) {
                Ok(()) => {}
                Err(Errno::EINVAL | Errno::EPERM) => {}
                Err(e) => {
                    return Err(Error::Sys {
                        message: format!("Dropping capability {n} from bounds").into(),
                        errno: e,
                    });
                }
            }
        }
    }
    Ok(())
}

/// Drop from the bounding set every capability not in `keep`
/// (bwrap's `drop_cap_bounding_set(false)`).
pub fn drop_bounding_set(keep: CapSet) -> Result<()> {
    prctl_caps(keep, true, false)
}

/// Drop the entire bounding set (bwrap's `drop_cap_bounding_set(true)`).
pub fn drop_all_bounding_set() -> Result<()> {
    prctl_caps(CapSet::EMPTY, true, false)
}

/// Raise into the ambient set every capability in `keep`
/// (bwrap's `set_ambient_capabilities`).
pub fn set_ambient(keep: CapSet) -> Result<()> {
    prctl_caps(keep, false, true)
}

/// Replace the effective/permitted/inheritable sets (bwrap's `drop_all_caps`).
///
/// `keep` is `Some(requested)` to keep exactly those caps, or `None` to drop
/// everything. Two bwrap quirks are preserved:
/// - When keeping caps as root and no `--cap-add`/`--cap-drop` was used,
///   `capset` is skipped entirely: a container manager such as systemd-nspawn
///   denies `capset` via seccomp, so issuing it there would fail spuriously;
///   bubblewrap skips it for the same reason.
/// - `EPERM` as root is ignored rather than fatal (same reason).
pub fn drop_all_caps(
    keep: Option<CapSet>,
    cap_add_or_drop_used: bool,
    is_root: bool,
) -> Result<()> {
    let state = match keep {
        Some(set) => {
            if !cap_add_or_drop_used && is_root {
                return Ok(());
            }
            let bits = set.bits();
            CapState {
                effective: bits,
                permitted: bits,
                inheritable: bits,
            }
        }
        None => CapState::default(),
    };

    match caps::capset(&state) {
        Ok(()) => Ok(()),
        Err(Errno::EPERM) if is_root => Ok(()),
        Err(e) => Err(Error::Sys {
            message: "capset failed".into(),
            errno: e,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_last_cap_is_sane() {
        let last = cap_last_cap();
        // Every kernel since the table was frozen has at least CAP_SYS_ADMIN (21).
        assert!(last >= 21, "cap_last_cap = {last}");
    }

    #[test]
    fn has_caps_runs() {
        // Just exercises capget; the value depends on how the test runs.
        assert!(has_caps().is_ok());
    }

    #[test]
    fn initial_requested_non_root_is_empty() {
        assert_eq!(initial_requested(false).unwrap(), CapSet::EMPTY);
    }

    #[test]
    fn bounding_drop_is_ignored_without_setpcap() {
        // Unprivileged: every PR_CAPBSET_DROP returns EPERM, which is ignored,
        // so this must succeed without error.
        drop_bounding_set(CapSet::EMPTY).expect("EPERM must be ignored");
    }

    #[test]
    fn set_ambient_empty_is_noop() {
        set_ambient(CapSet::EMPTY).expect("raising nothing must succeed");
    }

    #[test]
    fn drop_all_caps_root_without_capops_skips() {
        // No syscall is made in this case, so it must be Ok even in a test
        // process (which is not root but takes the keep=Some path only when
        // we ask it to; here we assert the skip branch directly).
        drop_all_caps(Some(CapSet::EMPTY), false, true).expect("skip branch");
    }

    #[test]
    fn drop_all_caps_to_empty_succeeds_unprivileged() {
        // Setting an empty set when we already hold ~nothing is allowed.
        drop_all_caps(None, false, false).expect("capset to empty");
    }
}
