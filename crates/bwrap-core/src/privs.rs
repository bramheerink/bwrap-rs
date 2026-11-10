//! Privilege acquisition and dropping around the sandbox (bwrap's
//! `acquire_privs`, `switch_to_user_with_privs`, `drop_privs`).
//!
//! bwrap only supports the unprivileged user-namespace mode and the `uid == 0`
//! (already-root, e.g. rpm-ostree) mode; the historical setuid / file-caps
//! configurations are refused.

use nix::sys::prctl::set_dumpable;
use nix::unistd::{Gid, Uid, getegid, geteuid, getgid, getuid, setgid, setuid};

use crate::caps::{drop_all_caps, drop_bounding_set, has_caps, initial_requested};
use crate::error::{Context, Error, Result};
use crate::types::CapSet;

/// Pure core of [`acquire_privs`]: classify the privilege mode from the real and
/// effective uids and whether we already hold capabilities. Returns `Ok(is_root)`,
/// or an error carrying bwrap's exact `die` text for the unsupported configs.
fn acquire_privs_decision(real_uid: u32, euid: u32, has_caps: bool) -> Result<bool> {
    if real_uid != euid {
        // Historically supported; now only user namespaces are.
        return Err(Error::invalid("setuid use of bubblewrap is not supported"));
    }
    if real_uid != 0 && has_caps {
        // Caps without being setuid => setcap'd binary, no longer supported.
        return Err(Error::invalid(
            "Unexpected capabilities but not setuid, old file caps config?",
        ));
    }
    Ok(real_uid == 0)
}

/// Determine the initially-requested capabilities (bwrap's `acquire_privs`).
///
/// As root, inherit the effective set (so `--cap-drop` can trim it); otherwise
/// start from nothing. Refuses the unsupported setuid / file-caps setups.
pub fn acquire_privs() -> Result<CapSet> {
    let real_uid = getuid().as_raw();
    let euid = geteuid().as_raw();
    let is_root = acquire_privs_decision(real_uid, euid, has_caps()?)?;
    initial_requested(is_root)
}

/// Once inside the namespace: clear the bounding set the new user namespace
/// restored (keeping the requested caps), and, when joining an existing userns
/// via `--userns`, switch to the target uid/gid (bwrap's
/// `switch_to_user_with_privs`).
#[allow(clippy::too_many_arguments)]
pub fn switch_to_user_with_privs(
    unshare_user: bool,
    have_userns_fd: bool,
    requested_caps: CapSet,
    real_uid: u32,
    sandbox_uid: u32,
    real_gid: u32,
    sandbox_gid: u32,
) -> Result<()> {
    if unshare_user || have_userns_fd {
        // bwrap's drop_cap_bounding_set(false): keep the requested caps.
        drop_bounding_set(requested_caps)?;
    }
    if have_userns_fd {
        if sandbox_uid != real_uid {
            setuid(Uid::from_raw(sandbox_uid))
                .with_context(|| format!("unable to switch to uid {sandbox_uid}"))?;
        }
        if sandbox_gid != real_gid {
            setgid(Gid::from_raw(sandbox_gid))
                .with_context(|| format!("unable to switch to gid {sandbox_gid}"))?;
        }
    }
    Ok(())
}

/// Drop capabilities and mark the process dumpable (bwrap's `drop_privs`).
///
/// `keep` is `Some(requested)` to keep exactly the requested caps (the sandbox
/// side), or `None` to drop everything (the launcher side). `cap_add_or_drop_used`
/// and `is_root` carry bwrap's quirks through [`drop_all_caps`].
pub fn drop_privs(keep: Option<CapSet>, cap_add_or_drop_used: bool, is_root: bool) -> Result<()> {
    drop_all_caps(keep, cap_add_or_drop_used, is_root)?;
    // No privs now, so make us dumpable: /proc/self is then owned by the user.
    set_dumpable(true).context("can't set dumpable")?;
    Ok(())
}

/// The real uid/gid, read once (helper for the orchestration).
pub fn real_ids() -> (u32, u32) {
    (getuid().as_raw(), getgid().as_raw())
}

/// The effective gid (helper for the orchestration).
pub fn effective_gid() -> u32 {
    getegid().as_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_decision_unprivileged() {
        // Normal unprivileged user: real == euid, not root, no caps -> not root.
        assert!(!acquire_privs_decision(1000, 1000, false).unwrap());
    }

    #[test]
    fn acquire_decision_root() {
        assert!(acquire_privs_decision(0, 0, true).unwrap());
        assert!(acquire_privs_decision(0, 0, false).unwrap());
    }

    #[test]
    fn acquire_decision_setuid_refused() {
        let e = acquire_privs_decision(1000, 0, false).unwrap_err();
        assert_eq!(e.to_string(), "setuid use of bubblewrap is not supported");
    }

    #[test]
    fn acquire_decision_unexpected_caps_refused() {
        let e = acquire_privs_decision(1000, 1000, true).unwrap_err();
        assert_eq!(
            e.to_string(),
            "Unexpected capabilities but not setuid, old file caps config?"
        );
    }
}
