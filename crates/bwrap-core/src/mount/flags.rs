//! Bind-mount options and `/proc/self/mountinfo` option decoding.

use nix::mount::MsFlags;

/// The bind options bwrap passes as `bind_option_t` bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BindOptions {
    /// Mount read-only (`BIND_READONLY`).
    pub readonly: bool,
    /// Allow device nodes (`BIND_DEVICES`); when false, `nodev` is applied.
    pub devices: bool,
    /// Apply recursively to submounts (`BIND_RECURSIVE`).
    pub recursive: bool,
    /// Tolerate per-submount remount failures (`BIND_FAIL_OPEN`,
    /// `--not-a-security-boundary`).
    pub fail_open: bool,
}

/// Decode a comma-separated `/proc/self/mountinfo` option string into the
/// `MsFlags` bwrap tracks (`decode_mountoptions`). Unknown tokens are ignored.
pub fn decode_mountoptions(options: &str) -> MsFlags {
    let mut flags = MsFlags::empty();
    for token in options.split(',') {
        let f = match token {
            "ro" => MsFlags::MS_RDONLY,
            "nosuid" => MsFlags::MS_NOSUID,
            "nodev" => MsFlags::MS_NODEV,
            "noexec" => MsFlags::MS_NOEXEC,
            "noatime" => MsFlags::MS_NOATIME,
            "nodiratime" => MsFlags::MS_NODIRATIME,
            "relatime" => MsFlags::MS_RELATIME,
            // "rw" and anything else contribute no flag.
            _ => MsFlags::empty(),
        };
        flags |= f;
    }
    flags
}

/// The extra `MsFlags` a bind should gain for a remount: always `nosuid`,
/// `nodev` unless devices are allowed, `ro` if read-only (bwrap's
/// `new_flags = current | (devices?0:NODEV) | NOSUID | (ro?RDONLY:0)`).
pub fn remount_added_flags(opts: BindOptions) -> MsFlags {
    let mut f = MsFlags::MS_NOSUID;
    if !opts.devices {
        f |= MsFlags::MS_NODEV;
    }
    if opts.readonly {
        f |= MsFlags::MS_RDONLY;
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_tokens() {
        let f = decode_mountoptions("rw,nosuid,nodev,relatime");
        assert!(f.contains(MsFlags::MS_NOSUID));
        assert!(f.contains(MsFlags::MS_NODEV));
        assert!(f.contains(MsFlags::MS_RELATIME));
        assert!(!f.contains(MsFlags::MS_RDONLY));
    }

    #[test]
    fn ignores_unknown_tokens() {
        let f = decode_mountoptions("rw,seclabel,attr2,inode64");
        assert_eq!(f, MsFlags::empty());
    }

    #[test]
    fn remount_flags_follow_options() {
        let ro_nodev = remount_added_flags(BindOptions {
            readonly: true,
            devices: false,
            ..BindOptions::default()
        });
        assert!(ro_nodev.contains(MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV));

        let dev_rw = remount_added_flags(BindOptions {
            readonly: false,
            devices: true,
            ..BindOptions::default()
        });
        assert_eq!(dev_rw, MsFlags::MS_NOSUID);
    }
}
