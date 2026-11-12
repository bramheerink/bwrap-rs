//! Filesystem setup operations.
//!
//! bwrap's `SetupOp` is one struct with a `type` tag and a union of fields;
//! which fields are valid depends on the tag. Here each operation is an enum
//! variant that carries only its own data, so an impossible combination (a
//! symlink with a `perms`, a tmpfs with a source fd) cannot be represented.

use std::os::fd::RawFd;

use super::path::{HostPath, SandboxPath};
use crate::cnum::c_strtou64;
use crate::error::Error;

/// A file mode (permission bits), `--perms` / `--chmod`.
///
/// bwrap parses an octal value and rejects anything above `07777`.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Mode(u16);

impl Mode {
    /// Parse an octal string `<= 07777`, like bwrap's `--perms` / `--chmod`
    /// (`strtoul(.., 8)` with the surrounding checks).
    ///
    /// Matches `strtoul` semantics: leading C whitespace and a leading sign are
    /// accepted (`-0` is 0; `-5` wraps to a huge value and is rejected), the
    /// whole string must be consumed, and an empty string is rejected.
    /// `option` names the flag for the error text.
    pub fn parse_octal(option: &str, value: &str) -> Result<Self, Error> {
        let bad = || {
            // --perms and --chmod share the "octal argument <= 07777" wording.
            Error::invalid(format!("{option} takes an octal argument <= 07777"))
        };
        let c = c_strtou64(value, 8);
        // No digits (covers the empty string, i.e. bwrap's `argv[1][0] == '\0'`
        // check), or trailing junk (bwrap's `*endptr != '\0'`).
        if c.digits == 0 || c.end != value.len() {
            return Err(bad());
        }
        // strtoul returns ULONG_MAX on overflow regardless of sign (ERANGE), so
        // an overflowing value is rejected. Otherwise the sign negates the
        // unsigned result by wrapping (so "-0" is 0, "-5" wraps huge and is
        // rejected).
        let v = if c.overflow {
            u64::MAX
        } else if c.neg {
            0u64.wrapping_sub(c.val)
        } else {
            c.val
        };
        if v > 0o7777 {
            return Err(bad());
        }
        // v <= 0o7777 (4095), so it fits a u16.
        Ok(Self(u16::try_from(v).unwrap_or(0)))
    }

    /// From raw bits (already known to be `<= 07777`).
    pub fn from_bits(bits: u16) -> Self {
        Self(bits & 0o7777)
    }

    /// The raw mode bits.
    pub fn bits(self) -> u16 {
        self.0
    }
}

impl std::fmt::Debug for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mode(0o{:04o})", self.0)
    }
}

/// How a bind mount exposes its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindKind {
    /// `--bind`: read-write.
    ReadWrite,
    /// `--ro-bind`: read-only.
    ReadOnly,
    /// `--dev-bind`: allow device nodes.
    Dev,
}

/// Whether a missing bind source is fatal (`--bind`) or skipped (`--bind-try`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnMissing {
    /// Fail if the source does not exist.
    Fail,
    /// Silently skip if the source does not exist (the `-try` variants).
    Skip,
}

/// The upper/work layer configuration of an overlay mount.
#[derive(Debug, Clone)]
pub enum OverlayUpper {
    /// `--overlay RWSRC WORKDIR DEST`: a persistent writable layer.
    Persistent {
        /// The writable upper directory.
        upper: HostPath,
        /// overlayfs work directory (must be on the same fs as `upper`).
        work: HostPath,
    },
    /// `--tmp-overlay DEST`: a throwaway tmpfs-backed writable layer.
    Tmp,
    /// `--ro-overlay DEST`: no writable layer.
    ReadOnly,
}

/// A single filesystem setup operation, in the order given on the command line.
#[derive(Debug, Clone)]
pub enum SetupOp {
    /// `--bind` / `--ro-bind` / `--dev-bind` (and the `-try` variants).
    Bind {
        /// Host source.
        src: HostPath,
        /// Destination in the sandbox.
        dest: SandboxPath,
        /// Read-write, read-only or device bind.
        kind: BindKind,
        /// What to do if the source is missing.
        missing: OnMissing,
    },
    /// `--bind-fd` / `--ro-bind-fd`: bind from an already-open directory fd.
    BindFd {
        /// The open source fd (bwrap formats `/proc/self/fd/N`).
        fd: RawFd,
        /// Destination in the sandbox.
        dest: SandboxPath,
        /// Read-write or read-only (`--dev-bind-fd` does not exist upstream).
        kind: BindKind,
    },
    /// `--overlay` / `--tmp-overlay` / `--ro-overlay`, with its `--overlay-src` layers.
    Overlay {
        /// Lower layers, bottom-to-top (the `--overlay-src` arguments).
        lower: Vec<HostPath>,
        /// The writable-layer configuration.
        upper: OverlayUpper,
        /// Destination in the sandbox.
        dest: SandboxPath,
    },
    /// `--proc DEST`: mount a new procfs.
    Proc {
        /// Destination.
        dest: SandboxPath,
    },
    /// `--dev DEST`: mount a minimal devtmpfs.
    Dev {
        /// Destination.
        dest: SandboxPath,
    },
    /// `--tmpfs DEST`: mount a tmpfs.
    Tmpfs {
        /// Destination.
        dest: SandboxPath,
        /// Mode: a preceding `--perms`, else the historical default 0755.
        perms: Mode,
        /// Size in bytes from a preceding `--size`, else `None` (kernel default).
        size: Option<u64>,
    },
    /// `--mqueue DEST`: mount a POSIX message queue fs.
    Mqueue {
        /// Destination.
        dest: SandboxPath,
    },
    /// `--dir DEST`: create a directory.
    Dir {
        /// Destination.
        dest: SandboxPath,
        /// Mode: a preceding `--perms`, else the historical default 0755.
        perms: Mode,
    },
    /// `--file FD DEST`: write the contents of `fd` to a new file.
    File {
        /// Source data fd.
        fd: RawFd,
        /// Destination.
        dest: SandboxPath,
        /// Mode: a preceding `--perms`, else the historical default 0666.
        perms: Mode,
    },
    /// `--bind-data` / `--ro-bind-data`: write `fd` to a file, then bind it.
    BindData {
        /// Source data fd.
        fd: RawFd,
        /// Destination.
        dest: SandboxPath,
        /// Read-write or read-only.
        kind: BindKind,
        /// Mode: a preceding `--perms`, else the historical default 0600.
        perms: Mode,
    },
    /// `--symlink TARGET DEST`: create a symlink. `target` is intentionally
    /// not validated as a path (it is the link's literal contents).
    Symlink {
        /// The link target (stored verbatim, may be anything non-empty).
        target: HostPath,
        /// Destination.
        dest: SandboxPath,
    },
    /// `--remount-ro DEST`: remount an existing mount read-only (non-recursive).
    RemountRo {
        /// Destination.
        dest: SandboxPath,
    },
    /// `--chmod OCTAL DEST`: change the mode of an existing path.
    Chmod {
        /// New mode.
        perms: Mode,
        /// Destination.
        dest: SandboxPath,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parses_octal() {
        assert_eq!(Mode::parse_octal("--perms", "0755").unwrap().bits(), 0o755);
        assert_eq!(Mode::parse_octal("--perms", "755").unwrap().bits(), 0o755);
        assert_eq!(Mode::parse_octal("--chmod", "7777").unwrap().bits(), 0o7777);
        assert_eq!(Mode::parse_octal("--perms", "0").unwrap().bits(), 0);
    }

    #[test]
    fn mode_rejects_out_of_range_and_junk() {
        for bad in ["", "10000", "8", "9", "0x20", "abc", "-1"] {
            let e = Mode::parse_octal("--perms", bad).unwrap_err();
            assert_eq!(
                e.to_string(),
                "--perms takes an octal argument <= 07777",
                "input {bad:?}"
            );
        }
        let e = Mode::parse_octal("--chmod", "10000").unwrap_err();
        assert_eq!(e.to_string(), "--chmod takes an octal argument <= 07777");
    }

    #[test]
    fn mode_follows_strtoul_sign_and_space_rules() {
        let p = |s: &str| Mode::parse_octal("--perms", s).map(Mode::bits);
        assert_eq!(p("+755").unwrap(), 0o755);
        assert_eq!(p(" \t\x0b755").unwrap(), 0o755);
        assert_eq!(p("-0").unwrap(), 0);
        assert_eq!(p("007777").unwrap(), 0o7777);
        // Overflow of u64 is rejected, as strtoul's ULONG_MAX is > 07777.
        assert!(p("7777777777777777777777777").is_err());
        for bad in ["+", "-", " ", "7 ", "1-"] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn mode_bits_and_debug() {
        assert_eq!(
            Mode::from_bits(0o17777).bits(),
            0o7777,
            "high bits are masked"
        );
        assert_eq!(format!("{:?}", Mode::from_bits(0o640)), "Mode(0o0640)");
        assert_eq!(Mode::default().bits(), 0);
    }
}
