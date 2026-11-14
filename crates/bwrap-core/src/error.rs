//! The error type for all of bwrap-rs.
//!
//! bwrap reports every failure as one line on stderr, `bwrap: <message>` or
//! `bwrap: <message>: <strerror>`, then exits with status 1. [`Error`]'s
//! `Display` produces exactly the part after `bwrap: `, so messages stay
//! comparable with the C implementation.
//!
//! Messages are formatted by the caller (`"Can't mkdir {path}"`), in the
//! same style as bwrap's `die_with_error (fmt, ...)`.

use std::borrow::Cow;
use std::fmt;
use std::io;

use bwrap_sys::strerror;
use nix::errno::Errno;

/// Result alias for bwrap-rs.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A bwrap-rs failure.
#[derive(Debug)]
pub enum Error {
    /// A syscall failed: `"<message>: <strerror>"`.
    Sys {
        /// What we were doing.
        message: Cow<'static, str>,
        /// The errno returned.
        errno: Errno,
    },
    /// A `mount(2)`-family syscall failed. Same as [`Error::Sys`], except
    /// `ENOSPC` is explained as the mount-count limit (bwrap's `mount_strerror`).
    Mount {
        /// What we were doing.
        message: Cow<'static, str>,
        /// The errno returned.
        errno: Errno,
    },
    /// A std I/O operation failed.
    Io {
        /// What we were doing.
        message: Cow<'static, str>,
        /// The underlying error.
        source: io::Error,
    },
    /// Invalid command line or configuration: `"<message>"` with no errno,
    /// as bwrap's `die (fmt, ...)`.
    Invalid(Cow<'static, str>),
    /// No command was given (bwrap's `argc <= 0` → `usage(EXIT_FAILURE,
    /// stderr)`). The binary prints the full usage text to stderr and exits 1;
    /// this variant is not rendered as a `bwrap: <text>` line.
    Usage,
}

impl Error {
    /// A configuration or usage error without an errno.
    pub fn invalid(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Invalid(message.into())
    }

    /// The errno behind this error, if there is one.
    pub fn errno(&self) -> Option<Errno> {
        match self {
            Self::Sys { errno, .. } | Self::Mount { errno, .. } => Some(*errno),
            Self::Io { source, .. } => source.raw_os_error().map(Errno::from_raw),
            Self::Invalid(_) | Self::Usage => None,
        }
    }
}

/// Text of bwrap's `mount_strerror()`.
pub(crate) fn mount_strerror(errno: Errno) -> String {
    match errno {
        // mount(2) uses ENOSPC for "too many mounts", not disk space.
        Errno::ENOSPC => "Limit exceeded (ENOSPC). \
             (Hint: Check that /proc/sys/fs/mount-max is sufficient, typically 100000)"
            .to_owned(),
        other => strerror(other),
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sys { message, errno } => write!(f, "{message}: {}", strerror(*errno)),
            Self::Mount { message, errno } => write!(f, "{message}: {}", mount_strerror(*errno)),
            // Print strerror text like C, not Rust's "... (os error N)".
            Self::Io { message, source } => match source.raw_os_error() {
                Some(code) => write!(f, "{message}: {}", strerror(Errno::from_raw(code))),
                None => write!(f, "{message}: {source}"),
            },
            Self::Invalid(message) => f.write_str(message),
            // Not normally printed; the binary renders the usage text instead.
            Self::Usage => f.write_str("usage error"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sys { errno, .. } | Self::Mount { errno, .. } => Some(errno),
            Self::Io { source, .. } => Some(source),
            Self::Invalid(_) | Self::Usage => None,
        }
    }
}

/// Attach a message to a low-level error, turning it into [`Error`].
pub trait Context<T> {
    /// Attach a fixed message.
    fn context(self, message: &'static str) -> Result<T>;
    /// Attach a message built only on failure.
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}

impl<T> Context<T> for std::result::Result<T, Errno> {
    fn context(self, message: &'static str) -> Result<T> {
        self.map_err(|errno| Error::Sys {
            message: message.into(),
            errno,
        })
    }
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.map_err(|errno| Error::Sys {
            message: f().into(),
            errno,
        })
    }
}

impl<T> Context<T> for io::Result<T> {
    fn context(self, message: &'static str) -> Result<T> {
        self.map_err(|source| Error::Io {
            message: message.into(),
            source,
        })
    }
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.map_err(|source| Error::Io {
            message: f().into(),
            source,
        })
    }
}

/// Like [`Context`], for the result of a mount-family syscall
/// (bwrap's `die_with_mount_error`).
pub trait MountContext<T> {
    /// Attach a fixed message.
    fn mount_context(self, message: &'static str) -> Result<T>;
    /// Attach a message built only on failure.
    fn with_mount_context<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}

impl<T> MountContext<T> for std::result::Result<T, Errno> {
    fn mount_context(self, message: &'static str) -> Result<T> {
        self.map_err(|errno| Error::Mount {
            message: message.into(),
            errno,
        })
    }
    fn with_mount_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.map_err(|errno| Error::Mount {
            message: f().into(),
            errno,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sys_formats_like_die_with_error() {
        let e = Err::<(), _>(Errno::EACCES)
            .context("Can't mkdir /x")
            .unwrap_err();
        assert_eq!(e.to_string(), "Can't mkdir /x: Permission denied");
        assert_eq!(e.errno(), Some(Errno::EACCES));
    }

    #[test]
    fn mount_enospc_gets_hint() {
        let e = Err::<(), _>(Errno::ENOSPC)
            .with_mount_context(|| "Can't mount tmpfs on /newroot/tmp".to_owned())
            .unwrap_err();
        assert!(
            e.to_string()
                .starts_with("Can't mount tmpfs on /newroot/tmp: Limit exceeded (ENOSPC).")
        );
        let e = Err::<(), _>(Errno::EPERM)
            .mount_context("pivot_root")
            .unwrap_err();
        assert_eq!(e.to_string(), "pivot_root: Operation not permitted");
    }

    #[test]
    fn io_uses_strerror_text() {
        let e = Err::<(), _>(io::Error::from_raw_os_error(libc_enoent()))
            .context("Can't open /etc/x")
            .unwrap_err();
        assert_eq!(
            e.to_string(),
            "Can't open /etc/x: No such file or directory"
        );
        let e = Err::<(), _>(io::Error::other("bad data"))
            .context("parse")
            .unwrap_err();
        assert_eq!(e.to_string(), "parse: bad data");
    }

    #[test]
    fn invalid_has_no_errno() {
        let e = Error::invalid("Specifying --hostname requires --unshare-uts");
        assert_eq!(
            e.to_string(),
            "Specifying --hostname requires --unshare-uts"
        );
        assert_eq!(e.errno(), None);
    }

    fn libc_enoent() -> i32 {
        Errno::ENOENT as i32
    }

    #[test]
    fn errno_per_variant() {
        let io_err = Error::Io {
            message: "m".into(),
            source: io::Error::from_raw_os_error(Errno::EBUSY as i32),
        };
        assert_eq!(io_err.errno(), Some(Errno::EBUSY));
        let io_plain = Error::Io {
            message: "m".into(),
            source: io::Error::other("x"),
        };
        assert_eq!(io_plain.errno(), None);
        let mount = Error::Mount {
            message: "m".into(),
            errno: Errno::EBUSY,
        };
        assert_eq!(mount.errno(), Some(Errno::EBUSY));
        assert_eq!(Error::Usage.errno(), None);
    }

    #[test]
    fn usage_display_and_source() {
        use std::error::Error as _;
        assert_eq!(Error::Usage.to_string(), "usage error");
        assert!(Error::Usage.source().is_none());
        assert!(Error::invalid("x").source().is_none());
    }

    #[test]
    fn source_is_the_underlying_error() {
        use std::error::Error as _;
        let sys = Error::Sys {
            message: "m".into(),
            errno: Errno::EPERM,
        };
        assert_eq!(sys.source().unwrap().to_string(), Errno::EPERM.to_string());
        let mount = Error::Mount {
            message: "m".into(),
            errno: Errno::EPERM,
        };
        assert!(mount.source().is_some());
        let io = Error::Io {
            message: "m".into(),
            source: io::Error::other("inner"),
        };
        assert_eq!(io.source().unwrap().to_string(), "inner");
    }

    #[test]
    fn mount_error_only_rewrites_enospc() {
        let e = Error::Mount {
            message: "Can't mount".into(),
            errno: Errno::ENOSPC,
        };
        assert_eq!(
            e.to_string(),
            "Can't mount: Limit exceeded (ENOSPC). (Hint: Check that /proc/sys/fs/mount-max is sufficient, typically 100000)"
        );
        // The same errno through the plain Sys path is the stock strerror text.
        let e = Error::Sys {
            message: "write".into(),
            errno: Errno::ENOSPC,
        };
        assert_eq!(e.to_string(), "write: No space left on device");
        let e = Error::Mount {
            message: "Can't mount".into(),
            errno: Errno::EBUSY,
        };
        assert_eq!(e.to_string(), "Can't mount: Device or resource busy");
    }

    #[test]
    fn context_on_result_and_closures() {
        let e = Err::<(), _>(io::Error::from_raw_os_error(Errno::EROFS as i32))
            .with_context(|| "Can't write /x".to_owned())
            .unwrap_err();
        assert_eq!(e.to_string(), "Can't write /x: Read-only file system");
        let e = Err::<(), _>(Errno::EBUSY)
            .with_context(|| "umount".to_owned())
            .unwrap_err();
        assert!(matches!(
            e,
            Error::Sys {
                errno: Errno::EBUSY,
                ..
            }
        ));
        let e = Err::<(), _>(Errno::EBUSY)
            .mount_context("mount x")
            .unwrap_err();
        assert!(matches!(
            e,
            Error::Mount {
                errno: Errno::EBUSY,
                ..
            }
        ));
        // Ok passes through untouched.
        assert_eq!(Ok::<_, Errno>(7).context("unused").unwrap(), 7);
        assert_eq!(
            Ok::<_, Errno>(8).with_mount_context(|| "u".into()).unwrap(),
            8
        );
        assert_eq!(
            Ok::<_, io::Error>(9).with_context(|| "u".into()).unwrap(),
            9
        );
    }
}
