//! Path newtypes.
//!
//! bwrap distinguishes two kinds of path, and rejects an empty one for either
//! (upstream `path_argument()`, change #771): a host path, resolved against
//! `/oldroot`, and a destination path inside the new root. Neither is
//! canonicalised here; bwrap resolves symlinks later, inside the sandbox.

use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::os::unix::ffi::OsStrExt;

use crate::error::Error;

/// A path on the host, as given to `--bind`, `--overlay-src`, `--ro-bind`, …
///
/// Non-empty and free of interior NUL. Stored as a `CString` so it can go
/// straight to a syscall.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HostPath(CString);

/// A destination path inside the sandbox, as given to `--bind` (2nd arg),
/// `--dir`, `--symlink` (2nd arg), …
///
/// Non-empty and free of interior NUL. bwrap concatenates it onto
/// `/newroot`, so leading slashes are allowed and meaningful.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SandboxPath(CString);

fn make_cstring(option: &str, value: &OsStr) -> Result<CString, Error> {
    if value.is_empty() {
        // Exact text of bwrap's path_argument().
        return Err(Error::invalid(format!(
            "{option} does not take an empty path argument"
        )));
    }
    // Build from the raw bytes, so a non-UTF-8 path (e.g. a Flatpak portal path)
    // is preserved verbatim for the syscall, exactly as bubblewrap passes its
    // `char *`. Only an interior NUL is rejected (CString::new), which real argv
    // and `--args` tokens cannot contain.
    CString::new(value.as_bytes())
        .map_err(|_| Error::invalid(format!("{option} path contains a NUL byte")))
}

impl HostPath {
    /// Build from a `--option` name (for the error message) and the value.
    /// The value is any OS string (so a non-UTF-8 path flows through verbatim);
    /// a `&str` literal still works via `AsRef<OsStr>`.
    pub fn parse(option: &str, value: impl AsRef<OsStr>) -> Result<Self, Error> {
        Ok(Self(make_cstring(option, value.as_ref())?))
    }

    /// Borrow as a C string for syscalls.
    pub fn as_c_str(&self) -> &CStr {
        &self.0
    }

    /// Borrow as a Rust string, lossily. Used only for error-message display;
    /// a non-UTF-8 path renders with U+FFFD (an open fidelity gap, DIFFERENCES
    /// #6 — the syscall still uses the verbatim bytes via [`as_c_str`]).
    pub fn as_str(&self) -> std::borrow::Cow<'_, str> {
        self.0.to_string_lossy()
    }
}

impl SandboxPath {
    /// Build from a `--option` name (for the error message) and the value.
    /// Accepts any OS string so a non-UTF-8 destination is kept verbatim; a
    /// `&str` literal still works via `AsRef<OsStr>`.
    pub fn parse(option: &str, value: impl AsRef<OsStr>) -> Result<Self, Error> {
        Ok(Self(make_cstring(option, value.as_ref())?))
    }

    /// Borrow as a C string for syscalls.
    pub fn as_c_str(&self) -> &CStr {
        &self.0
    }

    /// Borrow as a Rust string, lossily (see [`HostPath::as_str`]).
    pub fn as_str(&self) -> std::borrow::Cow<'_, str> {
        self.0.to_string_lossy()
    }
}

impl fmt::Debug for HostPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HostPath({:?})", self.as_str())
    }
}

impl fmt::Display for HostPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

impl fmt::Debug for SandboxPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SandboxPath({:?})", self.as_str())
    }
}

impl fmt::Display for SandboxPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_with_upstream_text() {
        let e = HostPath::parse("--bind", "").unwrap_err();
        assert_eq!(e.to_string(), "--bind does not take an empty path argument");
        let e = SandboxPath::parse("--dir", "").unwrap_err();
        assert_eq!(e.to_string(), "--dir does not take an empty path argument");
    }

    #[test]
    fn rejects_interior_nul() {
        assert!(HostPath::parse("--bind", "a\0b").is_err());
    }

    #[test]
    fn keeps_value_and_leading_slash() {
        assert_eq!(HostPath::parse("--bind", "/usr").unwrap().as_str(), "/usr");
        assert_eq!(
            SandboxPath::parse("--dir", "/foo").unwrap().as_str(),
            "/foo"
        );
        assert_eq!(
            HostPath::parse("--bind", "/usr")
                .unwrap()
                .as_c_str()
                .to_bytes(),
            b"/usr"
        );
    }

    #[test]
    fn display_and_debug_for_both_kinds() {
        let h = HostPath::parse("--bind", "/usr/lib").unwrap();
        assert_eq!(h.to_string(), "/usr/lib");
        assert_eq!(format!("{h:?}"), "HostPath(\"/usr/lib\")");
        let s = SandboxPath::parse("--dir", "/a b").unwrap();
        assert_eq!(s.to_string(), "/a b");
        assert_eq!(format!("{s:?}"), "SandboxPath(\"/a b\")");
    }

    #[test]
    fn sandbox_path_accessors_and_nul_message() {
        let s = SandboxPath::parse("--dir", "//x/").unwrap();
        assert_eq!(s.as_str(), "//x/");
        assert_eq!(s.as_c_str().to_bytes(), b"//x/");
        let e = SandboxPath::parse("--symlink", "a\0b").unwrap_err();
        assert_eq!(e.to_string(), "--symlink path contains a NUL byte");
        let e = HostPath::parse("--ro-bind", "x\0").unwrap_err();
        assert_eq!(e.to_string(), "--ro-bind path contains a NUL byte");
    }

    #[test]
    fn equality_and_clone() {
        let a = HostPath::parse("--bind", "/x").unwrap();
        assert_eq!(a.clone(), a);
        assert_ne!(a, HostPath::parse("--bind", "/y").unwrap());
        let b = SandboxPath::parse("--dir", "/x").unwrap();
        assert_eq!(b.clone(), b);
    }
}
