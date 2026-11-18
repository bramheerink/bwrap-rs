#![no_main]
//! Fuzz the argument grammar — the primary untrusted-input path. A crafted argv
//! reaching bwrap is a real, exploited class (Flatpak→bubblewrap arg injection),
//! so the parser must never panic/overflow on any input: a bad argument vector
//! is an `Err`, not a crash.

use bwrap_cli::{ParseHost, parse};
use libfuzzer_sys::fuzz_target;
use std::ffi::OsString;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;

/// A host that never touches real descriptors or process state: `--args`/
/// `--add-seccomp-fd` reads fail (exercising the parser's error path without
/// needing live fds), SELinux labels are accepted without being installed, and
/// warnings are dropped. This drives the pure argument grammar.
struct FuzzHost;

impl ParseHost for FuzzHost {
    fn validate_label(&mut self, _label: &std::ffi::OsStr) -> Result<(), bwrap_core::Error> {
        Ok(())
    }
    fn set_file_label(&mut self, _label: &std::ffi::OsStr) -> Result<(), bwrap_core::Error> {
        Ok(())
    }
    fn read_args(&mut self, _fd: RawFd) -> Result<Vec<u8>, bwrap_core::Error> {
        Err(bwrap_core::Error::invalid("fuzz: no fd available"))
    }
    fn read_seccomp_fd(&mut self, _fd: RawFd) -> Result<Vec<u8>, bwrap_core::Error> {
        Err(bwrap_core::Error::invalid("fuzz: no fd available"))
    }
    fn warn(&mut self, _msg: &str) {}
}

fuzz_target!(|data: &[u8]| {
    // Split the raw input into NUL-separated arguments, each kept as raw bytes.
    // `main` now passes argv through as `OsString` (arbitrary bytes), so the
    // parser must survive non-UTF-8 tokens too — this feeds them verbatim.
    let args: Vec<OsString> = data
        .split(|&b| b == 0)
        .map(|s| std::ffi::OsStr::from_bytes(s).to_os_string())
        .collect();
    let mut host = FuzzHost;
    // We only care that this never panics; the Result itself is not asserted.
    let _ = parse(&args, &mut host);
});
