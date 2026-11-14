//! Shared fd I/O loops. One definition each, so a correction lands once instead
//! of in the several hand-copied loops that had already drifted (all five write
//! loops reported a short write as `EIO`, where bubblewrap's `write_to_fd`
//! reports `ENOSPC`). The `EINTR` retry and the short-write/EOF handling here
//! match bubblewrap's `write_to_fd` / `load_file_data` (`utils.c`).

use std::os::fd::BorrowedFd;

use nix::errno::Errno;
use nix::unistd::{read, write};

/// Write the whole buffer, retrying `EINTR`. A short write (`Ok(0)`) is reported
/// as `ENOSPC`, exactly as bubblewrap's `write_to_fd` ("Sets errno on error, …
/// `ENOSPC` on short write"). Returns the raw errno so each caller can wrap it
/// in its own error type and message.
pub fn write_all(fd: BorrowedFd<'_>, mut data: &[u8]) -> Result<(), Errno> {
    while !data.is_empty() {
        match write(fd, data) {
            Ok(0) => return Err(Errno::ENOSPC),
            Ok(n) => data = &data[n..],
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read `fd` to EOF into a `Vec`, retrying `EINTR` (bubblewrap's
/// `load_file_data`). Returns the raw errno so callers wrap it themselves.
pub fn read_to_end(fd: BorrowedFd<'_>) -> Result<Vec<u8>, Errno> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match read(fd, &mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e),
        }
    }
}
