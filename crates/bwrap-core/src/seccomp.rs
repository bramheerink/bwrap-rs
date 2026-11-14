//! Seccomp policy: load the filter programs from the `--seccomp` /
//! `--add-seccomp-fd` descriptors and install them, last of all, before
//! `execvp`. Mirrors bwrap's `seccomp_program_new` and `seccomp_programs_apply`.
//!
//! The raw BPF framing and the `PR_SET_SECCOMP` install live in
//! `bwrap_sys::seccomp`; this layer just reads the fds and applies every
//! program in order. Reading an fd is delegated to the caller (the
//! orchestration owns the descriptors), keeping this crate `forbid(unsafe)`.

use std::os::fd::RawFd;

use bwrap_sys::seccomp::Program;
use nix::errno::Errno;

use crate::error::{Error, Result};
use crate::types::SeccompSource;

/// The validated seccomp programs to install, in order.
#[derive(Debug, Default)]
pub struct SeccompPrograms {
    programs: Vec<Program>,
}

impl SeccompPrograms {
    /// Build the ordered program list from `source`.
    ///
    /// `--seccomp` (`Single`) is read late, here, through `read_fd` (which reads
    /// the whole fd, like bwrap's `load_file_data`); `--add-seccomp-fd` (`Added`)
    /// was already read and validated at parse time, so its bytes are framed
    /// directly without touching `read_fd`. Both fold into the same ordered list.
    pub fn load(
        source: &SeccompSource,
        mut read_fd: impl FnMut(RawFd) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        // Framing errors (empty, not a multiple of 8, too long) carry the same
        // text as bwrap's seccomp_program_new.
        let frame =
            |bytes: &[u8]| Program::from_bytes(bytes).map_err(|e| Error::invalid(e.to_string()));
        let programs = match source {
            SeccompSource::None => Vec::new(),
            SeccompSource::Single(fd) => vec![frame(&read_fd(*fd)?)?],
            SeccompSource::Added(progs) => {
                progs.iter().map(|b| frame(b)).collect::<Result<Vec<_>>>()?
            }
        };
        Ok(Self { programs })
    }

    /// Whether there is anything to apply. The production path applies
    /// unconditionally; this is for callers and tests that inspect the set.
    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }

    /// Number of programs (used by the seccomp host test to count installs).
    pub fn len(&self) -> usize {
        self.programs.len()
    }

    /// Install every program with `PR_SET_SECCOMP`, in order
    /// (`seccomp_programs_apply`). Must be the last privileged action before
    /// `execvp`, so the filters need not whitelist the setup syscalls.
    pub fn apply(&self) -> Result<()> {
        for program in &self.programs {
            match program.install() {
                Ok(()) => {}
                Err(Errno::EINVAL) => {
                    // bwrap's exact hint text.
                    return Err(Error::invalid(
                        "Unable to set up system call filtering as requested: \
                         prctl(PR_SET_SECCOMP) reported EINVAL. \
                         (Hint: this requires a kernel configured with \
                         CONFIG_SECCOMP and CONFIG_SECCOMP_FILTER.)",
                    ));
                }
                Err(e) => {
                    return Err(Error::Sys {
                        message: "prctl(PR_SET_SECCOMP)".into(),
                        errno: e,
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal valid filter: one instruction (8 bytes). Framing-valid; whether
    // the kernel accepts it is tested in bwrap-sys / the host tests.
    fn one_insn() -> Vec<u8> {
        vec![0u8; 8]
    }

    #[test]
    fn none_loads_empty() {
        let p = SeccompPrograms::load(&SeccompSource::None, |_| panic!("should not read")).unwrap();
        assert!(p.is_empty());
    }

    #[test]
    fn single_reads_one_fd() {
        let p = SeccompPrograms::load(&SeccompSource::Single(7), |fd| {
            assert_eq!(fd, 7);
            Ok(one_insn())
        })
        .unwrap();
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn added_frames_prevalidated_bytes_without_reading() {
        // `Added` carries bytes already read at parse time, so `load` frames them
        // directly and must never touch `read_fd`.
        let p = SeccompPrograms::load(
            &SeccompSource::Added(vec![one_insn(), one_insn(), one_insn()]),
            |_| panic!("Added must not read an fd"),
        )
        .unwrap();
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn added_framing_error_is_reported() {
        // A malformed Added program (not a multiple of 8) still fails framing.
        let e = SeccompPrograms::load(&SeccompSource::Added(vec![vec![0u8; 12]]), |_| {
            panic!("Added must not read an fd")
        })
        .unwrap_err();
        assert_eq!(e.to_string(), "Invalid seccomp data, must be multiple of 8");
    }

    #[test]
    fn framing_error_is_reported_with_bwrap_text() {
        // 12 bytes is not a multiple of 8.
        let e =
            SeccompPrograms::load(&SeccompSource::Single(3), |_| Ok(vec![0u8; 12])).unwrap_err();
        assert_eq!(e.to_string(), "Invalid seccomp data, must be multiple of 8");
        // Empty data.
        let e = SeccompPrograms::load(&SeccompSource::Single(3), |_| Ok(Vec::new())).unwrap_err();
        assert_eq!(e.to_string(), "Invalid seccomp data, must not be empty");
    }

    #[test]
    fn read_error_propagates() {
        let e = SeccompPrograms::load(&SeccompSource::Single(3), |_| {
            Err(Error::Sys {
                message: "read".into(),
                errno: Errno::EBADF,
            })
        })
        .unwrap_err();
        assert!(e.to_string().starts_with("read"));
    }
}
