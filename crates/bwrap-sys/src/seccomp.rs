//! Classic-BPF seccomp filters, as passed to `--seccomp` / `--add-seccomp-fd`.
//!
//! bwrap does not compile filters. It reads a raw array of
//! `struct sock_filter` (8 bytes each, native endian) and installs it as is.

use std::fmt;

use nix::errno::Errno;
use nix::libc::{self, c_ulong, sock_filter, sock_fprog};

const INSN_SIZE: usize = std::mem::size_of::<sock_filter>();
const _: () = assert!(INSN_SIZE == 8);

/// Why bytes are not a valid filter program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramError {
    /// Zero instructions.
    Empty,
    /// The length is not a multiple of 8 bytes.
    NotMultipleOf8 {
        /// Byte length received.
        len: usize,
    },
    /// More instructions than `sock_fprog.len` (`u16`) can describe.
    TooLong {
        /// Instruction count received.
        instructions: usize,
    },
}

impl fmt::Display for ProgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Invalid seccomp data, must not be empty"),
            // Same text as bwrap's seccomp_program_new().
            Self::NotMultipleOf8 { .. } => {
                f.write_str("Invalid seccomp data, must be multiple of 8")
            }
            Self::TooLong { instructions } => {
                write!(
                    f,
                    "Invalid seccomp data, {instructions} instructions is too many"
                )
            }
        }
    }
}

impl std::error::Error for ProgramError {}

/// A validated seccomp filter program.
#[derive(Clone)]
pub struct Program {
    insns: Vec<sock_filter>,
}

impl fmt::Debug for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Program")
            .field("instructions", &self.insns.len())
            .finish()
    }
}

impl Program {
    /// Parse raw `struct sock_filter` bytes.
    ///
    /// Only the framing is checked. Whether the BPF itself is valid is up to
    /// the kernel at [`install`](Self::install) time, just as in bwrap.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        if bytes.is_empty() {
            return Err(ProgramError::Empty);
        }
        if !bytes.len().is_multiple_of(INSN_SIZE) {
            return Err(ProgramError::NotMultipleOf8 { len: bytes.len() });
        }
        let instructions = bytes.len() / INSN_SIZE;
        if u16::try_from(instructions).is_err() {
            return Err(ProgramError::TooLong { instructions });
        }
        let insns = bytes
            .chunks_exact(INSN_SIZE)
            .map(|c| sock_filter {
                code: u16::from_ne_bytes([c[0], c[1]]),
                jt: c[2],
                jf: c[3],
                k: u32::from_ne_bytes([c[4], c[5], c[6], c[7]]),
            })
            .collect();
        Ok(Self { insns })
    }

    /// Number of BPF instructions.
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    /// Always false: empty programs are rejected by [`from_bytes`](Self::from_bytes).
    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// Install this filter on the calling thread (`PR_SET_SECCOMP`).
    ///
    /// Requires `PR_SET_NO_NEW_PRIVS` or `CAP_SYS_ADMIN`. Filters stack: every
    /// installed program applies. `EINVAL` usually means the kernel lacks
    /// `CONFIG_SECCOMP_FILTER` or rejected the BPF.
    pub fn install(&self) -> nix::Result<()> {
        let len = u16::try_from(self.insns.len()).map_err(|_| Errno::EINVAL)?;
        let prog = sock_fprog {
            len,
            // The kernel only reads the instructions; the `*mut` is just the C type.
            filter: self.insns.as_ptr().cast_mut(),
        };
        let mode = c_ulong::from(libc::SECCOMP_MODE_FILTER);
        // SAFETY: `prog` points at `len` initialised `sock_filter`s owned by
        // `self.insns`, which outlives the call. The kernel copies the program
        // before returning and keeps no reference to our memory.
        let ret = unsafe { libc::prctl(libc::PR_SET_SECCOMP, mode, &raw const prog) };
        Errno::result(ret).map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert_eq!(Program::from_bytes(&[]).err(), Some(ProgramError::Empty));
    }

    #[test]
    fn rejects_bad_length() {
        assert_eq!(
            Program::from_bytes(&[0; 12]).err(),
            Some(ProgramError::NotMultipleOf8 { len: 12 })
        );
    }

    #[test]
    fn rejects_too_long() {
        let bytes = vec![0u8; (usize::from(u16::MAX) + 1) * 8];
        assert!(matches!(
            Program::from_bytes(&bytes),
            Err(ProgramError::TooLong { .. })
        ));
    }

    #[test]
    fn parses_native_endian() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0006u16.to_ne_bytes());
        bytes.extend_from_slice(&[1, 2]);
        bytes.extend_from_slice(&0x7fff_0000u32.to_ne_bytes());
        let p = Program::from_bytes(&bytes).expect("valid");
        assert_eq!(p.len(), 1);
        let i = &p.insns[0];
        assert_eq!((i.code, i.jt, i.jf, i.k), (6, 1, 2, 0x7fff_0000));
    }

    #[test]
    fn display_texts_match_bwrap() {
        assert_eq!(
            ProgramError::Empty.to_string(),
            "Invalid seccomp data, must not be empty"
        );
        assert_eq!(
            ProgramError::NotMultipleOf8 { len: 9 }.to_string(),
            "Invalid seccomp data, must be multiple of 8"
        );
        assert_eq!(
            ProgramError::TooLong {
                instructions: 70000
            }
            .to_string(),
            "Invalid seccomp data, 70000 instructions is too many"
        );
    }

    #[test]
    fn max_length_program_is_accepted() {
        let bytes = vec![0u8; usize::from(u16::MAX) * 8];
        let p = Program::from_bytes(&bytes).expect("65535 insns fit sock_fprog.len");
        assert_eq!(p.len(), usize::from(u16::MAX));
        assert!(!p.is_empty());
    }

    #[test]
    fn debug_shows_instruction_count_only() {
        let p = Program::from_bytes(&[0; 16]).unwrap();
        assert_eq!(format!("{p:?}"), "Program { instructions: 2 }");
    }

    #[test]
    fn clone_preserves_instructions() {
        let mut bytes = vec![0u8; 8];
        bytes[4..8].copy_from_slice(&0xdead_beefu32.to_ne_bytes());
        let p = Program::from_bytes(&bytes).unwrap();
        let q = p.clone();
        assert_eq!(q.len(), 1);
        assert_eq!(q.insns[0].k, 0xdead_beef);
    }
}
