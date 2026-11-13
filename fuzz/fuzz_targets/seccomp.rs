#![no_main]
//! Fuzz the seccomp-BPF framing validator — the second untrusted-input path
//! (`--seccomp`/`--add-seccomp-fd` deliver an attacker- or caller-supplied byte
//! program). The validator (empty / not a multiple of 8 / too long) must never
//! panic or overflow: a malformed program is an `Err`, not a crash.

use bwrap_sys::seccomp::Program;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Program::from_bytes(data);
});
