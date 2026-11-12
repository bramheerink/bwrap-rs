# Differences from bubblewrap 0.13.1

`bwrap-rs` aims to be a byte-exact, drop-in replacement for bubblewrap 0.13.1:
the same command-line surface, the same behaviour, the same output and exit
codes. Its behavioural conformance matrix (`tests/conformance.sh`) checks every
documented option against the real `/usr/bin/bwrap` 0.13.1 and requires
byte-identical exit code, stdout and stderr.

A small number of behaviours differ deliberately. They are listed here in full.
Most of them make `bwrap-rs` fail *more* strictly (fail-closed) than the C
original on malformed or degenerate input; none changes the result of a normal,
well-formed invocation.

## Deliberate deviations

1. **Seccomp programs that are empty or oversized are rejected at parse time.**
   bubblewrap accepts a zero-length filter (it fails later, at install, with a
   kernel `EINVAL`) and, for a program with more than 65535 instructions,
   silently truncates the length to a 16-bit value — which can install a
   truncated, wrong filter. `bwrap-rs` rejects both up front with a clear error
   (`Invalid seccomp data, must not be empty` / `… instructions is too many`).
   A valid filter behaves identically in both.

2. **`--die-with-parent` also guards the "parent already exited" race.**
   Both set `PR_SET_PDEATHSIG`. In addition, if the parent has already changed by
   the time the signal is armed (the race described in bubblewrap issue #700),
   `bwrap-rs` terminates itself rather than continue reparented. In normal
   operation the two are indistinguishable.

3. **`CAP_LAST_CAP` is probed at runtime.** `bwrap-rs` asks the running kernel
   for its highest capability via `PR_CAPBSET_READ`, instead of relying on a
   value fixed at compile time. The result is the same on any given kernel and
   more robust across kernel versions.

4. **SELinux detection reads `/proc/self/mountinfo`.** `is_selinux_enabled()` is
   determined by whether a `selinuxfs` filesystem is mounted. On the unusual
   configuration where `selinuxfs` is mounted but SELinux is disabled, this can
   report "enabled" where libselinux reports "disabled". On enforcing and
   permissive systems — the normal case — the two agree.

5. **The `/proc/self/mountinfo` parser rejects hostile/malformed input.** A line
   with too few fields, a truncated octal escape, or a cyclic mount tree is
   rejected rather than read past. This never arises for the mountinfo a kernel
   actually produces; it is defensive hardening.

6. **Non-UTF-8 arguments are rejected (known, parked limitation).** Arguments and
   paths that are not valid UTF-8 are rejected with
   `non-UTF-8 arguments are not yet supported by this build`, whereas bubblewrap
   passes arbitrary byte strings straight through to `openat`/`mount`/`execvp`.
   Byte-transparent paths are the correct Unix behaviour and the eventual target.
   Reaching byte-exactness here means carrying raw bytes through the whole parser
   — and through the error messages that embed a path — a change to the hot parse
   path that is deliberately deferred to the pre-adoption polish rather than
   rushed. The rejection is fail-closed, carries no security risk (the bytes only
   ever reach syscalls, never an interpreter), and no well-formed UTF-8
   invocation is affected; in practice no desktop caller (flatpak, glycin,
   portals) ever hits it.

7. **`--size` does not accept a `0b` binary literal.** bubblewrap parses
   `--size` with the C library's `strtoull(.., 0)`. glibc 2.38+ extended that
   base-0 autodetection to accept a `0b`/`0B` binary prefix, so on a recent
   glibc system `--size 0b100…` is read as a binary number; on musl and older
   glibc the same bubblewrap binary rejects it. `bwrap-rs` implements the
   portable, standard base-0 rule (`0x`→hex, leading `0`→octal, else decimal)
   and so rejects `0b…`, matching bubblewrap on musl and pre-2.38 glibc and
   differing only from bubblewrap on glibc ≥ 2.38. This is a libc artefact
   rather than a bubblewrap behaviour, affects only the obscure `0b` form (no
   real caller uses it), and leaves every well-formed decimal/hex/octal size
   identical.

## Everything else

Outside this list, any divergence from bubblewrap 0.13.1 is a bug. Please report
it — ideally with the exact command line and the differing output — so it can be
fixed or added here.
