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

6. **Non-UTF-8 arguments are not yet supported.** Arguments and paths that are
   not valid UTF-8 are rejected with
   `non-UTF-8 arguments are not yet supported by this build`, whereas bubblewrap
   processes arbitrary byte strings. This is a current limitation, not a design
   choice, and is planned to be lifted. For the same reason, a non-UTF-8
   `argv[0]` is shown in the usage line with U+FFFD replacement characters
   rather than its raw bytes; an *empty* argv[0] is printed verbatim, as C does.

7. **A launcher that dies before releasing the child aborts the child instead of
   leaking it.** bubblewrap signals the child to proceed through an eventfd; if
   the launcher dies after the clone but before signalling (for example an
   `--info-fd`/`--json-status-fd` write that fails, or the launcher being killed
   while it waits on `--userns-block-fd`), its child blocks on that eventfd
   forever — an unmonitored sandbox is left set up but idle. `bwrap-rs` uses a
   socketpair for the handshake, so the child sees EOF in that case and exits 1
   without ever building the sandbox or running the command. On the normal path
   the child receives the go byte and proceeds identically. The launcher sends
   with `MSG_NOSIGNAL` and ignores the result, so if the child has already died
   the launcher still reaps it and reports its real exit status, where bubblewrap
   would be killed by SIGPIPE and exit 141.

8. **Reusing one fd for two `--bind-fd`/`--ro-bind-fd` operations: same exit,
   different message.** Each `--bind-fd`/`--ro-bind-fd` closes its source fd
   after the operation (as bubblewrap does), so passing the *same* fd number to a
   second bind op fails in both — the fd is gone by then. The exit code is
   identical (1); only the error text differs. bubblewrap resolves the fd by
   opening `/proc/self/fd/N` through the old root and reports the failure from
   its post-mount race check (`Race condition binding dirfd`), whereas `bwrap-rs`
   resolves it with `readlink` and reports the earlier `readlink` failure
   (`Can't read link /proc/self/fd/N`). A single bind per fd — the only
   non-degenerate use — is byte-identical. (Passing the same fd twice is a caller
   bug; both binaries reject it.)

9. **Closed standard fds (0, 1, 2) are reopened as `/dev/null` at startup.** The
   Rust runtime's `sanitize_standard_fds` opens `/dev/null` on any of fds 0-2
   that were closed before `main` runs; bubblewrap leaves them closed. So when a
   launcher starts bwrap with, say, stdin closed (`cmd <&-`), the sandboxed
   command inherits `/dev/null` there rather than a closed fd, and an option that
   names such an fd (`--args 0`, `--file 0`, `--bind-data 0`, `--info-fd 1`,
   `--json-status-fd 2`) reads EOF / writes to `/dev/null` and succeeds, where
   bubblewrap fails with `Bad file descriptor`. A fully faithful fix needs a C
   `main` shim to record and re-close those fds before the runtime touches them;
   until then this is documented rather than worked around. A sandbox started
   with all of stdin/stdout/stderr open — the normal case — is unaffected.

## Everything else

Outside this list, any divergence from bubblewrap 0.13.1 is a bug. Please report
it — ideally with the exact command line and the differing output — so it can be
fixed or added here.
