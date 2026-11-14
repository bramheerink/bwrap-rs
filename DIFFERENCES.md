# Differences from bubblewrap 0.13.1

`bwrap-rs` is **byte-exact by default**: the same command-line surface, the same
behaviour, the same output and exit codes as bubblewrap 0.13.1. Its conformance
matrix (`tests/conformance.sh`) dual-runs every documented option against a real
bubblewrap 0.13.1 binary and requires byte-identical exit code, stdout and
stderr.

This file is the **divergence register**: every place the port is not
byte-identical, with the reason, sorted into three explicitly-labelled
categories. Keeping them apart is the whole point of the file —

- **Safer divergence (fail-closed).** A *deliberate* choice to be stricter than
  the C, where the C's observable behaviour on malformed or degenerate input is
  itself unsafe or lax. None of these changes the result of a normal, well-formed
  invocation.
- **Equivalent by design.** A different mechanism with the *same* observable
  result, noted only so a reader of the source is not surprised.
- **Known limitation (not yet byte-exact).** A place the port does *not* yet
  match the C and that is **not** a safety choice and **not** a deliberate
  deviation — a tracked fidelity gap, listed with the reason it is still open.
  These are recorded in full, on purpose: partly so the register is an honest
  account rather than a fig-leaf for divergences that are simply unclosed, and
  partly because several capture a genuinely *subtle* piece of bubblewrap
  behaviour that the project's own differential research surfaced (a stale errno,
  a fd-resolution path, a C use-after-free that prints `(null)`). Naming them
  here is how that understanding is kept — it is context for the issues behind
  this work, not an admission of neglect. Byte-exactness remains the goal for
  every one of them.

Entry numbers are stable (code comments and tests cite them); the category label
on each line is what says whether it is a design choice or an open gap. Anything
not listed here is a bug. See [THREAT-MODEL.md](THREAT-MODEL.md) for the security
framing and [ROADMAP.md](ROADMAP.md) for the north star.

## Register

1. **[safer divergence] Seccomp programs that are empty or oversized are rejected
   at parse time.** bubblewrap accepts a zero-length filter (it fails later, at
   install, with a kernel `EINVAL`) and, for a program with more than 65535
   instructions, silently truncates the length to a 16-bit value — which can
   install a truncated, wrong filter. `bwrap-rs` rejects both up front with a
   clear error (`Invalid seccomp data, must not be empty` /
   `… instructions is too many`). A valid filter behaves identically in both.

2. **[safer divergence] `--die-with-parent` also guards the "parent already
   exited" race, inside a new pid namespace too.** Both set `PR_SET_PDEATHSIG`,
   which only fires on a *future* parent death. In addition, `bwrap-rs` closes the
   race where the launcher dies between the clone and the signal being armed (the
   hole in bubblewrap issue #700): without a new pid namespace it compares
   `getppid()`; with `--unshare-pid` — where pid 1 always sees `getppid() == 0`,
   so a pid check is useless — it instead peeks the launcher handshake socket for
   EOF, which the kernel reports exactly when the launcher dies. On detection the
   sandbox terminates (pid 1 `_exit`s, tearing the namespace down, since a
   namespace's pid 1 cannot SIGKILL itself) rather than continue unmonitored. In
   normal operation this is a no-op. **Footprint:** under `--die-with-parent` the
   launcher's handshake socket is held open through setup — one fd more than
   bubblewrap — which can shift the numbers of setup-opened fds that appear in an
   error message (e.g. overlapping `--overlay-src` paths shown as
   `/proc/self/fd/N`). Without `--die-with-parent` no such fd is held and the
   numbering is byte-identical.

3. **[equivalent by design] `CAP_LAST_CAP` is probed at runtime.** `bwrap-rs`
   asks the running kernel for its highest capability via `PR_CAPBSET_READ`,
   instead of relying on a value fixed at compile time. The result is the same on
   any given kernel and more robust across kernel versions.

4. **[known limitation] SELinux detection reads `/proc/self/mountinfo`.**
   `is_selinux_enabled()` is determined by whether a `selinuxfs` filesystem is
   mounted. On the unusual configuration where `selinuxfs` is mounted but SELinux
   is disabled, this can report "enabled" where libselinux reports "disabled". On
   enforcing and permissive systems — the normal case — the two agree. Matching
   libselinux's enabled-state check on that edge case is not yet done.

5. **[safer divergence] The `/proc/self/mountinfo` parser rejects
   hostile/malformed input.** A line with too few fields, a truncated octal
   escape, or a cyclic mount tree is rejected rather than read past. This never
   arises for the mountinfo a kernel actually produces; it is defensive
   hardening.

6. **[known limitation] Non-UTF-8 arguments are not yet supported.** Arguments
   and paths that are not valid UTF-8 are rejected with
   `non-UTF-8 arguments are not yet supported by this build`, whereas bubblewrap
   processes arbitrary byte strings. This is a current limitation, not a design
   choice, and is planned to be lifted. For the same reason, a non-UTF-8
   `argv[0]` is shown in the usage line with U+FFFD replacement characters
   rather than its raw bytes; an *empty* argv[0] is printed verbatim, as C does.

7. **[safer divergence] A launcher that dies before releasing the child aborts
   the child instead of leaking it.** bubblewrap signals the child to proceed
   through an eventfd; if the launcher dies after the clone but before signalling
   (for example an `--info-fd`/`--json-status-fd` write that fails, or the
   launcher being killed while it waits on `--userns-block-fd`), its child blocks
   on that eventfd forever — an unmonitored sandbox is left set up but idle.
   `bwrap-rs` uses a socketpair for the handshake, so the child sees EOF in that
   case and exits 1 without ever building the sandbox or running the command. On
   the normal path the child receives the go byte and proceeds identically; the
   launcher sends with `MSG_NOSIGNAL` and reaps the child's real exit status just
   as bubblewrap does (bubblewrap's shared eventfd cannot raise SIGPIPE, so there
   is no difference on that path).

8. **[known limitation] Reusing one fd for two `--bind-fd`/`--ro-bind-fd`
   operations: same exit, different message.** Each `--bind-fd`/`--ro-bind-fd`
   closes its source fd after the operation (as bubblewrap does), so passing the
   *same* fd number to a second bind op fails in both — the fd is gone by then.
   The exit code is identical (1); only the error text differs. bubblewrap
   resolves the fd by opening `/proc/self/fd/N` through the old root and reports
   the failure from its post-mount race check (`Race condition binding dirfd`),
   whereas `bwrap-rs` resolves it with `readlink` and reports the earlier
   `readlink` failure (`Can't read link /proc/self/fd/N`). A single bind per fd —
   the only non-degenerate use — is byte-identical. (Passing the same fd twice is
   a caller bug; both binaries reject it.)

9. **[known limitation] Closed standard fds (0, 1, 2) are reopened as
   `/dev/null` at startup.** The Rust runtime's `sanitize_standard_fds` opens
   `/dev/null` on any of fds 0-2 that were closed before `main` runs; bubblewrap
   leaves them closed. So when a launcher starts bwrap with, say, stdin closed
   (`cmd <&-`), the sandboxed command inherits `/dev/null` there rather than a
   closed fd, and an option that names such an fd (`--args 0`, `--file 0`,
   `--bind-data 0`, `--info-fd 1`, `--json-status-fd 2`) reads EOF / writes to
   `/dev/null` and succeeds, where bubblewrap fails with `Bad file descriptor`. A
   fully faithful fix needs a C `main` shim to record and re-close those fds
   before the runtime touches them; until then this is documented rather than
   worked around. A sandbox started with all of stdin/stdout/stderr open — the
   normal case — is unaffected.

10. **[known limitation] The `--bind-fd` post-mount race error carries no errno
    suffix.** When a `--bind-fd`/`--ro-bind-fd` destination resolves to a
    different inode than the caller's fd (the path was swapped under the mount),
    both abort with exit 1 and the line `Race condition binding dirfd`.
    bubblewrap's `die_with_error` appends `: <strerror(errno)>` using whatever
    errno the last failing libc call happened to leave (in the reproducible case
    `: File exists`), so the suffix is a stale value not set by the check itself;
    `bwrap-rs` omits it and prints the message alone. This is a near-unreachable
    TOCTOU guard; the exit code is identical and a well-formed bind is
    byte-identical. (Distinct from entry 8, which is the fd-*reuse* path that
    fails earlier at `readlink`.) Matching the stale errno reliably is tracked as
    an open fidelity gap.

## Everything else

Outside this list, any divergence from bubblewrap 0.13.1 is a bug. Please report
it — ideally with the exact command line and the differing output — so it can be
fixed or added here.
