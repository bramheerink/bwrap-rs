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
   libselinux's enabled-state check on that edge case is not yet done. The state
   is detected once, before the sandbox's root is built, and a requested label is
   then either applied or the launch fails.

5. **[safer divergence] The `/proc/self/mountinfo` parser tolerates
   hostile/malformed input without crashing.** A line with too few fields or a
   non-numeric mount id is rejected with an error. A truncated octal escape is
   kept literally, and a cycle in the mount tree is cut by skipping nodes already
   visited, where bubblewrap's recursion would crash. This never arises for the
   mountinfo a kernel actually produces; it is defensive hardening.

6. **[known limitation] Non-UTF-8 values appear in *error text* with U+FFFD, not
   their raw bytes.** Arbitrary byte strings are now accepted and processed
   verbatim: a non-UTF-8 path, command, `argv[0]`, hostname or environment value
   flows through the parser as raw bytes to the syscall exactly as bubblewrap
   passes its `char *`, so a well-formed invocation using such values is
   byte-identical (verified against the oracle: a non-UTF-8 bind source, and a
   non-UTF-8 `--argv0` reaching the command's `$0`). The one remaining gap is
   *rendering*: where an error message echoes a value that is not valid UTF-8
   (e.g. `Can't find source path <path>`, `Invalid fd: <value>`), `bwrap-rs`
   prints it with U+FFFD replacement characters whereas bubblewrap prints the
   raw bytes. The **exit code is identical** and the message text is otherwise
   identical — only the non-UTF-8 bytes within it differ. The same applies to a
   non-UTF-8 `argv[0]` in the usage line (shown with U+FFFD; an *empty* argv[0]
   is still printed verbatim, as C does). Closing this needs the error type and
   its stderr path to carry raw bytes rather than a Rust `str`; tracked as an
   open fidelity gap. No normal, well-formed invocation is affected.

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

11. **[known limitation] A namespace id that cannot be read is reported as 0,
    not fatal.** For `--info-fd`/`--json-status-fd`, the launcher stats
    `/proc/<child>/ns/<name>` to report each unshared namespace's inode id. If a
    stat fails, `bwrap-rs` reports `0` for that namespace; bubblewrap instead
    aborts with `open /proc/<pid>/ns failed`. The child's namespace links exist
    the moment after the clone, so this is near-unreachable in practice; matching
    bubblewrap's abort on it is an open fidelity gap.

12. **[safer divergence] A *closed* or already consumed fd number is never
    confused with one of bwrap's internal descriptors.** Both binaries open their
    own descriptors during setup (an `O_PATH` handle to `/proc`, for example),
    which can land on a low number the caller left closed. `bwrap-rs` records which
    numbers are open before it opens any descriptor of its own, so `--bind-fd 3`
    with fd 3 closed fails with `Can't find source path /proc/self/fd/3: No such
    file or directory`, where bubblewrap's result depends on its internal fd
    layout. A number consumed by an earlier option likewise stays unusable
    even if the kernel reuses it. Every other fd option given a closed number
    matches bubblewrap's exit code and message (compared for `--userns`,
    `--userns2`, `--pidns`, `--file`, `--bind-data`, `--info-fd`,
    `--json-status-fd`, `--block-fd`, `--sync-fd`, `--seccomp` and `--args`). A
    valid fd is unaffected.

13. **[equivalent by design] The optional invocation log is an addition of the
    port.** With `BWRAP_RS_LOG` unset and no `/etc/bwrap-rs-log`, nothing changes.
    When enabled, each launch's full argv is appended to the named file, so argv
    (which can contain secrets) reaches a place it does not reach with bubblewrap.
    Output, exit codes and the sandbox are unaffected. The log is written only to a
    regular file owned by the current user with no group or other permissions, and
    is skipped entirely for a refused setuid or file-capability launch and for a
    lone `--version`.

14. **[safer divergence] With `--lock-file`, the command starts only after the
    locks are held.** bubblewrap forks the command first and takes the locks
    afterwards in pid 1, so the command can run without the lock, and still runs
    when the lock cannot be taken even though bubblewrap exits 1. `bwrap-rs` makes
    the command wait for pid 1, and ends it unrun if pid 1 fails. The exit code and
    error message are unchanged.

15. **[safer divergence] Numbers outside `0..=INT_MAX` are refused.** bubblewrap
    narrows the parsed `long` to an `int` before validating it, so `--uid 4294968296`
    means uid 1000, `--uid -4294966296` also means uid 1000, and `--bind-fd 4294967299`
    means fd 3. `bwrap-rs` rejects such values for every fd option, `--uid` and
    `--gid`, with the usual `Invalid fd` / `Invalid uid` / `Invalid gid` message.

16. **[safer divergence] The fallback path resolver limits symlinks, not depth.**
    bubblewrap's `chroot_realpath` counts every path component against its limit of
    32 symlinks, so its fallback (used without `openat2`, or with
    `--debug-opt=force-openat-fallback`) refuses deep paths that contain no symlinks
    at all. `bwrap-rs` counts only symlinks it follows. Symlink chains and loops are
    limited as before.

17. **[safer divergence] A failed descriptor cleanup is reported.** bubblewrap's
    `fdwalk` reports success when it cannot list `/proc/self/fd`, leaving descriptors
    open. `bwrap-rs` then closes them with `close_range(2)`, and fails if that does
    not work either.

## Everything else

Outside this list, any divergence from bubblewrap 0.13.1 is a bug. Please report
it — ideally with the exact command line and the differing output — so it can be
fixed or added here.
