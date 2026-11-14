#!/usr/bin/env bash
# Behavioural conformance matrix for the Rust bwrap port.
#
# For every documented option we run a "yes" form (the option takes effect) and,
# where meaningful, a "no" form (a guardrail rejects bad use, or the effect is
# absent / inverted). The oracle is the real binary: unless an assertion is an
# explicit ours-only invariant (inv), we require our binary and /usr/bin/bwrap
# 0.13.1 to produce byte-identical exit code, stdout AND stderr.
#
# This mirrors upstream's own test strategy (shell + the real binary) and is the
# "gortdroog" proof: a sceptic reruns this and sees ours == C, option by option.
#
# Run OUTSIDE the Bash sandbox (needs real user namespaces):
#   OURS=target/debug/bwrap tests/conformance.sh
set -u

OURS="${OURS:-target/debug/bwrap}"
REAL="${REAL:-/usr/bin/bwrap}"
[ -x "$OURS" ] || { echo "our binary not found: $OURS (build it first)"; exit 2; }
case "$OURS" in /*) ;; *) OURS="$PWD/$OURS";; esac

HAVE_REAL=0
if [ -x "$REAL" ] && [ "$("$REAL" --version 2>/dev/null)" = "bubblewrap 0.13.1" ]; then
    HAVE_REAL=1
fi

# Reject an oracle that is actually the port itself: the same file as OURS, or
# any bwrap-rs build (identified by its embedded `bwrap-rs <version>` marker,
# which the C binary never carries). On a host where bwrap-rs is deployed as the
# drop-in /usr/bin/bwrap — the project's own goal — the default
# REAL=/usr/bin/bwrap would otherwise compare the port with itself and report a
# green "byte-identical" verdict that proves nothing. `--version` cannot tell
# them apart (the port reproduces it exactly), so use the marker.
ORACLE_IS_PORT=0
if [ "$HAVE_REAL" = 1 ]; then
    if [ "$REAL" -ef "$OURS" ] || strings -a -- "$REAL" 2>/dev/null | grep -qE '^bwrap-rs '; then
        HAVE_REAL=0
        ORACLE_IS_PORT=1
    fi
fi

# REQUIRE_REAL=1 / REQUIRE_USERNS=1 turn a missing oracle or unavailable user
# namespaces into a hard failure instead of a silent pass/skip. CI sets both, so
# a run that cannot actually compare against bubblewrap 0.13.1 fails loudly
# rather than reporting green against nothing.
REQUIRE_REAL="${REQUIRE_REAL:-0}"
REQUIRE_USERNS="${REQUIRE_USERNS:-0}"
if [ "$REQUIRE_REAL" = 1 ] && [ "$HAVE_REAL" != 1 ]; then
    if [ "$ORACLE_IS_PORT" = 1 ]; then
        echo "conformance: REQUIRE_REAL=1 but the oracle at REAL=$REAL is bwrap-rs itself, not bubblewrap 0.13.1"
    else
        echo "conformance: REQUIRE_REAL=1 but no bubblewrap 0.13.1 oracle at REAL=$REAL"
    fi
    exit 1
fi

# A minimal read-only sandbox that is identical on any usr-merged distribution:
# bind /usr and recreate the usr-merge symlinks, so the command, its loader and
# its libraries resolve through /usr whether libc lives in /usr/lib64 (Fedora)
# or /usr/lib/<triplet> (Debian/Ubuntu). Deterministic root: bin lib lib64 proc
# sbin usr.
BASE=(--unshare-user --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/sbin /sbin --proc /proc)
if ! "$OURS" "${BASE[@]}" /bin/true >/dev/null 2>&1; then
    # Distinguish "user namespaces unavailable here" from "our binary is broken"
    # by probing with something independent of OURS: the real oracle's own base
    # sandbox if we have one, else `unshare -Ur`. If the independent probe works
    # but OURS does not, that is a real failure, not an environment limitation.
    userns_ok=0
    if [ "$HAVE_REAL" = 1 ] && "$REAL" "${BASE[@]}" /bin/true >/dev/null 2>&1; then
        userns_ok=1
    elif command -v unshare >/dev/null 2>&1 && unshare -Ur true >/dev/null 2>&1; then
        userns_ok=1
    fi
    if [ "$userns_ok" = 1 ]; then
        echo "conformance: user namespaces work, but OURS=$OURS cannot start the base sandbox — our binary is broken"
        exit 1
    fi
    if [ "$REQUIRE_USERNS" = 1 ]; then
        echo "conformance: REQUIRE_USERNS=1 but user namespaces are unavailable in this environment"
        exit 1
    fi
    echo "SKIP: user namespaces unavailable in this environment"
    exit 0
fi
B="${BASE[*]}"   # space-joined base for template cases
# A base WITHOUT --unshare-user, for cases that pass a caller namespace fd:
# --userns/--userns2 are about *joining* a namespace, and --userns is mutually
# exclusive with --unshare-user, so a bad-fd guardrail must drop --unshare-user
# or it dies on the incompatibility check before the fd is ever looked at.
UJOIN="--ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/sbin /sbin --proc /proc"

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
PASS=0 FAIL=0 SKIP=0; FAILED=()
ok()   { PASS=$((PASS+1)); }
fail() { FAIL=$((FAIL+1)); FAILED+=("  [$1] $2"); }
skip() { SKIP=$((SKIP+1)); echo "  SKIP [$1] $2"; }
norm() { sed -e "s#$OURS#BWRAP#g" -e "s#$REAL#BWRAP#g"; }

# ab NAME -- ARGS... : require ours == real (exit+stdout+stderr byte-identical).
ab() {
    local name="$1"; shift 2
    local oo oe oc ro re rc
    oo=$("$OURS" "$@" 2>"$WORK/oe" | norm); oc=${PIPESTATUS[0]}; oe=$(norm <"$WORK/oe")
    if [ "$HAVE_REAL" != 1 ]; then
        # No oracle: we ran ours (a smoke check) but cannot prove byte-identity,
        # so report SKIP rather than a dishonest pass. REQUIRE_REAL would already
        # have aborted the run above.
        skip "$name" "no bubblewrap 0.13.1 oracle (ours exit $oc)"
        return
    fi
    ro=$("$REAL" "$@" 2>"$WORK/re" | norm); rc=${PIPESTATUS[0]}; re=$(norm <"$WORK/re")
    [ "$oc" = "$rc" ] || { fail "$name" "exit ours=$oc real=$rc"; return; }
    [ "$oo" = "$ro" ] || { fail "$name" "stdout: ours=[$oo] real=[$ro]"; return; }
    [ "$oe" = "$re" ] || { fail "$name" "stderr: ours=[$oe] real=[$re]"; return; }
    ok "$name"
}

# abx NAME 'TEMPLATE' : TEMPLATE is a shell line with %B for the binary and may
# contain fd redirections. Require ours == real after %B substitution.
abx() {
    local name="$1" tmpl="$2"
    local oo oe oc ro re rc
    oo=$(eval "${tmpl//%B/$OURS}" 2>"$WORK/oe" | norm); oc=${PIPESTATUS[0]}; oe=$(norm <"$WORK/oe")
    if [ "$HAVE_REAL" != 1 ]; then
        skip "$name" "no bubblewrap 0.13.1 oracle (ours exit $oc)"
        return
    fi
    ro=$(eval "${tmpl//%B/$REAL}" 2>"$WORK/re" | norm); rc=${PIPESTATUS[0]}; re=$(norm <"$WORK/re")
    [ "$oc" = "$rc" ] || { fail "$name" "exit ours=$oc real=$rc (oe=$oe re=$re)"; return; }
    [ "$oo" = "$ro" ] || { fail "$name" "stdout: ours=[$oo] real=[$ro]"; return; }
    [ "$oe" = "$re" ] || { fail "$name" "stderr: ours=[$oe] real=[$re]"; return; }
    ok "$name"
}

# inv NAME WANTEXIT SUBSTR -- ARGS... : ours-only invariant.
inv() {
    local name="$1" wantc="$2" substr="$3"; shift 4
    local out c
    out=$("$OURS" "$@" 2>&1); c=$?
    [ "$c" = "$wantc" ] || { fail "$name" "exit ours=$c want=$wantc (out: $out)"; return; }
    [ -z "$substr" ] || [[ "$out" == *"$substr"* ]] || { fail "$name" "missing [$substr] in: $out"; return; }
    ok "$name"
}

# invx NAME WANTEXIT SUBSTR 'TEMPLATE' : ours-only, template form (for fds).
invx() {
    local name="$1" wantc="$2" substr="$3" tmpl="$4"
    local out c
    out=$(eval "${tmpl//%B/$OURS}" 2>&1); c=$?
    [ "$c" = "$wantc" ] || { fail "$name" "exit ours=$c want=$wantc (out: $out)"; return; }
    [ -z "$substr" ] || [[ "$out" == *"$substr"* ]] || { fail "$name" "missing [$substr] in: $out"; return; }
    ok "$name"
}

# ab0 / abx0: like ab / abx, but ALSO require exit 0 from both binaries. A "yes
# form" must actually succeed and observe the option's effect; otherwise a case
# that fails identically in both (a malformed command, or a mutant that drops the
# option so it errors out) would pass as "they agree". Use ab0/abx0 for yes forms
# and keep ab/abx/inv for guardrails that expect a specific non-zero exit.
ab0() {
    local name="$1"; shift 2
    local oo oe oc ro re rc
    oo=$("$OURS" "$@" 2>"$WORK/oe" | norm); oc=${PIPESTATUS[0]}; oe=$(norm <"$WORK/oe")
    if [ "$HAVE_REAL" != 1 ]; then skip "$name" "no bubblewrap 0.13.1 oracle (ours exit $oc)"; return; fi
    ro=$("$REAL" "$@" 2>"$WORK/re" | norm); rc=${PIPESTATUS[0]}; re=$(norm <"$WORK/re")
    [ "$oc" = "$rc" ] || { fail "$name" "exit ours=$oc real=$rc"; return; }
    [ "$oo" = "$ro" ] || { fail "$name" "stdout: ours=[$oo] real=[$ro]"; return; }
    [ "$oe" = "$re" ] || { fail "$name" "stderr: ours=[$oe] real=[$re]"; return; }
    [ "$rc" = 0 ] || { fail "$name" "yes-form must succeed but exit=$rc (err=$re)"; return; }
    ok "$name"
}
abx0() {
    local name="$1" tmpl="$2"
    local oo oe oc ro re rc
    oo=$(eval "${tmpl//%B/$OURS}" 2>"$WORK/oe" | norm); oc=${PIPESTATUS[0]}; oe=$(norm <"$WORK/oe")
    if [ "$HAVE_REAL" != 1 ]; then skip "$name" "no bubblewrap 0.13.1 oracle (ours exit $oc)"; return; fi
    ro=$(eval "${tmpl//%B/$REAL}" 2>"$WORK/re" | norm); rc=${PIPESTATUS[0]}; re=$(norm <"$WORK/re")
    [ "$oc" = "$rc" ] || { fail "$name" "exit ours=$oc real=$rc (oe=$oe re=$re)"; return; }
    [ "$oo" = "$ro" ] || { fail "$name" "stdout: ours=[$oo] real=[$ro]"; return; }
    [ "$oe" = "$re" ] || { fail "$name" "stderr: ours=[$oe] real=[$re]"; return; }
    [ "$rc" = 0 ] || { fail "$name" "yes-form must succeed but exit=$rc (err=$re)"; return; }
    ok "$name"
}

# ---- fixtures -------------------------------------------------------------
printf '\x06\x00\x00\x00\x00\x00\xff\x7f' > "$WORK/allow.bpf"   # RET ALLOW
python3 - "$WORK/deny.bpf" <<'PY'
import struct,sys
LD=0x20;JEQ=0x15;RET=0x06;ARCH=0xC000003E
prog=[(LD,0,0,4),(JEQ,0,5,ARCH),(LD,0,0,0),(JEQ,2,0,83),(JEQ,1,0,258),
      (RET,0,0,0x7fff0000),(RET,0,0,0x00050001),(RET,0,0,0)]
open(sys.argv[1],'wb').write(b''.join(struct.pack('<HBBI',*p) for p in prog))
PY
printf 'hello-from-fd\n' > "$WORK/data.txt"
printf -- '--setenv\0AFD\0yes\0/bin/sh\0-c\0echo $AFD\0' > "$WORK/args.nul"
# A uniquely-named command, reachable only through a PATH set in the sandbox env
# (its dir is bound at /cbin, which is not on the host PATH). Resolving it tests
# that the command search uses the sandbox PATH, like execvp — the flatpak bug.
mkdir -p "$WORK/cbin"; printf '#!/bin/sh\necho CUSTOM-PATH-OK\n' > "$WORK/cbin/zzconform"; chmod +x "$WORK/cbin/zzconform"
printf '%s\0' --setenv X Y > "$WORK/argsx.nul"       # a passed-fd whose fd must not leak
mkdir -p "$WORK/real"; ln -sfn real "$WORK/link"      # logical-cwd ($PWD) via a symlink
# Overlay layers (sources must be HOST paths) and a pre-created lock file, for
# the overlay/lock "yes form" cases that actually exercise the success path.
mkdir -p "$WORK"/ov/{low,low2,up,work}
printf 'from-lower\n'  > "$WORK/ov/low/f"
printf 'from-lower2\n' > "$WORK/ov/low2/g"
: > "$WORK/lock"
host_ipc=$(readlink /proc/self/ns/ipc 2>/dev/null)   # for the ipc-isolation observation

echo "Running conformance matrix (HAVE_REAL=$HAVE_REAL)..."

# === meta / args / env ====================================================
ab  version          -- --version
ab  help             -- --help
inv argv0-missing 1 "" -- --argv0
ab  argv0-sets       -- "${BASE[@]}" --argv0 ZZZ /bin/sh -c 'printf %s "$0"'
# An empty argv0 (exec -a '') is printed verbatim in the usage line, as C does
# (C substitutes "bwrap" only for a NULL argv0, which the kernel never delivers).
abx argv0-empty       "(exec -a '' %B --help)"
abx args-from-fd     '%B --args 8 '"$B"' 8<"'"$WORK"'/args.nul"'
invx args-bad-fd 1 "" '%B --args 8 '"$B"' /bin/true'
# Closed stdin is reopened as /dev/null by the Rust runtime (DIFFERENCES.md #9),
# so --args 0 reads EOF (empty args) and succeeds where bubblewrap would fail
# with EBADF. Ours-only invariant pinning the documented behaviour.
invx closed-stdin-args 0 "" '%B --ro-bind / / --args 0 /bin/true 0<&-'
ab  setenv           -- "${BASE[@]}" --setenv FOO bar /bin/sh -c 'echo $FOO'
ab  unsetenv         -- "${BASE[@]}" --unsetenv PATH /bin/sh -c 'echo p=${PATH-unset}'
ab  clearenv         -- "${BASE[@]}" --clearenv --setenv ONLY me /usr/bin/env
# Regression (flatpak): resolve a bare command via the sandbox PATH. bwrap uses
# execvp, whose PATH search reads the environment it installs — not bwrap's own.
# zzconform lives only in /cbin (set as PATH here), so finding it proves the
# search uses the sandbox PATH. This broke every flatpak launch ("execvp smile").
ab  path-search      -- "${BASE[@]}" --ro-bind "$WORK/cbin" /cbin --setenv PATH /cbin zzconform

# === regressions from the C<->Rust parity audit =============================
# Passed fds (--args / --seccomp) must be closed after reading, not leaked into
# the sandbox (bubblewrap.c:1815 / seccomp_program_new); the sandbox fd list
# must then be byte-identical to C.
abx args-fd-noleak    '%B --bind / / --dev /dev --proc /proc --args 9 /bin/sh -c "ls /proc/self/fd" 9<"'"$WORK"'/argsx.nul"'
abx seccomp-fd-noleak '%B --bind / / --dev /dev --proc /proc --seccomp 9 /bin/sh -c "ls /proc/self/fd" 9<"'"$WORK"'/allow.bpf"'
# The Rust runtime forces SIGPIPE to SIG_IGN; bwrap must present the sandboxed
# command the disposition it inherited, as C does. With the usual SIG_DFL a
# broken pipe is silent; a parent that passed SIG_IGN through (`trap '' PIPE`,
# as a CI runner does) must stay ignored, so `yes` prints "Broken pipe" under
# both the port and C. Both ambients are pinned so neither regresses.
ab  sigpipe          -- --bind / / --dev /dev /bin/sh -c 'yes | head -1 >/dev/null; echo ok'
abx sigpipe-ign       "( trap '' PIPE; %B --bind / / --dev /dev /bin/sh -c 'yes | head -1 >/dev/null; echo ok' )"
# A launcher started with SIGCHLD ignored (a common daemon idiom, trap '' CHLD)
# must still reap the sandbox child: C resets SIGCHLD to SIG_DFL at startup, so
# the port does too. Otherwise the monitor hangs/spins and the ignore leaks into
# the command, so the sandboxed SigIgn line would differ from C.
abx sigchld-ign       "( trap '' CHLD; %B --bind / / /bin/sh -c 'grep SigIgn /proc/self/status; exit 7' )"
# A child killed by a real-time signal (which nix's WaitStatus cannot represent)
# must map to 128+signal like C, both with and without a pid namespace, instead
# of hanging the launcher or taking the whole sandbox down.
abx rt-signal         "%B --bind / / /bin/sh -c 'kill -34 \$\$'"
abx rt-signal-pid     "%B --bind / / --unshare-pid /bin/sh -c 'kill -34 \$\$'"
# A data fd reused by a second op must fail with EBADF like C, not silently
# produce an empty second file: the fd is closed after its op.
abx file-fd-reuse     "%B --ro-bind / / --tmpfs /tmp --file 3 /tmp/a --file 3 /tmp/b /bin/sh -c 'wc -c /tmp/a /tmp/b' 3<<<hi"
# Logical cwd: $PWD reached through a symlink is kept (get_current_dir_name),
# not canonicalised to the physical path.
abx cwd-logical       'cd "'"$WORK"'/link" && %B --bind / / --dev /dev /bin/sh -c pwd'
# An empty SELinux label is rejected exactly as C (libselinux writes the NUL).
ab  empty-exec-label -- "${BASE[@]}" --exec-label '' /bin/true
ab  chdir            -- "${BASE[@]}" --chdir /usr /bin/sh -c 'pwd'
ab  chdir-missing    -- "${BASE[@]}" --chdir /no/such /bin/true
ab  level-prefix     -- --level-prefix "${BASE[@]}" --bind /no/such /x /bin/true

# === error grammar / parse guardrails =====================================
ab  unknown-opt      -- --this-is-not-an-option
ab  no-command       -- "${BASE[@]}"

# === binds ================================================================
ab  bind-missing     -- "${BASE[@]}" --bind /no/such /x /bin/true
ab  bind-try         -- "${BASE[@]}" --bind-try /no/such /x /bin/true
ab  robind-missing   -- "${BASE[@]}" --ro-bind /no/such /x /bin/true
ab  robind-try       -- "${BASE[@]}" --ro-bind-try /no/such /x /bin/true
# Regression (#6): a /proc source with a leading double slash must still be
# treated as /proc (bwrap's component-aware has_path_prefix), so its magic link
# is opened directly instead of failing in the in-root resolver.
ab  robind-dslash-proc -- "${BASE[@]}" --tmpfs /t --ro-bind-try //proc/self/ns/user /t/x /bin/sh -c 'test -e /t/x && echo yes || echo no'
ab  robind-is-ro     -- "${BASE[@]}" --ro-bind /usr /u /bin/sh -c 'touch /u/x 2>&1; echo e=$?'
# --dev-bind must make the device USABLE (no nodev), where a plain --bind would
# mount nodev and block device access. Observing the write catches a regression
# that turns --dev-bind into a plain bind (the node type alone would not).
ab  dev-bind         -- "${BASE[@]}" --dev-bind /dev /d /bin/sh -c 'echo x > /d/null 2>&1 && echo ok || echo fail'
ab  dev-bind-try     -- "${BASE[@]}" --dev-bind-try /no/such /x /bin/true
# Regression (glycin): --dev WITHOUT --proc. --dev triggers bwrap's devpts
# "second user namespace" path, which writes a uid/gid map and walks fds after
# the pivot — but this sandbox has no /proc. bwrap reads the kernel overflow ids
# and reaches /proc through a single O_PATH handle opened before the pivot;
# reading /proc by path late aborts here. Every BASE case mounts --proc, so this
# shape (what GNOME's glycin image loaders use) went uncovered.
ab  dev-without-proc -- --unshare-user --dev /dev --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin /usr/bin/true
ab  remount-ro       -- "${BASE[@]}" --tmpfs /t --remount-ro /t /bin/sh -c 'touch /t/f 2>&1; echo e=$?'

# === fs construction ======================================================
ab  symlink          -- "${BASE[@]}" --symlink /usr /u /bin/sh -c 'readlink /u'
# Regression (#8): a mount whose destination inside the new root is a symlink
# must be refused ("Can't mount on symlink destination"), so a symlink can't
# redirect a bind/tmpfs/remount elsewhere. Cover the bind, tmpfs and remount ops.
ab  symlink-dest-bind    -- "${BASE[@]}" --tmpfs /t --symlink /usr /t/x --bind /usr /t/x /bin/true
ab  symlink-dest-tmpfs   -- "${BASE[@]}" --tmpfs /t --symlink /usr /t/x --tmpfs /t/x /bin/true
ab  symlink-dest-remount -- "${BASE[@]}" --tmpfs /t --symlink /usr /t/x --remount-ro /t/x /bin/true
ab  dir              -- "${BASE[@]}" --dir /made /bin/sh -c 'test -d /made && echo yes'
ab  tmpfs            -- "${BASE[@]}" --tmpfs /t /bin/sh -c 'test -d /t && echo yes'
ab  perms-dir        -- "${BASE[@]}" --perms 0750 --dir /d /bin/sh -c 'stat -c %a /d'
ab  size-no-tmpfs    -- "${BASE[@]}" --size 4096 /bin/true
ab  chmod            -- "${BASE[@]}" --dir /d --chmod 0700 /d /bin/sh -c 'stat -c %a /d'
# A failing --chmod prints the mode with C's %#o formatting (0700, 0), not Rust's
# {:#o} (0o700, 0o0).
ab  chmod-ro-msg     -- --ro-bind / / --chmod 700 /etc true
ab  chmod-zero-msg   -- --ro-bind / / --chmod 0 /etc true
ab0 mqueue           -- "${BASE[@]}" --unshare-ipc --mqueue /q /bin/sh -c 'grep -c " - mqueue " /proc/self/mountinfo'
abx file             '%B '"$B"' --file 8 /f /bin/sh -c "cat /f" 8<"'"$WORK"'/data.txt"'
abx file-bad-fd      '%B '"$B"' --file 8 /f /bin/true'
abx bind-data        '%B '"$B"' --bind-data 8 /c /bin/sh -c "cat /c" 8<"'"$WORK"'/data.txt"'
abx ro-bind-data     '%B '"$B"' --ro-bind-data 8 /c /bin/sh -c "touch /c 2>&1; echo e=\$?" 8<"'"$WORK"'/data.txt"'
ab0 lock-file        -- "${BASE[@]}" --ro-bind "$WORK/lock" /lock --lock-file /lock /bin/sh -c 'echo ran'
# The lock is actually held: a READ lock appears in /proc/locks (ours-only, since
# the holder pid differs from the oracle's). Catches a regression that drops the
# lock while still exiting 0.
inv lock-held 0 'held'  -- "${BASE[@]}" --ro-bind "$WORK/lock" /lock --lock-file /lock /bin/sh -c 'grep -q READ /proc/locks && echo held || echo none'
abx bind-fd          '%B '"$B"' --bind-fd 8 /u /bin/sh -c "test -d /u && echo yes" 8</usr'
abx ro-bind-fd       '%B '"$B"' --ro-bind-fd 8 /u /bin/sh -c "touch /u/x 2>&1; echo e=\$?" 8</usr'
ab  bind-fd-bad      -- "${BASE[@]}" --bind-fd 99 /u /bin/true
ab0 overlay          -- "${BASE[@]}" --overlay-src "$WORK/ov/low" --overlay "$WORK/ov/up" "$WORK/ov/work" /ov /bin/sh -c 'cat /ov/f; touch /ov/n && echo wrote'

# === namespaces: deterministic observable A/B =============================
ab  uts-hostname     -- "${BASE[@]}" --unshare-uts --hostname sandbox /bin/hostname
ab  hostname-no-uts  -- "${BASE[@]}" --hostname nope /bin/true
# Each --hostname is an ordered op, as in bubblewrap: an invalid earlier value is
# still attempted and fails (exit 1), not silently superseded by a valid later
# one. HN is 70 chars, over HOST_NAME_MAX, so sethostname() returns EINVAL.
HN=$(printf 'a%.0s' $(seq 1 70))
ab  hostname-order   -- "${BASE[@]}" --unshare-uts --hostname "$HN" --hostname ok /bin/hostname
ab  net-only-lo      -- "${BASE[@]}" --unshare-net /bin/sh -c 'grep -oE "[a-z0-9]+:" /proc/net/dev | sort'
ab  share-net-ifs    -- "${BASE[@]}" --unshare-all --share-net --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/sbin /sbin --proc /proc /bin/sh -c 'grep -oE "[a-z0-9]+:" /proc/net/dev | sort'
ab  cgroup-root      -- "${BASE[@]}" --unshare-cgroup /bin/sh -c 'cat /proc/self/cgroup'
ab  cgroup-try       -- "${BASE[@]}" --unshare-cgroup-try /bin/true
ab  ipc              -- "${BASE[@]}" --unshare-ipc /bin/true
# ...and it actually isolates: the ipc namespace inode differs from the host's
# (ours-only, since the oracle's inode differs too). Catches a dropped --unshare-ipc.
inv ipc-isolated 0 'isolated' -- "${BASE[@]}" --unshare-ipc /bin/sh -c '[ "$(readlink /proc/self/ns/ipc)" != "'"$host_ipc"'" ] && echo isolated || echo shared'
ab  user-try         -- "${BASE[@]}" --unshare-user-try /bin/true
ab  uid-gid          -- "${BASE[@]}" --uid 0 --gid 0 /bin/sh -c 'id -u; id -g'
# With --dev (the second-user-namespace path) --gid must still map the requested
# gid, not gid 0. Observes id -u/-g so a mutant that maps gid 0 in the inner
# userns is caught (the uid-gid case above uses 0/0 and no --dev).
ab  dev-uid-gid      -- "${BASE[@]}" --dev /dev --uid 5 --gid 7 /bin/sh -c 'id -u; id -g'
ab  as-pid-1         -- "${BASE[@]}" --unshare-pid --as-pid-1 /bin/sh -c 'echo $$'
inv pid-small 0 "small" -- "${BASE[@]}" --unshare-pid /bin/sh -c 'test $$ -lt 50 && echo small'

# === userns / pidns handoff (positive needs live fds; here: guardrails) ===
# Reaching the fd: drop --unshare-user so --userns actually looks at the bad
# number and fails there (with --unshare-user it dies on the incompatibility check
# first — kept as userns-incompat below — so the fd was never the subject). This
# fails before the sandbox fork, so it exits cleanly even with stdout piped.
ab  userns-bad-fd    -- --userns 99 $UJOIN /bin/true
ab  userns-incompat  -- "${BASE[@]}" --userns 99 /bin/true
# --userns2's own bad fd cannot be an A/B case here: --userns2 is applied late, in
# the forked sandbox child, and bubblewrap's (and the port's, faithfully) error
# path there leaves a child holding the inherited stdout, so a piped `ab` capture
# hangs. So this stays at the incompatibility guard (fails before any fork). The
# late-userns2 bad-fd path, and that leaked-child teardown, belong in an in-process
# host test (tracked with #36; the leaked child is an upstream robustness finding).
ab  userns2-bad-fd   -- "${BASE[@]}" --userns 99 --userns2 98 /bin/true
ab  pidns-bad-fd     -- "${BASE[@]}" --unshare-pid --pidns 99 /bin/true
ab  disable-userns   -- "${BASE[@]}" --disable-userns /bin/sh -c 'cat /proc/sys/user/max_user_namespaces'
ab  assert-ok        -- "${BASE[@]}" --disable-userns --assert-userns-disabled /bin/true
ab  assert-fails     -- "${BASE[@]}" --assert-userns-disabled /bin/true

# Positive --userns join: create a user namespace, keep it alive, and join it by
# fd, requiring ours == real. This is inherently environment-dependent (the join
# needs the right kernel + namespace privileges), so it SKIPs gracefully instead
# of failing when the setup cannot be established. No --unshare-user here: it is
# mutually exclusive with --userns.
if command -v unshare >/dev/null 2>&1; then
    # `unshare -U -r sleep` holds a user namespace open (maps the caller to root);
    # $! is the unshare->sleep pid, so /proc/$!/ns/user is the joinable namespace.
    unshare -U -r sleep 20 >/dev/null 2>&1 &
    uns_pid=$!
    # Wait until the uid_map is actually written (the ns/user symlink appears at
    # clone, but joining before `-r` writes the map races and fails).
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        [ -s "/proc/$uns_pid/uid_map" ] && break; sleep 0.05
    done
    if [ -r "/proc/$uns_pid/ns/user" ] \
       && exec 9<"/proc/$uns_pid/ns/user" 2>/dev/null \
       && "$OURS" --userns 9 $UJOIN /bin/true >/dev/null 2>&1; then
        ab userns-join -- --userns 9 $UJOIN /bin/sh -c 'id -u; id -g'
        exec 9<&-
    else
        skip userns-join "cannot establish a joinable user namespace here"
        exec 9<&- 2>/dev/null || true
    fi
    kill "$uns_pid" 2>/dev/null || true
    wait "$uns_pid" 2>/dev/null || true
else
    skip userns-join "unshare/setsid unavailable"
fi

# === seccomp ==============================================================
abx seccomp-allow    '%B --seccomp 9 '"$B"' /bin/true 9<"'"$WORK"'/allow.bpf"'
abx seccomp-deny     '%B --seccomp 9 '"$B"' --tmpfs /w /bin/sh -c "mkdir /w/x 2>&1; echo e=\$?" 9<"'"$WORK"'/deny.bpf"'
abx add-seccomp-fd   '%B --add-seccomp-fd 9 '"$B"' /bin/true 9<"'"$WORK"'/allow.bpf"'
ab  seccomp-bad-fd   -- "${BASE[@]}" --seccomp 99 /bin/true
# Every --add-seccomp-fd must be installed, not just the first (flatpak passes
# several). With an allow-all filter (8) and a mkdir-denying filter (9), mkdir
# must still be blocked and Seccomp_filters must read 2; a mutant that installs
# only the first makes mkdir succeed and the count drop to 1.
abx add-seccomp-fd-two '%B '"$B"' --tmpfs /w --add-seccomp-fd 8 --add-seccomp-fd 9 /bin/sh -c "mkdir /w/x 2>&1; echo e=\$?; grep Seccomp_filters /proc/self/status" 8<"'"$WORK"'/allow.bpf" 9<"'"$WORK"'/deny.bpf"'

# === fds / blocking =======================================================
abx block-fd         '%B --block-fd 8 '"$B"' /bin/true 8<"'"$WORK"'/data.txt"'
abx sync-fd          '%B --sync-fd 8 '"$B"' /bin/true 8<>/dev/null'
ab  userns-block-bad -- "${BASE[@]}" --userns-block-fd 99 /bin/true
invx info-fd 0 '"child-pid"' '%B --info-fd 8 '"$B"' /bin/true 8>"'"$WORK"'/info.json"; cat "'"$WORK"'/info.json"'
invx json-status 0 '"exit-code"' '%B --json-status-fd 8 '"$B"' /bin/true 8>"'"$WORK"'/st.json"; cat "'"$WORK"'/st.json"'
# NOTE: the *blocking* behaviour of --block-fd / --sync-fd / --userns-block-fd
# (the supervisor hand-off: "don't start until I write", "hold the fd for my
# lifetime", "wait for my maps") is deliberately NOT tested here. Proving it needs
# a concurrent writer and a FIFO/EOF rendezvous, and the shell `N<fifo` open
# itself synchronises — which can mask the very read under test or hang the
# deterministic matrix if a reader never appears. It belongs in an in-process host
# test (harness=false, like process_host.rs) where fd and EOF lifetimes are
# controlled precisely. Tracked with #36; see also the --die-with-parent race (#32).

# === caps =================================================================
ab  cap-drop-all     -- "${BASE[@]}" --cap-drop ALL /bin/sh -c 'grep CapEff /proc/self/status'
ab  cap-add-one      -- "${BASE[@]}" --cap-drop ALL --cap-add CAP_SYS_ADMIN /bin/sh -c 'grep CapEff /proc/self/status'
ab  cap-bad-name     -- "${BASE[@]}" --cap-add NOT_A_CAP /bin/true
# The bounding set must stay empty after the second unshare(CLONE_NEWUSER) that
# --dev and --disable-userns trigger (that unshare restores CapBnd, so it must be
# re-dropped). cap-drop-all above only greps CapEff, which the re-restore does
# not change. Both paths must show CapBnd all-zero.
ab  capbnd-dev       -- "${BASE[@]}" --dev /dev /bin/sh -c 'grep CapBnd /proc/self/status'
ab  capbnd-disable-userns -- "${BASE[@]}" --disable-userns /bin/sh -c 'grep CapBnd /proc/self/status'

# === session / misc =======================================================
ab  new-session      -- "${BASE[@]}" --new-session /bin/sh -c 'echo ok'
# --new-session must actually setsid (its reason to exist: TIOCSTI protection),
# so the sandboxed process is a session leader (its session id equals its pid).
# The plain new-session case above runs echo and cannot tell setsid apart.
ab  new-session-setsid -- "${BASE[@]}" --new-session /bin/sh -c 'read -r a b c d e f g </proc/self/stat; [ "$f" = "$a" ] && echo session-leader || echo NOT-session-leader'
# The sandboxed command must run with the launcher's umask restored, not the 0
# bwrap uses during setup. Run under umask 027 so a mutant that skips the restore
# (child umask 0000) is caught; a hard-coded 0022 would not prove the restore.
abx umask-preserved  "( umask 027; %B $B /bin/sh -c umask )"
ab  die-with-parent  -- "${BASE[@]}" --die-with-parent /bin/true
ab  not-a-boundary   -- "${BASE[@]}" --not-a-security-boundary /bin/true

# === overlayfs (oracle decides; both fail identically if kernel lacks it) =
ab0 ro-overlay       -- "${BASE[@]}" --overlay-src "$WORK/ov/low" --overlay-src "$WORK/ov/low2" --ro-overlay /ov /bin/sh -c 'cat /ov/f /ov/g; touch /ov/x 2>&1; echo e=$?'
ab0 tmp-overlay      -- "${BASE[@]}" --overlay-src "$WORK/ov/low" --tmp-overlay /ov /bin/sh -c 'cat /ov/f; touch /ov/n && echo wrote'
# Overlapping lowerdirs: bubblewrap's error prints the destination as "(null)"
# (it formats op->dest after advancing op onto an overlay-src entry); match it
# byte-for-byte, including that quirk.
ab  overlay-overlap  -- --unshare-user --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --overlay-src /usr --overlay-src /usr --ro-overlay /mnt /bin/true

# === security invariants (ours-only; module-11 review regressions) ========
inv nnp-set       0 "NoNewPrivs:	1" -- "${BASE[@]}" /bin/sh -c 'grep NoNewPrivs /proc/self/status'
inv dev-has-null  0 "yes"            -- "${BASE[@]}" --dev /dev /bin/sh -c 'test -c /dev/null && echo yes'
invx info-fd-leak 2 "No such file" '%B --info-fd 7 '"$B"' /bin/sh -c "ls /proc/self/fd/7" 7>/dev/null'
invx sync-fd-leak 2 "No such file" '%B --sync-fd 8 '"$B"' /bin/sh -c "ls /proc/self/fd/8" 8<>/dev/null'
# The --json-status-fd must be closed in the child too, or the sandboxed command
# inherits it and can forge {"exit-code": …} to the supervisor. The info-fd/
# sync-fd leak guards above did not cover this fd.
invx json-status-fd-leak 2 "No such file" '%B --json-status-fd 7 '"$B"' /bin/sh -c "ls /proc/self/fd/7" 7>/dev/null'
# bwrap's close_ops_fd: the source fd of --file / --bind-data / --bind-fd must
# NOT leak into the sandbox (regression guard for the op-fd-leak fix).
invx file-fd-leak      2 "No such file" '%B --file 7 /f '"$B"' /bin/sh -c "ls /proc/self/fd/7" 7<"'"$WORK"'/data.txt"'
invx bind-data-fd-leak 2 "No such file" '%B --bind-data 7 /bd '"$B"' /bin/sh -c "ls /proc/self/fd/7" 7<"'"$WORK"'/data.txt"'
invx bind-fd-leak      2 "No such file" '%B --bind-fd 7 /bf '"$B"' /bin/sh -c "ls /proc/self/fd/7" 7<"'"$WORK"'"'

# Regression (#2, ours-only): if the launcher fails before releasing the child
# (here an --info-fd write to a full fd makes the launcher exit 1), the child
# must NOT run the command — no stray, unmonitored sandbox process. bwrap-rs
# exits the child on EOF; bubblewrap would instead leave it blocked forever, so
# this is an ours-only invariant, not an A/B case.
noexec_marker="$WORK/noexec.marker"; rm -f "$noexec_marker"
timeout 5 "$OURS" --ro-bind / / --bind "$WORK" "$WORK" --info-fd 9 \
    /bin/sh -c "echo ran > '$noexec_marker'" 9>/dev/full >/dev/null 2>&1
nc=$?
if [ "$nc" = 1 ] && [ ! -e "$noexec_marker" ]; then
    ok failed-launch-no-exec
else
    fail failed-launch-no-exec "rc=$nc marker=$([ -e "$noexec_marker" ] && echo present || echo absent)"
fi

# The monitor must not busy-loop: a sleeping sandbox should consume ~no CPU (a
# POLLHUP spin would peg a core). Ours-only resource invariant (B1 regression).
if command -v /usr/bin/time >/dev/null 2>&1; then
    cpu_ok() {
        local name="$1"; shift
        local pct
        pct=$(/usr/bin/time -v "$OURS" "$@" 2>&1 >/dev/null \
              | awk -F': ' '/Percent of CPU/{gsub(/%/,"",$2); print int($2)}')
        if [ -n "$pct" ] && [ "$pct" -lt 25 ]; then ok "$name"
        else fail "$name" "CPU ${pct}% (busy-loop?)"; fi
    }
    cpu_ok no-busy-loop            "${BASE[@]}" /bin/sleep 2
    cpu_ok no-busy-loop-unshare-pid --unshare-pid "${BASE[@]}" /bin/sleep 2
fi

# === SELinux label guardrails (identical whether SELinux on or off) =======
ab  exec-label-bad   -- "${BASE[@]}" --exec-label not_a_valid_label_t /bin/true
ab  file-label-bad   -- "${BASE[@]}" --file-label not_a_valid_label_t --dir /d /bin/true

# ---- report ---------------------------------------------------------------
echo
echo "conformance: $PASS passed, $FAIL failed, $SKIP skipped (of $((PASS+FAIL+SKIP)))"
if [ "$FAIL" -gt 0 ]; then printf '%s\n' "${FAILED[@]}"; exit 1; fi
# Strict by default: cases that were skipped for lack of a real oracle were NOT
# compared, so claiming "byte-identical" would be dishonest. Only print the pass
# banner when every case actually ran; otherwise report INCOMPLETE and exit 3,
# unless the caller opts into an oracle-less smoke run with ALLOW_NO_ORACLE=1.
if [ "$SKIP" -gt 0 ] && [ "${ALLOW_NO_ORACLE:-0}" != 1 ]; then
    echo "INCOMPLETE — $SKIP case(s) not compared (no bubblewrap 0.13.1 oracle at REAL=$REAL)."
    echo "Set REAL to a real 0.13.1 oracle, or ALLOW_NO_ORACLE=1 to accept an ours-only smoke run."
    exit 3
fi
if [ "$SKIP" -gt 0 ]; then
    echo "OURS-ONLY SMOKE — $PASS invariant(s) held; $SKIP case(s) NOT compared (ALLOW_NO_ORACLE=1)."
    exit 0
fi
echo "ALL PASS — every case byte-identical to bubblewrap 0.13.1 at REAL=$REAL"
