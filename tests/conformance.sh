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

# A minimal read-only sandbox that is identical on any usr-merged distribution:
# bind /usr and recreate the usr-merge symlinks, so the command, its loader and
# its libraries resolve through /usr whether libc lives in /usr/lib64 (Fedora)
# or /usr/lib/<triplet> (Debian/Ubuntu). Deterministic root: bin lib lib64 proc
# sbin usr.
BASE=(--unshare-user --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/sbin /sbin --proc /proc)
if ! "$OURS" "${BASE[@]}" /bin/true >/dev/null 2>&1; then
    echo "SKIP: user namespaces unavailable in this environment"
    exit 0
fi
B="${BASE[*]}"   # space-joined base for template cases

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
    if [ "$HAVE_REAL" = 1 ]; then
        ro=$("$REAL" "$@" 2>"$WORK/re" | norm); rc=${PIPESTATUS[0]}; re=$(norm <"$WORK/re")
        [ "$oc" = "$rc" ] || { fail "$name" "exit ours=$oc real=$rc"; return; }
        [ "$oo" = "$ro" ] || { fail "$name" "stdout: ours=[$oo] real=[$ro]"; return; }
        [ "$oe" = "$re" ] || { fail "$name" "stderr: ours=[$oe] real=[$re]"; return; }
    fi
    ok "$name"
}

# abx NAME 'TEMPLATE' : TEMPLATE is a shell line with %B for the binary and may
# contain fd redirections. Require ours == real after %B substitution.
abx() {
    local name="$1" tmpl="$2"
    local oo oe oc ro re rc
    oo=$(eval "${tmpl//%B/$OURS}" 2>"$WORK/oe" | norm); oc=${PIPESTATUS[0]}; oe=$(norm <"$WORK/oe")
    if [ "$HAVE_REAL" = 1 ]; then
        ro=$(eval "${tmpl//%B/$REAL}" 2>"$WORK/re" | norm); rc=${PIPESTATUS[0]}; re=$(norm <"$WORK/re")
        [ "$oc" = "$rc" ] || { fail "$name" "exit ours=$oc real=$rc (oe=$oe re=$re)"; return; }
        [ "$oo" = "$ro" ] || { fail "$name" "stdout: ours=[$oo] real=[$ro]"; return; }
        [ "$oe" = "$re" ] || { fail "$name" "stderr: ours=[$oe] real=[$re]"; return; }
    fi
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

echo "Running conformance matrix (HAVE_REAL=$HAVE_REAL)..."

# === meta / args / env ====================================================
ab  version          -- --version
ab  help             -- --help
inv argv0-missing 1 "" -- --argv0
ab  argv0-sets       -- "${BASE[@]}" --argv0 ZZZ /bin/sh -c 'printf %s "$0"'
abx args-from-fd     '%B --args 8 '"$B"' 8<"'"$WORK"'/args.nul"'
invx args-bad-fd 1 "" '%B --args 8 '"$B"' /bin/true'
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
# The Rust runtime ignores SIGPIPE; reset to default before exec so a broken
# pipe in the sandbox behaves like C (no spurious "Broken pipe").
ab  sigpipe          -- --bind / / --dev /dev /bin/sh -c 'yes | head -1 >/dev/null; echo ok'
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
ab  dev-bind         -- "${BASE[@]}" --dev-bind /dev /d /bin/sh -c 'test -c /d/null && echo yes'
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
ab  dir              -- "${BASE[@]}" --dir /made /bin/sh -c 'test -d /made && echo yes'
ab  tmpfs            -- "${BASE[@]}" --tmpfs /t /bin/sh -c 'test -d /t && echo yes'
ab  perms-dir        -- "${BASE[@]}" --perms 0750 --dir /d /bin/sh -c 'stat -c %a /d'
ab  size-no-tmpfs    -- "${BASE[@]}" --size 4096 /bin/true
ab  chmod            -- "${BASE[@]}" --dir /d --chmod 0700 /d /bin/sh -c 'stat -c %a /d'
ab  mqueue           -- "${BASE[@]}" --mqueue /q /bin/sh -c 'test -d /q && echo yes || echo no'
abx file             '%B '"$B"' --file 8 /f /bin/sh -c "cat /f" 8<"'"$WORK"'/data.txt"'
abx file-bad-fd      '%B '"$B"' --file 8 /f /bin/true'
abx bind-data        '%B '"$B"' --bind-data 8 /c /bin/sh -c "cat /c" 8<"'"$WORK"'/data.txt"'
abx ro-bind-data     '%B '"$B"' --ro-bind-data 8 /c /bin/sh -c "touch /c 2>&1; echo e=\$?" 8<"'"$WORK"'/data.txt"'
ab  lock-file        -- "${BASE[@]}" --dir /run --lock-file /run/l /bin/true
abx bind-fd          '%B '"$B"' --bind-fd 8 /u /bin/sh -c "test -d /u && echo yes" 8</usr'
abx ro-bind-fd       '%B '"$B"' --ro-bind-fd 8 /u /bin/sh -c "touch /u/x 2>&1; echo e=\$?" 8</usr'
ab  bind-fd-bad      -- "${BASE[@]}" --bind-fd 99 /u /bin/true
ab  overlay          -- "${BASE[@]}" --tmpfs /s --dir /s/up --dir /s/work --overlay-src /usr --overlay /s/up /s/work /ov /bin/sh -c 'ls /ov >/dev/null 2>&1; echo e=$?'

# === namespaces: deterministic observable A/B =============================
ab  uts-hostname     -- "${BASE[@]}" --unshare-uts --hostname sandbox /bin/hostname
ab  hostname-no-uts  -- "${BASE[@]}" --hostname nope /bin/true
ab  net-only-lo      -- "${BASE[@]}" --unshare-net /bin/sh -c 'grep -oE "[a-z0-9]+:" /proc/net/dev | sort'
ab  share-net-ifs    -- "${BASE[@]}" --unshare-all --share-net --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/sbin /sbin --proc /proc /bin/sh -c 'grep -oE "[a-z0-9]+:" /proc/net/dev | sort'
ab  cgroup-root      -- "${BASE[@]}" --unshare-cgroup /bin/sh -c 'cat /proc/self/cgroup'
ab  cgroup-try       -- "${BASE[@]}" --unshare-cgroup-try /bin/true
ab  ipc              -- "${BASE[@]}" --unshare-ipc /bin/true
ab  user-try         -- "${BASE[@]}" --unshare-user-try /bin/true
ab  uid-gid          -- "${BASE[@]}" --uid 0 --gid 0 /bin/sh -c 'id -u; id -g'
ab  as-pid-1         -- "${BASE[@]}" --unshare-pid --as-pid-1 /bin/sh -c 'echo $$'
inv pid-small 0 "small" -- "${BASE[@]}" --unshare-pid /bin/sh -c 'test $$ -lt 50 && echo small'

# === userns / pidns handoff (positive needs live fds; here: guardrails) ===
ab  userns-bad-fd    -- "${BASE[@]}" --userns 99 /bin/true
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
    UJOIN="--ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/sbin /sbin --proc /proc"
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

# === fds / blocking =======================================================
abx block-fd         '%B --block-fd 8 '"$B"' /bin/true 8<"'"$WORK"'/data.txt"'
abx sync-fd          '%B --sync-fd 8 '"$B"' /bin/true 8<>/dev/null'
ab  userns-block-bad -- "${BASE[@]}" --userns-block-fd 99 /bin/true
invx info-fd 0 '"child-pid"' '%B --info-fd 8 '"$B"' /bin/true 8>"'"$WORK"'/info.json"; cat "'"$WORK"'/info.json"'
invx json-status 0 '"exit-code"' '%B --json-status-fd 8 '"$B"' /bin/true 8>"'"$WORK"'/st.json"; cat "'"$WORK"'/st.json"'

# === caps =================================================================
ab  cap-drop-all     -- "${BASE[@]}" --cap-drop ALL /bin/sh -c 'grep CapEff /proc/self/status'
ab  cap-add-one      -- "${BASE[@]}" --cap-drop ALL --cap-add CAP_SYS_ADMIN /bin/sh -c 'grep CapEff /proc/self/status'
ab  cap-bad-name     -- "${BASE[@]}" --cap-add NOT_A_CAP /bin/true

# === session / misc =======================================================
ab  new-session      -- "${BASE[@]}" --new-session /bin/sh -c 'echo ok'
ab  die-with-parent  -- "${BASE[@]}" --die-with-parent /bin/true
ab  not-a-boundary   -- "${BASE[@]}" --not-a-security-boundary /bin/true

# === overlayfs (oracle decides; both fail identically if kernel lacks it) =
ab  ro-overlay       -- "${BASE[@]}" --overlay-src /usr --ro-overlay /ov /bin/sh -c 'touch /ov/x 2>&1; echo e=$?'
ab  tmp-overlay      -- "${BASE[@]}" --tmp-overlay /ov --overlay-src /usr /bin/sh -c 'echo done'

# === security invariants (ours-only; module-11 review regressions) ========
inv nnp-set       0 "NoNewPrivs:	1" -- "${BASE[@]}" /bin/sh -c 'grep NoNewPrivs /proc/self/status'
inv dev-has-null  0 "yes"            -- "${BASE[@]}" --dev /dev /bin/sh -c 'test -c /dev/null && echo yes'
invx info-fd-leak 2 "No such file" '%B --info-fd 7 '"$B"' /bin/sh -c "ls /proc/self/fd/7" 7>/dev/null'
invx sync-fd-leak 2 "No such file" '%B --sync-fd 8 '"$B"' /bin/sh -c "ls /proc/self/fd/8" 8<>/dev/null'
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
echo "conformance: $PASS passed, $FAIL failed, $SKIP skipped (of $((PASS+FAIL)))"
if [ "$FAIL" -gt 0 ]; then printf '%s\n' "${FAILED[@]}"; exit 1; fi
echo "ALL PASS — every case byte-identical to /usr/bin/bwrap 0.13.1 (or ours-only invariant held)"
