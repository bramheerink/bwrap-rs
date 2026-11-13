#!/bin/sh
# Runs INSIDE the QEMU VM as PID-1's child (root). bubblewrap 0.13.1 has TWO
# privilege paths the host's unprivileged-userns tests never reach:
#   A) setuid (euid != ruid)  -> explicitly REFUSED ("setuid use ... not supported")
#   B) real root (ruid == 0)  -> privileged setup; --cap-add/--cap-drop take effect
#      (this is how rpm-ostree drives bwrap)
# We disable unprivileged user namespaces so neither path can secretly fall back
# to the userns code, then A/B our binary against the real 0.13.1 for both.
set -u
OURS="${OURS:-/usr/bin/bwrap-ours}"
REAL="${REAL:-/usr/bin/bwrap-real}"
TESTDIR="${TESTDIR:-/test}"

# --role=root|setuid|all (default all): lets CI run the root role under sudo and
# the setuid-refusal role as the runner user without a full QEMU VM, while the VM
# still runs everything.
ROLE=all
case "${1:-}" in --role=*) ROLE="${1#--role=}" ;; esac
run_setuid=0; run_root=0
case "$ROLE" in
    all) run_setuid=1; run_root=1 ;;
    setuid) run_setuid=1 ;;
    root) run_root=1 ;;
    *) echo "unknown --role=$ROLE (use root|setuid|all)"; exit 2 ;;
esac

chown root:root "$OURS" "$REAL" 2>/dev/null || true

# Disabling unprivileged userns forces both paths to stay out of the userns code.
# Best-effort: a shared CI runner may forbid the write, in which case the single
# case that depends on it (userns-disabled-msg) is skipped rather than failing.
USERNS_DISABLED=0
if echo 0 > /proc/sys/user/max_user_namespaces 2>/dev/null; then USERNS_DISABLED=1; fi
echo "unprivileged userns limit = $(cat /proc/sys/user/max_user_namespaces 2>/dev/null) (0 = disabled; disabled-here=$USERNS_DISABLED)"

PASS=0; FAIL=0; FAILED=
norm() { sed -e "s#$OURS#BWRAP#g" -e "s#$REAL#BWRAP#g"; }
rec_ok() { PASS=$((PASS+1)); }
rec_no() { FAIL=$((FAIL+1)); FAILED="$FAILED
  [$1] $2"; }

# abx NAME RUNNER ARGS... : compare ours vs real (exit+stdout+stderr), where
# RUNNER is 'root' (run directly, uid 0) or 'user' (drop to uid 1000 via setpriv,
# which turns a setuid binary into the refused setuid case).
abx() {
    name="$1"; who="$2"; shift 2
    if [ "$who" = user ]; then pre="setpriv --reuid=1000 --regid=1000 --clear-groups"; else pre=""; fi
    oo=$($pre $OURS "$@" 2>/tmp/oe); oc=$?; oo=$(printf %s "$oo" | norm); oe=$(norm </tmp/oe)
    ro=$($pre $REAL "$@" 2>/tmp/re); rc=$?; ro=$(printf %s "$ro" | norm); re=$(norm </tmp/re)
    if [ "$oc" != "$rc" ]; then rec_no "$name" "exit ours=$oc real=$rc (oe=$oe|re=$re)"; return; fi
    if [ "$oo" != "$ro" ]; then rec_no "$name" "stdout ours=[$oo] real=[$ro]"; return; fi
    if [ "$oe" != "$re" ]; then rec_no "$name" "stderr ours=[$oe] real=[$re]"; return; fi
    rec_ok
}
# ours-only invariant, run as root.
invr() {
    name="$1"; wantc="$2"; substr="$3"; shift 3
    out=$($OURS "$@" 2>&1); c=$?
    if [ "$c" != "$wantc" ]; then rec_no "$name" "exit=$c want=$wantc ($out)"; return; fi
    if [ -n "$substr" ]; then case "$out" in *"$substr"*) ;; *) rec_no "$name" "missing [$substr]: $out"; return;; esac; fi
    rec_ok
}

BASE="--ro-bind /usr /usr --ro-bind /lib64 /lib64 --ro-bind /bin /bin --proc /proc"

if [ "$run_setuid" = 1 ]; then
echo "--- A) setuid role: must be REFUSED, identically ---"
chmod u+s $OURS $REAL
abx setuid-refused     user $BASE /bin/true
abx setuid-refused-msg user $BASE /bin/sh -c 'echo should-not-run'
chmod u-s $OURS $REAL

if [ "$USERNS_DISABLED" = 1 ]; then
echo "--- B4) non-root + unprivileged userns disabled: the EPERM guidance msg ---"
# A non-setuid, non-root invocation with userns disabled must fail with bwrap's
# debian-hint message (the diagnostic keys off the *resolved* unshare-user flag,
# which main() forces on for a non-root user). This is the only environment where
# that message is observable, so it lives here rather than in conformance.sh.
abx userns-disabled-msg user $BASE /bin/true
else
echo "--- B4) SKIP (could not disable unprivileged userns here) ---"
fi
fi

if [ "$run_root" = 1 ]; then
echo "--- B) real-root privileged role (uid 0, userns disabled), ours vs real ---"
abx root-runs          root $BASE /bin/sh -c 'id -u'
abx root-isolation     root $BASE /bin/sh -c 'ls / | sort | tr "\n" " "'
abx root-dev           root $BASE --dev /dev /bin/sh -c 'test -c /dev/null && echo yes'
abx root-pid           root $BASE --unshare-pid --as-pid-1 /bin/sh -c 'echo $$'
abx root-uts           root $BASE --unshare-uts --hostname vmbox /bin/hostname
abx root-bind          root $BASE --bind /usr /u /bin/sh -c 'test -d /u/bin && echo yes'
abx root-robind-ro     root $BASE --ro-bind /usr /u /bin/sh -c 'touch /u/x 2>&1; echo e=$?'
abx root-tmpfs         root $BASE --tmpfs /t /bin/sh -c 'test -d /t && echo yes'
abx root-uid-drop      root $BASE --uid 1000 --gid 1000 /bin/sh -c 'id -u; id -g'
# bind-data: each binary needs its OWN fd 8 (a shared fd is consumed by the
# first reader), so open it fresh per invocation instead of via abx's shared fd.
if [ -f "$TESTDIR/data.txt" ]; then
oo=$($OURS $BASE --bind-data 8 /c /bin/sh -c 'cat /c' 8<"$TESTDIR/data.txt" 2>/dev/null)
ro=$($REAL $BASE --bind-data 8 /c /bin/sh -c 'cat /c' 8<"$TESTDIR/data.txt" 2>/dev/null)
if [ "$oo" = "$ro" ] && [ "$oo" = "hello-from-fd" ]; then rec_ok; else rec_no root-bind-data "ours=[$oo] real=[$ro]"; fi
fi

echo "--- caps actually take effect in the privileged role ---"
abx root-cap-drop-all  root $BASE --cap-drop ALL /bin/sh -c 'grep CapEff /proc/self/status'
abx root-cap-add-one   root $BASE --cap-drop ALL --cap-add CAP_SYS_ADMIN /bin/sh -c 'grep CapEff /proc/self/status'
abx root-cap-bad       root $BASE --cap-add NOT_A_CAP /bin/true

echo "--- privileged-mode guardrails ---"
abx root-size-tmpfs    root $BASE --size 4096 --tmpfs /t /bin/true
abx root-perms-tmpfs   root $BASE --perms 0700 --tmpfs /t /bin/true

echo "--- seccomp + NNP in the privileged role (ours-only) ---"
if [ -f "$TESTDIR/deny.bpf" ] && [ -f "$TESTDIR/allow.bpf" ]; then
invr root-seccomp-deny  1 "" $BASE --tmpfs /w --seccomp 9 /bin/sh -c 'mkdir /w/x' 9<"$TESTDIR/deny.bpf"
invr root-seccomp-allow 0 "" $BASE --seccomp 9 /bin/true 9<"$TESTDIR/allow.bpf"
fi
invr root-nnp 0 "NoNewPrivs:	1" $BASE /bin/sh -c 'grep NoNewPrivs /proc/self/status'
fi  # run_root

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -gt 0 ] && printf '%s\n' "$FAILED"
[ "$FAIL" -eq 0 ] && echo "VM-RESULT: ALL-PASS" || echo "VM-RESULT: FAIL"
