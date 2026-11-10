#!/usr/bin/env bash
# Build a minimal initramfs that boots under QEMU to exercise bwrap's SETUID-ROOT
# role — the one path the host (with unprivileged userns) and bwrap's own CI never
# test. Inside the VM we install BOTH our binary and the real 0.13.1 setuid-root,
# run as a non-root user with unprivileged userns disabled, and A/B them.
#
# Produces: $OUT/initramfs.gz  (boot with the host kernel; see run-vm.sh)
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OURS="${OURS:?set OURS=/abs/path/to/our/bwrap}"
REAL="${REAL:-/usr/bin/bwrap}"
OUT="${OUT:-/tmp/claude-1000/bwrap-vm}"
ROOT="$OUT/root"
rm -rf "$ROOT"
mkdir -p "$ROOT"/{proc,sys,dev,tmp,etc,run,newroot,test,usr/bin,usr/sbin,usr/lib,usr/lib64}
# usrmerge layout (Fedora): /bin -> usr/bin etc., so /bin/sh, /lib64/ld-* resolve.
ln -s usr/bin   "$ROOT/bin"
ln -s usr/sbin  "$ROOT/sbin"
ln -s usr/lib   "$ROOT/lib"
ln -s usr/lib64 "$ROOT/lib64"

# --- copy a binary and its shared-library closure -------------------------
copy() {
    local src="$1" dst="${2:-$1}"
    [ -e "$src" ] || { echo "missing: $src" >&2; return 1; }
    install -D -m0755 "$src" "$ROOT$dst"
    ldd "$src" 2>/dev/null | grep -oE '/[^ ]+\.so[0-9.]*' | sort -u | while read -r lib; do
        [ -e "$ROOT$lib" ] || install -D -m0755 "$lib" "$ROOT$lib"
    done
}

# binaries under test
copy "$OURS" /usr/bin/bwrap-ours
copy "$REAL" /usr/bin/bwrap-real
# userland the test script needs
for b in bash sh ls cat mkdir rmdir stat id touch grep hostname env readlink \
         sort tr head cut sleep chmod chown mount umount mktemp uname sed wc \
         setpriv dmesg sync cp poweroff; do
    p=$(command -v "$b" 2>/dev/null) && copy "$p" || echo "note: no $b"
done
# true/false are shell builtins, so resolve them by path explicitly.
for b in true false echo; do
    for d in /usr/bin /bin; do [ -x "$d/$b" ] && { copy "$d/$b"; break; }; done
done
# the dynamic linker explicitly (ldd may not list it as a path we catch)
for ld in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux-x86-64.so.2; do
    [ -e "$ld" ] && install -D -m0755 "$ld" "$ROOT$ld"
done

# --- test fixtures (pre-generated on host; no python in the VM) -----------
printf '\x06\x00\x00\x00\x00\x00\xff\x7f' > "$ROOT/test/allow.bpf"
# deny-mkdir BPF (same program as tests/conformance.sh)
python3 - "$ROOT/test/deny.bpf" <<'PY'
import struct,sys
LD=0x20;JEQ=0x15;RET=0x06;ARCH=0xC000003E
prog=[(LD,0,0,4),(JEQ,0,5,ARCH),(LD,0,0,0),(JEQ,2,0,83),(JEQ,1,0,258),
      (RET,0,0,0x7fff0000),(RET,0,0,0x00050001),(RET,0,0,0)]
open(sys.argv[1],'wb').write(b''.join(struct.pack('<HBBI',*p) for p in prog))
PY
printf 'hello-from-fd\n' > "$ROOT/test/data.txt"

# passwd/group so setpriv --reuid has a real unprivileged user
cat > "$ROOT/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
tester:x:1000:1000:tester:/tmp:/bin/sh
EOF
cat > "$ROOT/etc/group" <<'EOF'
root:x:0:
tester:x:1000:
EOF

# the in-VM test driver (committed alongside this script)
install -D -m0755 "$HERE/vm-test.sh" "$ROOT/test/vm-test.sh"

# --- init: PID 1 ----------------------------------------------------------
cat > "$ROOT/init" <<'INIT'
#!/bin/sh
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
mount -t proc     proc /proc     2>/dev/null
mount -t sysfs    sys  /sys       2>/dev/null
mount -t devtmpfs dev  /dev       2>/dev/null || mount -t tmpfs dev /dev
mount -t tmpfs    tmp  /tmp       2>/dev/null
echo
echo "=== VM up: $(uname -sr) ==="
/bin/sh /test/vm-test.sh
echo "=== VM-TEST-DONE ==="
sync
# power off the VM cleanly
echo o > /proc/sysrq-trigger 2>/dev/null
# fallback
exec /sbin/poweroff -f 2>/dev/null || { echo b > /proc/sysrq-trigger; sleep 5; }
INIT
chmod +x "$ROOT/init"

# --- pack -----------------------------------------------------------------
( cd "$ROOT" && find . -print0 | cpio --null -o --format=newc 2>/dev/null ) | gzip -9 > "$OUT/initramfs.gz"
echo "built $OUT/initramfs.gz ($(du -h "$OUT/initramfs.gz" | cut -f1))"
