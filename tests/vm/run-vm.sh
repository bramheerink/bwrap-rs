#!/usr/bin/env bash
# Boot the setuid-role test VM with the host kernel + our initramfs, capture the
# serial console, and report. Powers itself off via sysrq when the tests finish.
set -eu
OUT="${OUT:-/tmp/claude-1000/bwrap-vm}"
KVER="${KVER:-$(uname -r)}"
KERNEL="${KERNEL:-/boot/vmlinuz-$KVER}"
[ -r "$KERNEL" ] || { echo "kernel not readable: $KERNEL"; exit 2; }
[ -r "$OUT/initramfs.gz" ] || { echo "no initramfs; run build-initramfs.sh"; exit 2; }

ACCEL=tcg; [ -w /dev/kvm ] && ACCEL=kvm
timeout "${VM_TIMEOUT:-180}" qemu-system-x86_64 \
    -machine accel=$ACCEL -m "${VM_MEM:-2048}" -smp "${VM_CPUS:-2}" \
    -nographic -no-reboot \
    -kernel "$KERNEL" -initrd "$OUT/initramfs.gz" \
    -append "console=ttyS0 panic=-1 rdinit=/init loglevel=4 random.trust_cpu=on" \
    2>&1 | tee "$OUT/serial.log"
