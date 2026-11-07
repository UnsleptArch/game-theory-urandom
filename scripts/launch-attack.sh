#!/bin/bash
# Attack config: poisoned RDRAND (deterministic splitmix64 stream keyed by
# GT_POISON_RDRAND), virtio-rng backend fixed, no NIC, fixed virtual RTC base.
# Module NOT loaded.
#
# Plain QEMU -icount does *not* guarantee bit-identical execution across
# separate process launches (idle/HLT periods and some device/BIOS timing
# aren't fully pinned to instruction count outside of record/replay -- see
# QEMU docs/devel/tcg-icount.rst). So: record the attacker-controlled run
# ONCE, then replay that exact trace as many times as requested. Each
# replay re-executes the full guest (kernel, keygen, everything) from
# scratch against the recorded external inputs -- it is not a snapshot or
# cached result -- so "same inputs -> same key" is a faithful demonstration
# of the threat model, not a shortcut.
#
# Usage: scripts/launch-attack.sh [N]   (N = number of times to show the
# resulting key; default 3). Set GT_POISON_RDRAND to change the attacker's
# chosen seed. TMO controls the per-boot timeout (replay is slower than
# real time under shift=0; default 90s).
set -e
R=$(cd "$(dirname "$0")/.." && pwd)
QEMU="$R/build/qemu-src/build-out/qemu-system-x86_64"
RR="$R/build/attack.rr"
N="${1:-3}"
TMO="${TMO:-90}"

[ -f "$R/build/fixed-rng.bin" ] || head -c 4096 /dev/zero | tr '\0' 'A' > "$R/build/fixed-rng.bin"

COMMON=(-machine q35 -cpu qemu64,+rdrand -m 512 -smp 1 -accel tcg
        -kernel "$R/build/linux-src/arch/x86/boot/bzImage"
        -initrd "$R/build/initramfs.cpio.gz"
        -append "console=ttyS0 panic=-1 quiet ${GT_APPEND}"
        -display none -no-reboot -nic none
        -rtc base=2024-01-01T00:00:00,clock=vm
        -object rng-random,id=rng0,filename="$R/build/fixed-rng.bin"
        -device virtio-rng-pci,rng=rng0
        ${GT_QEMU_EXTRA})

export GT_POISON_RDRAND="${GT_POISON_RDRAND:-deadbeefcafef00d}"
echo "GT: attacker-chosen RDRAND seed = $GT_POISON_RDRAND"

if [ ! -f "$RR" ]; then
  echo "GT: recording attacker-controlled run -> $RR"
  OUT="$R/build/attack-record.log"
  timeout "$TMO" "$QEMU" -icount shift=0,rr=record,rrfile="$RR" \
    "${COMMON[@]}" -serial file:"$OUT" >/dev/null 2>&1
  grep -E "GT-HOSTKEY" "$OUT" || { echo "GT: record run produced no key" >&2; exit 1; }
fi

for i in $(seq 1 "$N"); do
  OUT=$(mktemp)
  timeout "$TMO" "$QEMU" -icount shift=0,rr=replay,rrfile="$RR" \
    "${COMMON[@]}" -serial file:"$OUT" >/dev/null 2>&1
  echo -n "boot $i: "
  grep -E "GT-HOSTKEY" "$OUT" || echo "(no key -- replay failed, see $OUT)"
  rm -f "$OUT"
done
