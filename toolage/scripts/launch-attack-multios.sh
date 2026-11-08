#!/bin/bash
# "Three different operating systems, one host that already knows all
# three SSH host keys." Same attacker-controlled sources, same QEMU RDRAND
# patch, same icount record/replay determinism as toolage/scripts/launch-attack.sh
# -- but swaps which real distro's own ssh-keygen binary runs via
# gt_distro= on the kernel cmdline (toolage/guest/overlay-multios/init). Each
# distro gets its own independent recording (changing which distro runs
# changes the executed code path, so one shared recording can't cover
# all three -- same reason a changed GT_POISON_RDRAND invalidates a
# cached recording in launch-attack.sh).
#
# Usage: toolage/scripts/launch-attack-multios.sh [N]  (N = replays per distro
# shown; default 1 -- the general demo already proved repeatability
# exhaustively, this one's claim is breadth across distros, not depth of
# repetition per distro). Set GT_POISON_RDRAND to change the attacker's
# chosen seed.
set -e
R=$(cd "$(dirname "$0")/../.." && pwd)
. "$R/toolage/scripts/lib/style.sh"
QEMU="$R/build/qemu-src/build-out/qemu-system-x86_64"
N="${1:-1}"
TMO="${TMO:-45}"

[ -f "$R/build/multios-initramfs.cpio.gz" ] || "$R/toolage/scripts/build-multios-initramfs.sh"
[ -f "$R/build/fixed-rng.bin" ] || head -c 4096 /dev/zero | tr '\0' 'A' > "$R/build/fixed-rng.bin"

export GT_POISON_RDRAND="${GT_POISON_RDRAND:-deadbeefcafef00d}"
gt_log "seed 0x$GT_POISON_RDRAND, targets: alpine, arch, debian (same kernel)"

for DISTRO in alpine arch debian; do
  RR="$R/build/attack-multios-$DISTRO.rr"
  RR_SEED_STAMP="$RR.seed"
  COMMON=(-machine q35 -cpu max -m 512 -smp 1 -accel tcg
          -kernel "$R/build/linux-src/arch/x86/boot/bzImage"
          -initrd "$R/build/multios-initramfs.cpio.gz"
          -append "console=ttyS0 panic=-1 quiet gt_distro=$DISTRO"
          -display none -no-reboot -nic none
          -rtc base=2024-01-01T00:00:00,clock=vm
          -object rng-random,id=rng0,filename="$R/build/fixed-rng.bin"
          -device virtio-rng-pci,rng=rng0)

  if [ -f "$RR" ] && [ "$(cat "$RR_SEED_STAMP" 2>/dev/null)" != "$GT_POISON_RDRAND" ]; then
    rm -f "$RR"
  fi
  if [ ! -f "$RR" ]; then
    gt_log "[$DISTRO] recording attacker-controlled run"
    OUT="$R/build/attack-multios-$DISTRO-record.log"
    gt_cmd "qemu-system-x86_64 -icount shift=6,rr=record,rrfile=$RR -append gt_distro=$DISTRO"
    timeout "$TMO" "$QEMU" -icount shift=6,rr=record,rrfile="$RR" \
      "${COMMON[@]}" -serial file:"$OUT" >/dev/null 2>&1
    grep -q "GT-HOSTKEY" "$OUT" || { gt_log "[$DISTRO] record run produced no key"; exit 1; }
    echo "$GT_POISON_RDRAND" > "$RR_SEED_STAMP"
  fi

  keys=()
  for i in $(seq 1 "$N"); do
    OUT=$(mktemp)
    gt_cmd "qemu-system-x86_64 -icount shift=6,rr=replay,rrfile=$RR [$DISTRO boot $i]"
    timeout "$TMO" "$QEMU" -icount shift=6,rr=replay,rrfile="$RR" \
      "${COMMON[@]}" -serial file:"$OUT" >/dev/null 2>&1
    line=$(grep "GT-HOSTKEY" "$OUT") || { gt_log "[$DISTRO] replay $i: no key, see $OUT"; exit 1; }
    gt_log "[$DISTRO] boot $i: ${line#GT-HOSTKEY: }"
    keys+=("$line")
    rm -f "$OUT"
  done

  all_same=1
  for ((i = 1; i < ${#keys[@]}; i++)); do
    [ "${keys[i]}" = "${keys[0]}" ] || all_same=0
  done
  if [ "$all_same" = 1 ]; then
    gt_log "[$DISTRO] VERDICT: IDENTICAL across $N boots (host already knew this key)"
  else
    gt_log "[$DISTRO] VERDICT: keys DIFFER (unexpected!)"
    exit 1
  fi
done

gt_log "VERDICT: all three operating systems, same predicted key"
