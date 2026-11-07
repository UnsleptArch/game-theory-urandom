#!/bin/bash
# Fix config: identical guest image/kernel and identical poisoned sources
# (RDRAND, virtio-rng, no NIC) as scripts/launch-attack.sh, but the
# gt_urandom module is loaded (gt=1) and a trusted seed is injected via
# QEMU fw_cfg (opt/seed) -- the one channel outside the simulated
# hypervisor's reach. The module distrusts RDRAND/virtio-rng by policy and
# seeds the CRNG from the fw_cfg blob instead, so each boot should (and,
# unlike the attack config, is *expected* to) produce a different key.
#
# No -icount/rr determinism trickery is needed here, because this script
# isn't trying to prove reproducibility -- it's trying to prove the
# opposite: that the result is unpredictable to an attacker who only
# controls RDRAND/virtio-rng/timing.
#
# Usage: scripts/launch-fix.sh [N]   (N = number of independent boots to
# run; default 3). Set GT_POISON_RDRAND to match the attack config's
# attacker-chosen seed (same attacker, same tricks, module loaded this time).
set -e
R=$(cd "$(dirname "$0")/.." && pwd)
QEMU="$R/build/qemu-src/build-out/qemu-system-x86_64"
N="${1:-3}"
TMO="${TMO:-30}"

[ -f "$R/build/fixed-rng.bin" ] || head -c 4096 /dev/zero | tr '\0' 'A' > "$R/build/fixed-rng.bin"

export GT_POISON_RDRAND="${GT_POISON_RDRAND:-deadbeefcafef00d}"
echo "GT: attacker-chosen RDRAND seed = $GT_POISON_RDRAND (same attacker as the attack config)"

keys=()
for i in $(seq 1 "$N"); do
  # A fresh random seed blob per boot models a real provisioning/
  # attestation system handing each VM its own trusted material -- not the
  # attacker-controlled RDRAND/virtio-rng/timing channels above.
  SEED="$R/build/seed-$i.bin"
  head -c 32 /dev/urandom > "$SEED"
  OUT=$(mktemp)
  timeout "$TMO" "$QEMU" \
    -machine q35 -cpu qemu64,+rdrand -m 512 -smp 1 -accel tcg -icount shift=6,sleep=off \
    -kernel "$R/build/linux-src/arch/x86/boot/bzImage" \
    -initrd "$R/build/initramfs.cpio.gz" \
    -append "console=ttyS0 panic=-1 quiet gt=1 ${GT_APPEND}" \
    -display none -no-reboot -nic none \
    -object rng-random,id=rng0,filename="$R/build/fixed-rng.bin" \
    -device virtio-rng-pci,rng=rng0 \
    -fw_cfg name=opt/seed,file="$SEED" \
    -serial file:"$OUT" ${GT_QEMU_EXTRA} >/dev/null 2>&1
  echo -n "boot $i: "
  line=$(grep -E "GT-HOSTKEY" "$OUT") || { echo "(no key -- boot failed, see $OUT)"; rm -f "$OUT"; exit 1; }
  echo "$line"
  keys+=("$line")
  rm -f "$OUT"
done

all_same=1
for ((i = 1; i < ${#keys[@]}; i++)); do
  [ "${keys[i]}" = "${keys[0]}" ] || all_same=0
done
if [ "$all_same" = 1 ]; then
  echo "GT: VERDICT -- all $N boots produced the SAME key (unexpected for the fix config!)" >&2
  exit 1
else
  echo "GT: VERDICT -- keys DIFFER across boots (fix succeeded)"
fi
