#!/bin/bash
# Full demo: boot the attack config N times (module not loaded, expect
# identical SSH host key) and the fix config N times (module loaded, same
# poisoned RDRAND/virtio-rng/no-NIC, expect different keys), then show the
# module's debugfs telemetry from one fix-config boot.
set -e
R=$(cd "$(dirname "$0")/.." && pwd)
N="${1:-3}"

echo "=================================================================="
echo " ATTACK CONFIG: module NOT loaded ($N boots, same poisoned inputs)"
echo "=================================================================="
rm -f "$R/build/attack.rr"
"$R/scripts/launch-attack.sh" "$N"
echo
echo "=================================================================="
echo " FIX CONFIG: gt_urandom module loaded ($N independent boots,"
echo " same poisoned RDRAND/virtio-rng/no-NIC as the attack config)"
echo "=================================================================="
"$R/scripts/launch-fix.sh" "$N"
echo
echo "=================================================================="
echo " gt_urandom telemetry from a fix-config boot"
echo "=================================================================="
GT_QEMU_EXTRA="" TMO=30 bash -c '
R="'"$R"'"
QEMU="$R/build/qemu-src/build-out/qemu-system-x86_64"
head -c 32 /dev/urandom > "$R/build/seed-telemetry.bin"
OUT=$(mktemp)
GT_POISON_RDRAND=deadbeefcafef00d timeout 30 "$QEMU" \
  -machine q35 -cpu qemu64,+rdrand -m 512 -smp 1 -accel tcg -icount shift=0,sleep=off \
  -kernel "$R/build/linux-src/arch/x86/boot/bzImage" \
  -initrd "$R/build/initramfs.cpio.gz" \
  -append "console=ttyS0 panic=-1 quiet gt=1" \
  -display none -no-reboot -nic none \
  -object rng-random,id=rng0,filename="$R/build/fixed-rng.bin" \
  -device virtio-rng-pci,rng=rng0 \
  -fw_cfg name=opt/seed,file="$R/build/seed-telemetry.bin" \
  -serial file:"$OUT" >/dev/null 2>&1
sed -n "/== gt_urandom/,/^GT-HOSTKEY/p" "$OUT"
rm -f "$OUT"
'
