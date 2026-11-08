#!/bin/bash
# Terminal 1, fix version: opens the VM with gt_urandom_rs loaded (gt=1)
# and a fresh trusted seed injected via fw_cfg, same poisoned RDRAND and
# virtio-rng as the attack version (toolage/scripts/open-arch-vm.sh). Nothing
# else -- no prediction, no SSH, no exploit logic. That's all in
# toolage/scripts/exploit-arch-ssh-fixed.sh (terminal 2), which connects to this
# once it's up. A fresh random seed per boot models real per-VM
# provisioning, same convention as toolage/scripts/launch-fix.sh.
set -e
R=$(cd "$(dirname "$0")/../.." && pwd)
QEMU="$R/build/qemu-src/build-out/qemu-system-x86_64"

[ -f "$R/build/live-initramfs.cpio.gz" ] || "$R/toolage/scripts/build-live-initramfs.sh"
[ -f "$R/build/fixed-rng.bin" ] || head -c 4096 /dev/zero | tr '\0' 'A' > "$R/build/fixed-rng.bin"

SEED="$R/build/live-arch-seed.bin"
head -c 32 /dev/urandom > "$SEED"

export GT_POISON_RDRAND="${GT_POISON_RDRAND:-deadbeefcafef00d}"
rm -f "$R/build/live-arch.log"

exec "$QEMU" \
  -machine q35 -cpu max -m 512 -smp 1 -accel tcg \
  -kernel "$R/build/linux-src/arch/x86/boot/bzImage" \
  -initrd "$R/build/live-initramfs.cpio.gz" \
  -append "console=tty0 console=ttyS0 panic=-1 quiet gt_distro=arch gt=1" \
  -display curses -vga std -no-reboot \
  -netdev user,id=net0,hostfwd=tcp::2252-:22 -device virtio-net-pci,netdev=net0 \
  -object rng-random,id=rng0,filename="$R/build/fixed-rng.bin" \
  -device virtio-rng-pci,rng=rng0 \
  -fw_cfg name=opt/seed,file="$SEED" \
  -serial file:"$R/build/live-arch.log"
