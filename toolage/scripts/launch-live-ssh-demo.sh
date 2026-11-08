#!/bin/bash
# "Beat 2" of the two-beat SSH demo (see CLAUDE.md): a real, fast,
# interactive VM boot with networking and a real sshd -- NOT a re-proof
# of the prediction. Its host key will NOT match whatever "beat 1"
# (toolage/scripts/launch-attack-multios.sh or launch-attack.sh) predicted:
# that's expected, not a bug. This script exists to show the mechanics
# of a real login working (real network stack, real sshd, real pubkey
# auth), as a companion to the headless prediction demo, not a repeat of
# it. -icount deliberately isn't used here: it paces the *entire* QEMU
# process for its whole lifetime (confirmed directly -- a fresh, unrecorded
# SSH connection against an -icount-paced guest hung mid-banner-exchange
# even with a 90s timeout), which is incompatible with a live interactive
# session. Determinism and live interactivity are mutually exclusive with
# this toolset; this script is the live-interactivity half.
#
# Usage: toolage/scripts/launch-live-ssh-demo.sh [port]  (port = host port forwarded
# to the guest's sshd; default 2222). Shows the VM's boot console via
# QEMU's curses UI, right in this terminal (this QEMU build has no
# GTK/SDL UI compiled in -- only none/egl-headless/curses/spice-app are
# available; curses is the one that actually shows a VM console window
# without a rebuild). Once you see "network + login ready" on screen,
# connect FROM ANOTHER TERMINAL with the command this script prints below
# (this one is occupied by the curses UI).
set -e
R=$(cd "$(dirname "$0")/../.." && pwd)
. "$R/toolage/scripts/lib/style.sh"
QEMU="$R/build/qemu-src/build-out/qemu-system-x86_64"
PORT="${1:-2222}"

[ -f "$R/build/ssh-initramfs.cpio.gz" ] || "$R/toolage/scripts/build-ssh-initramfs.sh"
[ -f "$R/build/fixed-rng.bin" ] || head -c 4096 /dev/zero | tr '\0' 'A' > "$R/build/fixed-rng.bin"
[ -f "$R/build/demo-ssh/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -f "$R/build/demo-ssh/id_ed25519" -C demo-operator

export GT_POISON_RDRAND="${GT_POISON_RDRAND:-deadbeefcafef00d}"
gt_log "live boot, no -icount (see this script's header for why)"
gt_log "once the console shows 'network + login ready', connect with:"
gt_cmd "ssh -p $PORT -i $R/build/demo-ssh/id_ed25519 -o UserKnownHostsFile=$R/build/demo-ssh/known_hosts root@127.0.0.1"
rm -f "$R/build/demo-ssh/known_hosts"

"$QEMU" \
  -machine q35 -cpu max -m 512 -smp 1 -accel tcg \
  -kernel "$R/build/linux-src/arch/x86/boot/bzImage" \
  -initrd "$R/build/ssh-initramfs.cpio.gz" \
  -append "console=tty0 panic=-1 quiet" \
  -display curses -vga std -no-reboot \
  -netdev user,id=net0,hostfwd=tcp::"$PORT"-:22 -device virtio-net-pci,netdev=net0 \
  -object rng-random,id=rng0,filename="$R/build/fixed-rng.bin" \
  -device virtio-rng-pci,rng=rng0
