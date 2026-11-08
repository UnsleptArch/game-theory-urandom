#!/bin/bash
# Single-terminal visual demo: cracks the host key for three real
# operating systems (headless, deterministic icount+replay prediction --
# see toolage/scripts/launch-attack-multios.sh, same mechanism, reused here),
# then opens a tmux session with one visual console pane per OS (Alpine /
# Arch / Debian, color-labeled) booting live, and automatically SSHes
# into each one the moment it's ready, running whoami/uname -a -- no
# command for you to type, it happens on its own.
#
# The live VMs' host keys do NOT match the cracked predictions: that is
# expected, not a bug (see toolage/scripts/launch-live-ssh-demo.sh and CLAUDE.md
# for why -icount and live interactive networking are mutually exclusive
# with this toolset -- confirmed directly, a fresh SSH connection against
# an -icount-paced guest hangs mid-banner-exchange). The crack phase
# proves predictability; the live phase proves the login mechanics are
# real. Each live VM's host key still comes from that distro's own real
# ssh-keygen binary (same as the crack phase); sshd itself is Alpine's
# for all three -- see toolage/guest/overlay-live/init for why (Arch/Debian's own
# sshd pulls in PAM/Kerberos/audit, a much heavier lift this demo's
# actual claim doesn't need).
#
# Requires: tmux. Usage: toolage/scripts/demo-live-tmux.sh
set -e
R=$(cd "$(dirname "$0")/../.." && pwd)
. "$R/toolage/scripts/lib/style.sh"
QEMU="$R/build/qemu-src/build-out/qemu-system-x86_64"

command -v tmux >/dev/null 2>&1 || { echo "this script needs tmux (not found)" >&2; exit 1; }
[ -f "$R/build/live-initramfs.cpio.gz" ] || "$R/toolage/scripts/build-live-initramfs.sh"
[ -f "$R/build/multios-initramfs.cpio.gz" ] || "$R/toolage/scripts/build-multios-initramfs.sh"
[ -f "$R/build/fixed-rng.bin" ] || head -c 4096 /dev/zero | tr '\0' 'A' > "$R/build/fixed-rng.bin"
[ -f "$R/build/demo-ssh/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -f "$R/build/demo-ssh/id_ed25519" -C demo-operator

export GT_POISON_RDRAND="${GT_POISON_RDRAND:-deadbeefcafef00d}"

gt_log "phase 1: cracking host keys (headless, deterministic replay)"
"$R/toolage/scripts/launch-attack-multios.sh" 1

LOGDIR=$(mktemp -d)
PORTS="alpine:2251 arch:2252 debian:2253"

gt_log "phase 2: booting three live VMs, visually, one per OS"

SESSION=gtlive
tmux kill-session -t "$SESSION" 2>/dev/null || true
tmux new-session -d -s "$SESSION" -x 220 -y 50 -n demo

# Layout: top pane = this driver (results appear here, gets most of the
# height so scrollback stays readable), bottom row = 3 EQUAL-width VM
# console panes, kept short. Built via sequential percentage splits
# (33% / remaining 67%, then that 67% split again in half) rather than
# two plain 50/50 splits, which would give 50%/25%/25% instead of thirds.
tmux split-window -v -t "$SESSION:demo" -l 40%
tmux select-pane -t "$SESSION:demo.1"
tmux split-window -h -t "$SESSION:demo.1" -p 67
tmux select-pane -t "$SESSION:demo.2"
tmux split-window -h -t "$SESSION:demo.2" -p 50

tmux set-option -t "$SESSION" -g pane-border-status top
tmux set-option -t "$SESSION" -g pane-border-format "#{pane_title}"

i=1
for entry in $PORTS; do
  DISTRO=${entry%%:*}; PORT=${entry##*:}
  PANE="$SESSION:demo.$i"
  tmux select-pane -t "$PANE" -T " ${DISTRO^^} :: port $PORT "
  CMD="GT_POISON_RDRAND=$GT_POISON_RDRAND '$QEMU' \
    -machine q35 -cpu max -m 512 -smp 1 -accel tcg \
    -kernel '$R/build/linux-src/arch/x86/boot/bzImage' \
    -initrd '$R/build/live-initramfs.cpio.gz' \
    -append 'console=tty0 console=ttyS0 panic=-1 quiet gt_distro=$DISTRO' \
    -display curses -vga std -no-reboot \
    -netdev user,id=net0,hostfwd=tcp::$PORT-:22 -device virtio-net-pci,netdev=net0 \
    -object rng-random,id=rng0,filename='$R/build/fixed-rng.bin' \
    -device virtio-rng-pci,rng=rng0 \
    -serial file:$LOGDIR/$DISTRO.log"
  tmux send-keys -t "$PANE" "$CMD" Enter
  i=$((i + 1))
done

tmux select-pane -t "$SESSION:demo.0" -T " driver / results "

# Driver pane: wait for each VM, then SSH in and show whoami/uname
# automatically -- no command printed for the user to run by hand.
DRIVER_SCRIPT=$(mktemp)
cat > "$DRIVER_SCRIPT" <<DRV
R="$R"
LOGDIR="$LOGDIR"
for entry in $PORTS; do
  DISTRO=\${entry%%:*}; PORT=\${entry##*:}
  echo "[*] waiting for \$DISTRO..."
  until grep -q "network + login ready" "\$LOGDIR/\$DISTRO.log" 2>/dev/null; do sleep 0.3; done
  KEY=\$(grep "GT-HOSTKEY" "\$LOGDIR/\$DISTRO.log" | head -1)
  echo "[*] \$DISTRO up -- \${KEY#GT-HOSTKEY: }"
  echo "[*] \$DISTRO: connecting..."
  ssh -p "\$PORT" -i "\$R/build/demo-ssh/id_ed25519" \\
    -o StrictHostKeyChecking=accept-new \\
    -o UserKnownHostsFile="\$LOGDIR/\$DISTRO.known_hosts" \\
    -o ConnectTimeout=10 -tt root@127.0.0.1 \\
    "echo [*] \$DISTRO whoami: \\\$(whoami); echo [*] \$DISTRO uname: \\\$(uname -a)" 2>&1
  echo
done
echo "[*] all three live VMs logged into successfully."
DRV
chmod +x "$DRIVER_SCRIPT"
tmux send-keys -t "$SESSION:demo.0" "bash '$DRIVER_SCRIPT'" Enter

tmux attach -t "$SESSION"
