#!/bin/bash
# Builds build/ssh-initramfs.cpio.gz: Alpine/busybox base + toolage/guest/overlay-ssh/
# (networking + real sshd, not just ssh-keygen+poweroff) + the demo
# operator's public key baked in as /root/.ssh's authorized key.
set -e
R=$(cd "$(dirname "$0")/../.." && pwd)
S=$R/build/stage-ssh
rm -rf "$S"; mkdir -p "$S"
(cd "$R/toolage/guest/rootfs" && tar -c --exclude=./bin/bbsuid .) | tar -x -C "$S"
cp -a "$R/toolage/guest/overlay-ssh/." "$S/"
mkdir -p "$S/opt"
[ -f "$R/build/demo-ssh/id_ed25519.pub" ] || { echo "run: ssh-keygen -t ed25519 -N '' -f build/demo-ssh/id_ed25519" >&2; exit 1; }
cp "$R/build/demo-ssh/id_ed25519.pub" "$S/opt/demo-authorized_keys"
(cd "$S" && find . | cpio -o -H newc --quiet | gzip -1) > "$R/build/ssh-initramfs.cpio.gz"
ls -lh "$R/build/ssh-initramfs.cpio.gz"
