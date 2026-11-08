#!/bin/bash
# Builds build/live-initramfs.cpio.gz: Alpine/busybox base +
# toolage/guest/overlay-live/ (networking + sshd + per-distro ssh-keygen, see
# that file for why sshd is Alpine's regardless of gt_distro=) + the
# Arch/Debian ssh-keygen binaries from toolage/guest/multios/ + the demo
# operator's authorized key.
set -e
R=$(cd "$(dirname "$0")/../.." && pwd)
S=$R/build/stage-live
rm -rf "$S"; mkdir -p "$S"
(cd "$R/toolage/guest/rootfs" && tar -c --exclude=./bin/bbsuid .) | tar -x -C "$S"
cp -a "$R/toolage/guest/overlay-live/." "$S/"
mkdir -p "$S/lib/modules"
[ -f "$R/src/gt_urandom_rs/gt_urandom_rs.ko" ] && cp "$R/src/gt_urandom_rs/gt_urandom_rs.ko" "$S/lib/modules/"
mkdir -p "$S/opt"
cp -a "$R/toolage/guest/multios/arch/." "$S/opt/arch/"
cp -a "$R/toolage/guest/multios/debian/." "$S/opt/debian/"
[ -f "$R/build/demo-ssh/id_ed25519.pub" ] || { echo "run: ssh-keygen -t ed25519 -N '' -f build/demo-ssh/id_ed25519" >&2; exit 1; }
cp "$R/build/demo-ssh/id_ed25519.pub" "$S/opt/demo-authorized_keys"
(cd "$S" && find . | cpio -o -H newc --quiet | gzip -1) > "$R/build/live-initramfs.cpio.gz"
ls -lh "$R/build/live-initramfs.cpio.gz"
