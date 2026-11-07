#!/bin/bash
# Pack guest/rootfs + guest/overlay (+ module if built) into build/initramfs.cpio.gz
set -e
R=$(cd "$(dirname "$0")/.." && pwd)
S=$R/build/stage
rm -rf "$S"; mkdir -p "$S"
(cd "$R/guest/rootfs" && tar -c --exclude=./bin/bbsuid .) | tar -x -C "$S"
cp -a "$R/guest/overlay/." "$S/"
mkdir -p "$S/lib/modules"
[ -f "$R/kernel-module/gt_urandom.ko" ] && cp "$R/kernel-module/gt_urandom.ko" "$S/lib/modules/"
(cd "$S" && find . | cpio -o -H newc --quiet | gzip -1) > "$R/build/initramfs.cpio.gz"
