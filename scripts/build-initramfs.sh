#!/bin/bash
# Pack guest/rootfs + guest/overlay (+ module if built) into build/initramfs.cpio.gz
set -e
R=$(cd "$(dirname "$0")/.." && pwd)
S=$R/build/stage
rm -rf "$S"; mkdir -p "$S"
(cd "$R/guest/rootfs" && tar -c --exclude=./bin/bbsuid .) | tar -x -C "$S"
cp -a "$R/guest/overlay/." "$S/"
mkdir -p "$S/lib/modules"
# gt_urandom_rs.ko (Rust) is the module the demo actually loads; the C
# module (kernel-module/gt_urandom.c) stays in the repo as the original
# reference implementation but isn't packed in anymore.
[ -f "$R/kernel-module-rust/gt_urandom_rs.ko" ] && cp "$R/kernel-module-rust/gt_urandom_rs.ko" "$S/lib/modules/"
(cd "$S" && find . | cpio -o -H newc --quiet | gzip -1) > "$R/build/initramfs.cpio.gz"
