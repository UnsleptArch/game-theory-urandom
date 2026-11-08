#!/bin/bash
# Builds build/multios-initramfs.cpio.gz: the same Alpine/busybox base as
# the main demo's initramfs, plus the Arch and Debian ssh-keygen binaries
# (+ their own exact shared-library deps, extracted via debootstrap for
# Debian and from this Arch-based host for Arch -- see toolage/guest/multios/ and
# CLAUDE.md for how). toolage/guest/overlay-multios/init picks which one runs via
# gt_distro= on the kernel cmdline. Fingerprinting the resulting key
# (ssh-keygen -lf) always uses Alpine's own busybox ssh-keygen -- reading
# an existing public key file to print its fingerprint doesn't require
# the same binary that generated it.
set -e
R=$(cd "$(dirname "$0")/../.." && pwd)
S=$R/build/stage-multios
rm -rf "$S"; mkdir -p "$S"
(cd "$R/toolage/guest/rootfs" && tar -c --exclude=./bin/bbsuid .) | tar -x -C "$S"
cp -a "$R/toolage/guest/overlay-multios/." "$S/"
mkdir -p "$S/opt/arch" "$S/opt/debian"
cp -a "$R/toolage/guest/multios/arch/." "$S/opt/arch/"
cp -a "$R/toolage/guest/multios/debian/." "$S/opt/debian/"
(cd "$S" && find . | cpio -o -H newc --quiet | gzip -1) > "$R/build/multios-initramfs.cpio.gz"
ls -lh "$R/build/multios-initramfs.cpio.gz"
