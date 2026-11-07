#!/bin/bash
# Stages kernel-module-rust/gt_urandom_rs.rs into the guest kernel tree as
# an in-tree Rust sample and builds it.
#
# Why in-tree and not an out-of-tree M=... build like kernel-module/Makefile
# does for the C module: Rust-for-Linux's out-of-tree module support is
# still experimental/fragile, while samples/rust/ is the well-supported,
# documented path and we fully control + already rebuild this disposable
# guest kernel tree anyway. The .rs source of truth stays here in the repo
# (build/ is gitignored); this script copies it in and patches the sample
# Kconfig/Makefile idempotently before building.
set -e
R=$(cd "$(dirname "$0")/.." && pwd)
KDIR="$R/build/linux-src"
SRC="$R/kernel-module-rust/gt_urandom_rs.rs"
DST="$KDIR/samples/rust/gt_urandom_rs.rs"
KCONFIG="$KDIR/samples/rust/Kconfig"
MAKEFILE="$KDIR/samples/rust/Makefile"

[ -d "$KDIR" ] || { echo "build.sh: $KDIR not found -- build the guest kernel first" >&2; exit 1; }

cp "$SRC" "$DST"

if ! grep -q "SAMPLE_RUST_GT_URANDOM" "$KCONFIG"; then
  # Insert right after the "if SAMPLES_RUST" line.
  python3 - "$KCONFIG" <<'PYEOF'
import sys
path = sys.argv[1]
s = open(path).read()
marker = "if SAMPLES_RUST\n"
block = marker + """
config SAMPLE_RUST_GT_URANDOM
	tristate "game-theory-urandom entropy-source trust policy"
	help
	  This option builds the gt_urandom_rs sample: a game-theoretic
	  entropy-source trust policy against a hostile hypervisor. See
	  top-level CLAUDE.md in the game-theory-urandom repo.

	  To compile this as a module, choose M here:
	  the module will be called gt_urandom_rs.

	  If unsure, say N.
"""
assert marker in s, "marker not found in Kconfig"
s = s.replace(marker, block, 1)
open(path, "w").write(s)
PYEOF
fi

if ! grep -q "SAMPLE_RUST_GT_URANDOM" "$MAKEFILE"; then
  echo 'obj-$(CONFIG_SAMPLE_RUST_GT_URANDOM)		+= gt_urandom_rs.o' >> "$MAKEFILE"
fi

cd "$KDIR"
scripts/config -e SAMPLES -e SAMPLES_RUST --module SAMPLE_RUST_GT_URANDOM
make olddefconfig >/dev/null

# Rust samples build as part of the normal in-tree `make modules` (the
# Rust build rules aren't wired up for the external-module M=... path).
make -j"$(nproc)" modules 2>&1 | tee "$R/build/kbuild-rust-module.log" | tail -60
ls -la samples/rust/gt_urandom_rs.ko
cp samples/rust/gt_urandom_rs.ko "$R/kernel-module-rust/gt_urandom_rs.ko"
echo "GT: built -> $R/kernel-module-rust/gt_urandom_rs.ko"
