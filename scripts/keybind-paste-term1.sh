#!/bin/bash
# Bound to Ctrl+Alt+W: copies the Terminal 1 (VM boot) command to the
# clipboard. Press this, click/focus terminal 1, Ctrl+V, Enter.
#
# Currently points at the fix-demo VM (module loaded, gt=1): this is the
# 2nd PoC recording, showing the vulnerability is gone, not the attack
# recording. Swap back to toolage/scripts/open-arch-vm.sh for the attack version.
#
# Why clipboard and not auto-typing the command directly: xdotool (the
# only keystroke-injection tool installed) only sees XWayland-backed
# windows -- confirmed directly, `xdotool getactivewindow` returns
# nothing useful in this native-Wayland KDE session. wl-clipboard's
# clipboard set/get, by contrast, is confirmed working (tested a
# round-trip copy/paste). Clipboard + a manual Ctrl+V is the reliable
# option; silently failing to type into your terminal mid-recording
# would be worse than one extra keystroke.
# Debug trace -- see scripts/keybind-toggle-record.sh's comment for why.
exec >> /tmp/keybind-debug-paste1.log 2>&1
echo "=== $(date -Is) invoked, env: XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR WAYLAND_DISPLAY=$WAYLAND_DISPLAY DISPLAY=$DISPLAY ==="
set -x
echo -n "cd /home/unslept/game-theory-urandom && toolage/scripts/open-arch-vm-fixed.sh" | wl-copy
