#!/bin/bash
# Bound to Ctrl+Alt+E: copies the Terminal 2 (exploit/SSH) command to the
# clipboard. Press this, click/focus terminal 2, Ctrl+V, Enter.
# See scripts/keybind-paste-term1.sh for why clipboard, not auto-typing.
#
# Currently points at the fix-demo script (prediction fails against the
# loaded module): this is the 2nd PoC recording. Swap back to
# toolage/scripts/exploit-arch-ssh.sh for the attack version.
# Debug trace -- see scripts/keybind-toggle-record.sh's comment for why.
exec >> /tmp/keybind-debug-paste2.log 2>&1
echo "=== $(date -Is) invoked, env: XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR WAYLAND_DISPLAY=$WAYLAND_DISPLAY DISPLAY=$DISPLAY ==="
set -x
echo -n "cd /home/unslept/game-theory-urandom && toolage/scripts/exploit-arch-ssh-fixed.sh" | wl-copy
