#!/bin/bash
# Bound to Ctrl+Alt+Q: toggles a SILENT screen recording via
# gpu-screen-recorder -- no permission dialog, no visible overlay.
#
# Why this instead of Spectacle: Spectacle goes through the
# xdg-desktop-portal screencast path, which needs a one-time interactive
# permission click before it'll record anything -- no hotkey can get
# past that, it's a Wayland security boundary. gpu-screen-recorder
# instead captures straight from KMS/DRM via its gsr-kms-server helper
# (already set up on this system) -- confirmed directly: a test
# recording produced a valid, playable 1920x1080 h264 file with real
# desktop content, with no dialog and no manual click at any point.
#
# First press: starts recording to ~/Videos/demo-<timestamp>.mp4.
# Second press: stops it (SIGINT, which gpu-screen-recorder handles by
# cleanly finalizing the file -- confirmed directly, tested a start/stop
# cycle and the resulting file was valid).
# Debug trace: every invocation (by hotkey or by hand) appends full
# output + a timestamp + the environment it actually ran in to this log.
# If the hotkey "does nothing", check this file -- it'll show whether
# KDE even invoked the script at all, and with what environment
# (XDG_RUNTIME_DIR/WAYLAND_DISPLAY missing would explain silent
# wl-copy/gpu-screen-recorder failures that are invisible otherwise,
# since a hotkey-launched script has no terminal to show errors in).
exec >> /tmp/keybind-debug-record.log 2>&1
echo "=== $(date -Is) invoked, env: XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR WAYLAND_DISPLAY=$WAYLAND_DISPLAY DISPLAY=$DISPLAY ==="
set -x
set -e
PIDFILE="/tmp/gsr-recording.pid"
OUTDIR="$HOME/Videos"
mkdir -p "$OUTDIR"

# No notify-send here on purpose: a toast on screen is a toast in the
# recording, since this is the same screen being captured. Silent by
# design for the real take -- check /tmp/gsr-recording.pid (present while
# recording, removed when stopped) or this script's own debug log if you
# need to confirm state without it showing up on camera.
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  kill -INT "$(cat "$PIDFILE")"
  rm -f "$PIDFILE"
else
  MONITOR=$(gpu-screen-recorder --list-monitors | head -1 | cut -d'|' -f1)
  OUT="$OUTDIR/demo-$(date +%Y%m%d-%H%M%S).mp4"
  gpu-screen-recorder -w "$MONITOR" -f 60 -o "$OUT" >/tmp/gsr.log 2>&1 &
  disown
  echo $! > "$PIDFILE"
fi
