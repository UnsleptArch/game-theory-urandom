# Shared console output helpers, sourced by toolage/scripts/launch-*.sh and
# toolage/scripts/demo.sh. Cosmetic only -- doesn't touch verification logic.
# Minimal on purpose: every status line is "[*] ..."; the only thing that
# gets color is the actual command being executed, so it's visually clear
# which lines are real commands vs. narration. Degrades to plain text if
# stdout isn't a terminal (tput returns empty codes then).
if [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  C_RED=$(tput setaf 1); C_GREEN=$(tput setaf 2); C_RST=$(tput sgr0)
else
  C_RED=""; C_GREEN=""; C_RST=""
fi

gt_log() { printf '[*] %s\n' "$1"; }
gt_cmd() { printf '%s[*] $ %s%s\n' "$C_RED" "$1" "$C_RST"; }
# For scripts that are themselves "the exploit" end to end (the attack
# and SSH-in demos) -- every status line in red, not just commands.
gt_rlog() { printf '%s[*] %s%s\n' "$C_RED" "$1" "$C_RST"; }
# Same idea, green, for scripts that are themselves "the fix working"
# end to end -- the defended counterpart to gt_rlog, not a generic
# success color used everywhere.
gt_glog() { printf '%s[*] %s%s\n' "$C_GREEN" "$1" "$C_RST"; }
# A large, impossible-to-miss red block for a failure that should stop a
# recording cold rather than scroll past as one more red status line, or
# worse, fall through silently into steps that assume it worked.
gt_error_banner() {
  printf '%s\n' "$C_RED"
  printf '================================================================\n'
  printf '  ERROR: %s\n' "$1"
  printf '================================================================\n'
  printf '%s\n' "$C_RST"
}
