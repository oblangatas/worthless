#!/usr/bin/env bash
# Does the proxy survive WSL's idle shutdown? (WOR-853)
#
# WSL stops a distro ~15 s after its last Windows-side client (wsl.exe) exits
# (instanceIdleTimeout). systemd and linger do not keep it alive. Every earlier
# CI run kept wsl.exe open, so this was never observed.
#
#   save     run right after the service is installed; records two IDs
#   compare  run after a Windows-only wait with no wsl.exe; re-reads them
#
# boot_id changes when the WSL VM restarts. InvocationID changes when systemd
# starts the unit again. Both unchanged = the proxy survived. Either changed =
# it was restarted, which is NOT survival even if it answers now.
#
# Expects IDLE_EXPECTED=control|fix from the workflow matrix:
#   control  default config -> must have restarted, or the test is blind
#   fix      instanceIdleTimeout=-1 -> must have survived
set -uo pipefail

MODE="${1:?usage: wsl-idle-survival.sh save|compare}"
IDLE_EXPECTED="${IDLE_EXPECTED:?set IDLE_EXPECTED=control|fix}"
USER_NAME=worthless-wsl
STATE="$HOME/wsl-idle-survival.ids"  # on the distro's disk, survives a restart

ids() {
  local uid
  uid=$(id -u "$USER_NAME")
  printf 'boot_id=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
  printf 'invocation=%s\n' "$(runuser -u "$USER_NAME" -- env XDG_RUNTIME_DIR="/run/user/$uid" \
    systemctl --user show -p InvocationID --value worthless-proxy 2>/dev/null)"
}

case "$MODE" in
  save)
    ids | tee "$STATE"
    # An empty InvocationID means the unit is not running; comparing nothing to
    # nothing would read as "survived".
    grep -q '^invocation=.\+' "$STATE" || { echo "FAIL  service not running, nothing to compare"; exit 1; }
    ;;
  compare)
    [ -f "$STATE" ] || { echo "FAIL  no saved IDs (save step did not run)"; exit 1; }
    AFTER=$(ids)
    printf 'before:\n%s\nafter:\n%s\n' "$(cat "$STATE")" "$AFTER"
    if [ "$(cat "$STATE")" = "$AFTER" ]; then OUTCOME=survived; else OUTCOME=restarted; fi
    echo "outcome: $OUTCOME (expected for $IDLE_EXPECTED leg: $([ "$IDLE_EXPECTED" = fix ] && echo survived || echo restarted))"
    if [ "$IDLE_EXPECTED" = fix ] && [ "$OUTCOME" = survived ]; then echo "PASS"; exit 0; fi
    if [ "$IDLE_EXPECTED" = control ] && [ "$OUTCOME" = restarted ]; then echo "PASS"; exit 0; fi
    echo "FAIL"; exit 1
    ;;
  *) echo "unknown mode: $MODE"; exit 2 ;;
esac
