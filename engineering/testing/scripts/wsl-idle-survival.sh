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
# Expects IDLE_EXPECTED=control|fix|restart from the workflow matrix:
#   control  default config -> must have restarted, or the test is blind
#   fix      instanceIdleTimeout=-1 -> must have survived
#   restart  the distro was deliberately stopped and started again (the closest
#            thing to a reboot that CI can do). Here a CHANGED boot_id is the
#            point, not a failure: what is under test is whether the proxy comes
#            back by itself afterwards, with nobody starting it.
set -uo pipefail

MODE="${1:?usage: wsl-idle-survival.sh save|compare}"
IDLE_EXPECTED="${IDLE_EXPECTED:?set IDLE_EXPECTED=control|fix|restart}"
USER_NAME=worthless-wsl
PORT=8787
STATE="$HOME/wsl-idle-survival.ids"  # on the distro's disk, survives a restart

inv() {
  local uid
  uid=$(id -u "$USER_NAME")
  runuser -u "$USER_NAME" -- env XDG_RUNTIME_DIR="/run/user/$uid" \
    systemctl --user show -p InvocationID --value worthless-proxy 2>/dev/null
}

ids() {
  printf 'boot_id=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
  printf 'invocation=%s\n' "$(inv)"
}

field() { printf '%s\n' "$2" | sed -n "s/^$1=//p"; }

case "$MODE" in
  save)
    ids | tee "$STATE"
    # An empty InvocationID means the unit is not running; comparing nothing to
    # nothing would read as "survived".
    grep -q '^invocation=.\+' "$STATE" || { echo "FAIL  service not running, nothing to compare"; exit 1; }
    ;;
  compare)
    [ -f "$STATE" ] || { echo "FAIL  no saved IDs (save step did not run)"; exit 1; }
    # A freshly started distro needs a moment for the user manager to come up.
    # Waiting cannot manufacture a pass: a unit that never starts still fails.
    if [ "$IDLE_EXPECTED" = restart ]; then
      for _ in $(seq 30); do [ -n "$(inv)" ] && break; sleep 1; done
    fi
    AFTER=$(ids)
    printf 'before:\n%s\nafter:\n%s\n' "$(cat "$STATE")" "$AFTER"

    if [ "$IDLE_EXPECTED" = restart ]; then
      BOOT_BEFORE=$(field boot_id "$(cat "$STATE")")
      BOOT_AFTER=$(field boot_id "$AFTER")
      if [ "$BOOT_BEFORE" = "$BOOT_AFTER" ]; then
        echo "FAIL  boot_id unchanged — the distro never actually restarted, so this leg proves nothing"
        exit 1
      fi
      if [ -z "$(field invocation "$AFTER")" ]; then
        echo "FAIL  restart: the proxy did NOT come back. A user who restarts is unprotected until they run it by hand."
        exit 1
      fi
      for _ in $(seq 15); do
        CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz" 2>/dev/null || echo 000)
        [ "$CODE" = 200 ] && break
        sleep 1
      done
      echo "healthz after restart: $CODE"
      [ "$CODE" = 200 ] || { echo "FAIL  restart: the unit is up but the proxy does not answer"; exit 1; }
      echo "PASS  restart: the proxy came back by itself and answers"
      exit 0
    fi

    if [ "$(cat "$STATE")" = "$AFTER" ]; then OUTCOME=survived; else OUTCOME=restarted; fi
    echo "outcome: $OUTCOME (expected for $IDLE_EXPECTED leg: $([ "$IDLE_EXPECTED" = fix ] && echo survived || echo restarted))"
    if [ "$IDLE_EXPECTED" = fix ] && [ "$OUTCOME" = survived ]; then echo "PASS"; exit 0; fi
    if [ "$IDLE_EXPECTED" = control ] && [ "$OUTCOME" = restarted ]; then echo "PASS"; exit 0; fi
    echo "FAIL"; exit 1
    ;;
  *) echo "unknown mode: $MODE"; exit 2 ;;
esac
