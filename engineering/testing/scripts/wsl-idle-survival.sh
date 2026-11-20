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
#            back by itself afterwards, with nobody starting it — and whether a
#            real request still works through it (worthless-vck0).
set -uo pipefail

MODE="${1:?usage: wsl-idle-survival.sh save|compare}"
IDLE_EXPECTED="${IDLE_EXPECTED:?set IDLE_EXPECTED=control|fix|restart}"
USER_NAME=worthless-wsl
PORT=8787
PROVIDER_PORT=9999
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="$HOME/wsl-idle-survival.ids"  # on the distro's disk, survives a restart
PLOG="$HOME/wsl-provider.log"

# worthless-vck0: a chat request the way an app sends it — the half-key and the
# proxy URL that lock left in .env. fake_provider.py answers 200 only for the
# exact original key (written by wsl-live-lifecycle.sh), so a 200 it logged as
# key_matches=True proves the proxy rebuilt the real key. /healthz does not.
real_request() {
  local pid mark code base ok=1
  # Stand alone: a 200 only proves protection if the request went via the proxy.
  base=$(sed -n 's/^LOCALMOCK_BASE_URL=//p' "$(getent passwd "$USER_NAME" | cut -d: -f6)/proj/.env")
  case "$base" in
    "http://127.0.0.1:$PORT/"*) ;;
    *) echo "real request ($1): LOCALMOCK_BASE_URL '$base' is not the proxy on $PORT"; return 1 ;;
  esac
  EXPECTED_KEY="$(cat "$HOME/wsl-localmock.key")" python3 "$HERE/fake_provider.py" "$PROVIDER_PORT" >> "$PLOG" 2>&1 &
  pid=$!
  for _ in $(seq 20); do (exec 3<>"/dev/tcp/127.0.0.1/$PROVIDER_PORT") 2>/dev/null && break; sleep 0.5; done
  mark=$(wc -l < "$PLOG")
  # shellcheck disable=SC2016  # expanded by the user's shell, from their .env
  code=$(runuser -l "$USER_NAME" -c 'set -a; . ~/proj/.env; set +a; curl -s --max-time 20 -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $LOCALMOCK_API_KEY" -H "content-type: application/json" \
    -d "{\"model\":\"gpt-4o-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}" \
    "$LOCALMOCK_BASE_URL/chat/completions"')
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  echo "real request through the proxy ($1): ${code:-none}"
  [ "$code" = 200 ] && tail -n +"$((mark + 1))" "$PLOG" | grep -q "key_matches=True" && ok=0
  [ "$ok" = 0 ] || { echo "fake provider log (last 10 lines):"; tail -10 "$PLOG" | sed 's/^/  | /'; }
  return "$ok"
}

inv() {
  local uid
  uid=$(id -u "$USER_NAME")
  runuser -u "$USER_NAME" -- env XDG_RUNTIME_DIR="/run/user/$uid" \
    systemctl --user show -p InvocationID --value worthless-proxy 2>/dev/null
}

ids() {
  printf 'boot_id=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
  # PID 1's start time. Measured 2026-09-17: `wsl --terminate` restarts the
  # distro but NOT the lightweight VM every distro shares, so boot_id does NOT
  # change (only `wsl --shutdown` changes it). A new PID 1 is what proves this
  # distro restarted.
  printf 'pid1_start=%s\n' "$(awk '{print $22}' /proc/1/stat)"
  printf 'invocation=%s\n' "$(inv)"
}

field() { printf '%s\n' "$2" | sed -n "s/^$1=//p"; }

case "$MODE" in
  save)
    ids | tee "$STATE"
    # An empty InvocationID means the unit is not running; comparing nothing to
    # nothing would read as "survived".
    grep -q '^invocation=.\+' "$STATE" || { echo "FAIL  service not running, nothing to compare"; exit 1; }
    # Without a working request BEFORE the restart, a failure after it could not
    # be blamed on the restart.
    if [ "$IDLE_EXPECTED" = restart ]; then
      real_request "before restart" || { echo "FAIL  a real request fails before any restart"; exit 1; }
    fi
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
      if [ "$(field pid1_start "$(cat "$STATE")")" = "$(field pid1_start "$AFTER")" ]; then
        echo "FAIL  same PID 1 — the distro never actually restarted, so this leg proves nothing"
        exit 1
      fi
      if [ "$(field invocation "$(cat "$STATE")")" = "$(field invocation "$AFTER")" ]; then
        echo "FAIL  same InvocationID across a restart — impossible; the save step's state is stale"
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
      real_request "after restart" || { echo "FAIL  restart: the proxy answers /healthz but a real request fails — not protected"; exit 1; }
      echo "PASS  restart: the proxy came back by itself and a real request still works"

      # Teardown: uninstall must leave nothing. The port check is the one that
      # cannot be fooled: an empty InvocationID also reads as "not running".
      runuser -l "$USER_NAME" -c "$(cat "$HOME/wsl-worthless-bin") service uninstall --yes" 2>&1 | tail -2
      UNIT="$(getent passwd "$USER_NAME" | cut -d: -f6)/.config/systemd/user/worthless-proxy.service"
      LEFT=0
      [ ! -e "$UNIT" ] || { echo "FAIL  uninstall left the unit file"; LEFT=1; }
      [ -z "$(inv)" ] || { echo "FAIL  uninstall left the service running"; LEFT=1; }
      sleep 2
      CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz" 2>/dev/null)
      [ "${CODE:-000}" = 000 ] || { echo "FAIL  something still answers on $PORT after uninstall"; LEFT=1; }
      [ "$LEFT" = 0 ] || exit 1
      echo "PASS  uninstall: no unit, no service, nothing on port $PORT"
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
