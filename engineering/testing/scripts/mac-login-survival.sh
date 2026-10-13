#!/usr/bin/env bash
# Does the macOS background service come back after you log out and in? (WOR-861)
#
# A LaunchAgent with RunAtLoad starts at LOGIN, so logging out and back in is
# the real trigger. CI Macs cannot log out, so this runs on a real Mac:
#
#   save     install the service from this checkout into a throwaway home
#            (fake key, port 18791); record its PID and start time
#   (you log out of macOS and back in)
#   check    PASS only if: a NEW process, started AFTER the save, launched by
#            launchd, answers /healthz, with nobody starting it
#   cleanup  uninstall and delete everything this script created
#
# WHAT THIS DOES NOT PROVE: a log-out is not a cold boot. It proves the login
# item starts Worthless at login; it skips firmware and the pre-login boot.
set -uo pipefail

REPO="${REPO:-$(pwd)}"
D="$HOME/.worthless-login-test"
PORT=18791
LABEL=sh.worthless.proxy
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
STATE="$D/state"

run() {
  env WORTHLESS_HOME="$D/home" WORTHLESS_KEYRING_BACKEND=null WORTHLESS_PORT="$PORT" \
    PATH="$D/venv/bin:$PATH" "$@"
}
job_pid() { launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | awk '/^\tpid = /{print $3; exit}'; }
started_epoch() { date -j -f "%a %b %d %T %Y" "$(ps -o lstart= -p "$1" | sed 's/  */ /g')" +%s 2>/dev/null; }
health() { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz" 2>/dev/null || echo 000; }

case "${1:-}" in
  save)
    [ "$(uname)" = Darwin ] || { echo "macOS only"; exit 2; }
    if [ -f "$PLIST" ] && [ ! -d "$D" ]; then
      echo "REFUSING: $PLIST already exists and is not from this test (your real service?)"; exit 2
    fi
    mkdir -p "$D/home" "$D/project"
    echo "building a private copy of worthless from $REPO ..."
    uv venv -q --clear "$D/venv" && uv pip install -q --python "$D/venv/bin/python" "$REPO" || exit 1
    KEY="sk-proj-$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
    printf 'OPENAI_API_KEY=%s\n' "$KEY" > "$D/project/.env"
    # Lock under a throwaway HOME: with the real one, lock finds the user's
    # OpenClaw config (~/.openclaw) and tries to wire this fake key into it.
    # Only the service install below needs the real HOME, because launchd
    # loads login items from ~/Library/LaunchAgents and nowhere else.
    mkdir -p "$D/lock-home"
    (cd "$D/project" && HOME="$D/lock-home" run worthless lock >/dev/null 2>&1) \
      || { echo "lock failed"; exit 1; }
    run worthless service install --yes 2>&1 | tail -3
    for _ in $(seq 30); do [ "$(health)" = 200 ] && break; sleep 1; done
    PID=$(job_pid)
    [ -n "$PID" ] && [ "$(health)" = 200 ] || { echo "FAIL: service not up after install"; exit 1; }
    {
      echo "saved_at=$(date +%s)"
      echo "pid=$PID"
      echo "started=$(started_epoch "$PID")"
      echo "commit=$(git -C "$REPO" rev-parse HEAD 2>/dev/null)"
    } > "$STATE"
    echo "SAVED: pid $PID, healthz 200, binary $(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$PLIST")"
    echo "Now log out of macOS (Apple menu > Log Out), log back in, then run: check"
    ;;
  check)
    [ -f "$STATE" ] || { echo "no saved state: run save first"; exit 2; }
    # shellcheck disable=SC1090
    . "$STATE"
    FAILS=0
    ok()  { printf '  PASS  %s\n' "$1"; }
    bad() { printf '  FAIL  %s\n' "$1"; FAILS=$((FAILS + 1)); }
    for _ in $(seq 30); do [ "$(health)" = 200 ] && break; sleep 1; done
    NOW_PID=$(job_pid)
    echo "before log-out: pid $pid, started $(date -r "$started" '+%T'), saved $(date -r "$saved_at" '+%T')"
    echo "console login:  $(who | awk '/console/{print $3, $4, $5}' | head -1)"
    if [ -z "$NOW_PID" ]; then
      bad "no $LABEL process: the login item did not start"
    else
      NOW_STARTED=$(started_epoch "$NOW_PID")
      echo "now:            pid $NOW_PID, started $(date -r "$NOW_STARTED" '+%T')"
      [ "$NOW_PID" != "$pid" ] && ok "a new process (the old one died at log-out)" || bad "same PID: you did not log out, or it never stopped"
      [ "$NOW_STARTED" -gt "$saved_at" ] && ok "it started after the log-out" || bad "it started before the save: not a fresh start"
      launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | grep -q "state = running" \
        && ok "launchd reports the job running (launchd started it, not this script)" \
        || bad "launchd does not report the job running"
    fi
    [ "$(health)" = 200 ] && ok "proxy answers /healthz" || bad "proxy does not answer on $PORT"
    echo "VERDICT: $([ "$FAILS" -eq 0 ] && echo PASS || echo "FAIL ($FAILS)")"
    [ "$FAILS" -eq 0 ]
    ;;
  cleanup)
    [ -d "$D" ] || { echo "nothing to clean"; exit 0; }
    run worthless service uninstall --yes 2>&1 | tail -1
    rm -rf "$D"
    echo "left behind: plist=$([ -f "$PLIST" ] && echo yes || echo no) job=$(launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 && echo yes || echo no) folder=$([ -d "$D" ] && echo yes || echo no)"
    ;;
  *) echo "usage: $0 save|check|cleanup"; exit 2 ;;
esac
