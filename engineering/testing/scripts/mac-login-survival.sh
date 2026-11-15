#!/usr/bin/env bash
# Does macOS background protection survive a log-out or a restart? (WOR-861)
#
# A LaunchAgent with RunAtLoad starts at LOGIN, so logging out and in (or a
# full restart) is the real trigger. CI Macs cannot log out, so this runs on a
# real Mac:
#
#   save     install the service from this checkout into a throwaway home
#            (fake key routed to fake_provider.py, port 18791); prove a real
#            request works through it; record PID and times
#   (you log out of macOS and back in, or restart)
#   check    PASS only if: you really logged in after the save; a NEW process
#            started after that login, by launchd, from this test's copy, owns
#            the port; and a real request through it still reaches the
#            provider with the rebuilt key (/healthz never touches the key)
#   cleanup  uninstall; delete the folder only once nothing is left
#
# WHAT THIS DOES NOT PROVE: the install used a file-backed key
# (WORTHLESS_KEYRING_BACKEND=null). After boot the service reads that file
# first on every platform, as it does for Keychain users once install has
# synced the key, but a Keychain-to-file sync is not exercised here. One Mac,
# one restart.
set -uo pipefail

REPO="${REPO:-$(pwd)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
D="$HOME/.worthless-login-test"
PORT=18791
PROVIDER_PORT=18792
LABEL=sh.worthless.proxy
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
STATE="$D/state"
OURS="$D/venv/bin/worthless"

run() {
  env WORTHLESS_HOME="$D/home" WORTHLESS_KEYRING_BACKEND=null WORTHLESS_PORT="$PORT" \
    PATH="$D/venv/bin:$PATH" "$@"
}
job_pid() { launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | awk '/^\tpid = /{print $3; exit}'; }
# LC_ALL=C: ps and date must agree on English day/month names.
started_epoch() { LC_ALL=C date -j -f "%a %b %d %T %Y" "$(LC_ALL=C ps -o lstart= -p "$1" | sed 's/  */ /g')" +%s 2>/dev/null; }
# Your most recent console login, from the login records (minute precision).
# loginwindow alone is not enough: macOS keeps it across a plain log-out.
console_login_epoch() {
  local when
  when=$(LC_ALL=C last "$USER" | awk '$2=="console"{print $3, $4, $5, $6; exit}')
  [ -n "$when" ] && LC_ALL=C date -j -f "%a %b %d %H:%M:%S %Y" "${when}:00 $(date +%Y)" +%s 2>/dev/null || echo 0
}
# curl already prints 000 when nothing listens; `|| echo 000` would make 000000.
health() { local c; c=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz" 2>/dev/null); echo "${c:-000}"; }
plist_binary() { /usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$PLIST" 2>/dev/null; }
# True if $1 is $2 or one of its descendants.
descends_from() {
  local p="$1"
  while [ -n "$p" ] && [ "$p" -gt 1 ]; do
    [ "$p" = "$2" ] && return 0
    p=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')
  done
  return 1
}
start_provider() {
  EXPECTED_KEY="$KEY" nohup python3 "$HERE/fake_provider.py" "$PROVIDER_PORT" >> "$D/provider.log" 2>&1 &
  echo $! > "$D/provider.pid"
  for _ in $(seq 20); do nc -z 127.0.0.1 "$PROVIDER_PORT" 2>/dev/null && return 0; sleep 0.5; done
  return 1
}
stop_provider() { [ -f "$D/provider.pid" ] && kill "$(cat "$D/provider.pid")" 2>/dev/null; rm -f "$D/provider.pid"; }
# A real chat request the way an app sends it: the half-key and proxy URL lock left in .env.
roundtrip() {
  (set -a; . "$D/project/.env"; set +a
   curl -s -o /dev/null -w '%{http_code}' \
     -H "Authorization: Bearer $LOCALMOCK_API_KEY" -H 'content-type: application/json' \
     -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
     "$LOCALMOCK_BASE_URL/chat/completions")
}
# Read only lines written after the request; `tail -1` matched an older line.
provider_mark() { wc -l < "$D/provider.log" 2>/dev/null | tr -d ' ' || echo 0; }
provider_saw_real_key() { tail -n +"$((${1:-0} + 1))" "$D/provider.log" 2>/dev/null | grep -q "key_matches=True"; }

case "${1:-}" in
  save)
    [ "$(uname)" = Darwin ] || { echo "macOS only"; exit 2; }
    # Never overwrite a login item that is not this test's own copy.
    if [ -f "$PLIST" ] && [ "$(plist_binary)" != "$OURS" ]; then
      echo "REFUSING: $PLIST runs $(plist_binary), not this test (your real service?)"; exit 2
    fi
    mkdir -p "$D/home" "$D/project" "$D/src" "$D/lock-home"
    echo "building a private copy of worthless from $REPO ..."
    # Build from a copy: installing straight from the checkout leaves build/ in it.
    rm -rf "$D/src"/* && cp -R "$REPO/pyproject.toml" "$REPO/src" "$REPO/README.md" "$D/src/"
    uv venv -q --clear "$D/venv" && uv pip install -q --python "$D/venv/bin/python" "$D/src" || exit 1
    KEY="sk-live-$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
    # The provider registry is read from ~/.worthless/providers.toml under HOME,
    # not under WORTHLESS_HOME, so it goes in the throwaway lock HOME. The
    # user's real ~/.worthless is never written.
    mkdir -p "$D/lock-home/.worthless"
    printf '[provider.localmock]\nurl = "http://127.0.0.1:%s/v1"\nprotocol = "openai"\n' "$PROVIDER_PORT" > "$D/lock-home/.worthless/providers.toml"
    printf 'LOCALMOCK_API_KEY=%s\nLOCALMOCK_BASE_URL=http://127.0.0.1:%s/v1\n' "$KEY" "$PROVIDER_PORT" > "$D/project/.env"
    start_provider || { echo "FAIL: fake provider did not start"; exit 1; }
    # Lock under a throwaway HOME: with the real one, lock finds the user's
    # OpenClaw config (~/.openclaw) and tries to wire this fake key into it.
    # Only the service install below needs the real HOME, because launchd
    # loads login items from ~/Library/LaunchAgents and nowhere else.
    (cd "$D/project" && HOME="$D/lock-home" run worthless lock >/dev/null 2>&1) \
      || { echo "lock failed"; stop_provider; exit 1; }
    run worthless service install --yes 2>&1 | tail -3
    for _ in $(seq 30); do [ "$(health)" = 200 ] && break; sleep 1; done
    PID=$(job_pid)
    [ -n "$PID" ] && [ "$(health)" = 200 ] || { echo "FAIL: service not up after install"; stop_provider; exit 1; }
    MARK=$(provider_mark); CODE=$(roundtrip)
    [ "$CODE" = 200 ] && provider_saw_real_key "$MARK" || { echo "FAIL: a real request through the service failed ($CODE)"; stop_provider; exit 1; }
    stop_provider
    umask 077
    {
      echo "saved_at=$(date +%s)"
      echo "pid=$PID"
      echo "started=$(started_epoch "$PID")"
      echo "commit=$(git -C "$REPO" rev-parse HEAD 2>/dev/null)"
      echo "KEY=$KEY"
    } > "$STATE"
    echo "SAVED: pid $PID, healthz 200, a real request worked (provider got the real key), binary $(plist_binary)"
    echo "Now log out of macOS (Apple menu > Log Out) or restart, log back in, then run: check"
    ;;
  check)
    [ -f "$STATE" ] || { echo "no saved state: run save first"; exit 2; }
    # shellcheck disable=SC1090
    . "$STATE"
    FAILS=0
    ok()  { printf '  PASS  %s\n' "$1"; }
    bad() { printf '  FAIL  %s\n' "$1"; FAILS=$((FAILS + 1)); }
    # Latest of: your console login (covers a plain log-out) and your own
    # loginwindow's start (covers a restart). -u: never another user's session.
    LOGIN_PID=$(pgrep -x -u "$(id -u)" loginwindow | head -1)
    LW_AT=$( [ -n "$LOGIN_PID" ] && started_epoch "$LOGIN_PID" || echo 0 )
    CONSOLE_AT=$(console_login_epoch)
    LOGIN_AT=$(( LW_AT > CONSOLE_AT ? LW_AT : CONSOLE_AT ))
    for _ in $(seq 30); do [ "$(health)" = 200 ] && break; sleep 1; done
    NOW_PID=$(job_pid)
    echo "saved:   $(date -r "$saved_at" '+%F %T'), pid $pid"
    echo "login:   $(date -r "$LOGIN_AT" '+%F %T') (loginwindow pid ${LOGIN_PID:-none})"
    [ "$LOGIN_AT" -gt "$saved_at" ] && ok "you logged in after the save (a crash-restart alone cannot pass)" \
      || bad "no login since the save: log out or restart first"
    if [ -z "$NOW_PID" ]; then
      bad "no $LABEL process: the login item did not start"
    else
      NOW_STARTED=$(started_epoch "$NOW_PID")
      echo "now:     $(date -r "$NOW_STARTED" '+%F %T'), pid $NOW_PID"
      [ "$NOW_PID" != "$pid" ] && ok "a new process (the old one died at log-out)" || bad "same PID: it never stopped"
      [ "$NOW_STARTED" -ge "$LOGIN_AT" ] && ok "it started after your login, with nobody running it" \
        || bad "it started before your login: not started by the login item"
      launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | grep -q "state = running" \
        && ok "launchd reports the job running" || bad "launchd does not report the job running"
      [ "$(plist_binary)" = "$OURS" ] && ok "the job runs this test's copy" || bad "the job runs $(plist_binary), not this test"
      OWNERS=$(lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t 2>/dev/null)
      OWNED=no; for o in $OWNERS; do descends_from "$o" "$NOW_PID" && OWNED=yes; done
      [ "$OWNED" = yes ] && ok "that process owns port $PORT" || bad "port $PORT is held by ${OWNERS:-nothing}, not the job"
    fi
    [ "$(health)" = 200 ] && ok "proxy answers /healthz" || bad "proxy does not answer on $PORT"
    if start_provider; then
      MARK=$(provider_mark); CODE=$(roundtrip)
      [ "$CODE" = 200 ] && provider_saw_real_key "$MARK" && ok "a real request works after the restart (the proxy rebuilt the real key)" \
        || bad "the proxy is up but a real request fails ($CODE): not protected"
      stop_provider
    else
      bad "fake provider did not start"
    fi
    echo "VERDICT: $([ "$FAILS" -eq 0 ] && echo PASS || echo "FAIL ($FAILS)")"
    [ "$FAILS" -eq 0 ]
    ;;
  cleanup)
    [ -d "$D" ] || { echo "nothing to clean"; exit 0; }
    stop_provider
    if [ -f "$PLIST" ] && [ "$(plist_binary)" != "$OURS" ]; then
      echo "REFUSING: $PLIST is not this test's; not uninstalling it"; exit 2
    fi
    run worthless service uninstall --yes 2>&1 | tail -1
    PLIST_LEFT=$([ -f "$PLIST" ] && echo yes || echo no)
    JOB_LEFT=$(launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 && echo yes || echo no)
    if [ "$PLIST_LEFT" = no ] && [ "$JOB_LEFT" = no ]; then
      rm -rf "$D"
    else
      echo "uninstall did not finish; keeping $D so it can be retried"
    fi
    echo "left behind: plist=$PLIST_LEFT job=$JOB_LEFT port=$(lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t 2>/dev/null | wc -l | tr -d ' ') folder=$([ -d "$D" ] && echo yes || echo no)"
    ;;
  *) echo "usage: $0 save|check|cleanup"; exit 2 ;;
esac
