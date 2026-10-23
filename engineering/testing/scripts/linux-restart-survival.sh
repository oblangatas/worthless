#!/usr/bin/env bash
# Does Linux background protection survive a restart? (WOR-861)
#
# Boots systemd as PID 1 inside a privileged Docker container: the same boot
# sequence a Linux machine runs, including lingering, which is what starts a
# user's services before anyone logs in. Installs worthless as a normal user,
# locks a fake key routed to a local fake provider (fake_provider.py answers
# 200 ONLY for the exact original key), installs the service, then:
#
#   1. restart   -> the proxy must come back by itself (new PID 1, new
#                   InvocationID) AND a real request through it must still
#                   reach the provider with the rebuilt key. /healthz alone
#                   does not touch the key, so it is not proof of protection.
#   2. control   -> lingering off, restart -> it must NOT come back, or this
#                   test cannot see a failure and pass 1 proves nothing.
#   3. teardown  -> `worthless service uninstall` leaves no unit, no process,
#                   nothing on the port.
#
# WHAT THIS DOES NOT PROVE: a container restart is not a kernel reboot (same
# kernel, same Docker VM). The key is file-backed (WORTHLESS_KEYRING_BACKEND=
# null), which is the real path on headless Linux and WSL but NOT on a desktop
# with a Secret Service keyring. Lingering is enabled by root here, because a
# user without a local login cannot enable it — step 2 asserts that install
# says so plainly instead of pointing at a dead end (worthless-8kn5).
# Run from the repo root:  bash engineering/testing/scripts/linux-restart-survival.sh
set -uo pipefail

REPO="${REPO:-$(pwd)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE="worthless-systemd-restart-$$"  # per run: a shared tag let one run delete another's image
C="worthless-restart-$$"
U=worthless-test
PORT=8787
PROVIDER_PORT=9999
FAILURES=0

say()  { printf '\n=== %s ===\n' "$1"; }
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
known() { printf '  KNOWN %s\n' "$1"; }
cleanup() {
  docker rm -f "$C" >/dev/null 2>&1 || true
  docker rmi -f "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

as_user() {
  local uid
  uid=$(docker exec "$C" id -u "$U")
  docker exec -u "$U" -w "/home/$U" \
    -e HOME="/home/$U" \
    -e XDG_RUNTIME_DIR="/run/user/$uid" \
    -e DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
    -e PATH="/home/$U/venv/bin:/usr/local/bin:/usr/bin:/bin" \
    -e WORTHLESS_KEYRING_BACKEND=null \
    "$C" "$@"
}
pid1_start() { docker exec "$C" awk '{print $22}' /proc/1/stat; }
invocation() { as_user systemctl --user show -p InvocationID --value worthless-proxy 2>/dev/null; }
# curl already prints 000 when nothing listens; appending `|| echo 000` made it
# "000000", which read as "something answered" (found the hard way).
health() {
  local code
  code=$(docker exec "$C" curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz" 2>/dev/null)
  echo "${code:-000}"
}
wait_running() {
  for _ in $(seq 60); do
    state=$(docker exec "$C" systemctl is-system-running 2>/dev/null)
    case "$state" in running|degraded) return 0 ;; esac
    sleep 1
  done
  return 1
}
# Waits up to $1 s for the service to be up AND answering. Waiting cannot
# manufacture a pass: a unit that never starts still fails.
wait_back() {
  for _ in $(seq "$1"); do
    [ -n "$(invocation)" ] && [ "$(health)" = 200 ] && return 0
    sleep 1
  done
  return 1
}
# The fake provider dies with the container; it is the stand-in, not the thing
# under test, so the script (re)starts it after every boot.
start_provider() {
  docker exec -d -e EXPECTED_KEY="$KEY" "$C" \
    bash -c "python3 /opt/proof/fake_provider.py $PROVIDER_PORT >> /opt/proof/provider.log 2>&1"
  for _ in $(seq 20); do
    docker exec "$C" bash -c "exec 3<>/dev/tcp/127.0.0.1/$PROVIDER_PORT" 2>/dev/null && return 0
    sleep 0.5
  done
  return 1
}
# A real chat request the way an app would send it: the half-key lock left in
# .env, to the proxy URL lock left in .env. Prints the HTTP status.
roundtrip() {
  as_user bash -c 'set -a; . ~/proj/.env; set +a; curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $LOCALMOCK_API_KEY" -H "content-type: application/json" \
    -d "{\"model\":\"gpt-4o-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}" \
    "$LOCALMOCK_BASE_URL/chat/completions"' 2>/dev/null
}
# Lines in the provider log before a request; the check then reads only lines
# written after it. A plain `tail -1` matched the line from before the restart.
provider_mark() { docker exec "$C" bash -c "wc -l < /opt/proof/provider.log 2>/dev/null || echo 0" | tr -d ' '; }
provider_saw_real_key() { docker exec "$C" tail -n +"$(($1 + 1))" /opt/proof/provider.log | grep -q "key_matches=True"; }

say "0. build a Linux image that boots systemd"
docker build -q -t "$IMAGE" - >/dev/null <<'EOF' || { echo "image build failed"; exit 2; }
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq systemd systemd-sysv dbus dbus-user-session python3 python3-venv curl >/dev/null \
 && apt-get clean && useradd -m -s /bin/bash worthless-test
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
docker run -d --name "$C" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock "$IMAGE" >/dev/null
wait_running && pass "systemd booted as PID 1 ($(docker exec "$C" cat /proc/1/comm))" || { fail "systemd never reached running"; exit 1; }

say "1. install worthless as a normal user, lock a fake key"
docker exec "$C" mkdir -p /tmp/src
for f in pyproject.toml src README.md; do docker cp "$REPO/$f" "$C:/tmp/src/"; done
# Not /tmp: systemd empties /tmp at every boot, which deleted it the first time.
docker exec "$C" mkdir -p /opt/proof
docker cp "$HERE/fake_provider.py" "$C:/opt/proof/fake_provider.py"
docker exec "$C" bash -c "rm -rf /tmp/src/src/*.egg-info; chown -R $U:$U /tmp/src"
as_user bash -c 'python3 -m venv ~/venv && ~/venv/bin/pip install -q --no-input /tmp/src' > /dev/null 2>&1 \
  && pass "installed worthless from this checkout" || { fail "pip install failed"; exit 1; }
KEY="sk-live-$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
# A user provider entry is the documented way to point lock at a non-default
# upstream; without it lock refuses an unregistered URL.
as_user bash -c "mkdir -p ~/.worthless ~/proj && printf '[provider.localmock]\nurl = \"http://127.0.0.1:$PROVIDER_PORT/v1\"\nprotocol = \"openai\"\n' > ~/.worthless/providers.toml"
as_user bash -c "printf 'LOCALMOCK_API_KEY=%s\nLOCALMOCK_BASE_URL=http://127.0.0.1:$PROVIDER_PORT/v1\n' '$KEY' > ~/proj/.env"
start_provider || fail "fake provider did not start"
as_user bash -c 'cd ~/proj && worthless lock' >/dev/null 2>&1 && pass "lock" || fail "lock"
as_user grep -q "$KEY" "/home/$U/proj/.env"
case $? in 1) pass "the real key is gone from .env" ;; 0) fail "the real key is still in .env" ;; *) fail "could not read .env" ;; esac
DIRECT=$(as_user bash -c 'set -a; . ~/proj/.env; set +a; curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $LOCALMOCK_API_KEY" -d "{}" http://127.0.0.1:'"$PROVIDER_PORT"'/v1/chat/completions')
[ "$DIRECT" = 401 ] && pass "the half-key left in .env is useless on its own (provider says $DIRECT)" || fail "the half-key worked directly against the provider ($DIRECT): the test provider is not checking keys"

say "2. install the background service"
# docker exec has no login session: polkit refuses linger AND there is no user
# manager. worthless-8kn5: say what an admin must run, never the dead end.
FIRST=$(as_user worthless service install --yes 2>&1)
printf '%s\n' "$FIRST" | sed 's/^/  | /' | tail -6
FIRST_FLAT=$(printf '%s' "$FIRST" | tr '\n' ' ' | tr -s ' ')
case "$FIRST_FLAT" in *"sudo loginctl enable-linger $U"*) pass "no session: install names the admin command" ;; *) fail "no session: install did not name \`sudo loginctl enable-linger $U\`" ;; esac
case "$FIRST_FLAT" in *"Run \`loginctl enable-linger"*|*"WRTLS-199"*|*"internal error"*) fail "no session: install still gives the dead end or a raw error" ;; *) pass "no session: no dead-end advice, no raw error" ;; esac
case "$FIRST_FLAT" in *machinectl*) fail "no session: told to log in via machinectl — a container can't" ;; *) pass "no session: not told to log in another way" ;; esac
as_user test -f "/home/$U/.config/systemd/user/worthless-proxy.service" && fail "no session: a refused install left its unit file behind" || pass "no session: no unit file left behind"
# The SSH case: a login would start the user's manager; linger is still refused.
# Root starts user@UID directly — a running manager, no linger, no session.
UID_U=$(docker exec "$C" id -u "$U")
docker exec "$C" systemctl start "user@$UID_U.service"
MID=$(as_user worthless service install --yes 2>&1)
printf '%s\n' "$MID" | sed 's/^/  | /' | tail -6
MID_FLAT=$(printf '%s' "$MID" | tr '\n' ' ' | tr -s ' ')
case "$MID_FLAT" in *"sudo loginctl enable-linger $U"*) pass "manager up, linger refused: install warns with the admin command" ;; *) fail "manager up, linger refused: no admin command in the install output" ;; esac
case "$MID_FLAT" in *"Lingering is now on"*) fail "manager up, linger refused: banner claims lingering is on" ;; *) pass "manager up, linger refused: banner does not claim lingering" ;; esac
[ "$(health)" = 200 ] && pass "manager up, linger refused: the service runs and answers" || fail "manager up, linger refused: the service does not answer"
docker exec "$C" test -f "/var/lib/systemd/linger/$U" && fail "manager up: lingering got enabled without an admin" || pass "manager up: lingering stays off until an admin enables it"
docker exec "$C" loginctl enable-linger "$U"
SECOND=$(as_user worthless service install --yes 2>&1)
printf '%s\n' "$SECOND" | sed 's/^/  | /' | tail -4
printf '%s' "$SECOND" | tr '\n' ' ' | grep -q "Lingering is now on" && pass "after the admin step: banner says lingering is on" || fail "after the admin step: banner does not say lingering is on"
BEFORE_INV=$(invocation); BEFORE_PID1=$(pid1_start)
[ -n "$BEFORE_INV" ] && pass "service running (InvocationID $BEFORE_INV)" || fail "service not running after install"
[ "$(health)" = 200 ] && pass "proxy answers /healthz" || fail "proxy does not answer"
docker exec "$C" test -f "/var/lib/systemd/linger/$U" && pass "lingering on" || fail "lingering not enabled"
MARK=$(provider_mark); CODE=$(roundtrip)
[ "$CODE" = 200 ] && provider_saw_real_key "$MARK" && pass "a real request works through the service (provider got the real key)" \
  || fail "a request through the service failed before any restart ($CODE)"

say "3. restart: does protection come back by itself?"
docker restart "$C" >/dev/null
wait_running || fail "systemd did not come back after restart"
if wait_back 60; then
  AFTER_INV=$(invocation); AFTER_PID1=$(pid1_start)
  [ "$AFTER_PID1" != "$BEFORE_PID1" ] && pass "the machine really restarted (new PID 1)" || fail "same PID 1: no restart happened, this proves nothing"
  [ "$AFTER_INV" != "$BEFORE_INV" ] && pass "systemd started the service again (new InvocationID $AFTER_INV)" || fail "same InvocationID across a restart: stale state"
  pass "proxy answers /healthz after restart, nobody started it"
  start_provider || fail "fake provider did not restart"
  MARK=$(provider_mark); CODE=$(roundtrip)
  [ "$CODE" = 200 ] && provider_saw_real_key "$MARK" && pass "a real request works after restart (the proxy rebuilt the real key)" \
    || fail "after restart the proxy is up but a real request fails ($CODE): not protected"
else
  fail "restart: the proxy did NOT come back within 60 s"
fi

say "4. control: lingering off, restart -> must NOT come back"
docker exec "$C" loginctl disable-linger "$U"
docker restart "$C" >/dev/null
if ! wait_running; then
  fail "control: the container did not come back, so this run cannot tell 'stayed down' from 'never booted'"
elif wait_back 60; then  # as long as step 3 allowed, or a slow comeback reads as "stayed down"
  fail "control: it came back WITHOUT lingering. This test cannot see a failure; pass 3 proves nothing"
else
  pass "control: without lingering it stays down (the test can see a failure)"
fi

say "5. teardown: uninstall leaves nothing"
docker exec "$C" loginctl enable-linger "$U"
wait_back 30 >/dev/null || true
as_user worthless service uninstall --yes 2>&1 | sed 's/^/  | /' | tail -2
# Each check must fail when it cannot run, not pass: a dead container would
# otherwise read as "no unit, not running, nothing on the port".
docker exec "$C" true || { fail "container gone before teardown could be checked"; exit 1; }
as_user test -e "/home/$U/.config/systemd/user/worthless-proxy.service"
case $? in 1) pass "no unit file" ;; 0) fail "unit file still there" ;; *) fail "could not check for the unit file" ;; esac
ACTIVE=$(as_user systemctl --user is-active worthless-proxy 2>/dev/null)
case "$ACTIVE" in inactive|unknown|failed|"") pass "service not running ($ACTIVE)" ;; *) fail "service still $ACTIVE after uninstall" ;; esac
sleep 2
if [ "$(health)" = 000 ]; then
  pass "nothing answers on port $PORT"
else
  fail "something still answers on $PORT after uninstall"
  docker exec "$C" bash -c "ps -eo pid,ppid,user,etime,args | grep -iE 'worthless|uvicorn|python' | grep -v grep" | sed 's/^/  | /'
fi

say "VERDICT"
if [ "$FAILURES" -eq 0 ]; then echo "  all checks passed"; exit 0; fi
echo "  $FAILURES check(s) failed"; exit 1
