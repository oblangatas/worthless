#!/usr/bin/env bash
# Does the Linux background service come back after a restart? (WOR-861)
#
# Boots systemd as PID 1 inside a privileged Docker container: the same boot
# sequence a Linux machine runs, including lingering, which is what starts a
# user's services before anyone logs in. Installs worthless as a normal user,
# locks a fake key, installs the service, then:
#
#   1. restart  -> the proxy must come back by itself: new PID 1, new
#                  InvocationID, /healthz 200, with nobody starting it.
#   2. control  -> lingering turned OFF, restart again -> it must NOT come
#                  back. If it does, this test cannot see a failure and pass 1
#                  proves nothing.
#
# WHAT THIS DOES NOT PROVE: a container restart is not a kernel reboot (same
# kernel, same Docker VM). It proves systemd's real boot path starts the unit;
# it says nothing about firmware, disk encryption unlock, or a real login
# screen. Run from the repo root:  bash engineering/testing/scripts/linux-restart-survival.sh
set -uo pipefail

REPO="${REPO:-$(pwd)}"
IMAGE=worthless-systemd-restart
C="worthless-restart-$$"
U=worthless-test
PORT=8787
FAILURES=0

say()  { printf '\n=== %s ===\n' "$1"; }
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
cleanup() { docker rm -f "$C" >/dev/null 2>&1 || true; }
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
health() { docker exec "$C" curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz" 2>/dev/null || echo 000; }
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
docker exec "$C" bash -c "rm -rf /tmp/src/src/*.egg-info; chown -R $U:$U /tmp/src"
as_user bash -c 'python3 -m venv ~/venv && ~/venv/bin/pip install -q --no-input /tmp/src' 2>&1 | tail -2
KEY="sk-proj-$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
as_user bash -c "mkdir -p ~/proj && printf 'OPENAI_API_KEY=%s\n' '$KEY' > ~/proj/.env"
as_user bash -c 'cd ~/proj && worthless lock' >/dev/null 2>&1 && pass "lock" || fail "lock"

say "2. install the background service"
# Found by this script: a user with no local login session (SSH, a container,
# `docker exec`) may not turn lingering on for themselves; polkit refuses and
# install stops with WRTLS-119, telling them to run `loginctl enable-linger`.
# Pinned here so that finding stays visible, then the documented fix is
# applied the way an admin would, and the user installs again.
as_user worthless service install --yes > /tmp/svc1.log 2>&1
if grep -q "enable-linger" /tmp/svc1.log; then
  pass "without lingering, install refuses and names \`loginctl enable-linger\`"
else
  sed 's/^/  | /' /tmp/svc1.log | tail -4
  echo "  note: install did not refuse here (lingering may be allowed for this user)"
fi
docker exec "$C" loginctl enable-linger "$U"
as_user worthless service install --yes 2>&1 | sed 's/^/  | /' | tail -4
BEFORE_INV=$(invocation); BEFORE_PID1=$(pid1_start)
[ -n "$BEFORE_INV" ] && pass "service running (InvocationID $BEFORE_INV)" || fail "service not running after install"
[ "$(health)" = 200 ] && pass "proxy answers /healthz" || fail "proxy does not answer"
docker exec "$C" test -f "/var/lib/systemd/linger/$U" && pass "lingering on" || fail "lingering not enabled"

say "3. restart: does it come back by itself?"
docker restart "$C" >/dev/null
wait_running || fail "systemd did not come back after restart"
if wait_back 60; then
  AFTER_INV=$(invocation); AFTER_PID1=$(pid1_start)
  [ "$AFTER_PID1" != "$BEFORE_PID1" ] && pass "the machine really restarted (new PID 1)" || fail "same PID 1: no restart happened, this proves nothing"
  [ "$AFTER_INV" != "$BEFORE_INV" ] && pass "systemd started the service again (new InvocationID $AFTER_INV)" || fail "same InvocationID across a restart: stale state"
  pass "proxy answers /healthz after restart, nobody started it"
else
  fail "restart: the proxy did NOT come back within 60 s"
fi

say "4. control: lingering off, restart -> must NOT come back"
docker exec "$C" loginctl disable-linger "$U"
docker restart "$C" >/dev/null
wait_running || true
if wait_back 20; then
  fail "control: it came back WITHOUT lingering. This test cannot see a failure; pass 3 proves nothing"
else
  pass "control: without lingering it stays down (the test can see a failure)"
fi

say "VERDICT"
if [ "$FAILURES" -eq 0 ]; then echo "  all checks passed"; exit 0; fi
echo "  $FAILURES check(s) failed"; exit 1
