#!/usr/bin/env bash
# Real WSL coverage for worthless (worthless-2z8y).
#
# Runs INSIDE a real WSL2 distribution on a GitHub Windows runner, installed by
# Vampire/setup-wsl. Not Docker, not a monkeypatched platform: this is the
# environment our primary user — a Windows developer working in WSL — runs.
#
# Expects SYSTEMD_EXPECTED=on|off from the workflow matrix, which controls
# whether /etc/wsl.conf enabled systemd before WSL booted.
#
# WHAT THIS DOES NOT PROVE: this is WSL2 inside a GitHub VM, not a user's
# laptop. It says nothing about /mnt/c interop — though worthless refuses
# /mnt/c by design (fs_check.py), so that gap is narrow.
set -uo pipefail

REPO="${REPO:-$(pwd)}"
SYSTEMD_EXPECTED="${SYSTEMD_EXPECTED:?set SYSTEMD_EXPECTED=on|off}"
USER_NAME=worthless-wsl
PORT=8787
FAILURES=0

say()  { printf '\n=== %s ===\n' "$1"; }
fact() { printf '  %-28s %s\n' "$1" "$2"; }
check() {
  if eval "$2"; then printf '  PASS  %s\n' "$1"
  else printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); fi
}

say "1. are we really in WSL?"
fact "WSL_DISTRO_NAME" "${WSL_DISTRO_NAME:-<unset>}"
fact "kernel" "$(uname -r)"
fact "PID 1" "$(cat /proc/1/comm 2>/dev/null || echo unknown)"
check "running inside WSL" '[ -n "${WSL_DISTRO_NAME:-}" ] || grep -qi microsoft /proc/version'

say "2. is systemd in the state the matrix asked for?"
PID1=$(cat /proc/1/comm 2>/dev/null)
fact "expected" "$SYSTEMD_EXPECTED"
fact "actual PID 1" "$PID1"
if [ "$SYSTEMD_EXPECTED" = "on" ]; then
  check "systemd is PID 1" '[ "$PID1" = "systemd" ]'
else
  check "systemd is NOT PID 1" '[ "$PID1" != "systemd" ]'
fi

say "3. install worthless as a normal user"
id -u "$USER_NAME" >/dev/null 2>&1 || useradd -m -s /bin/bash "$USER_NAME"
HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)
SRC=/tmp/worthless-src
rm -rf "$SRC"; mkdir -p "$SRC"
cp -R "$REPO/pyproject.toml" "$REPO/src" "$REPO/README.md" "$SRC"/
rm -rf "$SRC"/src/*.egg-info
chown -R "$USER_NAME:$USER_NAME" "$SRC"
runuser -l "$USER_NAME" -c "python3 -m venv ~/venv && ~/venv/bin/pip install -q --no-input $SRC" 2>&1 | tail -3
# A real install puts worthless on PATH; the service installer resolves the
# binary from PATH, so mirror that rather than calling it by absolute path.
RUN="export PATH=\$HOME/venv/bin:\$PATH &&"
check "worthless installed and runs" "runuser -l $USER_NAME -c '$RUN worthless --version' >/dev/null 2>&1"

say "4. which keyring does WSL actually pick?"
# worthless-2z8y: this has only ever been inferred from reading keystore.py.
# Deliberately NOT forcing WORTHLESS_KEYRING_BACKEND — we want the real answer.
runuser -l "$USER_NAME" -c "$RUN python -c 'import keyring; print(type(keyring.get_keyring()).__module__ + \".\" + type(keyring.get_keyring()).__name__)'" 2>&1 | sed 's/^/  backend: /'

say "5. lock a .env"
PROJ="$HOME_DIR/proj"
runuser -l "$USER_NAME" -c "mkdir -p $PROJ"
KEY="sk-proj-$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
runuser -l "$USER_NAME" -c "printf 'OPENAI_API_KEY=%s\n' '$KEY' > $PROJ/.env"
runuser -l "$USER_NAME" -c "$RUN cd $PROJ && worthless lock" > /tmp/lock.log 2>&1
LOCK_RC=$?
sed 's/^/  | /' /tmp/lock.log | tail -15
check "lock exits 0" "[ $LOCK_RC -eq 0 ]"
check "the real key is gone from .env" "! grep -q '$KEY' $PROJ/.env"

say "6. service install — the WSL-specific behaviour"
UNIT="$HOME_DIR/.config/systemd/user/worthless-proxy.service"
runuser -l "$USER_NAME" -c "$RUN worthless --yes service install" > /tmp/svc.log 2>&1
SVC_RC=$?
sed 's/^/  | /' /tmp/svc.log | tail -12
fact "service install exit" "$SVC_RC"
fact "unit file left on disk" "$([ -f "$UNIT" ] && echo yes || echo no)"

if [ "$SYSTEMD_EXPECTED" = "on" ]; then
  check "service install succeeds with systemd on" "[ $SVC_RC -eq 0 ]"
  sleep 3
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz" 2>/dev/null || echo 000)
  fact "healthz" "$CODE"
  check "proxy answers" "[ '$CODE' = '200' ]"
else
  # The default WSL user's reality. Must not claim success.
  check "service install does NOT succeed with systemd off" "[ $SVC_RC -ne 0 ]"
  # Reported, not asserted: before PR #599 lands, the old path writes the unit
  # BEFORE checking linger and leaves it orphaned; #599 reorders that. Asserting
  # it would make this job red for a known, already-fixed bug.
  if grep -q 'wsl.conf' /tmp/svc.log; then
    fact "error names /etc/wsl.conf" "yes (PR #599 behaviour)"
  else
    fact "error names /etc/wsl.conf" "no — pre-#599 message"
  fi
fi

say "VERDICT (systemd=$SYSTEMD_EXPECTED)"
if [ "$FAILURES" -eq 0 ]; then echo "  all checks passed"; exit 0; fi
echo "  $FAILURES check(s) failed"
exit 1
