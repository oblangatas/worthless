#!/usr/bin/env bash
# Real WSL coverage for worthless (worthless-2z8y).
#
# Runs INSIDE a real WSL2 distribution on a GitHub Windows runner, installed by
# Vampire/setup-wsl. Not Docker, not a monkeypatched platform: this is the
# environment our primary user — a Windows developer working in WSL — runs.
#
# Expects SYSTEMD_EXPECTED=on|off|default from the workflow matrix, which
# controls whether /etc/wsl.conf enabled systemd before WSL booted. `default`
# writes no wsl.conf and records what the distro ships.
#
# WHAT THIS DOES NOT PROVE: this is WSL2 inside a GitHub VM, not a user's
# laptop. It says nothing about /mnt/c interop — though worthless refuses
# /mnt/c by design (fs_check.py), so that gap is narrow.
set -uo pipefail

REPO="${REPO:-$(pwd)}"
SYSTEMD_EXPECTED="${SYSTEMD_EXPECTED:?set SYSTEMD_EXPECTED=on|off|default}"
# checkout = this branch's code; release = what `curl worthless.sh | sh` installs.
INSTALL_FROM="${INSTALL_FROM:-checkout}"
USER_NAME=worthless-wsl
PORT=8787
PROVIDER_PORT=9999  # fake_provider.py, for the restart leg's real request
FAILURES=0
# shellcheck source=engineering/testing/scripts/_live-pack-lib.sh
source "$(dirname "$0")/_live-pack-lib.sh"

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
if [ "$SYSTEMD_EXPECTED" = "default" ]; then
  # No wsl-conf was written: record what the distro really ships, don't assert.
  echo "  /etc/wsl.conf as shipped:"
  sed 's/^/  | /' /etc/wsl.conf 2>/dev/null || echo "  | <no /etc/wsl.conf>"
  SYSTEMD_EXPECTED=$([ "$PID1" = "systemd" ] && echo on || echo off)
  fact "shipped default" "systemd $SYSTEMD_EXPECTED"
elif [ "$SYSTEMD_EXPECTED" = "on" ]; then
  check "systemd is PID 1" '[ "$PID1" = "systemd" ]'
else
  check "systemd is NOT PID 1" '[ "$PID1" != "systemd" ]'
fi

say "3. install worthless as a normal user (from: $INSTALL_FROM)"
id -u "$USER_NAME" >/dev/null 2>&1 || useradd -m -s /bin/bash "$USER_NAME"
HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)
if [ "$INSTALL_FROM" = release ]; then
  # WOR-854: what a user gets is the installer https://worthless.sh serves today
  # and the release IT pins — not this checkout's install.sh, which on main can
  # pin a version not yet on PyPI.
  curl -fsSL https://worthless.sh -o /tmp/worthless-install.sh || { echo "  FAIL  could not download https://worthless.sh"; exit 1; }
  # RELEASE_VERSION (matrix `release_version`, or the workflow_dispatch input)
  # tests a newer release before worthless.sh pins it; empty = the pin users get.
  EXPECT="${RELEASE_VERSION:-$(sed -n 's/^WORTHLESS_VERSION_PIN="\(.*\)"$/\1/p' /tmp/worthless-install.sh)}"
  # It goes into a shell string below, and a dispatch input is typed by a person.
  [[ "$EXPECT" =~ ^[0-9][0-9A-Za-z.+-]*$ ]] || { echo "  FAIL  not a version: '$EXPECT'"; exit 1; }
  runuser -l "$USER_NAME" -c "WORTHLESS_VERSION='$EXPECT' sh /tmp/worthless-install.sh" 2>&1 | tail -5
  INSTALL_RC=${PIPESTATUS[0]}  # `| tail` would otherwise hide a failed install
  [ "$INSTALL_RC" -eq 0 ] || { echo "  FAIL  install.sh exited $INSTALL_RC"; exit 1; }
  BIN="$HOME_DIR/.local/bin/worthless"
else
  SRC=/tmp/worthless-src
  rm -rf "$SRC"; mkdir -p "$SRC"
  cp -R "$REPO/pyproject.toml" "$REPO/src" "$REPO/README.md" "$SRC"/
  rm -rf "$SRC"/src/*.egg-info
  chown -R "$USER_NAME:$USER_NAME" "$SRC"
  runuser -l "$USER_NAME" -c "python3 -m venv ~/venv && ~/venv/bin/pip install -q --no-input $SRC" 2>&1 | tail -3
  EXPECT=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO/pyproject.toml" | head -1)
  BIN="$HOME_DIR/venv/bin/worthless"
fi
# Before any worthless check: name the binary and its version, and stop if it is
# not the build this run means to test (lp_use_binary exits on a mismatch). An
# empty EXPECT would skip that comparison, so it is a failure, not a default.
[ -n "$EXPECT" ] || { echo "  FAIL  could not tell which version this run should test"; exit 1; }
# Root runs the user's binary here; leave no root-owned bytecode in their install.
PYTHONDONTWRITEBYTECODE=1 WORTHLESS_BIN="$BIN" WORTHLESS_EXPECT_VERSION="$EXPECT" lp_use_binary
echo "$BIN" > "$HOME/wsl-worthless-bin"  # the restart leg uninstalls with it
# A real install puts worthless on PATH; the service installer resolves the
# binary from PATH, so mirror that rather than calling it by absolute path.
RUN="export PATH=$(dirname "$BIN"):\$PATH &&"
check "worthless installed and runs" "runuser -l $USER_NAME -c '$RUN worthless --version' >/dev/null 2>&1"

say "4. which keyring does WSL actually pick?"
# worthless-2z8y: this has only ever been inferred from reading keystore.py.
# Deliberately NOT forcing WORTHLESS_KEYRING_BACKEND — we want the real answer.
runuser -l "$USER_NAME" -c "$RUN python -c 'import keyring; print(type(keyring.get_keyring()).__module__ + \".\" + type(keyring.get_keyring()).__name__)'" 2>&1 | sed 's/^/  backend: /'

say "5. lock a .env"
PROJ="$HOME_DIR/proj"
runuser -l "$USER_NAME" -c "mkdir -p $PROJ"
KEY="sk-proj-$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
# worthless-vck0: a second, stand-in key routed to fake_provider.py, which says
# 200 only for this exact key. The restart leg sends a real request with it:
# /healthz never touches the key, so it cannot show protection still works.
MOCK_KEY="sk-live-$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
(umask 077; printf '%s' "$MOCK_KEY" > "$HOME/wsl-localmock.key")
runuser -l "$USER_NAME" -c "mkdir -p ~/.worthless && printf '[provider.localmock]\nurl = \"http://127.0.0.1:$PROVIDER_PORT/v1\"\nprotocol = \"openai\"\n' > ~/.worthless/providers.toml"
runuser -l "$USER_NAME" -c "printf 'OPENAI_API_KEY=%s\nLOCALMOCK_API_KEY=%s\nLOCALMOCK_BASE_URL=http://127.0.0.1:$PROVIDER_PORT/v1\n' '$KEY' '$MOCK_KEY' > $PROJ/.env"
runuser -l "$USER_NAME" -c "$RUN cd $PROJ && worthless lock" > /tmp/lock.log 2>&1
LOCK_RC=$?
sed 's/^/  | /' /tmp/lock.log | tail -15
check "lock exits 0" "[ $LOCK_RC -eq 0 ]"
check "the real key is gone from .env" "! grep -q '$KEY' $PROJ/.env"
check "the stand-in key is gone from .env" "! grep -q '$MOCK_KEY' $PROJ/.env"

say "5b. an unreadable key is refused, never replaced (worthless-6hu7)"
# WSL is where modes drift: drvfs/\/mnt\/c mounts, copies from Windows, and
# restores all land at 0644. A key we refuse to READ must never be WRITTEN
# over — before the fix this was read as "no key" and a replacement was minted.
KEYFILE="$HOME_DIR/.worthless/fernet.key"
# A missing key here means step 5 did not leave one behind — that is a FAILURE,
# not a reason to skip. A conditional check reports green whether or not it ran.
check "a key exists to test against" "[ -f $KEYFILE ]"
if [ -f "$KEYFILE" ]; then
  BEFORE_SUM=$(md5sum "$KEYFILE" | cut -d" " -f1)
  runuser -l "$USER_NAME" -c "chmod 0644 $KEYFILE"
  runuser -l "$USER_NAME" -c "$RUN worthless status" > /tmp/refused.log 2>&1
  AFTER_SUM=$(md5sum "$KEYFILE" | cut -d" " -f1)
  fact "mode under test" "0644"
  check "the key is byte-identical afterwards" "[ \"$BEFORE_SUM\" = \"$AFTER_SUM\" ]"
  check "the refusal names the chmod fix" "grep -q 'chmod 0600' /tmp/refused.log"
  runuser -l "$USER_NAME" -c "chmod 0600 $KEYFILE"
fi

say "6. service install — the WSL-specific behaviour"
UNIT="$HOME_DIR/.config/systemd/user/worthless-proxy.service"
# The command's OWN --yes. The global `worthless --yes service install` is
# ignored by this command, which then prompts, finds no stdin, and cancels with
# exit 130 — the first real run did exactly that on both legs.
runuser -l "$USER_NAME" -c "$RUN worthless service install --yes" > /tmp/svc.log 2>&1
SVC_RC=$?
sed 's/^/  | /' /tmp/svc.log | tail -12
fact "service install exit" "$SVC_RC"
fact "unit file left on disk" "$([ -f "$UNIT" ] && echo yes || echo no)"

if [ "$SYSTEMD_EXPECTED" = "on" ]; then
  check "service install succeeds with systemd on" "[ $SVC_RC -eq 0 ]"
  check "it did not stop at a prompt" "! grep -q 'Cancelled' /tmp/svc.log"
  sleep 3
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz" 2>/dev/null || echo 000)
  fact "healthz" "$CODE"
  check "proxy answers" "[ '$CODE' = '200' ]"
  # WOR-860: on real WSL `status` must give the WSL wording, not the Linux one.
  # Run through `runuser -l`, which clears WSL_DISTRO_NAME, so this also proves
  # the kernel-string WSL detection reaches the message.
  runuser -l "$USER_NAME" -c "$RUN worthless status" > /tmp/status-svc.log 2>&1
  sed 's/^/  | /' /tmp/status-svc.log | head -3
  check "status says it starts with this WSL distro" "grep -q 'starts with this WSL distro' /tmp/status-svc.log"
  check "status gives the .wslconfig fix" "grep -q 'instanceIdleTimeout=-1' /tmp/status-svc.log"
else
  # The default WSL user's reality. Must not claim success.
  # Must fail for a REAL reason. Exit 130 is a cancelled prompt, which says
  # nothing about systemd — counting it as a pass would be a false green.
  check "service install is refused with systemd off" "[ $SVC_RC -ne 0 ] && [ $SVC_RC -ne 130 ]"
  check "the refusal is not a cancelled prompt" "! grep -q 'Cancelled' /tmp/svc.log"
  # Reported, not asserted: before PR #599 lands, the old path writes the unit
  # BEFORE checking linger and leaves it orphaned; #599 reorders that. Asserting
  # it would make this job red for a known, already-fixed bug.
  if grep -q 'wsl.conf' /tmp/svc.log; then
    fact "error names /etc/wsl.conf" "yes (PR #599 behaviour)"
  else
    fact "error names /etc/wsl.conf" "no — pre-#599 message"
  fi
  # WOR-860: without a service, a proxy from `worthless up` must be reported as
  # ending at a restart OR when the last WSL window closes (the distro stops).
  runuser -l "$USER_NAME" -c "$RUN nohup worthless up > /tmp/up.log 2>&1 &"
  for _ in $(seq 20); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz" 2>/dev/null)" = 200 ] && break
    sleep 1
  done
  # Say it plainly if `up` never answered, so that reads as "proxy never
  # started", not as a wording failure.
  fact "worthless up healthz" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz" 2>/dev/null)"
  runuser -l "$USER_NAME" -c "$RUN worthless status" > /tmp/status-up.log 2>&1
  sed 's/^/  | /' /tmp/status-up.log | head -3
  check "status says protected now, not after a restart" "grep -q \"You're protected now\" /tmp/status-up.log"
  check "status says the last WSL window ends it" "grep -q 'once your last WSL window closes' /tmp/status-up.log"
  runuser -l "$USER_NAME" -c "$RUN worthless down" > /dev/null 2>&1
fi

say "VERDICT (systemd=$SYSTEMD_EXPECTED)"
if [ "$FAILURES" -eq 0 ]; then echo "  all checks passed"; exit 0; fi
echo "  $FAILURES check(s) failed"
exit 1
