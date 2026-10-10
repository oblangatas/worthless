#!/usr/bin/env bash
# Does the launchd accept path actually work? (worthless-tg4q)
#
# Every launchd test in this repo patches `run_cmd`, so `launchctl` has never
# run in CI — `grep -rl launchctl tests/ .github/` found only mocked files.
# A macOS user can say yes to the service offer today and nobody has ever
# watched that install and serve. macOS is the primary platform. This is the
# WSL suite's sibling: same shape, same assert-don't-report rule.
#
# WHAT THIS CAN DISCOVER, and why it is worth running even if it goes red:
# `launchd.py` registers in `gui/$UID`, which needs a graphical login session.
# A CI runner, an SSH-only Mac, or a build box may have no Aqua session at all.
# If that is so, the background service cannot install there, and that is a
# real product limitation nobody has written down — not a broken test. The
# environment block below reports exactly which domains exist so a red run
# says WHY rather than just failing.
set -uo pipefail

# Resolved before HOME is redirected, so the checkout is still findable.
REPO="${REPO:-$(pwd)}"
PORT="${WORTHLESS_PORT:-18799}"
FAILURES=0

say() { printf '\n=== %s ===\n' "$1"; }
fact() { printf '  %-30s %s\n' "$1" "$2"; }
check() {
  if eval "$2"; then printf '  PASS  %s\n' "$1"
  else printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); fi
}

say "1. what kind of macOS session is this?"
UID_NUM=$(id -u)
fact "uid" "$UID_NUM"
fact "launchctl managername" "$(launchctl managername 2>/dev/null || echo '<unavailable>')"
for domain in "gui/$UID_NUM" "user/$UID_NUM"; do
  if launchctl print "$domain" >/dev/null 2>&1; then
    fact "$domain" "exists"
  else
    fact "$domain" "NOT AVAILABLE"
  fi
done
# Not a check: a missing gui domain is the finding, and step 4 is where it
# surfaces as a real install failure with launchctl's own error attached.
if ! launchctl print "gui/$UID_NUM" >/dev/null 2>&1; then
  printf '  NOTE  gui/%s is absent. worthless installs there, so the accept\n' "$UID_NUM"
  printf '        path cannot work on a Mac without a graphical login. If the\n'
  printf '        install below fails, that is the product, not the harness.\n'
fi

say "2. install worthless from this checkout"
HOME_DIR=$(mktemp -d)
export HOME="$HOME_DIR"
export WORTHLESS_HOME="$HOME_DIR/.worthless"
export WORTHLESS_KEYRING_BACKEND=null
export WORTHLESS_PORT="$PORT"
fact "throwaway HOME" "$HOME_DIR"
python3 -m venv "$HOME_DIR/venv" >/dev/null 2>&1
"$HOME_DIR/venv/bin/pip" install -q --no-input "$REPO" 2>&1 | tail -2
WORTHLESS="$HOME_DIR/venv/bin/worthless"
check "worthless is installed" "[ -x '$WORTHLESS' ]"
fact "version" "$("$WORTHLESS" --version 2>&1 | head -1)"

say "3. a key exists, so the service preflight can pass"
PROJ="$HOME_DIR/proj"
mkdir -p "$PROJ"
# Generated, not a literal. A realistic-looking key committed to the repo trips
# gitleaks (correctly), and a repeated-character placeholder is skipped by
# worthless's own scanner — so it has to be built at runtime to be both.
FAKE_BODY=$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 48)
printf 'OPENAI_API_KEY=%s-%s\n' "sk-proj" "$FAKE_BODY" > "$PROJ/.env"
"$WORTHLESS" lock --env "$PROJ/.env" > "$HOME_DIR/lock.log" 2>&1
LOCK_RC=$?
fact "lock exit" "$LOCK_RC"
check "lock succeeded" "[ $LOCK_RC -eq 0 ]"
check "fernet key exists for the preflight" "[ -f '$WORTHLESS_HOME/fernet.key' ]"

say "4. THE ACCEPT PATH — install the service for real"
"$WORTHLESS" service install --yes > "$HOME_DIR/install.log" 2>&1
INSTALL_RC=$?
fact "service install exit" "$INSTALL_RC"
sed 's/^/  | /' "$HOME_DIR/install.log"
check "service install succeeded" "[ $INSTALL_RC -eq 0 ]"

PLIST="$HOME_DIR/Library/LaunchAgents/sh.worthless.proxy.plist"
check "a plist was written" "[ -f '$PLIST' ]"
if launchctl print "gui/$UID_NUM/sh.worthless.proxy" >/dev/null 2>&1; then
  fact "job registered with launchd" "yes"
else
  fact "job registered with launchd" "NO"
  FAILURES=$((FAILURES + 1))
  printf '  FAIL  launchd does not know about the job\n'
fi

say "5. does it actually serve? (the altitude that matters)"
CODE=000
for _ in $(seq 30); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz" 2>/dev/null || echo 000)
  [ "$CODE" = "200" ] && break
  sleep 1
done
fact "healthz" "$CODE"
check "the proxy answers" "[ '$CODE' = '200' ]"

say "6. uninstall leaves nothing behind"
"$WORTHLESS" service uninstall --yes > "$HOME_DIR/uninstall.log" 2>&1
UNINSTALL_RC=$?
fact "uninstall exit" "$UNINSTALL_RC"
check "uninstall succeeded" "[ $UNINSTALL_RC -eq 0 ]"
check "plist is gone" "[ ! -f '$PLIST' ]"
check "launchd forgot the job" "! launchctl print 'gui/$UID_NUM/sh.worthless.proxy' >/dev/null 2>&1"

say "VERDICT"
# Always try to clean up, even on failure: a registered job outliving the run
# would poison the next one on a reused runner.
launchctl bootout "gui/$UID_NUM" "$PLIST" >/dev/null 2>&1 || true
rm -rf "$HOME_DIR"
if [ "$FAILURES" -eq 0 ]; then
  echo "  the macOS accept path works end to end"
  exit 0
fi
echo "  $FAILURES check(s) failed"
exit 1
