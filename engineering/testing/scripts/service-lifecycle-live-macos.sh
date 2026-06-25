#!/usr/bin/env bash
# Service lifecycle live pack — macOS launchd. See ../wor-193-live-checklist.md
set -euo pipefail

PORT="${WORTHLESS_PORT:-8787}"
PLIST="$HOME/Library/LaunchAgents/dev.worthless.proxy.plist"
if [[ -n "${WORTHLESS_HOME:-}" ]]; then
  resolved_home="$(cd "$WORTHLESS_HOME" && pwd)"
  default_home="$(cd "$HOME/.worthless" && pwd)"
  if [[ "$resolved_home" != "$default_home" ]]; then
    echo "WORTHLESS_HOME=$WORTHLESS_HOME (resolved: $resolved_home)"
    echo "This live pack expects ~/.worthless. Run: unset WORTHLESS_HOME"
    exit 1
  fi
fi
WORTHLESS_HOME="${WORTHLESS_HOME:-$HOME/.worthless}"

if [[ -f "$PLIST" ]]; then
  if ! grep -q "$(cd "$WORTHLESS_HOME" && pwd)" "$PLIST" && ! grep -q "$WORTHLESS_HOME" "$PLIST"; then
    echo "Foreign plist (different WORTHLESS_HOME). Manual cleanup required:"
    echo "  grep WORTHLESS_HOME $PLIST"
    echo "  launchctl bootout gui/$(id -u) $PLIST 2>/dev/null || true"
    echo "  rm -f $PLIST"
    echo "Then re-run this script."
    exit 1
  fi
  echo "Removing existing owned plist before install..."
  worthless service uninstall --yes || true
fi

# Stop session proxy (pid file) so install owns port 8787 cleanly
worthless down 2>/dev/null || true

# --- L720-0: baseline ---
worthless --json service status | tee /tmp/worthless-service-lifecycle-0.json
worthless service install --yes
test -f "$PLIST"
grep -q "WORTHLESS_SERVICE_MANAGED" "$PLIST"
grep -q "WORTHLESS_HOME" "$PLIST"
launchctl print "gui/$(id -u)/dev.worthless.proxy" >/dev/null

# --- L720-2: status running + healthy ---
worthless --json service status | tee /tmp/worthless-service-lifecycle-1.json
curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null

# --- L720-3: stop ---
worthless service stop
worthless --json service status | tee /tmp/worthless-service-lifecycle-2.json
curl -sf "http://127.0.0.1:${PORT}/healthz" && echo "UNEXPECTED: still healthy after stop" && exit 1 || true

# --- L720-4: start ---
worthless service start
worthless --json service status | tee /tmp/worthless-service-lifecycle-3.json
curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null

# --- L720-5: restart ---
worthless service restart
curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null

# --- L720-6: logs (smoke) ---
worthless service logs | tail -5

# --- L720-7: uninstall, keys intact ---
SHARD_COUNT_BEFORE=$(find "${WORTHLESS_HOME:-$HOME/.worthless}"/shard_a -type f 2>/dev/null | wc -l | tr -d ' ')
worthless service uninstall --yes
test ! -f "$PLIST"
SHARD_COUNT_AFTER=$(find "${WORTHLESS_HOME:-$HOME/.worthless}"/shard_a -type f 2>/dev/null | wc -l | tr -d ' ')
test "$SHARD_COUNT_BEFORE" = "$SHARD_COUNT_AFTER"

echo "service lifecycle live pack (macOS): PASS"
