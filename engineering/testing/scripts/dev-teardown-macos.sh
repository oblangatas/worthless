#!/usr/bin/env bash
# Dev teardown: stop launchd/foreground proxy and remove stale sidecar run dirs.
# Does NOT purge Fernet key (Keychain/file) or ~/.worthless DB — see wor-193-live-checklist.md.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=engineering/testing/scripts/_live-pack-lib.sh
source "${SCRIPT_DIR}/_live-pack-lib.sh"

PORT="${WORTHLESS_PORT:-8787}"
PLIST="${HOME}/Library/LaunchAgents/dev.worthless.proxy.plist"

kill_sidecar_orphans() {
  command -v pgrep >/dev/null 2>&1 || return 0
  local pids
  pids="$(pgrep -f '[p]ython -m worthless\.sidecar' 2>/dev/null || true)"
  [[ -n "$pids" ]] || return 0
  lp_step "killing orphan sidecar PID(s): ${pids}"
  # shellcheck disable=SC2086
  kill -TERM ${pids} 2>/dev/null || true
  sleep 0.5
  pids="$(pgrep -f '[p]ython -m worthless\.sidecar' 2>/dev/null || true)"
  if [[ -n "$pids" ]]; then
    # shellcheck disable=SC2086
    kill -KILL ${pids} 2>/dev/null || true
  fi
}

lp_banner "dev-teardown (macOS)"

lp_phase "Stop launchd + foreground proxy"
lp_step "worthless service uninstall --yes"
worthless service uninstall --yes 2>/dev/null || true
lp_step "worthless down"
worthless down 2>/dev/null || true
kill_sidecar_orphans

lp_phase "Clear proxy state"
lp_step "remove ~/.worthless/proxy.pid and run/"
rm -f "${HOME}/.worthless/proxy.pid" 2>/dev/null || true
rm -rf "${HOME}/.worthless/run" 2>/dev/null || true
lp_ok "pid file + run/ cleared"

if command -v lsof >/dev/null 2>&1; then
  pids="$(lsof -ti "tcp:${PORT}" -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "$pids" ]]; then
    lp_step "kill stale listener(s) on :${PORT}: ${pids}"
    # shellcheck disable=SC2086
    kill -TERM ${pids} 2>/dev/null || true
  fi
fi

if [[ -f "$PLIST" ]]; then
  lp_fail "plist still present: ${PLIST}"
  exit 1
fi

lp_ok "launchd job removed, proxy stopped"
lp_warn "Fernet key + enrollments preserved (not a full uninstall)"
lp_step "full machine purge → wor-193-live-checklist.md § Dev machine reset"
lp_step "Background Items UI may lag — toggle off in System Settings if shown"
