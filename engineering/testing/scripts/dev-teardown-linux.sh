#!/usr/bin/env bash
# Dev teardown: stop systemd user unit / foreground proxy, clear stale sidecar run dirs.
# Does NOT purge libsecret/keyring Fernet key or ~/.worthless DB.
set -euo pipefail

PORT="${WORTHLESS_PORT:-8787}"
UNIT="${HOME}/.config/systemd/user/worthless-proxy.service"

echo "Dev teardown (Linux): stopping worthless user service..."

worthless service uninstall --yes 2>/dev/null || true
worthless down 2>/dev/null || true

rm -f "${HOME}/.worthless/proxy.pid" 2>/dev/null || true
rm -rf "${HOME}/.worthless/run" 2>/dev/null || true

if [[ -f "$UNIT" ]]; then
  echo "WARN: systemd unit still present at $UNIT"
  exit 1
fi

echo "Dev teardown done: unit removed, proxy stopped, run/ cleared."
echo "Fernet key + enrollments preserved. Full purge: docs/install/linux.md § uninstall."
