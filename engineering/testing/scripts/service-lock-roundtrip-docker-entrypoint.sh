#!/usr/bin/env bash
# Runs inside Dockerfile.service-lifecycle-live-linux — boot systemd, then lock roundtrip pack.
set -euo pipefail

if [[ ! -d /repo ]]; then
  echo "Expected repo bind-mount at /repo"
  exit 1
fi

system_state="$(systemctl is-system-running 2>/dev/null || true)"
if [[ "$system_state" != "running" && "$system_state" != "degraded" ]]; then
  echo "systemd is not ready (state=${system_state:-unknown}) — start container with --privileged and cgroup mount"
  exit 1
fi

export XDG_RUNTIME_DIR="/run/user/0"
mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"

loginctl enable-linger root 2>/dev/null || true

cd /repo
uv sync --frozen 2>/dev/null || uv sync
uv pip install -e .

export PATH="/repo/.venv/bin:${PATH}"
unset WORTHLESS_HOME

exec dbus-run-session -- bash /repo/engineering/testing/scripts/service-lock-roundtrip-live-linux.sh
