#!/usr/bin/env bash
# Single-container supervisor for the WOR-307 sidecar prototype.
#
# Starts the sidecar as uid worthless-crypto, waits for its ready line,
# then runs the smoke client as uid worthless-proxy. Exits with the
# smoke client's status. Sidecar is killed on exit so tini reaps it.
#
# tini (PID 1) forwards SIGTERM to us; we forward it to both children.
# This is deliberately the simplest thing that demonstrates the pattern
# for WOR-307 gate — WOR-309's production deploy can swap in a proper
# supervisor (systemd, s6-overlay) behind the same interface.

set -euo pipefail

SOCKET="${WORTHLESS_SIDECAR_SOCKET:-/var/run/worthless/sidecar.sock}"
SHARE_A="${WORTHLESS_SIDECAR_SHARE_A:-/secrets/share_a.bin}"
SHARE_B="${WORTHLESS_SIDECAR_SHARE_B:-/secrets/share_b.bin}"

log() { printf '[supervise] %s\n' "$*" >&2; }

# Generate test shares in-image if none mounted. Prototype only — production
# shares are mounted read-only from a secrets manager.
if [[ ! -f "${SHARE_A}" || ! -f "${SHARE_B}" ]]; then
  log "no shares mounted; generating ephemeral ones for smoke test"
  gosu worthless-crypto python /usr/local/bin/gen_shares.py "${SHARE_A}" "${SHARE_B}"
fi

# Install the cleanup trap BEFORE spawning the sidecar so a SIGTERM that
# arrives between the `&` fork and the PID capture still reaps the child.
# SIDECAR_PID is unset at install time; the `:-` default makes the kill
# a no-op in that window.
SIDECAR_PID=""
cleanup() {
  local code=$?
  if [[ -n "${SIDECAR_PID:-}" ]]; then
    log "cleanup: killing sidecar (pid=${SIDECAR_PID})"
    kill -TERM "${SIDECAR_PID}" 2>/dev/null || true
    wait "${SIDECAR_PID}" 2>/dev/null || true
  fi
  exit "${code}"
}
trap cleanup EXIT INT TERM

log "starting sidecar as worthless-crypto"
gosu worthless-crypto python -m worthless.sidecar &
SIDECAR_PID=$!

# Wait up to 5s for the sidecar socket to appear. The __main__ entry
# prints a "sidecar: ready socket=..." line but we watch the FS path
# because the client can't start until the socket actually exists.
for _ in $(seq 1 50); do
  if [[ -S "${SOCKET}" ]]; then
    break
  fi
  sleep 0.1
done

if [[ ! -S "${SOCKET}" ]]; then
  log "sidecar did not create ${SOCKET} within 5s"
  exit 1
fi

log "sidecar ready at ${SOCKET}; running smoke client as worthless-proxy"
gosu worthless-proxy python /usr/local/bin/smoke_client.py
