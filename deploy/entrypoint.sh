#!/bin/sh
# Composes uvicorn bind + proxy-header trust list from WORTHLESS_DEPLOY_MODE.
set -e

HOME_DIR="${WORTHLESS_HOME:-/data}"
FERNET_PATH="${WORTHLESS_FERNET_KEY_PATH:-$HOME_DIR/fernet.key}"
MODE="${WORTHLESS_DEPLOY_MODE:-loopback}"
PORT="${PORT:-8787}"

# Refuse unsafe combinations before Python startup. Exit 78 = sysexits EX_CONFIG.
if [ "$MODE" = "public" ]; then
  if [ "${WORTHLESS_ALLOW_INSECURE:-}" = "true" ] || [ "${WORTHLESS_ALLOW_INSECURE:-}" = "1" ]; then
    echo "FATAL: WORTHLESS_ALLOW_INSECURE is forbidden when WORTHLESS_DEPLOY_MODE=public." >&2
    echo "       Set WORTHLESS_TRUSTED_PROXIES=<edge-CIDR> instead." >&2
    exit 78
  fi
  if [ -z "${WORTHLESS_TRUSTED_PROXIES:-}" ]; then
    echo "FATAL: WORTHLESS_DEPLOY_MODE=public requires WORTHLESS_TRUSTED_PROXIES" >&2
    echo "       (CIDR of the edge layer, e.g. Render/Fly internal CIDR)." >&2
    exit 78
  fi
fi

# Migrate fernet.key to a separate volume when WORTHLESS_FERNET_KEY_PATH is
# explicitly set (e.g., docker-compose with a secrets volume).  Without the
# env var the key stays on the data volume — safe for single-volume PaaS.
if [ -n "$WORTHLESS_FERNET_KEY_PATH" ] && [ ! -f "$FERNET_PATH" ] && [ -f "$HOME_DIR/fernet.key" ]; then
  install -m 0400 "$HOME_DIR/fernet.key" "$FERNET_PATH"
  rm "$HOME_DIR/fernet.key"
fi

# Bootstrap on first boot only (idempotent but skips Python startup on restarts)
if [ ! -f "$FERNET_PATH" ]; then
  python -c "from worthless.cli.bootstrap import get_home; get_home()"
  # Lock down fernet.key after bootstrap — can't use umask 0377 during
  # bootstrap because SQLite WAL/SHM files also get created and need
  # to be writable.
  chmod 0400 "$FERNET_PATH"
fi

# Best-effort: seed the OpenClaw config stub on the shared volume so that
# `worthless lock` can detect openclaw before the openclaw container starts.
# Only runs when WORTHLESS_OPENCLAW_CONFIG_SHARED=1 (all-container Docker
# setup). In host or single-container deployments the openclaw config dir
# is the user's ~/.openclaw and must keep its default permissions.
if [ "${WORTHLESS_OPENCLAW_CONFIG_SHARED:-}" = "1" ]; then
  OPENCLAW_DIR="${HOME_DIR}/.openclaw"
  mkdir -p "$OPENCLAW_DIR" 2>/dev/null || true
  chmod 777 "$OPENCLAW_DIR" 2>/dev/null || true
  [ -f "${OPENCLAW_DIR}/openclaw.json" ] || {
    printf '{}' > "${OPENCLAW_DIR}/openclaw.json" 2>/dev/null || true
    chmod 666 "${OPENCLAW_DIR}/openclaw.json" 2>/dev/null || true
  }
fi

# Pass Fernet key via file descriptor (not env var — env is visible in /proc)
exec 3< "$FERNET_PATH"
export WORTHLESS_FERNET_FD=3

case "$MODE" in
  public)
    HOST="0.0.0.0"
    set -- uvicorn worthless.proxy.app:create_app --factory \
      --host "$HOST" --port "$PORT" \
      --proxy-headers --forwarded-allow-ips="$WORTHLESS_TRUSTED_PROXIES"
    ;;
  lan)
    HOST="${WORTHLESS_HOST:-0.0.0.0}"
    if [ -n "${WORTHLESS_TRUSTED_PROXIES:-}" ]; then
      set -- uvicorn worthless.proxy.app:create_app --factory \
        --host "$HOST" --port "$PORT" \
        --proxy-headers --forwarded-allow-ips="$WORTHLESS_TRUSTED_PROXIES"
    else
      set -- uvicorn worthless.proxy.app:create_app --factory \
        --host "$HOST" --port "$PORT"
    fi
    ;;
  loopback)
    HOST="${WORTHLESS_HOST:-127.0.0.1}"
    set -- uvicorn worthless.proxy.app:create_app --factory \
      --host "$HOST" --port "$PORT"
    ;;
  *)
    echo "FATAL: unknown WORTHLESS_DEPLOY_MODE=$MODE (expected loopback|lan|public)" >&2
    exit 78
    ;;
esac

exec "$@"
