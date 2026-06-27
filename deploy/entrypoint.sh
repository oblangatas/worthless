#!/bin/sh
# Composes uvicorn bind + proxy-header trust list from WORTHLESS_DEPLOY_MODE.
# Single-container lifecycle: deploy/start.py runs split_to_tmpfs +
# spawn_sidecar and then execs uvicorn so tini supervises both processes as
# siblings. The proxy requires an IPC peer and refuses to start without one,
# so a plain ``exec uvicorn`` would never bind.
set -e

# WOR-310 Phase D: belt-and-suspenders core-dump disable. Phase A's
# PR_SET_DUMPABLE=0 (in the sidecar process via ctypes prctl) is the
# primary defense — the kernel won't write a core dump for the sidecar
# even if uvicorn or some other process in the container faults
# spectacularly. ulimit -c 0 here protects EVERY process in the
# container (including the briefly-root entrypoint itself) from being
# core-dumped if it crashes before set_dumpable_zero runs.  Set BEFORE
# any python executes so even bootstrap errors can't dump.
ulimit -c 0 || true

# WOR-465 A4: the IPC-only topology is permanent — fernet.key is locked to
# worthless-crypto:worthless-crypto 0400 unconditionally.  An explicit =0
# override would cause the proxy uid to attempt a direct file read that the
# kernel will reject with EACCES.  Fail closed immediately rather than letting
# the container start in a half-broken state.
if [ "${WORTHLESS_FERNET_IPC_ONLY:-1}" = "0" ]; then
  echo "FATAL: WORTHLESS_FERNET_IPC_ONLY=0 is not valid in this image." >&2
  echo "  fernet.key is locked to worthless-crypto:worthless-crypto 0400 unconditionally." >&2
  echo "  The proxy uid cannot read it directly — =0 would break the container." >&2
  echo "  Remove the WORTHLESS_FERNET_IPC_ONLY=0 override from your environment." >&2
  echo "  For bare-metal installs (no sidecar), use install.sh, not Docker." >&2
  exit 78
fi

HOME_DIR="${WORTHLESS_HOME:-/data}"
FERNET_PATH="${WORTHLESS_FERNET_KEY_PATH:-$HOME_DIR/fernet.key}"
MODE="${WORTHLESS_DEPLOY_MODE:-loopback}"
PORT="${PORT:-8787}"

# Refuse unsafe combinations before Python startup. Exit 78 = sysexits EX_CONFIG.
case "$MODE" in
  loopback|lan|public)
    ;;
  *)
    echo "FATAL: unknown WORTHLESS_DEPLOY_MODE=$MODE (expected loopback|lan|public)" >&2
    exit 78
    ;;
esac

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
  # Mode 0440 at copy time (owner root, group root — proxy uid 10001 cannot
  # read it; neither can worthless-crypto until the chown below).  The
  # priv-drop block re-owns to worthless-crypto:worthless-crypto and sets
  # 0400; proxy uid has no access at any point. WOR-465 A4.
  install -m 0440 "$HOME_DIR/fernet.key" "$FERNET_PATH"
  rm "$HOME_DIR/fernet.key"
fi

# Bootstrap on first boot only (idempotent but skips Python startup on restarts)
if [ ! -f "$FERNET_PATH" ]; then
  python -c "from worthless.cli.bootstrap import get_home; get_home()"
fi

# Best-effort: seed the OpenClaw config stub on the shared volume so that
# `worthless lock` can detect openclaw before the openclaw container starts.
# Only runs when WORTHLESS_OPENCLAW_CONFIG_SHARED=1 (all-container Docker
# setup). In host or single-container deployments the openclaw config dir
# is the user's ~/.openclaw and must keep its default permissions.
# Runs as root (entrypoint starts as uid 0); the priv-drop block below
# re-owns this dir to worthless-proxy:worthless via the recursive find.
if [ "${WORTHLESS_OPENCLAW_CONFIG_SHARED:-}" = "1" ]; then
  OPENCLAW_DIR="${HOME_DIR}/.openclaw"
  mkdir -p "$OPENCLAW_DIR" 2>/dev/null || true
  chmod 770 "$OPENCLAW_DIR" 2>/dev/null || true
  [ -f "${OPENCLAW_DIR}/openclaw.json" ] || printf '{}' > "${OPENCLAW_DIR}/openclaw.json" 2>/dev/null || true
  chmod 660 "${OPENCLAW_DIR}/openclaw.json" 2>/dev/null || true
fi

# WOR-310: bootstrap ran as root (entrypoint started as uid 0 so
# deploy/start.py can do the priv-drop dance) — every file/dir it
# touched is now root:root.  After the dance the proxy runs as
# worthless-proxy (uid 10001) and the sidecar reads shares as
# worthless-crypto (uid 10002); without this chown they hit
# PermissionError on /data/shard_a, /data/worthless.db, fernet.key.
# Idempotent: chown is no-op if already correct, safe on every boot.
# We narrow to the dirs/files we own at the image level (created by
# the Dockerfile or by bootstrap) — never blanket-chown /data because
# user-mounted volumes might have prior content with different
# semantics.
if [ "$(id -u)" = "0" ]; then
  # CR-3204010079 (CRITICAL): a recursive chown on $HOME_DIR would
  # re-own fernet.key to worthless-proxy, letting a proxy-RCE
  # `chmod 0600` and re-create the file.  Skip fernet.key in the
  # recursive chown.
  find "$HOME_DIR" -mindepth 1 -not -path "$FERNET_PATH" \
    -exec chown worthless-proxy:worthless {} + 2>/dev/null || true
  # WOR-465 A4: sidecar owns the Fernet key unconditionally — the A1 flag
  # gate is gone. Fail closed: a host bind-mount on macOS Docker Desktop or
  # WSL /mnt/c/... can silently swallow chown/chmod; the stat check verifies
  # the kernel applied our changes and exits 78 (EX_CONFIG) on mismatch.
  if [ -f "$FERNET_PATH" ]; then
    chown worthless-crypto:worthless-crypto "$FERNET_PATH" 2>/dev/null || true
    chmod 0400 "$FERNET_PATH" 2>/dev/null || true
    actual="$(stat -c '%U:%G %a' "$FERNET_PATH" 2>/dev/null || echo unknown)"
    if [ "$actual" != "worthless-crypto:worthless-crypto 400" ]; then
      echo "FATAL: $FERNET_PATH permissions were not enforced." >&2
      echo "  Got:      $actual" >&2
      echo "  Expected: worthless-crypto:worthless-crypto 400" >&2
      echo "  Fix: use a Docker named volume — storage backends (macOS Docker Desktop bind-mounts, WSL /mnt/c) silently drop chown/chmod." >&2
      exit 78
    fi
  fi
  # bootstrap.ensure_home pinned $HOME_DIR to mode 0o700 — that's
  # owner-only.  After we chowned to worthless-proxy:worthless, the
  # sidecar (worthless-crypto, in group worthless) can't traverse
  # into $HOME_DIR to reach the share files at all.  Bump to 0o710:
  # owner rwx, worthless group --x (traverse only — no list of
  # sibling files in /data).
  chmod 0710 "$HOME_DIR" 2>/dev/null || true
fi

# WORTHLESS_DEPLOY_MODE / WORTHLESS_TRUSTED_PROXIES / WORTHLESS_HOST flow
# through the environment into deploy/start.py, which composes the uvicorn
# argv (host + --proxy-headers + --forwarded-allow-ips) before exec.
export WORTHLESS_DEPLOY_MODE="$MODE"
export PORT="$PORT"

# WOR-310 C3: signal to deploy/start.py that we're in the Docker single-
# container topology. start.py uses this AND euid==0 to decide whether
# to resolve worthless-proxy/worthless-crypto via getpwnam and run the
# priv-drop dance. Bare-metal install.sh never sets this; bare-metal
# start.py path returns service_uids=None and preserves single-uid
# behavior. Without this signal, even sudo-running this script would
# skip the drop — only the container path triggers it.
export WORTHLESS_DOCKER_PRIVDROP_REQUIRED=1

exec python /deploy/start.py
