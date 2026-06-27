#!/usr/bin/env bash
# Live pack: lock → service install → proxied request → upstream receives real key.
# Manual L7 proof (not CI). Uses mock-upstream in Docker on localhost:9999.
#
# Cleanup on exit: service uninstall, worthless down, unlock+remove temp project dir.
# Does NOT purge Keychain or ~/.worthless — intentional (see wor-193-live-checklist.md).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Bare-metal live pack: lock must encrypt in-process, not via a stale sidecar IPC.
unset WORTHLESS_FERNET_IPC_ONLY WORTHLESS_KEYRING_BACKEND
# shellcheck source=engineering/testing/scripts/_live-pack-lib.sh
source "${SCRIPT_DIR}/_live-pack-lib.sh"
# shellcheck source=/dev/null
bash "${SCRIPT_DIR}/dev-teardown-macos.sh"
LP_PHASE_NUM=0
lp_banner "service-lock-roundtrip-live-macos (L7)"
lp_step "repo: ${REPO_ROOT}"
lp_step "worthless: $(command -v worthless 2>/dev/null || echo 'not on PATH yet')"
export PATH="${REPO_ROOT}/.venv/bin:${PATH}"
lp_step "PATH prefers: ${REPO_ROOT}/.venv/bin"
PORT="${WORTHLESS_PORT:-8787}"
MOCK_PORT="${MOCK_UPSTREAM_PORT:-9999}"
MOCK_URL="http://127.0.0.1:${MOCK_PORT}"
MOCK_BASE="${MOCK_URL}/v1"
MOCK_IMAGE="${MOCK_UPSTREAM_IMAGE:-worthless-mock-upstream:local}"
PLIST="$HOME/Library/LaunchAgents/dev.worthless.proxy.plist"

WORK_DIR="$(mktemp -d /tmp/worthless-live-project-XXXXXX)"
ENV_FILE=""
export WORTHLESS_ALLOW_INSECURE=true

MOCK_CID=""

cleanup() {
  lp_phase "Cleanup (trap EXIT)"
  worthless service uninstall --yes 2>/dev/null || true
  worthless down 2>/dev/null || true
  if [[ -n "${ENV_FILE:-}" && -f "$ENV_FILE" ]]; then
    lp_step "unlock temp project ${WORK_DIR} (WOR-747)"
    if ! worthless --yes unlock --env "$ENV_FILE"; then
      lp_warn "unlock failed for ${ENV_FILE}; run worthless doctor --fix before next run"
    fi
  fi
  if [[ -n "$MOCK_CID" ]]; then
    docker rm -f "$MOCK_CID" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK_DIR" 2>/dev/null || true
}
trap cleanup EXIT

if [[ -n "${WORTHLESS_HOME:-}" ]]; then
  resolved_home="$(cd "$WORTHLESS_HOME" && pwd)"
  default_home="$(cd "$HOME/.worthless" && pwd)"
  if [[ "$resolved_home" != "$default_home" ]]; then
    echo "WORTHLESS_HOME=$WORTHLESS_HOME (resolved: $resolved_home)"
    echo "This live pack expects ~/.worthless (providers.toml lives there). Run: unset WORTHLESS_HOME"
    exit 1
  fi
fi

if [[ -f "$PLIST" ]]; then
  if ! grep -q "$(cd "${HOME}/.worthless" && pwd)" "$PLIST" && ! grep -q "${HOME}/.worthless" "$PLIST"; then
    echo "Foreign plist (different WORTHLESS_HOME). Manual cleanup required:"
    echo "  grep WORTHLESS_HOME $PLIST"
    echo "  launchctl bootout gui/$(id -u) $PLIST 2>/dev/null || true"
    echo "  rm -f $PLIST"
    exit 1
  fi
  worthless service uninstall --yes 2>/dev/null || true
fi
worthless down 2>/dev/null || true

kill_port_listeners() {
  local port=$1
  command -v lsof >/dev/null 2>&1 || return 0
  local pids
  pids="$(lsof -ti "tcp:${port}" -sTCP:LISTEN 2>/dev/null || true)"
  [[ -n "$pids" ]] || return 0
  echo "Killing stale listener(s) on port ${port}: ${pids}"
  # shellcheck disable=SC2086
  kill -TERM ${pids} 2>/dev/null || true
  sleep 0.5
  pids="$(lsof -ti "tcp:${port}" -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "$pids" ]]; then
    # shellcheck disable=SC2086
    kill -KILL ${pids} 2>/dev/null || true
  fi
}

ensure_proxy_port_free() {
  lp_step "ensure :${PORT} free (orphan /healthz → sidecar-less 401)"
  worthless service uninstall --yes 2>/dev/null || true
  worthless down 2>/dev/null || true
  if command -v pgrep >/dev/null 2>&1; then
    local sidecar_pids
    sidecar_pids="$(pgrep -f '[p]ython -m worthless\.sidecar' 2>/dev/null || true)"
    if [[ -n "$sidecar_pids" ]]; then
      lp_step "kill orphan sidecar(s): ${sidecar_pids}"
      # shellcheck disable=SC2086
      kill -TERM ${sidecar_pids} 2>/dev/null || true
      sleep 0.5
    fi
  fi
  rm -f "${HOME}/.worthless/proxy.pid" 2>/dev/null || true
  rm -rf "${HOME}/.worthless/run" 2>/dev/null || true
  local attempt
  for attempt in 1 2 3 4 5 6; do
    if ! curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
      lp_ok "port ${PORT} free"
      return 0
    fi
    kill_port_listeners "$PORT"
    sleep 0.5
  done
  if curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
    lp_fail "port ${PORT} still serves /healthz after cleanup (worthless-6gkb orphan)"
    curl -s "http://127.0.0.1:${PORT}/healthz" || true
    exit 1
  fi
}

lp_phase "Preflight: port + enrollment hygiene"
ensure_proxy_port_free

# Stale lock files block doctor/lock if a prior run crashed mid-flight.
if [[ -f "${HOME}/.worthless/.lock-in-progress" ]]; then
  lock_age=$(( $(date +%s) - $(stat -f %m "${HOME}/.worthless/.lock-in-progress" 2>/dev/null || echo 0) ))
  if (( lock_age > 300 )); then
    rm -f "${HOME}/.worthless/.lock-in-progress"
  fi
fi
rm -f "${HOME}/.worthless/.up.lock" 2>/dev/null || true

lp_step "worthless doctor --fix (orphan enrollments)"
worthless doctor --fix --yes 2>/dev/null || true

lp_step "purge stale live-pack temp enrollments from DB"
(cd "$REPO_ROOT" && uv run python -c "
import asyncio
from worthless.cli.bootstrap import ensure_home
from worthless.storage.repository import ShardRepository

async def main() -> None:
    home = ensure_home()
    repo = ShardRepository(str(home.db_path), home.fernet_key)
    stale_aliases: set[str] = set()
    for rec in await repo.list_enrollments():
        if not rec.env_path or 'worthless-live-project' not in rec.env_path:
            continue
        await repo.delete_enrollment(rec.key_alias, rec.env_path)
        stale_aliases.add(rec.key_alias)
    for alias in stale_aliases:
        if not await repo.list_enrollments(alias):
            await repo.delete_enrolled(alias)

asyncio.run(main())
") 2>/dev/null || true

preflight_doctor() {
  lp_step "doctor check: fernet_drift (keyring vs fernet.key)"
  local drift_msg
  if ! drift_msg="$(cd "$REPO_ROOT" && uv run python -c "
import sys
from worthless.cli.bootstrap import ensure_home
from worthless.cli.commands.doctor.checks import fernet_drift
from worthless.cli.commands.doctor.registry import CheckContext
from worthless.storage.repository import ShardRepository

home = ensure_home()
repo = ShardRepository(str(home.db_path), home.fernet_key)
result = fernet_drift.run(
    CheckContext(home=home, repo=repo, fix=False, dry_run=False)
)
if result['status'] == 'error':
    print(result.get('summary', 'Fernet key drift detected'))
    sys.exit(1)
")"; then
    lp_fail "$drift_msg"
    lp_step "fix: worthless doctor — resolve fernet_drift, then re-run"
    exit 1
  fi
  lp_ok "no fernet drift"
}

sync_fernet_for_launchd() {
  lp_step "sync canonical Fernet → ~/.worthless/fernet.key (for launchd)"
  (cd "$REPO_ROOT" && uv run python -c "
from worthless.cli.bootstrap import ensure_home
from worthless.cli.keystore import _write_key_file, read_fernet_key
from worthless.crypto.types import zero_buf

home = ensure_home()
key = read_fernet_key(home.base_dir)
try:
    _write_key_file(bytes(key), home.base_dir)
finally:
    zero_buf(key)
")
  if [[ ! -f "${HOME}/.worthless/fernet.key" ]]; then
    lp_fail "fernet.key missing after sync — launchd will hit WRTLS-102"
    exit 1
  fi
  lp_ok "fernet.key present"
  preflight_doctor
}

lp_phase "Fernet sync (pre-lock)"
sync_fernet_for_launchd

wait_mock_healthy() {
  local deadline=$((SECONDS + 30))
  while ((SECONDS < deadline)); do
    if curl -sf "${MOCK_URL}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "mock-upstream did not become healthy on ${MOCK_URL}"
  return 1
}

lp_phase "Mock upstream (Docker :${MOCK_PORT})"
lp_step "docker build ${MOCK_IMAGE}"
docker build -t "$MOCK_IMAGE" "$REPO_ROOT/tests/openclaw/mock-upstream" >/dev/null

lp_step "docker run -p ${MOCK_PORT}:9999"
MOCK_CID="$(docker run -d --rm -p "${MOCK_PORT}:9999" "$MOCK_IMAGE")"
wait_mock_healthy
lp_ok "mock-upstream healthy at ${MOCK_URL}"

lp_phase "Lock temp project"
read -r REAL_KEY ALIAS <<<"$(cd "$REPO_ROOT" && uv run python -c "
import hashlib
import secrets
from tests.helpers import fake_key
key = fake_key('sk-proj-', seed=secrets.token_hex(16))
alias = 'openai-' + hashlib.sha256(key.encode()).hexdigest()[:8]
print(key, alias)
")"
lp_step "temp dir: ${WORK_DIR}"
lp_step "alias: ${ALIAS}"

ENV_FILE="$WORK_DIR/.env"
printf 'OPENAI_API_KEY=%s\nOPENAI_BASE_URL=%s\n' "$REAL_KEY" "$MOCK_BASE" >"$ENV_FILE"

if ! worthless providers list 2>/dev/null | grep -q 'openai-mock'; then
  lp_step "register provider openai-mock → ${MOCK_BASE}"
  worthless providers register \
    --name openai-mock \
    --url "$MOCK_BASE" \
    --protocol openai
fi

lp_step "worthless lock --env .env (in temp project)"
(cd "$WORK_DIR" && worthless --yes lock --env ".env")
SHARD_A="$(grep '^OPENAI_API_KEY=' "$ENV_FILE" | cut -d= -f2-)"
if [[ -z "$SHARD_A" || "$SHARD_A" == "$REAL_KEY" ]]; then
  lp_fail "lock did not rewrite OPENAI_API_KEY to shard-A"
  exit 1
fi
lp_ok "lock complete (shard-A in .env)"

lp_phase "Fernet sync (post-lock)"
sync_fernet_for_launchd

lp_phase "Verify lock ciphertext (local Fernet)"
lp_step "decrypt shard_b_enc with fernet.key on disk"
if ! (cd "$REPO_ROOT" && uv run python -c "
import asyncio, sys
from cryptography.fernet import Fernet
from worthless.cli.bootstrap import ensure_home
from worthless.cli.keystore import read_fernet_key_from_file
from worthless.storage.repository import ShardRepository

alias = sys.argv[1]

async def main() -> None:
    home = ensure_home()
    key = read_fernet_key_from_file(home.base_dir)
    repo = ShardRepository(str(home.db_path), key)
    enc = await repo.fetch_encrypted(alias)
    if enc is None:
        raise SystemExit(f'alias {alias!r} not in DB')
    Fernet(bytes(key)).decrypt(bytes(enc.shard_b_enc))
    print('local fernet decrypt ok')

asyncio.run(main())
" "$ALIAS"); then
  lp_fail "locked shard does not decrypt with ~/.worthless/fernet.key"
  lp_diag \
    "likely fernet drift or lock used stale sidecar IPC" \
    "WORTHLESS_FERNET_IPC_ONLY=${WORTHLESS_FERNET_IPC_ONLY:-unset} (script unsets this)" \
    "pgrep -fl worthless.sidecar"
  exit 1
fi
lp_ok "local fernet decrypt ok"

lp_phase "Launchd service install"
ensure_proxy_port_free

lp_step "worthless service install --yes"
if ! worthless service install --yes; then
  lp_fail "worthless service install failed"
  lp_log_tail "~/.worthless/proxy.log" "${HOME}/.worthless/proxy.log" 30
  exit 1
fi
lp_ok "plist installed, launchd job started"

wait_proxy_healthy() {
  local deadline=$((SECONDS + 60))
  while ((SECONDS < deadline)); do
    if curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "proxy did not become healthy on :${PORT} within 60s"
  lp_log_tail "~/.worthless/proxy.log" "${HOME}/.worthless/proxy.log" 10
  return 1
}

test -f "$PLIST"
wait_proxy_healthy
lp_ok "GET /healthz on 127.0.0.1:${PORT}"

dump_proxy_log() {
  lp_log_tail "~/.worthless/proxy.log" "${HOME}/.worthless/proxy.log" 30
}

lp_phase "Sidecar IPC decrypt preflight"
lp_step "alias ${ALIAS} — find socket that can open shard_b_enc"
sidecar_decrypt_preflight() {
  (cd "$REPO_ROOT" && uv run python -c "
import asyncio, os, sys
from worthless.cli.bootstrap import ensure_home
from worthless.cli.keystore import read_fernet_key
from worthless.sidecar.health import find_sidecar_socket_for_open
from worthless.storage.repository import ShardRepository

alias = sys.argv[1]
os.environ['WORTHLESS_SERVICE_MANAGED'] = '1'

async def main() -> None:
    home = ensure_home()
    key = read_fernet_key(home.base_dir)
    repo = ShardRepository(str(home.db_path), key)
    enc = await repo.fetch_encrypted(alias)
    if enc is None:
        raise SystemExit(f'alias {alias!r} not in DB')
    if enc.base_url is None:
        raise SystemExit(f'alias {alias!r} has NULL base_url — relock required')
    run_root = home.base_dir / 'run'
    try:
        sock = await find_sidecar_socket_for_open(
            run_root,
            ciphertext=enc.shard_b_enc,
            key_id=alias.encode(),
        )
    except FileNotFoundError:
        raise SystemExit('no live sidecar socket under ~/.worthless/run (proxy-only orphan?)') from None
    except Exception as exc:
        raise SystemExit(f'sidecar IPC open failed: {exc}') from exc
    print(f'sidecar decrypt ok via {sock}')

asyncio.run(main())
" "$ALIAS")
}

sidecar_ready=false
deadline=$((SECONDS + 60))
while ((SECONDS < deadline)); do
  if sidecar_decrypt_preflight 2>/dev/null; then
    sidecar_ready=true
    break
  fi
  sleep 1
done
if [[ "$sidecar_ready" != true ]]; then
  lp_fail "sidecar IPC decrypt failed after 60s"
  sidecar_decrypt_preflight || true
  lp_diag \
    "WORTHLESS_FERNET_IPC_ONLY=${WORTHLESS_FERNET_IPC_ONLY:-unset}" \
    "which worthless: $(command -v worthless 2>/dev/null || echo missing)"
  if [[ -f "$PLIST" ]]; then
    lp_step "launchd ProgramArguments:"
    grep -A2 'ProgramArguments' "$PLIST" || true
  fi
  if command -v pgrep >/dev/null 2>&1; then
    lp_step "running worthless processes:"
    pgrep -fl 'worthless' 2>/dev/null || true
  fi
  if [[ -d "${HOME}/.worthless/run" ]]; then
    lp_step "sidecar sockets:"
    find "${HOME}/.worthless/run" -name sidecar.sock 2>/dev/null || true
  fi
  dump_proxy_log
  exit 1
fi
sidecar_decrypt_preflight
lp_ok "sidecar IPC decrypt preflight passed"

lp_phase "Proxied request roundtrip"

curl_expect_2xx() {
  local method="$1"
  local url="$2"
  local data="${3:-}"
  local tmp
  tmp="$(mktemp)"
  local status
  if [[ -n "$data" ]]; then
    status="$(curl -s -o "$tmp" -w '%{http_code}' -X "$method" "$url" \
      -H "Content-Type: application/json" \
      -d "$data")"
  else
    status="$(curl -s -o "$tmp" -w '%{http_code}' -X "$method" "$url")"
  fi
  if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
    lp_fail "${method} ${url} → HTTP ${status}"
    cat "$tmp" 2>/dev/null || true
    dump_proxy_log
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
}

lp_step "clear mock-upstream capture buffer"
curl_expect_2xx DELETE "${MOCK_URL}/captured-headers"

lp_step "POST /${ALIAS}/v1/chat/completions via launchd proxy :${PORT}"
RESP_FILE="$(mktemp)"
HTTP_STATUS=""
deadline=$((SECONDS + 45))
while ((SECONDS < deadline)); do
  HTTP_STATUS="$(
    curl -s -o "$RESP_FILE" -w '%{http_code}' \
      -X POST "http://127.0.0.1:${PORT}/${ALIAS}/v1/chat/completions" \
      -H "Authorization: Bearer ${SHARD_A}" \
      -H "Content-Type: application/json" \
      -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}'
  )"
  if [[ "$HTTP_STATUS" == "200" ]]; then
    break
  fi
  if [[ "$HTTP_STATUS" == "503" || "$HTTP_STATUS" == "502" || "$HTTP_STATUS" == "504" ]]; then
    sleep 1
    continue
  fi
  break
done
if [[ "$HTTP_STATUS" != "200" ]]; then
  lp_fail "proxy returned HTTP ${HTTP_STATUS}"
  cat "$RESP_FILE" 2>/dev/null || true
  if [[ "$HTTP_STATUS" == "401" ]]; then
    lp_diag \
      "401 under launchd → orphan proxy without sidecar (re-run)" \
      "or Fernet mismatch (worthless doctor; script syncs keyring→file)"
  fi
  dump_proxy_log
  rm -f "$RESP_FILE"
  exit 1
fi
rm -f "$RESP_FILE"
lp_ok "proxy returned HTTP 200"

lp_step "verify mock-upstream received real API key (not shard-A)"
RECEIVED="$(
  cd "$REPO_ROOT" && uv run python -c "
import json, urllib.request
data = json.load(urllib.request.urlopen('${MOCK_URL}/captured-headers'))
headers = data.get('headers') or []
if not headers:
    raise SystemExit('mock-upstream saw no requests')
auth = headers[-1].get('authorization', '').replace('Bearer ', '')
print(auth)
"
)"

if [[ "$RECEIVED" != "$REAL_KEY" ]]; then
  lp_fail "upstream got wrong key (expected ${REAL_KEY:0:10}..., got ${RECEIVED:0:10}...)"
  dump_proxy_log
  exit 1
fi
lp_ok "mock-upstream Authorization matches enrolled key"

lp_step "worthless service uninstall --yes (cleanup before trap)"
worthless service uninstall --yes
test ! -f "$PLIST"

lp_footer_pass "service lock roundtrip live pack: PASS"
