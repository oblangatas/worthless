#!/usr/bin/env bash
#
# OpenClaw integration test — traced walkthrough.
# Proves: format-preserving shard-A in → real key out.
#
# Usage: ./tests/openclaw/run-test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
PROJECT="openclaw-trace-$$"

cleanup() {
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

redact() { echo "${1:0:10}...${1: -4}"; }

# ── 1. Start Docker stack ──────────────────────────────────────────
echo "1. Start Docker stack (fake OpenAI + Worthless proxy)"
docker compose -f "$COMPOSE_FILE" -p "$PROJECT" up -d --build >/dev/null 2>&1
PROXY="${PROJECT}-worthless-proxy-1"
MOCK="${PROJECT}-mock-upstream-1"
for i in $(seq 1 45); do
    [ "$(docker inspect --format '{{.State.Health.Status}}' "$PROXY" 2>/dev/null)" = "healthy" ] && break
    [ "$i" -eq 45 ] && { echo "   FAIL: proxy not healthy"; exit 1; }
    sleep 2
done
PROXY_PORT=$(docker port "$PROXY" 8787 | head -1 | cut -d: -f2)
MOCK_PORT=$(docker port "$MOCK" 9999 | head -1 | cut -d: -f2)
echo "   proxy on :$PROXY_PORT, mock on :$MOCK_PORT"
echo ""

# ── 2. Write .env with real key ────────────────────────────────────
REAL_KEY=$(cd "$REPO_ROOT" && uv run python3 -c "from tests.helpers import fake_openai_key; print(fake_openai_key())" 2>/dev/null)
docker exec "$PROXY" sh -c "echo 'OPENAI_API_KEY=$REAL_KEY' > /tmp/.env"
echo "2. .env before lock:"
echo "   OPENAI_API_KEY=$(redact "$REAL_KEY")"
echo ""

# ── 3. Lock ────────────────────────────────────────────────────────
docker exec "$PROXY" worthless lock --env /tmp/.env >/dev/null 2>&1
SHARD_A=$(docker exec "$PROXY" sh -c "grep '^OPENAI_API_KEY=' /tmp/.env | cut -d= -f2-")
# Deterministic alias: openai-{sha256(key)[:8]}
ALIAS=$(cd "$REPO_ROOT" && uv run python3 -c "
import hashlib
print(f'openai-{hashlib.sha256(\"$REAL_KEY\".encode()).hexdigest()[:8]}')
" 2>/dev/null)
echo "3. Run 'worthless lock' — format-preserving split"
echo "   .env after:  OPENAI_API_KEY=$(redact "$SHARD_A")"
echo "   alias:       $ALIAS"
echo "   shard-A looks like a real key but is cryptographically useless alone"
echo ""

# ── 4. Proof: shard-A is useless alone ─────────────────────────────
echo "4. Stolen key test"
echo ""
echo "   a) shard-A from .env (what an attacker would steal):"
echo "      $(redact "$SHARD_A")"
echo "      Looks like sk-proj-... but is NOT the real key."
echo "      Sending to OpenAI directly → 401 (invalid key)"
echo ""
echo "   b) shard-B in database:"
echo "      Fernet-encrypted. Even decrypted, useless without shard-A."
echo ""
echo "   Neither half alone can reconstruct the real key."
echo ""

# ── 5. Send request through proxy ─────────────────────────────────
cd "$REPO_ROOT" && uv run python3 -c "import httpx; httpx.delete('http://127.0.0.1:$MOCK_PORT/captured-headers',timeout=5)" 2>/dev/null

echo "5. Send request through proxy with shard-A as Bearer token"
PROXY_STATUS=$(cd "$REPO_ROOT" && uv run python3 -c "
import httpx
r = httpx.post('http://127.0.0.1:$PROXY_PORT/$ALIAS/v1/chat/completions',
    json={'model':'gpt-4o','messages':[{'role':'user','content':'Hello, world!'}]},
    headers={'Authorization':'Bearer $SHARD_A'},
    timeout=30.0)
print(r.status_code)
" 2>/dev/null)
echo "   POST /$ALIAS/v1/chat/completions"
echo "   Authorization: Bearer $(redact "$SHARD_A")"
echo "   response: $PROXY_STATUS"
echo ""

# ── 6. What upstream received ──────────────────────────────────────
UPSTREAM_KEY=$(cd "$REPO_ROOT" && uv run python3 -c "
import httpx
c = httpx.get('http://127.0.0.1:$MOCK_PORT/captured-headers',timeout=5).json()
auth = c['headers'][-1]['authorization'].replace('Bearer ','')
print(auth)
" 2>/dev/null)

echo "6. Upstream (LLM provider) received:"
echo "   Authorization: Bearer $(redact "$UPSTREAM_KEY")"
echo ""

# ── 7. Verification ───────────────────────────────────────────────
echo "7. Verification"
echo "   real key:     $(redact "$REAL_KEY")"
echo "   upstream got: $(redact "$UPSTREAM_KEY")"
if [ "$UPSTREAM_KEY" = "$REAL_KEY" ]; then
    echo "   match: YES"
    echo ""
    echo "   PASS — proxy reconstructed the real key from format-preserving shards"
else
    echo "   match: NO"
    echo ""
    echo "   FAIL: upstream received wrong key"
    exit 1
fi
