#!/usr/bin/env bash
# Reusable OpenClaw + worthless-proxy stack launcher for manual reproduction
# and e2e work. Brings up a working all-container stack and prints the
# Control-UI URL (with auth token) so you can open it in a browser.
#
# WHY THIS EXISTS (and why it's not just `docker compose up`):
#   The published deploy/docker-compose.yml puts the openclaw service ONLY on
#   the `internal: true` openclaw-net network. Docker then silently drops the
#   host port-publish for 18789 (NetworkSettings.Ports is empty), so the
#   Control UI is unreachable from the host browser. See WOR-546.
#   Until that's fixed in the compose, this script starts openclaw on the
#   `frontend` network (so 18789 publishes to the host) and THEN attaches it
#   to openclaw-net (so it can still reach the proxy via Docker DNS).
#   Once WOR-546 lands (openclaw on both networks in the compose), the manual
#   `docker run` + `docker network connect` here can collapse to a plain
#   `docker compose --profile openclaw up -d`.
#
# Usage:
#   ./launch_stack.sh up         # build + start; print Control-UI URL  (default)
#   ./launch_stack.sh down       # tear down containers + volumes + networks
#   ./launch_stack.sh url        # print the Control-UI URL with token
#   ./launch_stack.sh provider   # seed an OpenRouter provider from $OPENROUTER_API_KEY
#
# Env overrides: WOR514_PROJECT (default wor514), OPENCLAW_IMG.

set -euo pipefail

PROJECT="${WOR514_PROJECT:-wor514}"
IMG="${OPENCLAW_IMG:-ghcr.io/openclaw/openclaw:2026.5.3-1}"
DEPLOY_DIR="$(cd "$(dirname "$0")/../../../deploy" && pwd)"
OC="${PROJECT}-openclaw-1"
PROXY="${PROJECT}-proxy-1"

_wait_healthy() {  # $1 = container, $2 = max tries
  local i
  for i in $(seq 1 "${2:-30}"); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null)" = "healthy" ] && return 0
    sleep 2
  done
  return 1
}

down() {
  docker rm -f "$OC" >/dev/null 2>&1 || true
  docker compose -p "$PROJECT" -f "$DEPLOY_DIR/docker-compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
  docker volume ls -q | grep -E "^${PROJECT}_" | xargs -r docker volume rm >/dev/null 2>&1 || true
  docker network ls -q --filter "name=${PROJECT}_" | xargs -r docker network rm >/dev/null 2>&1 || true
  echo "torn down: $PROJECT"
}

url() {
  docker exec "$OC" cat /home/node/.openclaw/openclaw.json 2>/dev/null \
    | python3 -c "import sys,json;print('http://localhost:18789/#token='+json.load(sys.stdin)['gateway']['auth']['token'])"
}

up() {
  down
  ( cd "$DEPLOY_DIR" && cp -f docker-compose.env.example docker-compose.env 2>/dev/null || true
    docker compose -p "$PROJECT" up -d proxy )
  _wait_healthy "$PROXY" 30 || { echo "proxy did not become healthy"; docker logs "$PROXY" 2>&1 | tail -20; exit 1; }

  # WOR-546 workaround: start on frontend (port publishes), attach openclaw-net (reaches proxy).
  docker run -d --name "$OC" \
    -p 18789:18789 \
    --network "${PROJECT}_frontend" \
    -v "${PROJECT}_openclaw-config:/home/node/.openclaw" \
    -e OPENCLAW_ACCEPT_TERMS=yes \
    --user node \
    "$IMG" >/dev/null
  docker network connect "${PROJECT}_openclaw-net" "$OC"
  _wait_healthy "$OC" 45 || echo "warning: openclaw still 'starting' (startup grace) — UI may need a few more seconds"

  echo "stack up ($PROJECT). proxy=8787, openclaw=18789"
  echo "Control UI:"
  url
}

provider() {
  : "${OPENROUTER_API_KEY:?set OPENROUTER_API_KEY first (or export from your shell rc)}"
  docker exec "$OC" node openclaw.mjs config set models.providers.openrouter \
    '{"baseUrl":"https://openrouter.ai/api/v1","api":"openai-completions","models":[]}' --strict-json
  docker exec -e ORK="$OPENROUTER_API_KEY" "$OC" sh -c \
    'node openclaw.mjs config set models.providers.openrouter.apiKey "$ORK"'
  docker exec "$OC" node openclaw.mjs config set agents.defaults.model.primary openrouter/openai/gpt-4o-mini
  docker restart "$OC" >/dev/null
  _wait_healthy "$OC" 45 || true
  echo "openrouter provider seeded + openclaw restarted. model=openrouter/openai/gpt-4o-mini"
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  url) url ;;
  provider) provider ;;
  *) echo "usage: $0 {up|down|url|provider}"; exit 2 ;;
esac
