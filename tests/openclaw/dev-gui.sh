#!/usr/bin/env bash
# WOR-664 F13c — hands-on OpenClaw GUI with the Worthless skill (local dev).
#
# WHAT THIS IS
#   A throwaway OpenClaw you open in your browser to drive the real journey:
#   install the Worthless *skill* → it installs Worthless → protect a key →
#   kill the proxy → the agent goes dark. Worthless is NOT pre-installed — the
#   skill installs it (from your LOCAL branch wheel, so you see YOUR fix, not
#   the published version).
#
#   Security: NO host filesystem access (zero mounts), --cap-drop ALL +
#   no-new-privileges, docker socket not mounted, GUI bound to 127.0.0.1 only.
#   Your AI key lives in the container and dies with it.
#
# USAGE
#   ./tests/openclaw/dev-gui.sh up      # build (if needed) + run + open browser
#   ./tests/openclaw/dev-gui.sh open    # just (re)open the browser
#   ./tests/openclaw/dev-gui.sh url     # print the authenticated URL
#   ./tests/openclaw/dev-gui.sh reset   # clear OpenClaw's auth rate-limit, reopen
#   ./tests/openclaw/dev-gui.sh stop    # tear it all down
#
# NOTE: do NOT read the gateway token via `openclaw.mjs config get gateway` —
# OpenClaw redacts it to "__OPENCLAW_REDACTED__" there by design. This script
# reads the raw config file inside the container so the URL is usable.
#
# THEN, in the GUI:
#   1. Settings → add your AI provider key (the agent needs a brain).
#   2. Chat: "Install Worthless from the local wheel
#      /opt/worthless/worthless-*.whl, run `worthless up`, and protect my
#      OpenAI key with `worthless lock`."
#   3. `docker restart worthless-oc-gui` → re-open → `worthless up` again
#      (install + locked config survive; only the daemon needs restarting).
#   4. Prove load-bearing: `docker exec worthless-oc-gui sh -c 'worthless down'`
#      → ask the agent something → it can't reach the model → `worthless up`.
set -euo pipefail

NAME=worthless-oc-gui
IMG=worthless-oc-dev:local
OC_IMAGE=ghcr.io/openclaw/openclaw:2026.5.3-1
UV_IMAGE=ghcr.io/astral-sh/uv:0.11.7
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

_url() {
  # WOR-664: do NOT use `openclaw.mjs config get gateway` — it redacts the
  # token to the literal "__OPENCLAW_REDACTED__" by design (good safety
  # default; wrong for our dev launcher). Read the raw config inside the
  # container instead — the token only ever transits the local pipe to
  # python and the file we write below; it never lands on stdout.
  printf 'http://localhost:18789/#token=%s' \
    "$(docker exec "$NAME" sh -c 'cat ~/.openclaw/openclaw.json' \
        | python3 -c "import sys,json;print(json.load(sys.stdin)['gateway']['auth']['token'])")"
}

case "${1:-up}" in
  up)
    ls "$ROOT"/dist/worthless-*.whl >/dev/null 2>&1 || (cd "$ROOT" && uv build --wheel)
    if ! docker image inspect "$IMG" >/dev/null 2>&1; then
      docker build -t "$IMG" -f - "$ROOT/dist" <<DF
FROM $OC_IMAGE
COPY --from=$UV_IMAGE /uv /usr/local/bin/uv
COPY worthless-*.whl /opt/worthless/
USER node
ENV PATH=/home/node/.local/bin:\$PATH
DF
    fi
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" \
      --cap-drop ALL --security-opt no-new-privileges \
      -p 127.0.0.1:18789:18789 -e OPENCLAW_ACCEPT_TERMS=yes --user node \
      "$IMG" >/dev/null
    echo "waiting for OpenClaw to boot..."
    for _ in $(seq 1 40); do
      docker exec "$NAME" node openclaw.mjs config get gateway >/dev/null 2>&1 && break
      sleep 2
    done
    docker exec "$NAME" sh -c 'mkdir -p /home/node/.openclaw/workspace/skills/worthless'
    docker cp "$ROOT/src/worthless/openclaw/skill_assets/SKILL.md" \
      "$NAME:/home/node/.openclaw/workspace/skills/worthless/SKILL.md"
    "$0" open
    ;;
  open)
    url="$(_url)"
    if command -v open >/dev/null 2>&1; then open "$url"; fi
    echo "OpenClaw GUI: $url"
    echo "(container: $NAME — stop with: $0 stop)"
    ;;
  url)
    _url; echo
    ;;
  reset)
    # Clear OpenClaw's gateway-auth rate-limit ("too many failed attempts").
    # In-memory counter, so a container restart drops it. The skill, the
    # local wheel, and any state under ~/.openclaw / ~/.worthless persist
    # because the container keeps its layer state across restart.
    docker restart "$NAME" >/dev/null && echo "restarted $NAME (auth rate-limit cleared)"
    for _ in $(seq 1 40); do
      docker exec "$NAME" node openclaw.mjs config get gateway >/dev/null 2>&1 && break
      sleep 2
    done
    "$0" open
    ;;
  stop)
    docker rm -f "$NAME" >/dev/null 2>&1 && echo "stopped $NAME" || echo "$NAME not running"
    ;;
  *)
    echo "usage: $0 {up|open|url|reset|stop}"; exit 1
    ;;
esac
