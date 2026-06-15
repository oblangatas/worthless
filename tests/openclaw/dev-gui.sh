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
#   ./tests/openclaw/dev-gui.sh up            # build (if needed) + run + open browser
#   ./tests/openclaw/dev-gui.sh open          # just (re)open the browser
#   ./tests/openclaw/dev-gui.sh url           # print the authenticated URL
#   ./tests/openclaw/dev-gui.sh reload-skill  # hot-reload SKILL.md (no restart — file watcher picks it up)
#   ./tests/openclaw/dev-gui.sh reset         # clear OpenClaw's auth rate-limit, reopen
#   ./tests/openclaw/dev-gui.sh stop          # tear it all down
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

# WOR-664: plant the operator's OpenRouter key + baseUrl + a real model so
# the GUI chat works immediately (skips the manual "Settings → add key" dance).
# Key sourced from $OPENROUTER_API_KEY in ~/.zshrc so it works regardless of
# what shell `up` was invoked from. Never hardcoded, never committed.
#
# Source-read finding: OpenClaw's openai provider plugin calls
# resolveUsableCustomProviderApiKey (model-auth-DauuBD3l.js:56-101), which
# reads `models.providers.openai.apiKey` DIRECTLY from openclaw.json. No
# auth-profiles.json needed for the OpenRouter case. `models auth
# paste-token` writes a token-mode profile that openai's api_key path
# ignores → why our earlier attempt silently no-op'd.
_wire_provider() {
  local tok
  # Pull the key from zshrc (works under bash/sh too). Single sourcing point.
  tok="$(zsh -ic 'printf %s "${OPENROUTER_API_KEY:-}"' 2>/dev/null)"
  if [ -z "$tok" ]; then
    echo "(skipping provider wire-up: \$OPENROUTER_API_KEY not in ~/.zshrc)"
    return 0
  fi

  # baseUrl + api + default model — argv-safe (no secret material).
  # --merge so re-runs don't try to overwrite an already-set apiKey field.
  docker exec "$NAME" node openclaw.mjs config set models.providers.openai \
    '{"baseUrl":"https://openrouter.ai/api/v1","api":"openai-completions","models":[]}' \
    --strict-json --merge >/dev/null
  docker exec "$NAME" node openclaw.mjs config set agents.defaults.model.primary \
    openai/gpt-4o-mini >/dev/null

  # Plant the apiKey by piping over stdin → reading inside the container.
  # NEVER on argv (process listings) or environ (avoid). NEVER on host disk.
  printf '%s' "$tok" \
    | docker exec -i "$NAME" sh -c '
        KEY=$(cat)
        [ -n "$KEY" ] || { echo "  ! empty key from stdin" >&2; exit 1; }
        node openclaw.mjs config set models.providers.openai.apiKey "$KEY" >/dev/null
      ' \
    && echo "  wired: OpenRouter key + baseUrl + default model openai/gpt-4o-mini" \
    || { echo "  ! provider wire-up failed (the chat will work after you add a key in Settings)"; return 1; }
  unset tok

  # The provider config writer logs "Restart the gateway to apply." — even
  # though some changes hot-reload, the apiKey path is safest restarted, and
  # restart also clears any auth rate-limit from earlier 401s.
  docker restart "$NAME" >/dev/null
  for _ in $(seq 1 40); do
    docker exec "$NAME" node openclaw.mjs config get gateway >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "  ! container not ready after restart"
  return 1
}

# WOR-664: validate the side-loaded skill via OpenClaw's own check command.
# Catches frontmatter regressions (missing name/description/bins) BEFORE the
# agent ever sees the skill — the only "lint" OpenClaw ships. Per the dev-
# workflow research (~/Projects/worthless/worthless-wor621-phase3/
# .understand-anything/openclaw-skill-dev-workflow.md): there is no
# `skills test` or `skills lint`; `skills check --json` is the closest gate.
_skills_check() {
  # OpenClaw's `skills check` returns:
  #   eligible            : list[str]                 (bin present, agent can call)
  #   missingRequirements : list[{name, missing, …}]  (bin not on PATH yet)
  #   blocked / disabled  : list[str]                 (parse error / disabled)
  # So we need string OR dict-with-name membership.
  docker exec "$NAME" node openclaw.mjs skills check --json 2>/dev/null \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
def has(bucket, name):
    items = d.get(bucket) or []
    for it in items:
        n = it if isinstance(it, str) else (it.get('name') if isinstance(it, dict) else None)
        if n == name: return True
    return False
if has('eligible', 'worthless'):
    print('  skill check: worthless ELIGIBLE + modelVisible')
    sys.exit(0)
if has('missingRequirements', 'worthless'):
    print('  skill check: worthless NEEDS SETUP (bin not on PATH — expected on a clean container; the agent installs it)')
    sys.exit(0)
if has('blocked', 'worthless') or has('disabled', 'worthless'):
    print('  skill check: worthless BLOCKED / DISABLED (frontmatter parse error?)', file=sys.stderr)
    sys.exit(1)
print('  skill check: worthless NOT FOUND in any OpenClaw bucket (skill file not loaded?)', file=sys.stderr)
sys.exit(1)
"
}

# Hot-reload the side-loaded skill. OpenClaw's file watcher (250ms debounce,
# default ON via skills.load.watch:true) picks the file up automatically —
# no docker restart needed. Saves ~10s per skill-edit iteration.
#
# IMPORTANT: do NOT use `docker cp` — it writes as root, the node user can't
# subsequently modify the file, and OpenClaw's watcher (running as node)
# sees a permission-EACCES read and silently drops the skill from its index
# (proven live: `skills check` total dropped 55 → 54 after a docker cp).
# Pipe the file in via `docker exec -i` so it lands owned by node.
_reload_skill() {
  docker exec "$NAME" sh -c 'mkdir -p /home/node/.openclaw/workspace/skills/worthless'
  cat "$ROOT/src/worthless/openclaw/skill_assets/SKILL.md" \
    | docker exec -i "$NAME" sh -c \
        'cat > /home/node/.openclaw/workspace/skills/worthless/SKILL.md'
  # File watcher needs a beat to notice the change.
  sleep 1
  _skills_check
}

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
    _reload_skill
    _wire_provider
    "$0" open
    ;;
  reload-skill)
    # Hot-reload SKILL.md without restarting OpenClaw. Use after editing the
    # skill — the file watcher picks it up in ~250ms, then re-validate.
    _reload_skill
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
    # _wire_provider handles its own restart (planted apiKey needs gateway
    # reload), and that same restart clears OpenClaw's in-memory auth-attempt
    # rate-limit — so one restart, not two. State under ~/.openclaw and
    # ~/.worthless persists across the restart (layer state).
    _wire_provider || true
    "$0" open
    ;;
  stop)
    docker rm -f "$NAME" >/dev/null 2>&1 && echo "stopped $NAME" || echo "$NAME not running"
    ;;
  *)
    echo "usage: $0 {up|open|url|reload-skill|reset|stop}"; exit 1
    ;;
esac
