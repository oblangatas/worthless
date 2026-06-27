#!/usr/bin/env bash
#
# Live OpenClaw demo of the WOR-514 install incident.
#
# Boots the REAL OpenClaw daemon (ghcr.io/openclaw/openclaw) against a real
# `openclaw onboard`-generated config, runs `worthless lock`, and shows -- with
# the container's own exit code -- both incident failures:
#
#   Act A (WOR-515): lock "succeeds", OpenClaw still boots, but its agent
#                    still uses the real provider -- the proxy is bypassed.
#   Act B (WOR-516): lock rewrites an unreadable config and OpenClaw then
#                    refuses to start (exit 78) -- the user's app is broken.
#
# Usage: tests/openclaw/install_incident/live_demo.sh
# Requires: Docker running.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../../.." && pwd)"
IMG="ghcr.io/openclaw/openclaw:latest"
WORK="$(mktemp -d /tmp/wor514-demo.XXXXXX)"
NET="wor514-demo-net"

# A format-valid fake key (deterministic, not a live credential).
KEY="$(python3 -c "import base64,hashlib;print('sk-proj-'+base64.urlsafe_b64encode(hashlib.sha256(b'test-fixture-seed').digest()).decode().rstrip('=')[:48])")"

cleanup() {
    docker rm -f oc-demo >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
line() { printf '%s\n' "----------------------------------------------------------------------"; }

# Boot OpenClaw against an .openclaw config dir; echo "<state>:<exitcode>".
# Deterministic: an OpenClaw that blocks on config exits within seconds; one
# that boots cleanly stays up. Poll for an exit for up to 30s, else it is up.
boot_openclaw() {
    docker rm -f oc-demo >/dev/null 2>&1 || true
    docker run -d --name oc-demo --network "$NET" \
        -v "$1":/home/node/.openclaw -e OPENCLAW_ACCEPT_TERMS=yes \
        "$IMG" >/dev/null 2>&1
    local i
    for i in $(seq 1 30); do
        [ "$(docker inspect -f '{{.State.Status}}' oc-demo 2>/dev/null)" = "exited" ] && break
        sleep 1
    done
    echo "$(docker inspect -f '{{.State.Status}}' oc-demo 2>/dev/null):$(docker inspect -f '{{.State.ExitCode}}' oc-demo 2>/dev/null)"
}

# Run `worthless lock` as a host user would, against a scenario home.
run_lock() {
    local home="$1"
    mkdir -p "$home/project"
    printf 'OPENAI_API_KEY=%s\n' "$KEY" > "$home/project/.env"
    HOME="$home" USERPROFILE="$home" WORTHLESS_HOME="$home/whome" \
        uv run --project "$REPO" worthless lock --env "$home/project/.env" \
        >/dev/null 2>&1
    echo "$?"
}

siblings() {  # top-level openclaw.json keys other than "models"
    python3 -c "
import json
try: d=json.load(open('$1'))
except Exception as e: print('UNPARSABLE'); raise SystemExit
print(','.join(sorted(k for k in d if k!='models')) or '(none)')
" 2>/dev/null || echo "UNPARSABLE"
}

docker network create "$NET" >/dev/null 2>&1 || true

printf '%s\n' "======================================================================"
echo "WOR-514 -- LIVE OpenClaw incident demo   (image: $IMG)"
printf '%s\n' "======================================================================"

# --- STEP 1: a real user's working OpenClaw --------------------------------
echo
echo "STEP 1  Generate a genuine OpenClaw config via 'openclaw onboard'."
BASE="$WORK/base/.openclaw"
mkdir -p "$BASE"
docker run --rm -v "$BASE":/home/node/.openclaw -e OPENCLAW_ACCEPT_TERMS=yes \
    "$IMG" node openclaw.mjs onboard \
    --non-interactive --accept-risk --mode local --skip-health \
    --auth-choice custom-api-key --custom-api-key "$KEY" \
    --custom-base-url "http://api.openai.com/v1" \
    --custom-model-id "gpt-4o" --custom-compatibility openai >/dev/null 2>&1
if [ ! -f "$BASE/openclaw.json" ]; then
    echo "  FAILED: onboard produced no config. Aborting."; exit 1
fi
# OpenClaw caches the credential on first agent use; seed that file.
mkdir -p "$BASE/agents/main/agent"
printf '{"profiles":{"default":{"token":"%s"}}}\n' "$KEY" \
    > "$BASE/agents/main/agent/auth-profiles.json"
PRIMARY="$(python3 -c "import json;print(json.load(open('$BASE/openclaw.json'))['agents']['defaults']['model']['primary'])")"
echo "  agent's model  : $PRIMARY"
echo "  config keys    : models + [$(siblings "$BASE/openclaw.json")]"
echo "  boot check     : OpenClaw container -> $(boot_openclaw "$BASE")  (running = works)"

# --- STEP 2 / Act A: WOR-515 silent bypass ---------------------------------
echo
line
echo "ACT A (WOR-515)  Run 'worthless lock' on a readable config."
A="$WORK/a"; mkdir -p "$A"; cp -R "$WORK/base/.openclaw" "$A/.openclaw"
echo "  worthless lock exit code : $(run_lock "$A")   (0 = lock reports SUCCESS)"
PROVIDERS="$(python3 -c "import json;print(', '.join(json.load(open('$A/.openclaw/openclaw.json'))['models']['providers']))")"
PRIMARY_A="$(python3 -c "import json;print(json.load(open('$A/.openclaw/openclaw.json'))['agents']['defaults']['model']['primary'])")"
AUTH_A="$(python3 -c "print('UNCHANGED' if open('$A/.openclaw/agents/main/agent/auth-profiles.json').read().find('$KEY')>=0 else 'cleared')")"
echo "  providers now            : $PROVIDERS"
echo "  agent STILL uses         : $PRIMARY_A"
echo "  cached auth-profiles.json: $AUTH_A (real key still on disk)"
echo "  OpenClaw boot            : $(boot_openclaw "$A/.openclaw")"
echo
echo "  >> lock added a 'worthless-' provider but never repointed the agent,"
echo "  >> and never touched the cached token. OpenClaw keeps using the real"
echo "  >> provider -- the Worthless proxy is never in the request path."

# --- STEP 3 / Act B: WOR-516 config corruption -----------------------------
echo
line
echo "ACT B (WOR-516)  Run 'worthless lock' when openclaw.json is unreadable"
echo "                 to the worthless process. OpenClaw writes the file"
echo "                 0600 owner-only; a foreign-uid / container deploy"
echo "                 cannot read it."
B="$WORK/b"; mkdir -p "$B"; cp -R "$WORK/base/.openclaw" "$B/.openclaw"
BEFORE_KEYS="$(siblings "$B/.openclaw/openclaw.json")"
chmod 000 "$B/.openclaw/openclaw.json"
echo "  worthless lock exit code : $(run_lock "$B")   (0 = lock reports SUCCESS)"
chmod 600 "$B/.openclaw/openclaw.json" 2>/dev/null || true
echo "  openclaw.json keys besides 'models':"
echo "    before lock : [$BEFORE_KEYS]"
echo "    after lock  : [$(siblings "$B/.openclaw/openclaw.json")]"
echo "  >> lock wiped the entire config -- gateway auth token, the agent's"
echo "  >> model, channels, tools, skills -- and wrote NO backup."
echo
echo "  Boot OpenClaw on the wiped config (with the user's residual state):"
echo "    -> $(boot_openclaw "$B/.openclaw")"
echo "  Boot OpenClaw on the wiped config on a clean host (no residual state):"
S="$WORK/b-clean/.openclaw"; mkdir -p "$S"
cp "$B/.openclaw/openclaw.json" "$S/openclaw.json"
RESULT_B="$(boot_openclaw "$S")"
echo "    -> $RESULT_B"
docker logs oc-demo 2>&1 | grep -i 'blocked\|gateway.mode' | head -1 | sed 's/^/    log: /'
echo
echo "  >> WOR-516: 'worthless lock' reported success, destroyed the user's"
echo "  >> entire OpenClaw configuration, and wrote NO backup. OpenClaw then"
echo "  >> refuses to start (exit 78 -- 'suspicious or clobbered config')."
echo "  >> Recovery requires a backup file -- exactly what the user fell back on."

printf '%s\n' "======================================================================"
echo "Demo complete."
printf '%s\n' "======================================================================"
