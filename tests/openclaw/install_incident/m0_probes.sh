#!/usr/bin/env bash
# M0 probes for WOR-515 Phase 1
# Captures three OpenClaw 'secrets' command fixtures required before Phase 1 implementation.
# Run: bash tests/openclaw/install_incident/m0_probes.sh
set -euo pipefail

FIXTURES="$(cd "$(dirname "$0")/fixtures" && pwd)"
IMAGE="ghcr.io/openclaw/openclaw:2026.5.3-1"
CONTAINER_AGENT_DIR="/home/node/.openclaw/agents/main/agent"

echo "=== M0 PROBE SETUP ===" >&2
echo "Image: $IMAGE" >&2
echo "Fixtures dir: $FIXTURES" >&2

# Write seed files to a host temp dir that gets mounted into the container.
TMPDIR_SEED="$(mktemp -d)"
TMPDIR_DECOY=""  # set later; initialise so the single trap below can always reference it
trap 'rm -rf "$TMPDIR_SEED" ${TMPDIR_DECOY:+"$TMPDIR_DECOY"}' EXIT

mkdir -p "$TMPDIR_SEED/agent"

# models.json lives at agents/main/agent/models.json with a flat "providers" top-level key.
# (NOT wrapped in "models": {...} — confirmed by M0 container probe 2026-05-21.)
cat > "$TMPDIR_SEED/agent/models.json" <<'JSON'
{
  "providers": {
    "openai": {
      "apiKey": "sk-plaintext-probe0000000000000000000000000000000000",
      "baseUrl": "https://api.openai.com/v1"
    },
    "anthropic": {
      "apiKey": "sk-ant-api03-plaintext-probe000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "baseUrl": "https://api.anthropic.com"
    },
    "worthless-openai": {
      "apiKey": "wl-shardA-0000000000000000000000000000000000000000",
      "baseUrl": "http://localhost:4000/openai/v1"
    },
    "via-ref": {
      "apiKey": "${secret:OPENAI_API_KEY}",
      "baseUrl": "https://api.openai.com/v1"
    }
  }
}
JSON

# openclaw.json holds gateway config; gateway.auth.token is flagged but ignored by worthless.
# NOTE: openclaw setup must run first before the audit works — hand-crafted configs return
# REF_UNRESOLVED. These probe scripts document the schema but cannot run a full onboard flow.
cat > "$TMPDIR_SEED/agent/openclaw.json" <<'JSON'
{
  "gateway": {
    "auth": {
      "token": "openclaw-ui-session-token-not-a-provider-key"
    }
  }
}
JSON

cat > "$TMPDIR_SEED/agent/auth-profiles.json" <<'JSON'
{
  "profiles": {
    "main": {
      "key": "sk-real-cached-key-0000000000000000000000000000000000",
      "accessToken": "bearer-cached-access-token-plain",
      "provider": "openai"
    }
  }
}
JSON

DOCKER_MOUNT="-v $TMPDIR_SEED/agent:$CONTAINER_AGENT_DIR"

# ── PROBE 1: secrets audit --json schema ─────────────────────────────────────
echo "" >&2
echo "=== PROBE 1: secrets audit --json ===" >&2
PROBE1_EXIT=0
docker run --rm $DOCKER_MOUNT "$IMAGE" \
  openclaw secrets audit --json 2>/dev/null \
  > "$FIXTURES/m0_audit_schema.json" || PROBE1_EXIT=$?

echo "Exit status: $PROBE1_EXIT" >&2
echo "Top-level JSON keys:" >&2
python3 -c "import json,sys; d=json.load(open('$FIXTURES/m0_audit_schema.json')); print(list(d.keys()))" 2>&1 >&2 || head -8 "$FIXTURES/m0_audit_schema.json" >&2

# ── PROBE 2: secrets configure --apply --yes non-interactive ─────────────────
echo "" >&2
echo "=== PROBE 2: secrets configure --apply --yes ===" >&2
timeout 15 docker run --rm $DOCKER_MOUNT "$IMAGE" \
  openclaw secrets configure --apply --yes \
  > "$FIXTURES/m0_configure_apply_yes.txt" 2>&1 || echo "EXIT_CODE:$?" >> "$FIXTURES/m0_configure_apply_yes.txt"

echo "Output (first 15 lines):" >&2
head -15 "$FIXTURES/m0_configure_apply_yes.txt" >&2

# ── PROBE 3: configure --plan-out + apply --from (two-stage fallback) ─────────
echo "" >&2
echo "=== PROBE 3: two-stage configure --plan-out + apply --from ===" >&2
{
  echo "--- configure --plan-out ---"
  timeout 10 docker run --rm $DOCKER_MOUNT "$IMAGE" \
    openclaw secrets configure --plan-out /tmp/plan.json --json 2>&1 \
    || echo "EXIT_CODE:$?"

  echo "--- test if --plan-out produced output ---"
  # run in container with plan written to a shared volume
  TMPDIR_PLAN="$(mktemp -d)"
  DOCKER_PLAN_MOUNT="-v $TMPDIR_PLAN:/tmp/probe-plan"
  timeout 10 docker run --rm $DOCKER_MOUNT $DOCKER_PLAN_MOUNT "$IMAGE" \
    bash -c 'openclaw secrets configure --plan-out /tmp/probe-plan/plan.json --json 2>&1; echo EXIT:$?' \
    || echo "outer exit: $?"
  echo "--- plan.json content ---"
  cat "$TMPDIR_PLAN/plan.json" 2>/dev/null || echo "NO_PLAN_FILE"
  rm -rf "$TMPDIR_PLAN"

  echo "--- apply --from and --yes availability ---"
  timeout 10 docker run --rm "$IMAGE" openclaw secrets apply --help 2>&1 || true
  timeout 10 docker run --rm "$IMAGE" openclaw secrets configure --help 2>&1 || true
} > "$FIXTURES/m0_twostage_configure.txt" 2>&1

echo "Output (first 20 lines):" >&2
head -20 "$FIXTURES/m0_twostage_configure.txt" >&2

# ── PROBE 4: filesScanned field shape + decoy file exclusion ─────────────────
echo "" >&2
echo "=== PROBE 4: filesScanned shape + decoy file exclusion ===" >&2
TMPDIR_DECOY="$(mktemp -d)"
mkdir -p "$TMPDIR_DECOY/evil"
cat > "$TMPDIR_DECOY/evil/openclaw.json" <<'DECOY'
{"providers":{"evil":{"apiKey":"sk-decoy-key-000000000000000000000000000000"}}}
DECOY

timeout 15 docker run --rm \
  $DOCKER_MOUNT \
  -v "$TMPDIR_DECOY/evil:/etc/evil" \
  "$IMAGE" \
  openclaw secrets audit --json 2>/dev/null \
  > "$FIXTURES/m0_filesscanned_probe.json" || true

echo "filesScanned field:" >&2
python3 -c "
import json, sys
try:
    d = json.load(open('$FIXTURES/m0_filesscanned_probe.json'))
    print('top keys:', list(d.keys()))
    print('filesScanned:', d.get('filesScanned', 'NOT_PRESENT'))
    print('findings count:', len(d.get('findings', [])))
    if d.get('findings'):
        print('first finding:', json.dumps(d['findings'][0], indent=2))
except Exception as e:
    print('parse error:', e)
    sys.exit(1)
" 2>&1 >&2 || cat "$FIXTURES/m0_filesscanned_probe.json" | head -20 >&2

echo "" >&2
echo "=== M0 PROBES COMPLETE ===" >&2
echo "Fixtures:" >&2
ls -lh "$FIXTURES/"m0_* >&2
