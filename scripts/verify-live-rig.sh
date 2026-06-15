#!/usr/bin/env bash
# verify-live-rig.sh — confirm the live test container is running BRANCH HEAD code,
# not a stale installed package. Run BEFORE any live lock/chat/proxy test.
#
# Usage:
#   ./scripts/verify-live-rig.sh [container_name] [signature_grep]
#
# Default container: worthless-oc-gui
# Default signature: F1 marker — `provider_name = provider` in openclaw/integration.py
#
# Exits 0 if installed code matches branch on the signature, nonzero with a remediation hint otherwise.

set -euo pipefail

CONTAINER="${1:-worthless-oc-gui}"
SIG="${2:-provider_name = provider$}"
BRANCH_INTEGRATION="src/worthless/openclaw/integration.py"

WORKTREE_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
echo "worktree=$WORKTREE_ROOT branch=$(git -C "$WORKTREE_ROOT" rev-parse --abbrev-ref HEAD) head=$(git -C "$WORKTREE_ROOT" rev-parse --short HEAD)"

# 1. container alive?
if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "FAIL: container '$CONTAINER' not running. start it first." >&2
  exit 2
fi

# 2. installed version
INSTALLED_VER=$(docker exec "$CONTAINER" bash -c 'WORTHLESS_KEYRING_BACKEND=null worthless --version 2>&1' | head -1)
echo "installed_version=$INSTALLED_VER"

# 3. branch signature present in worktree source?
BRANCH_HITS=$(grep -cE "$SIG" "$WORKTREE_ROOT/$BRANCH_INTEGRATION" 2>/dev/null || true)
BRANCH_HITS=${BRANCH_HITS:-0}
echo "branch_signature_hits=$BRANCH_HITS  (pattern: '$SIG')"
if [ "$BRANCH_HITS" -eq 0 ]; then
  echo "FAIL: signature not in branch source — wrong signature, or wrong worktree" >&2
  exit 3
fi

# 4. installed signature?
# Resolve the actual path INSIDE the container via Python introspection so we
# don't hardcode the python3.NN site-packages segment (CR finding on PR #276:
# uv tool path includes a version-specific segment; pinning python3.11 missed
# any other Python build).
CONTAINER_INTEGRATION=$(docker exec "$CONTAINER" bash -c \
  "WORTHLESS_KEYRING_BACKEND=null python3 -c 'import worthless.openclaw.integration as m; print(m.__file__)' 2>/dev/null" \
  | tr -d '[:space:]')
if [ -z "$CONTAINER_INTEGRATION" ]; then
  echo "FAIL: could not resolve installed integration.py path inside $CONTAINER" >&2
  exit 5
fi
echo "container_integration_path=$CONTAINER_INTEGRATION"
INSTALLED_HITS=$(docker exec "$CONTAINER" bash -c "grep -cE '$SIG' '$CONTAINER_INTEGRATION' 2>/dev/null || true" | head -1 | tr -d '[:space:]')
INSTALLED_HITS=${INSTALLED_HITS:-0}
echo "installed_signature_hits=$INSTALLED_HITS"
if [ "$INSTALLED_HITS" -eq 0 ]; then
  cat >&2 <<EOF
FAIL: installed package does NOT contain the branch signature.
You are about to test against STALE code. Fix with:

  cd "$WORKTREE_ROOT"
  uv build --wheel
  WHL=\$(ls -t dist/*.whl | head -1)
  docker cp "\$WHL" $CONTAINER:/tmp/
  docker exec $CONTAINER uv tool install --reinstall --no-cache "/tmp/\$(basename \$WHL)"

Then re-run this script.
EOF
  exit 4
fi

echo "OK: installed package contains the branch signature — safe to run live tests."
