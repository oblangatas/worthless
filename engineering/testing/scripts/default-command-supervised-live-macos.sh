#!/usr/bin/env bash
# Default command live pack — supervised ``worthless --yes`` + idempotent second run.
# See ../wor-193-live-checklist.md
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export PATH="${REPO_ROOT}/.venv/bin:${PATH}"
PORT="${WORTHLESS_PORT:-8787}"
if [[ -n "${LIVE_PROJECT_DIR:-}" ]]; then
  WORK_DIR="$LIVE_PROJECT_DIR"
  CREATED_WORK_DIR=0
else
  WORK_DIR="$(mktemp -d /tmp/worthless-live-project-XXXXXX)"
  CREATED_WORK_DIR=1
fi

cleanup() {
  worthless down 2>/dev/null || true
  worthless service uninstall --yes 2>/dev/null || true
  if [[ "${CREATED_WORK_DIR}" -eq 1 ]]; then
    rm -rf "$WORK_DIR" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ -n "${WORTHLESS_HOME:-}" ]]; then
  resolved_home="$(cd "$WORTHLESS_HOME" && pwd)"
  default_home="$(cd "$HOME/.worthless" && pwd)"
  if [[ "$resolved_home" != "$default_home" ]]; then
    echo "WORTHLESS_HOME=$WORTHLESS_HOME (resolved: $resolved_home)"
    echo "This live pack expects ~/.worthless. Run: unset WORTHLESS_HOME"
    exit 1
  fi
fi

worthless service uninstall --yes 2>/dev/null || true
worthless down 2>/dev/null || true

FAKE_KEY="$(cd "$REPO_ROOT" && uv run python -c "from tests.helpers import fake_openai_key; print(fake_openai_key())")"
mkdir -p "$WORK_DIR"
printf 'OPENAI_API_KEY=%s\n' "$FAKE_KEY" >"$WORK_DIR/.env"
cd "$WORK_DIR"

count_up_procs() {
  pgrep -f "[w]orthless up" 2>/dev/null | wc -l | tr -d ' '
}

worthless --yes | tee /tmp/worthless-default-command-first.txt
after_first="$(count_up_procs)"
test "$after_first" -ge 1
grep -qi "proxy healthy" /tmp/worthless-default-command-first.txt
curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null
test ! -f "$HOME/Library/LaunchAgents/dev.worthless.proxy.plist"

worthless --yes | tee /tmp/worthless-default-command-second.txt
after_second="$(count_up_procs)"
test "$after_second" = "$after_first"
grep -qi "proxy healthy" /tmp/worthless-default-command-second.txt

echo "default command supervised live pack (macOS): PASS (workdir=$WORK_DIR)"
