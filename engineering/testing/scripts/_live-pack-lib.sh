# Shared terminal helpers for L7 live-pack dev scripts (not CI).
# Source from bash:  source "$(dirname "$0")/_live-pack-lib.sh"
#
# Env:
#   LIVE_PACK_NO_COLOR=1  — plain ASCII headers (CI logs)

_live_pack_lib_loaded=1

LP_PHASE_NUM=0

lp_banner() {
  local title="${1:-worthless live pack}"
  echo ""
  if [[ "${LIVE_PACK_NO_COLOR:-}" == "1" ]]; then
    echo "================================================================"
    echo "  ${title}"
    echo "================================================================"
  else
    echo "╔══════════════════════════════════════════════════════════════╗"
    printf "║  %-60s║\n" "$title"
    echo "╚══════════════════════════════════════════════════════════════╝"
  fi
}

lp_phase() {
  LP_PHASE_NUM=$((LP_PHASE_NUM + 1))
  echo ""
  printf "── [%d] %s\n" "$LP_PHASE_NUM" "$1"
  echo "────────────────────────────────────────────────────────────────"
}

lp_step() {
  printf "  → %s\n" "$*"
}

lp_ok() {
  printf "  ✓ %s\n" "$*"
}

lp_warn() {
  printf "  ! %s\n" "$*"
}

lp_fail() {
  printf "  ✗ %s\n" "$*" >&2
}

lp_diag() {
  echo ""
  echo "── diagnostics ────────────────────────────────────────────────"
  while (($#)); do
    printf "  %s\n" "$1"
    shift
  done
}

lp_footer_pass() {
  local msg="${1:-PASS}"
  echo ""
  if [[ "${LIVE_PACK_NO_COLOR:-}" == "1" ]]; then
    echo "================================================================"
    echo "  ${msg}"
    echo "================================================================"
  else
    echo "╔══════════════════════════════════════════════════════════════╗"
    printf "║  %-60s║\n" "$msg"
    echo "╚══════════════════════════════════════════════════════════════╝"
  fi
  echo ""
}

lp_log_tail() {
  local label="$1"
  local path="$2"
  local lines="${3:-30}"
  echo ""
  printf "── %s (last %s lines) ──\n" "$label" "$lines"
  tail -"${lines}" "$path" 2>/dev/null || echo "  (missing: ${path})"
}

# Fail if any live non-worthless process listens on port (ignores stale lsof PIDs).
lp_port_foreign_listeners_block() {
  local port=$1
  command -v lsof >/dev/null 2>&1 || return 0
  local pids pid args
  pids="$(lsof -ti "tcp:${port}" -sTCP:LISTEN 2>/dev/null || true)"
  [[ -n "$pids" ]] || return 0
  for pid in $pids; do
    args="$(ps -p "$pid" -o args= 2>/dev/null || true)"
    [[ -n "$args" ]] || continue
    if [[ "$args" != *worthless* ]]; then
      lp_fail "port ${port} is occupied by non-worthless process ${pid}: ${args}"
      return 1
    fi
  done
  return 0
}

# Kill only worthless listeners on port; fail if a foreign process owns it.
lp_kill_worthless_port_listeners() {
  local port=$1
  command -v lsof >/dev/null 2>&1 || return 0
  local pids
  pids="$(lsof -ti "tcp:${port}" -sTCP:LISTEN 2>/dev/null || true)"
  [[ -n "$pids" ]] || return 0
  local pid args
  for pid in $pids; do
    args="$(ps -p "$pid" -o args= 2>/dev/null || true)"
    [[ -n "$args" ]] || continue
    if [[ "$args" != *worthless* ]]; then
      lp_fail "port ${port} is occupied by non-worthless process ${pid}: ${args}"
      return 1
    fi
  done
  echo "Killing stale worthless listener(s) on port ${port}: ${pids}"
  # shellcheck disable=SC2086
  kill -TERM ${pids} 2>/dev/null || true
  sleep 0.5
  pids="$(lsof -ti "tcp:${port}" -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "$pids" ]]; then
    for pid in $pids; do
      args="$(ps -p "$pid" -o args= 2>/dev/null || true)"
      [[ -n "$args" ]] || continue
      if [[ "$args" != *worthless* ]]; then
        lp_fail "port ${port} was re-occupied by non-worthless process ${pid}: ${args}"
        return 1
      fi
    done
    # shellcheck disable=SC2086
    kill -KILL ${pids} 2>/dev/null || true
  fi
}
