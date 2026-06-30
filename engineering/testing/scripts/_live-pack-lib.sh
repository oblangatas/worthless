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
