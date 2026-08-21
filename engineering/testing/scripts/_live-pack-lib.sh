# Shared terminal helpers for L7 live-pack dev scripts (not CI).
# Source from bash:  source "$(dirname "$0")/_live-pack-lib.sh"
#
# Env:
#   LIVE_PACK_NO_COLOR=1  — plain ASCII headers (CI logs)
#   WORTHLESS_BIN=<path>  — test THIS binary instead of whatever PATH resolves
#                           (worthless-d4h2). Point it at an installed wheel to
#                           exercise the artifact users actually get.

_live_pack_lib_loaded=1

LP_PHASE_NUM=0

# worthless-d4h2: these packs call bare `worthless`, so PATH silently decides
# which build is under test. Run from a worktree and PATH hands you .venv —
# the branch copy, not the artifact a user installs. That is how three bugs
# reached a release with a green suite: the lane existed but tested the wrong
# thing, and never said which thing.
#
# Two jobs here: honour an explicit WORTHLESS_BIN, and ALWAYS print the
# resolved path + version so a run can never be silently about the wrong
# binary again. Prepending to PATH (rather than rewriting every call site)
# keeps the packs readable and covers subprocesses the CLI spawns.
lp_use_binary() {
  if [[ -n "${WORTHLESS_BIN:-}" ]]; then
    if [[ ! -x "$WORTHLESS_BIN" ]]; then
      echo "WORTHLESS_BIN is set but not executable: $WORTHLESS_BIN" >&2
      exit 1
    fi
    # Select the named file EXACTLY. Prepending dirname($WORTHLESS_BIN) and then
    # resolving bare `worthless` is not the same thing: if the override has a
    # different basename (worthless-0.3.12), or a second `worthless` sits in that
    # directory, PATH would pick the other one and the pack would report a green
    # run for a binary nobody asked for. In a lane whose entire purpose is "prove
    # the artifact you named", that is the bug it exists to prevent.
    #
    # A private shim dir holding one symlink named `worthless` makes the
    # resolution exact while keeping the packs' bare `worthless` calls readable.
    local shim_dir target
    target="$(cd "$(dirname "$WORTHLESS_BIN")" && pwd)/$(basename "$WORTHLESS_BIN")"
    shim_dir="$(mktemp -d "${TMPDIR:-/tmp}/worthless-bin-shim.XXXXXX")"
    ln -s "$target" "$shim_dir/worthless"
    PATH="$shim_dir:$PATH"
    export PATH
  fi

  local resolved
  resolved="$(command -v worthless 2>/dev/null || true)"
  if [[ -z "$resolved" ]]; then
    echo "no 'worthless' on PATH — set WORTHLESS_BIN or install it first" >&2
    exit 1
  fi
  # Assert, don't assume: if an override was given, what actually resolved must
  # BE that file (-ef compares inode, so the symlink hop is fine).
  if [[ -n "${WORTHLESS_BIN:-}" && ! "$resolved" -ef "$WORTHLESS_BIN" ]]; then
    echo "resolved '$resolved' is not WORTHLESS_BIN '$WORTHLESS_BIN'" >&2
    exit 1
  fi
  echo "  binary under test: ${WORTHLESS_BIN:-$resolved}"
  echo "  version:           $(worthless --version 2>&1 | tail -1)"
}

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
