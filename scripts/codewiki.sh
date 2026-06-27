#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEWIKI_VENV="${CODEWIKI_VENV:-$ROOT/.venvs/codewiki}"
CODEWIKI_HOME_DIR="${CODEWIKI_HOME_DIR:-$ROOT/.codewiki-home}"
CODEWIKI_PYTHON="${CODEWIKI_PYTHON:-python3.12}"
CODEWIKI_REPO="${CODEWIKI_REPO:-git+https://github.com/FSoft-AI4Code/CodeWiki.git}"

mkdir -p "$CODEWIKI_HOME_DIR"

export CODEWIKI_NO_KEYRING=1
export HOME="$CODEWIKI_HOME_DIR"

if ! command -v "$CODEWIKI_PYTHON" >/dev/null 2>&1; then
  echo "Missing required interpreter: $CODEWIKI_PYTHON" >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "Missing required dependency: node" >&2
  exit 1
fi

if [ ! -x "$CODEWIKI_VENV/bin/python" ]; then
  "$CODEWIKI_PYTHON" -m venv "$CODEWIKI_VENV"
fi

if [ ! -x "$CODEWIKI_VENV/bin/codewiki" ]; then
  "$CODEWIKI_VENV/bin/pip" install --upgrade pip
  "$CODEWIKI_VENV/bin/pip" install "$CODEWIKI_REPO"
fi

exec "$CODEWIKI_VENV/bin/codewiki" "$@"
