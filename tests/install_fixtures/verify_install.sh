#!/bin/sh
# Post-install verification — run inside the test container after install.sh.
# Asserts more than `worthless --version`: exit codes, stderr cleanliness,
# resolved binary path, and that `--help` loads the subcommand registry
# (catches lazy-import failures that --version sidesteps).
set -eu

export PATH="$HOME/.local/bin:$PATH"

# Per-run temp files so a reused container doesn't inherit stale stderr.
VERSION_ERR=$(mktemp)
HELP_OUT=$(mktemp)
HELP_ERR=$(mktemp)
trap 'rm -f "$VERSION_ERR" "$HELP_OUT" "$HELP_ERR"' EXIT

# Resolve path; must live under $HOME/.local/bin (not a system shim).
WORTHLESS_PATH=$(command -v worthless)
case "$WORTHLESS_PATH" in
    "$HOME/.local/bin/worthless") ;;
    *) echo "FAIL: worthless resolved to $WORTHLESS_PATH, expected $HOME/.local/bin/worthless" >&2; exit 1 ;;
esac

# --version must exit 0 and contain "worthless".
if ! VERSION_OUT=$(worthless --version 2>"$VERSION_ERR"); then
    echo "FAIL: worthless --version exited non-zero" >&2
    cat "$VERSION_ERR" >&2
    exit 1
fi
echo "$VERSION_OUT"
if ! echo "$VERSION_OUT" | grep -qi "worthless"; then
    echo "FAIL: --version output missing 'worthless': $VERSION_OUT" >&2
    exit 1
fi
# -E for portable alternation (busybox grep on Alpine accepts it; BRE \| does not).
if grep -qiE "Traceback|ModuleNotFoundError" "$VERSION_ERR"; then
    echo "FAIL: --version emitted Traceback/ModuleNotFoundError" >&2
    cat "$VERSION_ERR" >&2
    exit 1
fi

# --help must exit 0 (exercises lazy subcommand imports — cryptography, keyring).
if ! worthless --help >"$HELP_OUT" 2>"$HELP_ERR"; then
    echo "FAIL: worthless --help exited non-zero" >&2
    cat "$HELP_ERR" >&2
    exit 1
fi
if grep -qiE "Traceback|ModuleNotFoundError" "$HELP_ERR"; then
    echo "FAIL: --help emitted Traceback/ModuleNotFoundError" >&2
    cat "$HELP_ERR" >&2
    exit 1
fi

echo "OK: install verified at $WORTHLESS_PATH"
