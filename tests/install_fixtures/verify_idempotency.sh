#!/bin/sh
# Verify install.sh is idempotent: a second `curl … | sh` must produce the
# same on-disk state as the first. No version bump, no re-downloaded wheels,
# no binary-hash drift. Exits 0 on match, 1 on diff (with the diff in stdout).
#
# Why this matters: people put `curl … | sh` in CI bootstraps and Dockerfiles.
# A non-idempotent installer turns every job into a wheel re-download and
# a tool-dir rewrite, slows builds, and risks pulling a newer (untested)
# version mid-pipeline.
set -eu

INSTALL_SH="${WORTHLESS_INSTALL_SH:-/work/install.sh}"
SNAP1="/tmp/idempotency-snap-1.txt"
SNAP2="/tmp/idempotency-snap-2.txt"

snapshot() {
    out="$1"
    {
        echo "=== worthless --version ==="
        # `uv run` finds the binary even before PATH is sourced.
        uv run --no-project worthless --version 2>&1 || true
        echo "=== uv --version ==="
        uv --version 2>&1 || true
        echo "=== bin shas ==="
        # Hash the installed binaries — anything that re-downloaded or
        # re-linked them shows up here.
        for bin in "$HOME/.local/bin/worthless" "$HOME/.local/bin/uv"; do
            if [ -e "$bin" ]; then
                if command -v sha256sum >/dev/null 2>&1; then
                    sha256sum "$bin"
                else
                    shasum -a 256 "$bin"
                fi
            fi
        done
        echo "=== tool tree (name + size, no mtime) ==="
        # mtime drifts on a no-op (uv touches some metadata files), so we
        # explicitly DROP timestamps from the snapshot. Names + sizes catch
        # real changes (new wheels, removed files, re-linked metadata).
        tools_dir="$HOME/.local/share/uv/tools/worthless"
        if [ -d "$tools_dir" ]; then
            # Detect `-printf` support explicitly: piping through `sort`
            # masks `find`'s exit code, so a `... -printf … || ...` chain
            # silently falls through to an empty snapshot on BusyBox.
            if find "$tools_dir" -maxdepth 0 -printf '' 2>/dev/null; then
                find "$tools_dir" -type f -printf '%P %s\n' | sort
            else
                find "$tools_dir" -type f | sort
            fi
        fi
    } > "$out"
}

echo ">>> First install"
sh "$INSTALL_SH"
PATH="$HOME/.local/bin:$PATH"
export PATH

echo ">>> First snapshot"
snapshot "$SNAP1"

echo ">>> Second install (should be no-op)"
sh "$INSTALL_SH"

echo ">>> Second snapshot"
snapshot "$SNAP2"

echo ">>> Diff"
if ! diff -u "$SNAP1" "$SNAP2"; then
    echo "FAIL: install.sh not idempotent — second run changed installed state"
    exit 1
fi

echo "OK: install.sh is idempotent (snapshots match)"
