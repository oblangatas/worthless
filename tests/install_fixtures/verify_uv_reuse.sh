#!/bin/sh
# Hash uv before and after install.sh. sha256 equality = same binary, i.e.
# install.sh reused the pre-installed uv rather than reinstalling. Stronger
# than mtime (1s-resolution race) and inode (a same-content mv would fool).
set -eu

UV_PATH="$HOME/.local/bin/uv"
[ -x "$UV_PATH" ] || { echo "FAIL: expected uv at $UV_PATH before install" >&2; exit 1; }

UV_BEFORE=$(sha256sum "$UV_PATH" | cut -d' ' -f1)
sh /work/install.sh
UV_AFTER=$(sha256sum "$UV_PATH" | cut -d' ' -f1)

if [ "$UV_BEFORE" != "$UV_AFTER" ]; then
    echo "FAIL: uv was reinstalled (hash changed: $UV_BEFORE -> $UV_AFTER)" >&2
    exit 1
fi

sh /work/verify_install.sh
