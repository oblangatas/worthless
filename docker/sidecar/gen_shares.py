#!/usr/bin/env python3
"""Generate a pair of XOR shares whose XOR is a valid Fernet key.

Prototype convenience — the container uses this when no mounted secrets
are present (smoke test). Production shares are mounted read-only from
a secrets manager; this file MUST NOT be used to mint real keys.

Usage:

    gen_shares.py <path_a> <path_b>
"""

from __future__ import annotations

import base64
import secrets
import sys
from pathlib import Path


def _write_share(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o400)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: gen_shares.py <path_a> <path_b>", file=sys.stderr)
        return 2
    a_path, b_path = Path(sys.argv[1]), Path(sys.argv[2])

    # Fernet key = urlsafe_b64(32 random bytes) = 44 bytes.
    key = base64.urlsafe_b64encode(secrets.token_bytes(32))
    share_a = secrets.token_bytes(len(key))
    share_b = bytes(a ^ k for a, k in zip(share_a, key, strict=True))
    assert bytes(a ^ b for a, b in zip(share_a, share_b, strict=True)) == key

    _write_share(a_path, share_a)
    _write_share(b_path, share_b)
    return 0


if __name__ == "__main__":
    sys.exit(main())
