"""Bootstrapped home builders for CLI adversarial and stability tests."""

from __future__ import annotations

import os
from pathlib import Path

from worthless.cli.bootstrap import WorthlessHome


def write_secure_fernet_key(path: Path, content: bytes = b"x" * 32) -> None:
    """Write ``fernet.key`` with mode 0o600 via ``os.open`` (no chmod race)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content)
    finally:
        os.close(fd)


def make_bootstrapped_home(
    base: Path,
    *,
    fernet_content: bytes = b"x" * 32,
    base_mode: int = 0o700,
) -> WorthlessHome:
    """Return a post-bootstrap home: fernet.key, marker, shard_a dir."""
    base.mkdir(mode=base_mode, parents=True, exist_ok=True)
    write_secure_fernet_key(base / "fernet.key", fernet_content)
    (base / ".bootstrapped").touch(mode=0o600, exist_ok=True)
    (base / "shard_a").mkdir(mode=0o700, exist_ok=True)
    return WorthlessHome(base_dir=base)
