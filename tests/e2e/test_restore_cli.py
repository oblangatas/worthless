"""E2E tests for ``worthless restore`` (WOR-276 v2, commit 7).

The v2 ``restore`` subcommand is a thin wrapper around
:func:`worthless.cli.safe_rewrite.safe_restore` — it reads replacement
bytes from stdin and atomically rewrites the target ``.env`` file,
bypassing only the DELTA blowup-ratio gate. Every other invariant still
fires. The fs_check gate itself is covered by the unit suite under
``tests/fs_check/``; here we stay at the CLI surface.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _child_env(tmp_path: Path) -> dict[str, str]:
    env = dict(os.environ)
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    env["HOME"] = str(home)
    env["XDG_DATA_HOME"] = str(tmp_path / "xdg")
    return env


def test_restore_from_stdin_writes_bytes_atomically(
    tmp_path: Path, worthless_cli: list[str]
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    env_file = repo / ".env"
    env_file.write_bytes(b"OLD=1\n")

    payload = b"API_KEY=restored\nDB_URL=postgres://x\n"

    proc = subprocess.run(
        [*worthless_cli, "restore", str(env_file)],
        env=_child_env(tmp_path),
        cwd=str(repo),
        input=payload,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0
    assert _sha256(env_file.read_bytes()) == _sha256(payload)


def test_restore_refuses_non_env_basename(tmp_path: Path, worthless_cli: list[str]) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    bogus = repo / "secrets.txt"
    bogus.write_bytes(b"NOT_AN_ENV=1\n")

    proc = subprocess.run(
        [*worthless_cli, "restore", str(bogus)],
        env=_child_env(tmp_path),
        cwd=str(repo),
        input=b"EVIL=1\n",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode != 0
    assert bogus.read_bytes() == b"NOT_AN_ENV=1\n"
    assert b"unchanged" in proc.stderr.lower()
    assert b"UnsafeReason." not in proc.stderr


def test_restore_refuses_empty_stdin(tmp_path: Path, worthless_cli: list[str]) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    env_file = repo / ".env"
    env_file.write_bytes(b"OLD=1\n")

    proc = subprocess.run(
        [*worthless_cli, "restore", str(env_file)],
        env=_child_env(tmp_path),
        cwd=str(repo),
        input=b"",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode != 0
    assert env_file.read_bytes() == b"OLD=1\n"
