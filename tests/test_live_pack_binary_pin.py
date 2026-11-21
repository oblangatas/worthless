"""The live harness says which build it tests, and refuses the wrong one (WOR-854).

A live run that cannot say which ``worthless`` it exercised is evidence of
nothing: the 2026-06-30 launchd run silently tested whatever PATH resolved.
``lp_use_binary`` pins ``WORTHLESS_BIN``; ``WORTHLESS_EXPECT_VERSION`` makes a
run that resolved a different release fail before any check runs.

These drive the real shell function against stand-in executables, so no real
``worthless`` (and no keyring, no ~/.worthless) is ever touched.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

LIB = Path(__file__).resolve().parents[1] / "engineering/testing/scripts/_live-pack-lib.sh"


def _fake_worthless(tmp_path: Path, version: str) -> Path:
    exe = tmp_path / "bin" / "worthless"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text(f'#!/bin/sh\necho "worthless {version}"\n')
    exe.chmod(0o755)
    return exe


def _use_binary(tmp_path: Path, exe: Path, expect: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
        "WORTHLESS_HOME": str(tmp_path / ".worthless"),
        "WORTHLESS_KEYRING_BACKEND": "null",
        "WORTHLESS_BIN": str(exe),
        "WORTHLESS_EXPECT_VERSION": expect,
    }
    return subprocess.run(
        ["bash", "-c", 'source "$1" && lp_use_binary && echo AFTER', "_", str(LIB)],  # noqa: S607
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.mark.skipif(os.name == "nt", reason="bash harness")
@pytest.mark.parametrize(
    ("installed", "expected"),
    [
        ("0.3.10", "0.3.17"),  # the real 2026-08 case: an older release on PATH
        ("0.3.17", "0.3.1"),  # a prefix is not a match
    ],
)
def test_a_different_version_stops_the_run(tmp_path: Path, installed: str, expected: str) -> None:
    result = _use_binary(tmp_path, _fake_worthless(tmp_path, installed), expected)
    assert result.returncode != 0, result.stdout
    assert "AFTER" not in result.stdout
    assert installed in result.stderr and expected in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="bash harness")
def test_the_intended_version_runs_and_is_named_first(tmp_path: Path) -> None:
    exe = _fake_worthless(tmp_path, "0.3.17")
    result = _use_binary(tmp_path, exe, "0.3.17")
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert str(exe) in lines[0]
    assert "0.3.17" in lines[1]
    assert lines[-1] == "AFTER"
