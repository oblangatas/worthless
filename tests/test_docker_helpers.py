"""Docker probes used in module-level ``skipif`` must never raise.

They run at import time, so an exception is a collection error that aborts
the whole run on any machine without a ``docker`` binary.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


# ponytail: child interpreter + full collection is ~3s idle, 10s+ on a loaded box;
# own timeout so a slow runner can't hit the global 30s and kill the xdist worker.
@pytest.mark.timeout(120)
def test_whole_suite_collects_without_docker(tmp_path: Path) -> None:
    """The user-visible promise: a machine with no docker can still collect."""
    env = {k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"}
    env["PATH"] = str(tmp_path)
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-o",
            "addopts=",
            "--strict-markers",
            "--strict-config",
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
            str(REPO_ROOT / "tests"),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=110,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-1000:]
