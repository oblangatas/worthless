"""Meta-test: the pre-existing ``tests/test_dotenv_rewriter.py`` MUST still pass.

After wiring the rewriter through ``safe_rewrite``, all 24 tests in the
original ``tests/test_dotenv_rewriter.py`` module must remain green.
This belt-and-suspenders check runs pytest on that specific module in
a subprocess and asserts a clean exit code, catching any behavioural
regression that the formatting/safety suites might miss.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_existing_dotenv_rewriter_test_module_still_passes() -> None:
    """Run ``tests/test_dotenv_rewriter.py`` via pytest subprocess; assert exit 0.

    Runs in a subprocess so that the current pytest session's
    instrumentation/fixtures cannot mask a regression. The module path
    is resolved relative to this file so the test is not coupled to
    the caller's cwd.
    """
    # Locate repo root: two levels up from tests/dotenv_rewriter/.
    here = Path(__file__).resolve()
    repo_root = here.parents[2]
    legacy_module = repo_root / "tests" / "test_dotenv_rewriter.py"
    assert legacy_module.exists(), (
        f"legacy dotenv rewriter test module not found at {legacy_module}"
    )

    # Run in a clean subprocess with ALL plugins disabled so the parent
    # pytest's xdist / rerunfailures / timeout machinery cannot recurse
    # or reconfigure the child. The child uses ``-p no:...`` to disable
    # each plugin that our pyproject.toml would otherwise auto-load.
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "pytest",
            str(legacy_module),
            "-q",
            "--no-header",
            "--tb=short",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:xdist",
            "-p",
            "no:rerunfailures",
            "-p",
            "no:benchmark",
            "-o",
            "addopts=",
            "-o",
            "timeout=10",
        ],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"legacy tests/test_dotenv_rewriter.py regressed (exit={result.returncode}):\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )
