"""A test can't leave the CLI's process-globals changed for the tests after it.

The suite runs shuffled across xdist workers, so a leak only bites when the
right two tests share a worker in the right order. This pins that order in a
real pytest subprocess that loads the suite's own conftest as a plugin.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
# A developer shell can reshape the child run; the order pin must not depend on it.
_CHILD_ENV_DROP = ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONSAFEPATH")

ORDERED_TESTS = """
from worthless.cli import console, errors
from worthless.cli.console import WorthlessConsole, set_console


def test_1_leaves_quiet_console_and_debug_on():
    set_console(WorthlessConsole(quiet=True, json_mode=True))
    errors.set_debug(True)


def test_2_starts_with_cli_defaults():
    assert console._console is None
    assert errors._debug is False
"""


@pytest.mark.timeout(90)
def test_quiet_console_and_debug_do_not_leak_into_the_next_test(tmp_path: Path) -> None:
    test_file = tmp_path / "test_ordered.py"
    test_file.write_text(ORDERED_TESTS)
    ini = tmp_path / "pytest.ini"
    ini.write_text("[pytest]\n")
    env = {k: v for k, v in os.environ.items() if k not in _CHILD_ENV_DROP}
    env["PYTHONPATH"] = str(REPO_ROOT)

    result = subprocess.run(  # noqa: S603 — fixed argv, no shell
        [
            sys.executable,
            "-m",
            "pytest",
            str(test_file),
            "-c",
            str(ini),
            "--rootdir",
            str(tmp_path),
            "-p",
            "tests.conftest",
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
            "-q",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=80,
        check=False,
    )

    assert result.returncode == 0 and "2 passed" in result.stdout, (
        f"a CLI global leaked from test_1 into test_2:\n{result.stdout}\n{result.stderr}"
    )
