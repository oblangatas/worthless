"""shellcheck static analysis for install.sh and its test fixtures.

Skipped if shellcheck is not installed locally; required in CI.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from tests._install_helpers import INSTALL_FIXTURES, INSTALL_SH

SHELL_SCRIPTS = [
    INSTALL_SH,
    INSTALL_FIXTURES / "verify_install.sh",
    INSTALL_FIXTURES / "verify_uv_reuse.sh",
]


@pytest.mark.skipif(
    shutil.which("shellcheck") is None,
    reason="shellcheck not installed; install via 'brew install shellcheck' or apt",
)
@pytest.mark.parametrize("script", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_install_scripts_pass_shellcheck(script) -> None:
    """Every shell script in the install flow must pass shellcheck cleanly."""
    assert script.is_file(), f"missing script: {script}"
    result = subprocess.run(  # noqa: S603
        ["shellcheck", "--shell=sh", "--severity=warning", str(script)],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, (
        f"shellcheck reported issues in {script.name}:\n{result.stdout}\n{result.stderr}"
    )
