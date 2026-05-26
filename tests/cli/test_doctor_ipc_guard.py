"""Tests for doctor command refusal under WORTHLESS_FERNET_IPC_ONLY (WOR-465 A4).

When ipc_mode_active() returns True, ``worthless doctor`` is refused.
The command's design (interleaved asyncio.run + synchronous typer.confirm
prompts) cannot be bracketed by a single async IPCClient context manager,
so refusal is the correct response rather than a partial implementation.

Three pinned invariants:
  - Flag ON + non-root → refused with non-zero exit.
  - Refusal message contains the operator escape hatch (``docker exec``).
  - Flag OFF → doctor proceeds normally (regression direction).
"""

from __future__ import annotations

import pytest

from worthless.cli.bootstrap import WorthlessHome

from tests.cli.conftest import cli_invoke


class TestDoctorIpcGuard:
    def test_doctor_refused_under_ipc_mode(
        self, home_dir: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Flag ON + non-root: doctor exits non-zero with actionable hint."""
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        result = cli_invoke(["doctor"], home_dir)

        assert result.exit_code != 0, "doctor must exit non-zero under WORTHLESS_FERNET_IPC_ONLY=1"
        assert "docker exec" in result.output, (
            "doctor refusal must include the 'docker exec --user root' operator hint "
            f"so operators know how to run doctor inside the container; got:\n{result.output}"
        )

    def test_doctor_fix_flag_does_not_bypass_ipc_guard(
        self, home_dir: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--fix does not bypass the IPC guard."""
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        result = cli_invoke(["doctor", "--fix", "--yes"], home_dir)

        assert result.exit_code != 0

    def test_doctor_proceeds_when_flag_off(
        self, home_dir: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression direction: flag OFF → doctor runs normally (clean state)."""
        monkeypatch.delenv("WORTHLESS_FERNET_IPC_ONLY", raising=False)
        result = cli_invoke(["doctor"], home_dir)

        assert result.exit_code == 0, (
            f"doctor must succeed on bare metal (flag off):\n{result.output}"
        )
        assert "no issues found" in result.output.lower(), (
            f"doctor on empty DB must report clean state:\n{result.output}"
        )
