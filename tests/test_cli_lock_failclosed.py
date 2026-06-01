"""Fail-closed contract for ``worthless lock``'s bypass-URL scan (worthless-61tw).

After c5kc, the .env scan + MCP tool + --code scan all fail closed on an
incomplete scan. ``worthless lock`` was the last entry point still missing
this guard — its call to ``scan_source_for_hardcoded_provider_urls`` ran with
no deadline and no skipped list, so a hostile or oversized source file could
hang ``lock`` the same way it used to hang ``scan``.

These tests pin the new contract:
  * skipped non-empty → exit 2 with a ``scan incomplete — refusing to lock``
    stderr block (the fail-closed signal);
  * ``--allow-hardcoded-urls`` does NOT waive an incomplete scan — you can't
    acknowledge bypass URLs that were never surfaced;
  * happy path (no skipped) → falls through to the existing flow unchanged.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.scanner import SkippedFile

runner = CliRunner(mix_stderr=False)


@pytest.fixture
def env_with_key(tmp_path: Path) -> Path:
    """A small .env so lock would otherwise have something to do."""
    env = tmp_path / ".env"
    env.write_text("OPENAI_API_KEY=sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2\n")
    return env


def test_lock_fails_closed_when_source_scan_incomplete(
    tmp_path: Path, env_with_key: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An incomplete source scan must block ``worthless lock`` with exit 2 —
    the integrity guarantee from c5kc now applies to the lock entry point too."""
    monkeypatch.setenv("WORTHLESS_HOME", str(tmp_path / "wh"))

    def fake_scan(_root, *, deadline=None, skipped=None, **_kw):
        # Pre-c5kc, this could have hung forever. Now the caller MUST pass a
        # mutable skipped list; we simulate a truncated source file.
        assert skipped is not None, (
            "lock must pass a mutable ``skipped`` list — that's the whole point of 61tw"
        )
        skipped.append(SkippedFile(file=str(tmp_path / "big.py"), reason="truncated"))
        return []  # no findings, but scan was incomplete

    with patch(
        "worthless.cli.commands.lock.scan_source_for_hardcoded_provider_urls",
        side_effect=fake_scan,
    ):
        result = runner.invoke(app, ["lock", "--env", str(env_with_key)])

    assert result.exit_code == 2, (
        f"incomplete source scan must exit 2 (fail-closed). got {result.exit_code!r}\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    assert "scan incomplete" in result.stderr.lower()
    assert "refusing to lock" in result.stderr.lower()
    # The reason word must appear (bracket form ``[truncated]`` may be eaten
    # by sanitise_for_message on long paths, but the word itself survives).
    assert "truncated" in result.stderr.lower()


def test_allow_hardcoded_urls_does_not_waive_incomplete_scan(
    tmp_path: Path, env_with_key: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--allow-hardcoded-urls`` waives FINDINGS, not the INTEGRITY of the scan.
    You can't acknowledge bypass URLs that were never surfaced."""
    monkeypatch.setenv("WORTHLESS_HOME", str(tmp_path / "wh"))

    def fake_scan(_root, *, deadline=None, skipped=None, **_kw):
        skipped.append(SkippedFile(file=str(tmp_path / "big.py"), reason="truncated"))
        return []

    with patch(
        "worthless.cli.commands.lock.scan_source_for_hardcoded_provider_urls",
        side_effect=fake_scan,
    ):
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_with_key), "--allow-hardcoded-urls"],
        )

    assert result.exit_code == 2, (
        f"--allow-hardcoded-urls must NOT waive an incomplete scan. "
        f"got {result.exit_code!r}\nstderr: {result.stderr!r}"
    )
    assert "scan incomplete" in result.stderr.lower()


def test_happy_path_no_skipped_proceeds_to_existing_flow(
    tmp_path: Path, env_with_key: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No skipped, no findings → the new guard is invisible; lock continues."""
    monkeypatch.setenv("WORTHLESS_HOME", str(tmp_path / "wh"))

    deadline_received: dict[str, float | None] = {"value": None}

    def fake_scan(_root, *, deadline=None, skipped=None, **_kw):
        # Pin that lock now actually passes a deadline (not None) — proves the
        # caller wired the bounded-time guard, not just the skipped list.
        deadline_received["value"] = deadline
        return []

    with patch(
        "worthless.cli.commands.lock.scan_source_for_hardcoded_provider_urls",
        side_effect=fake_scan,
    ):
        result = runner.invoke(app, ["lock", "--env", str(env_with_key)])

    # We don't assert exit_code == 0 — actual lock may exit non-zero for
    # downstream reasons (no keyring in CI, etc). The contract this test pins is:
    # the 61tw guard didn't fire (no "scan incomplete" message) AND the caller
    # passed a real deadline value into the source scanner.
    assert "scan incomplete" not in result.stderr.lower()
    assert deadline_received["value"] is not None
    assert deadline_received["value"] > 0
