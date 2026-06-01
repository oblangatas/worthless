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


# ---------------------------------------------------------------------------
# worthless-8vvg: post-lock _maybe_prompt_code_scan is ADVISORY not blocking
#
# Unlike the pre-flight scan (which fail-closes on incomplete), the post-lock
# prompt is opportunistic — lock has already committed, exit code MUST NOT
# change. Skipped non-empty → emit advisory note and skip the prompt.
# ---------------------------------------------------------------------------


class TestPostLockPromptAdvisoryOnly:
    """Direct unit tests for ``_maybe_prompt_code_scan`` — the post-lock
    opportunistic scan that runs AFTER enrollment succeeded. A hostile or
    oversized source file must not freeze the terminal, and must not change
    the lock's exit code."""

    def test_incomplete_scan_emits_advisory_note_and_returns_silently(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """8vvg: when the bounded scan reports skipped files, the prompt is
        suppressed and a one-line advisory goes to stderr. No raise."""
        from worthless.cli.commands.lock import _maybe_prompt_code_scan

        deadline_received: dict[str, float | None] = {"value": None}

        def fake_scan(_roots, *, deadline=None, skipped=None, **_kw):
            # 8vvg requires both arguments be plumbed through.
            assert skipped is not None, "lock must pass mutable skipped list (8vvg)"
            assert deadline is not None and deadline > 0, (
                "lock must bound the post-lock scan with a real deadline (8vvg)"
            )
            deadline_received["value"] = deadline
            skipped.append(SkippedFile(file=str(tmp_path / "big.py"), reason="truncated"))
            return []  # no findings, scan incomplete

        monkeypatch.setattr(
            "worthless.cli.commands.lock.scan_for_hardcoded_provider_urls",
            fake_scan,
        )

        # Must NOT raise. Lock has already succeeded; exit code is owned by
        # the caller and we don't touch it here.
        _maybe_prompt_code_scan(tmp_path)

        captured = capsys.readouterr()
        # Advisory note appears on stderr.
        assert "post-lock source scan incomplete" in captured.err
        # Reason summary survives the message renderer.
        assert "1 truncated" in captured.err
        # User knows how to retry.
        assert "worthless scan --code" in captured.err

    def test_incomplete_scan_suppresses_the_interactive_prompt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """8vvg: an incomplete scan must NOT trigger the typer.confirm prompt
        — the prompt would block the post-lock flow waiting for input that
        will never arrive on a CI machine or scripted invocation."""
        from worthless.cli.commands.lock import _maybe_prompt_code_scan

        def fake_scan(_roots, *, deadline=None, skipped=None, **_kw):
            skipped.append(SkippedFile(file=str(tmp_path / "big.py"), reason="timeout"))
            return []

        confirm_called = {"count": 0}

        def fake_confirm(*_a, **_kw):
            confirm_called["count"] += 1
            return True

        monkeypatch.setattr(
            "worthless.cli.commands.lock.scan_for_hardcoded_provider_urls",
            fake_scan,
        )
        monkeypatch.setattr("worthless.cli.commands.lock.typer.confirm", fake_confirm)

        _maybe_prompt_code_scan(tmp_path)

        assert confirm_called["count"] == 0, (
            "8vvg: the interactive prompt must NOT fire on an incomplete scan"
        )

    def test_happy_path_no_skipped_no_findings_silent(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression guard: happy path (no skipped, no findings) stays
        completely silent — same as before 8vvg."""
        from worthless.cli.commands.lock import _maybe_prompt_code_scan

        def fake_scan(_roots, *, deadline=None, skipped=None, **_kw):
            return []  # no findings, no skips

        monkeypatch.setattr(
            "worthless.cli.commands.lock.scan_for_hardcoded_provider_urls",
            fake_scan,
        )

        _maybe_prompt_code_scan(tmp_path)

        captured = capsys.readouterr()
        assert captured.err == "", (
            f"happy path must stay silent; got stderr: {captured.err!r}"
        )
