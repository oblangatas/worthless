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
        assert captured.err == "", f"happy path must stay silent; got stderr: {captured.err!r}"

    def test_multi_reason_summary_sorts_most_frequent_first(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """8vvg: when multiple skip reasons are present, the summary sorts
        most-frequent-first with deterministic alphabetical tie-break.

        Pre-fix the summary sorted alphabetically by reason key, but rendered
        count-first ("1 truncated, 2 timeout") — confusing to read. Code-reviewer
        agent flagged this on PR #264. Sort key is now (-count, reason).
        """
        from worthless.cli.commands.lock import _maybe_prompt_code_scan

        def fake_scan(_roots, *, deadline=None, skipped=None, **_kw):
            # 1 truncated, 2 timeout, 3 unreadable — expected order:
            # "3 unreadable, 2 timeout, 1 truncated" (most-frequent-first)
            skipped.append(SkippedFile(file=str(tmp_path / "big.py"), reason="truncated"))
            skipped.append(SkippedFile(file=str(tmp_path / "slow1.py"), reason="timeout"))
            skipped.append(SkippedFile(file=str(tmp_path / "slow2.py"), reason="timeout"))
            skipped.append(SkippedFile(file=str(tmp_path / "denied1.py"), reason="unreadable"))
            skipped.append(SkippedFile(file=str(tmp_path / "denied2.py"), reason="unreadable"))
            skipped.append(SkippedFile(file=str(tmp_path / "denied3.py"), reason="unreadable"))
            return []

        monkeypatch.setattr(
            "worthless.cli.commands.lock.scan_for_hardcoded_provider_urls",
            fake_scan,
        )

        _maybe_prompt_code_scan(tmp_path)

        captured = capsys.readouterr()
        # Most-frequent-first ordering — the readable + deterministic shape.
        assert "3 unreadable, 2 timeout, 1 truncated" in captured.err, (
            f"reason summary should sort most-frequent-first; got: {captured.err!r}"
        )

    def test_tie_break_in_reason_summary_is_alphabetical(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """8vvg: when two reasons have the same count, alphabetical tie-break
        gives a stable output."""
        from worthless.cli.commands.lock import _maybe_prompt_code_scan

        def fake_scan(_roots, *, deadline=None, skipped=None, **_kw):
            # 1 timeout, 1 truncated — same count, alpha tie-break → timeout, truncated
            skipped.append(SkippedFile(file=str(tmp_path / "slow.py"), reason="timeout"))
            skipped.append(SkippedFile(file=str(tmp_path / "big.py"), reason="truncated"))
            return []

        monkeypatch.setattr(
            "worthless.cli.commands.lock.scan_for_hardcoded_provider_urls",
            fake_scan,
        )

        _maybe_prompt_code_scan(tmp_path)

        captured = capsys.readouterr()
        assert "1 timeout, 1 truncated" in captured.err, (
            f"ties should break alphabetically; got: {captured.err!r}"
        )

    def test_incomplete_scan_drops_partial_findings(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """8vvg: when the scan returns BOTH skipped files AND findings, the
        partial findings are deliberately DROPPED (not shown to the user) —
        an incomplete scan can't be trusted to be representative.

        Without this test, a future refactor could silently start emitting the
        partial findings as if they were complete, which would be misleading.
        """
        from worthless.cli.commands.lock import _maybe_prompt_code_scan

        def fake_scan(_roots, *, deadline=None, skipped=None, **_kw):
            # Both populated: scan found a URL in one file but couldn't
            # finish reading another. We MUST NOT report the partial result.
            skipped.append(SkippedFile(file=str(tmp_path / "big.py"), reason="truncated"))
            # Anonymous truthy entry — _maybe_prompt_code_scan never iterates
            # findings when skipped is non-empty, so the exact shape is
            # immaterial; what matters is that ``if findings`` is True.
            return [object(), object()]

        monkeypatch.setattr(
            "worthless.cli.commands.lock.scan_for_hardcoded_provider_urls",
            fake_scan,
        )

        _maybe_prompt_code_scan(tmp_path)

        captured = capsys.readouterr()
        # The advisory note is present — user knows the scan was incomplete.
        assert "post-lock source scan incomplete" in captured.err
        # The partial-findings block must NOT appear — phrases that would
        # only render when findings are reported:
        assert "Found 2 hardcoded provider URLs" not in captured.err
        assert "bypass the proxy" not in captured.err
        # User is told to retry rather than shown partial data.
        assert "worthless scan --code" in captured.err


# ---------------------------------------------------------------------------
# worthless-k82c follow-up: terminal-escape spoofing defense
#
# A file in the user's repo with attacker-controlled bytes in its name
# (npm tarball, hostile git clone, supply-chain dep) reaches the
# "refusing to lock" error message via SkippedFile.file. Without
# sanitisation, the bytes flow into the terminal:
#   - ESC \x1b[31m...\x1b[0m → fake colored "FAKE_PROTECTED" text
#   - C1 CSI \x9b...           → same effect on 8-bit-aware terminals
#   - U+202E bidi override     → visual filename spoofing (Trojan Source)
#
# These tests pin that _lock_keys's skip block strips all three classes
# from the file path before raising WorthlessError.
# ---------------------------------------------------------------------------


class TestSkipBlockSanitisesAttackerControlledFilenames:
    """k82c follow-up: file paths in the skip-block error must be stripped
    of terminal control characters / bidi overrides so an attacker who
    lands a maliciously-named file in the victim's repo can't spoof the
    security-gate error message."""

    def _run_with_malicious_skip(
        self,
        tmp_path: Path,
        env_with_key: Path,
        monkeypatch: pytest.MonkeyPatch,
        malicious_filename: str,
    ) -> object:
        """Helper: inject a SkippedFile carrying ``malicious_filename`` into
        the bypass scan and invoke ``worthless lock`` end-to-end. Returns
        the CliRunner result."""
        monkeypatch.setenv("WORTHLESS_HOME", str(tmp_path / "wh"))

        def fake_scan(_root, *, deadline=None, skipped=None, **_kw):
            skipped.append(SkippedFile(file=malicious_filename, reason="truncated"))
            return []

        with patch(
            "worthless.cli.commands.lock.scan_source_for_hardcoded_provider_urls",
            side_effect=fake_scan,
        ):
            return runner.invoke(app, ["lock", "--env", str(env_with_key)])

    def test_esc_ansi_in_filename_is_stripped(
        self, tmp_path: Path, env_with_key: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An ``\\x1b[31m...\\x1b[0m`` payload in the filename must NOT
        reach the terminal — it would render fake red text inside the
        WRTLS-106 'refusing to lock' security message."""
        malicious = "evil\x1b[31mFAKE_PROTECTED\x1b[0m.py"
        result = self._run_with_malicious_skip(tmp_path, env_with_key, monkeypatch, malicious)

        # Exit 2 still — the fail-closed contract is unaffected.
        assert result.exit_code == 2
        # The raw ESC byte (0x1b) must NOT appear anywhere in the stderr
        # output. Even the filename text gets shown, but with the escape
        # sequence stripped.
        assert "\x1b" not in result.stderr, (
            f"ESC byte leaked to user's terminal — Trojan Source vector unfixed. "
            f"stderr={result.stderr!r}"
        )
        # Stripped text remains visible (so the user can still see the
        # attempted attack and tell us about it).
        assert "FAKE_PROTECTED" in result.stderr

    def test_c1_csi_in_filename_is_stripped(
        self, tmp_path: Path, env_with_key: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """C1 CSI (U+009B) in a filename must NOT reach the terminal —
        8-bit-aware terminals interpret it as a CSI introducer just like
        ESC ``[``."""
        malicious = "evil\x9b31mFAKE\x9b0m.py"
        result = self._run_with_malicious_skip(tmp_path, env_with_key, monkeypatch, malicious)

        assert result.exit_code == 2
        # U+009B serializes as UTF-8 bytes 0xc2 0x9b — neither should
        # appear in the encoded stderr output.
        assert "\x9b" not in result.stderr, (
            f"C1 CSI codepoint leaked to terminal. stderr={result.stderr!r}"
        )
        # Spot-check the encoded bytes too (defensive: in case stderr is
        # already encoded).
        encoded = result.stderr.encode("utf-8", errors="replace")
        assert b"\xc2\x9b" not in encoded

    def test_bidi_override_in_filename_is_stripped(
        self, tmp_path: Path, env_with_key: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """U+202E (RIGHT-TO-LEFT OVERRIDE) is the Trojan Source class
        (CVE-2021-42574) — visual filename spoofing inside the security
        gate. Must be stripped before rendering."""
        malicious = "good\u202emoc.evil.py"
        result = self._run_with_malicious_skip(tmp_path, env_with_key, monkeypatch, malicious)

        assert result.exit_code == 2
        assert "\u202e" not in result.stderr, (
            f"Bidi override leaked to terminal — Trojan Source unfixed. stderr={result.stderr!r}"
        )

    def test_clean_filename_passes_through_unchanged(
        self, tmp_path: Path, env_with_key: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression guard: a clean filename (no attack chars) must render
        intact AND with its ``[reason]`` token. Pins that
        ``sanitise_for_message`` doesn't over-strip, and that
        ``rich.markup.escape`` keeps the reason token readable.

        If a future overzealous sanitiser tweak silently breaks normal
        paths, the 3 attack-vector tests above would still pass (they
        only assert ON-ABSENCE of attack bytes) — this test catches that
        regression."""
        clean = "src/api/client.py"
        result = self._run_with_malicious_skip(tmp_path, env_with_key, monkeypatch, clean)

        assert result.exit_code == 2
        # Clean filename appears intact — no over-stripping.
        assert "src/api/client.py" in result.stderr
        # Reason token survives the k82c renderer escape.
        assert "[truncated]" in result.stderr
        # And the surrounding message body is intact.
        assert "scan incomplete" in result.stderr.lower()
