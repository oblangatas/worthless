"""Tests for the post-lock hardcoded-URL prompt (WOR-493).

After ``worthless lock`` successfully enrolls keys, it quietly scans the
project for hardcoded provider URLs and either:

  - TTY + findings   → interactive "Scan now? [Y/n]" prompt
  - non-TTY/CI + findings → one-line stderr warning (no prompt)
  - zero findings    → silent (no output at all)
  - scanner raises   → lock exits 0, warning logged (never breaks lock)
  - count == 0       → no prompt (no keys enrolled, nothing to protect)
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.code_scanner import CodeFinding
from worthless.cli.commands.scan import (
    _format_code_findings_human,
    _format_lock_block_human,
    _is_test_path,
)
from worthless.cli.console import WorthlessConsole
from worthless.cli.scanner import HardcodedUrlFinding
from tests.helpers import fake_openai_key

_SCAN_FN = "worthless.cli.commands.lock.scan_for_hardcoded_provider_urls"
_IS_TTY = "worthless.cli.commands.lock._scan_prompt_is_tty"

# mix_stderr=False: lock's console (print_success/print_warning) → result.stderr
# typer.confirm prompt text → result.output (stdout)
runner = CliRunner(mix_stderr=False)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _env(home: WorthlessHome) -> dict[str, str]:
    return {"WORTHLESS_HOME": str(home.base_dir)}


def _make_env_file(tmp_path: Path) -> Path:
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    return env


def _make_finding(tmp_path: Path) -> CodeFinding:
    return CodeFinding(
        file=str(tmp_path / "app.py"),
        line=1,
        column=18,
        matched_url="https://api.openai.com/v1",
        provider_name="openai",
        suggested_env_var="OPENAI_BASE_URL",
        line_text='client = OpenAI(base_url="https://api.openai.com/v1")',
    )


# ---------------------------------------------------------------------------
# Happy flow — TTY mode (interactive prompt)
# ---------------------------------------------------------------------------


class TestLockScanPromptHappyFlow:
    def test_dirty_project_shows_prompt_on_tty(
        self, home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After enrolling keys, user is prompted when hardcoded URLs found."""
        env_file = _make_env_file(tmp_path)
        finding = _make_finding(tmp_path)

        with (
            patch(_SCAN_FN, return_value=[finding]),
            patch(_IS_TTY, return_value=True),
        ):
            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=_env(home_dir),
                input="n\n",  # answer No so scan output doesn't flood
            )

        assert result.exit_code == 0, result.stderr
        # typer.confirm prompt goes to stdout; bypass summary is in the prompt text
        assert "bypass" in result.output.lower() or "hardcoded" in result.output.lower()

    def test_user_answers_yes_shows_scan_output(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Y at the prompt → scan findings printed inline."""
        env_file = _make_env_file(tmp_path)
        finding = _make_finding(tmp_path)

        with (
            patch(_SCAN_FN, return_value=[finding]),
            patch(_IS_TTY, return_value=True),
        ):
            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=_env(home_dir),
                input="y\n",
            )

        assert result.exit_code == 0, result.stderr
        # findings written via typer.echo(err=True) → captured in result.stderr
        # post-lock uses collapse mode: env var shown, raw URL omitted (file-level summary)
        assert "OPENAI_BASE_URL" in result.stderr

    def test_user_answers_no_exits_cleanly(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """N at the prompt → lock exits 0, no scan output."""
        env_file = _make_env_file(tmp_path)
        finding = _make_finding(tmp_path)

        with (
            patch(_SCAN_FN, return_value=[finding]),
            patch(_IS_TTY, return_value=True),
        ):
            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=_env(home_dir),
                input="n\n",
            )

        assert result.exit_code == 0
        assert "OPENAI_BASE_URL" not in result.output

    def test_clean_project_no_prompt(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Zero findings → no prompt, no scan noise whatsoever."""
        env_file = _make_env_file(tmp_path)

        with (
            patch(_SCAN_FN, return_value=[]),
            patch(_IS_TTY, return_value=True),
        ):
            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=_env(home_dir),
            )

        assert result.exit_code == 0
        # Both stdout and stderr must be completely clear of scan-related noise.
        assert "hardcoded" not in result.output.lower()
        assert "bypass" not in result.output.lower()
        assert "Scan now" not in result.output
        assert "hardcoded" not in result.stderr.lower()
        assert "bypass" not in result.stderr.lower()
        assert "Scan now" not in result.stderr

    def test_no_keys_enrolled_skips_scan_entirely(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """When lock finds no API keys, scan must not be called at all."""
        env = tmp_path / ".env"
        env.write_text("DATABASE_URL=postgres://localhost/db\n")

        with patch(_SCAN_FN) as mock_scan:
            result = runner.invoke(
                app,
                ["lock", "--env", str(env)],
                env=_env(home_dir),
            )

        assert result.exit_code == 0
        assert mock_scan.call_count == 0, "scanner must not run when no keys were enrolled"


# ---------------------------------------------------------------------------
# Non-TTY / CI mode — warning, no interactive prompt
# ---------------------------------------------------------------------------


class TestLockScanPromptNonTTY:
    def test_non_tty_shows_warning_not_prompt(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Non-TTY → one-line warning to stderr, no interactive prompt."""
        env_file = _make_env_file(tmp_path)
        finding = _make_finding(tmp_path)

        with (
            patch(_SCAN_FN, return_value=[finding]),
            patch(_IS_TTY, return_value=False),
        ):
            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=_env(home_dir),
            )

        assert result.exit_code == 0
        assert "Scan now" not in result.output
        assert "Scan now" not in result.stderr
        # _maybe_prompt_code_scan writes the warning to sys.stderr
        assert "hardcoded" in result.stderr.lower() or "bypass" in result.stderr.lower()

    def test_ci_env_var_skips_prompt(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """CI=true suppresses the interactive prompt even when stdin appears as a TTY."""
        env_file = _make_env_file(tmp_path)
        finding = _make_finding(tmp_path)

        # Simulate a pseudo-TTY CI environment: stdin says isatty()=True, but
        # CI=true should override and force the non-interactive warning path.
        with (
            patch(_SCAN_FN, return_value=[finding]),
            patch("worthless.cli.commands.lock.sys.stdin.isatty", return_value=True),
        ):
            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env={**_env(home_dir), "CI": "true"},
            )

        assert result.exit_code == 0
        assert "Scan now" not in result.output
        assert "bypass" in result.stderr.lower()

    def test_scan_not_called_when_no_findings_non_tty(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Non-TTY + zero findings → completely silent, no warning."""
        env_file = _make_env_file(tmp_path)

        with (
            patch(_SCAN_FN, return_value=[]),
            patch(_IS_TTY, return_value=False),
        ):
            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=_env(home_dir),
            )

        assert result.exit_code == 0
        assert "hardcoded" not in result.stderr.lower()
        assert "bypass" not in result.stderr.lower()
        assert "Scan now" not in result.output


# ---------------------------------------------------------------------------
# Insulation — lock contract must never be broken by the scanner
# ---------------------------------------------------------------------------


class TestLockScanPromptInsulation:
    def test_scanner_exception_doesnt_break_lock(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """If the scanner raises, lock still exits 0 — fire-and-forget."""
        env_file = _make_env_file(tmp_path)

        with patch(_SCAN_FN, side_effect=RuntimeError("scanner blew up")):
            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=_env(home_dir),
            )

        assert result.exit_code == 0, result.output

    def test_lock_exit_code_unchanged_with_findings(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Hardcoded URL findings must not change lock's exit code from 0."""
        env_file = _make_env_file(tmp_path)
        finding = _make_finding(tmp_path)

        with (
            patch(_SCAN_FN, return_value=[finding]),
            patch(_IS_TTY, return_value=True),
        ):
            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=_env(home_dir),
                input="n\n",
            )

        assert result.exit_code == 0

    def test_prompt_fires_after_enrollment_not_before(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Scanner is called only after the [OK] success message — not as a gate."""
        env_file = _make_env_file(tmp_path)
        finding = _make_finding(tmp_path)
        call_order: list[str] = []
        # Capture the unbound function BEFORE patching so the spy can delegate
        # to the real implementation without infinite recursion.
        _original_print_success = WorthlessConsole.print_success

        def _fake_scan(*_a, **_kw):
            call_order.append("scan")
            return [finding]

        def _mark_success(self_console, message: str) -> None:
            # Called as a plain function via the class patch; Python's descriptor
            # protocol binds self_console automatically.
            call_order.append("ok")
            _original_print_success(self_console, message)

        with (
            patch(_SCAN_FN, side_effect=_fake_scan),
            patch(_IS_TTY, return_value=True),
            patch.object(WorthlessConsole, "print_success", _mark_success),
        ):
            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=_env(home_dir),
                input="n\n",
            )

        assert result.exit_code == 0
        assert "ok" in call_order, "lock success message must be emitted"
        assert "scan" in call_order, "scanner must have been called"
        assert call_order.index("ok") < call_order.index("scan")

    def test_scanner_called_with_cwd_not_env_parent(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Scanner must receive Path.cwd(), not env_path.parent.

        Using env_path.parent would silently miss files outside the .env's
        directory (e.g. frontend/ in a monorepo when --env backend/.env is
        passed).  Path.cwd() keeps the scan root consistent with
        ``worthless scan --code``.
        """
        env_file = _make_env_file(tmp_path)

        with patch(_SCAN_FN, return_value=[]) as mock_scan:
            runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=_env(home_dir),
            )

        mock_scan.assert_called_once()
        (roots,), _ = mock_scan.call_args
        assert roots == [Path.cwd()], (
            f"scanner received {roots!r} — expected [Path.cwd()] == [{Path.cwd()!r}]"
        )

    def test_existing_lock_tests_not_broken(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Smoke: scanner patched out → existing lock behaviour fully preserved."""
        env_file = _make_env_file(tmp_path)

        with patch(_SCAN_FN, return_value=[]):
            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=_env(home_dir),
            )

        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# _is_test_path unit tests (worthless-yvzn)
# ---------------------------------------------------------------------------


class TestIsTestPath:
    def test_tests_dir_segment(self) -> None:
        assert _is_test_path("tests/test_foo.py")
        assert _is_test_path("/project/tests/helpers.py")

    def test_test_prefix_filename(self) -> None:
        assert _is_test_path("src/test_client.py")
        assert _is_test_path("test_utils.py")

    def test_test_suffix_filename(self) -> None:
        assert _is_test_path("src/client_test.py")

    def test_conftest(self) -> None:
        assert _is_test_path("conftest.py")
        assert _is_test_path("src/conftest.py")

    def test_src_file_not_matched(self) -> None:
        assert not _is_test_path("src/worthless/cli/commands/lock.py")
        assert not _is_test_path("app/client.py")

    def test_windows_path_normalised(self) -> None:
        assert _is_test_path("project\\tests\\test_foo.py")


# ---------------------------------------------------------------------------
# collapse_tests formatter behaviour (worthless-yvzn)
# ---------------------------------------------------------------------------


def _make_src_finding(tmp_path: Path) -> CodeFinding:
    return CodeFinding(
        file=str(tmp_path / "src" / "app.py"),
        line=10,
        column=5,
        matched_url="https://api.openai.com/v1",
        provider_name="openai",
        suggested_env_var="OPENAI_BASE_URL",
        line_text='client = OpenAI(base_url="https://api.openai.com/v1")',
    )


def _make_test_finding(tmp_path: Path) -> CodeFinding:
    return CodeFinding(
        file=str(tmp_path / "tests" / "test_client.py"),
        line=5,
        column=1,
        matched_url="https://api.openai.com/v1",
        provider_name="openai",
        suggested_env_var="OPENAI_BASE_URL",
        line_text='base_url="https://api.openai.com/v1"',
    )


class TestFormatCodeFindingsCollapseTests:
    def test_collapse_omits_test_findings_inline(self, tmp_path: Path) -> None:
        findings = [_make_src_finding(tmp_path), _make_test_finding(tmp_path)]
        output = _format_code_findings_human(findings, collapse_tests=True)

        assert "src/app.py" in output
        assert "test_client.py" not in output
        assert "1 test-file finding omitted" in output

    def test_collapse_shows_src_findings_inline(self, tmp_path: Path) -> None:
        findings = [_make_src_finding(tmp_path), _make_test_finding(tmp_path)]
        output = _format_code_findings_human(findings, collapse_tests=True)

        assert "OPENAI_BASE_URL" in output
        assert "[code]" in output

    def test_collapse_false_shows_all(self, tmp_path: Path) -> None:
        findings = [_make_src_finding(tmp_path), _make_test_finding(tmp_path)]
        output = _format_code_findings_human(findings, collapse_tests=False)

        assert "src/app.py" in output
        assert "test_client.py" in output
        assert "omitted" not in output

    def test_all_test_findings_no_inline_detail(self, tmp_path: Path) -> None:
        findings = [_make_test_finding(tmp_path)]
        output = _format_code_findings_human(findings, collapse_tests=True)

        assert "[code]" not in output
        assert "1 test-file finding omitted" in output
        assert "Found 1 hardcoded provider URL(s)." in output

    def test_honesty_footer_always_present(self, tmp_path: Path) -> None:
        findings = [_make_test_finding(tmp_path)]
        output = _format_code_findings_human(findings, collapse_tests=True)

        assert "NOTE" in output


# ---------------------------------------------------------------------------
# Post-lock integration: collapse_tests active on TTY path (worthless-yvzn)
# ---------------------------------------------------------------------------


class TestPostLockCollapseTests:
    def test_test_file_finding_omitted_in_post_lock_output(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Post-lock TTY scan: test-file findings appear as a count, not inline."""
        env_file = _make_env_file(tmp_path)
        with (
            patch(_SCAN_FN, return_value=[_make_test_finding(tmp_path)]),
            patch(_IS_TTY, return_value=True),
        ):
            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=_env(home_dir),
                input="y\n",
            )

        assert result.exit_code == 0
        assert "test_client.py" not in result.stderr
        assert "omitted" in result.stderr

    def test_src_finding_still_shown_inline(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Post-lock TTY scan: src/ findings are still printed in full."""
        env_file = _make_env_file(tmp_path)
        with (
            patch(_SCAN_FN, return_value=[_make_src_finding(tmp_path)]),
            patch(_IS_TTY, return_value=True),
        ):
            result = runner.invoke(
                app,
                ["lock", "--env", str(env_file)],
                env=_env(home_dir),
                input="y\n",
            )

        assert result.exit_code == 0
        assert "OPENAI_BASE_URL" in result.stderr
        assert "[OK]" in result.stderr  # console writes to stderr with mix_stderr=False


# ---------------------------------------------------------------------------
# Pre-lock block formatter unit tests (worthless-foh6)
# ---------------------------------------------------------------------------


def _make_hardcoded_finding(
    file: str, line: int = 10, provider: str = "openai"
) -> HardcodedUrlFinding:
    return HardcodedUrlFinding(
        file=file,
        line=line,
        url=f"https://api.{provider}.com/v1",
        provider=provider,
    )


class TestFormatLockBlockHuman:
    def test_blocking_true_header(self) -> None:
        findings = [_make_hardcoded_finding("src/app.py")]
        output = _format_lock_block_human(findings, blocking=True)
        assert output.startswith("Can't lock")
        assert "Warning" not in output

    def test_blocking_false_header(self) -> None:
        findings = [_make_hardcoded_finding("src/app.py")]
        output = _format_lock_block_human(findings, blocking=False)
        assert output.startswith("Warning")
        assert "Can't lock" not in output

    def test_src_finding_shows_file_and_env_var(self) -> None:
        findings = [_make_hardcoded_finding("src/client.py", line=42, provider="anthropic")]
        output = _format_lock_block_human(findings)
        assert "src/client.py" in output
        assert "ANTHROPIC_BASE_URL" in output
        assert "42" in output

    def test_ai_prompt_present_when_src_findings_exist(self) -> None:
        findings = [_make_hardcoded_finding("src/app.py")]
        output = _format_lock_block_human(findings)
        assert "Paste this into Claude Code" in output
        assert "worthless found hardcoded provider URLs" in output

    def test_test_only_findings_no_ai_prompt(self) -> None:
        findings = [_make_hardcoded_finding("tests/test_client.py")]
        output = _format_lock_block_human(findings)
        assert "Paste this into Claude Code" not in output
        assert "test" in output.lower()

    def test_test_count_line_present_when_mixed(self) -> None:
        findings = [
            _make_hardcoded_finding("src/app.py"),
            _make_hardcoded_finding("tests/test_foo.py"),
        ]
        output = _format_lock_block_human(findings)
        assert "test file" in output
        assert "Paste this into Claude Code" in output

    def test_sanitize_applied_to_file_path(self) -> None:
        findings = [_make_hardcoded_finding("/secret/path/src/app.py")]
        output = _format_lock_block_human(findings, sanitize=lambda p: "<redacted>")
        assert "<redacted>" in output
        assert "/secret/path" not in output
