"""Tests for the scan CLI command."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.key_patterns import KEY_PATTERN

from tests.helpers import fake_openai_key as _fake_openai_key
from tests.helpers import fake_anthropic_key as _fake_anthropic_key


def _strip_env_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove env vars whose value matches any known API key pattern.

    The deep-scan env dump reads the entire process environment, so a real
    developer's shell (e.g. CLAUDE_CODE_OAUTH_TOKEN, HF_TOKEN) can leak
    pattern-matching values into "clean dir" tests. Filter by value, not name.
    """
    for key, value in list(os.environ.items()):
        if KEY_PATTERN.search(value):
            monkeypatch.delenv(key, raising=False)


runner = CliRunner(mix_stderr=False)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent scan from picking up the project-root .env."""
    monkeypatch.chdir(tmp_path)


@pytest.fixture()
def env_with_real_key(tmp_path: Path) -> Path:
    """Create a .env with a real (unprotected) OpenAI key."""
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={_fake_openai_key()}\n")
    return env


@pytest.fixture()
def env_clean(tmp_path: Path) -> Path:
    """Create a .env with no API keys."""
    env = tmp_path / ".env"
    env.write_text("DATABASE_URL=postgres://localhost/db\nAPP_NAME=myapp\n")
    return env


@pytest.fixture()
def file_with_key(tmp_path: Path) -> Path:
    """Create a generic file with an API key in it."""
    f = tmp_path / "config.py"
    f.write_text(f'API_KEY = "{_fake_openai_key()}"\n')
    return f


# ---------------------------------------------------------------------------
# Tests: fake key guard — fail fast if key generation drifts from scanner
# ---------------------------------------------------------------------------


class TestFakeKeyGuard:
    """Ensure generated test keys match scanner expectations."""

    def test_fake_openai_key_matches_pattern(self) -> None:
        from worthless.cli.key_patterns import KEY_PATTERN

        assert KEY_PATTERN.match(_fake_openai_key()), "fake key no longer matches KEY_PATTERN"

    def test_fake_openai_key_above_entropy_threshold(self) -> None:
        from worthless.cli.dotenv_rewriter import shannon_entropy
        from worthless.cli.key_patterns import ENTROPY_THRESHOLD

        assert shannon_entropy(_fake_openai_key()) >= ENTROPY_THRESHOLD

    def test_fake_anthropic_key_matches_pattern(self) -> None:
        from worthless.cli.key_patterns import KEY_PATTERN

        assert KEY_PATTERN.match(_fake_anthropic_key()), (
            "fake anthropic key no longer matches KEY_PATTERN"
        )

    def test_fake_anthropic_key_above_entropy_threshold(self) -> None:
        from worthless.cli.dotenv_rewriter import shannon_entropy
        from worthless.cli.key_patterns import ENTROPY_THRESHOLD

        assert shannon_entropy(_fake_anthropic_key()) >= ENTROPY_THRESHOLD


class TestEntropyThresholdRegression:
    """The entropy gate is slated for replacement; this is a thin shim that
    just pins the user-visible contract: real-shape provider keys clear
    whatever threshold ships, common placeholders fall below it. When the
    gate is removed/replaced, delete this class.
    """

    def test_real_shape_key_admitted(self) -> None:
        from worthless.cli.dotenv_rewriter import shannon_entropy
        from worthless.cli.key_patterns import ENTROPY_THRESHOLD

        real_shape = "sk-or-v1-" + "a8b3c9d2e1f70" * 4 + "abcde"
        assert shannon_entropy(real_shape) >= ENTROPY_THRESHOLD

    def test_common_placeholders_rejected(self) -> None:
        from worthless.cli.dotenv_rewriter import shannon_entropy
        from worthless.cli.key_patterns import ENTROPY_THRESHOLD

        for placeholder in ("sk-your-key-here", "sk-aaaa", "sk-PLACEHOLDER_VALUE"):
            assert shannon_entropy(placeholder) < ENTROPY_THRESHOLD, placeholder


# ---------------------------------------------------------------------------
# Tests: basic scan
# ---------------------------------------------------------------------------


class TestScanBasic:
    """Tests for basic scan behavior."""

    def test_scan_file_with_unprotected_key_exits_1(self, file_with_key: Path) -> None:
        """Scan file with real key -> exit 1, shows UNPROTECTED."""
        result = runner.invoke(app, ["scan", str(file_with_key)])
        assert result.exit_code == 1, f"stdout={result.stdout}\nstderr={result.stderr}"
        assert "UNPROTECTED" in result.stderr or "unprotected" in result.stderr.lower()

    def test_scan_clean_file_exits_0(self, env_clean: Path) -> None:
        """Scan file with no API keys -> exit 0."""
        result = runner.invoke(app, ["scan", str(env_clean)])
        assert result.exit_code == 0

    def test_scan_locked_file_decoy_filtered_by_entropy(
        self, home_dir: WorthlessHome, env_with_real_key: Path
    ) -> None:
        """After lock, decoy in .env has low entropy and is filtered out."""
        # First lock the key
        lock_result = runner.invoke(
            app,
            ["lock", "--env", str(env_with_real_key)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert lock_result.exit_code == 0, lock_result.output

        # Now scan -- the original file has a decoy, but shard_a has the real value
        # The scan should find NO unprotected keys (decoy is low entropy, filtered out)
        result = runner.invoke(
            app,
            ["scan", str(env_with_real_key)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, f"stdout={result.stdout}\nstderr={result.stderr}"

    def test_scan_nonexistent_file_exits_0(self, tmp_path: Path) -> None:
        """Scanning a nonexistent file should not crash (exit 0 = clean)."""
        result = runner.invoke(app, ["scan", str(tmp_path / "nope.env")])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Tests: output formats
# ---------------------------------------------------------------------------


class TestScanFormats:
    """Tests for --format sarif, --json, --quiet."""

    def test_format_sarif_valid_json(self, file_with_key: Path) -> None:
        """--format sarif should produce valid SARIF v2.1.0 JSON on stdout."""
        result = runner.invoke(app, ["scan", "--format", "sarif", str(file_with_key)])
        assert result.exit_code == 1  # unprotected key found
        sarif = json.loads(result.stdout)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) >= 1

    def test_format_json_valid_object(self, file_with_key: Path) -> None:
        """--json produces {schema_version, findings, orphans} object on stdout (HF5)."""
        result = runner.invoke(app, ["scan", "--json", str(file_with_key)])
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert isinstance(data, dict)
        # Contract test: pin EXACT schema_version. A future shape change
        # bumps this to 3 and the test fails on purpose so the CHANGELOG +
        # SKILL.md update can't be skipped. CodeRabbit PR #131.
        assert data["schema_version"] == 2
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) >= 1
        assert "provider" in data["findings"][0]
        assert "is_protected" in data["findings"][0]
        assert "orphans" in data and isinstance(data["orphans"], list)

    def test_quiet_suppresses_output(self, file_with_key: Path) -> None:
        """--quiet should produce no stderr output (exit code only)."""
        result = runner.invoke(app, ["-q", "scan", str(file_with_key)])
        assert result.exit_code == 1
        assert result.stderr.strip() == ""

    def test_show_suffix_reveals_chars(self, file_with_key: Path) -> None:
        """--show-suffix should reveal last 4 chars of key in output."""
        result = runner.invoke(app, ["scan", "--show-suffix", str(file_with_key)])
        assert result.exit_code == 1
        expected_suffix = _fake_openai_key()[-4:]
        assert expected_suffix in result.stderr


# ---------------------------------------------------------------------------
# Tests: exit codes
# ---------------------------------------------------------------------------


class TestScanExitCodes:
    """Test exit code convention: 0=clean, 1=unprotected, 2=error."""

    def test_exit_0_clean(self, env_clean: Path) -> None:
        result = runner.invoke(app, ["scan", str(env_clean)])
        assert result.exit_code == 0

    def test_exit_1_unprotected(self, file_with_key: Path) -> None:
        result = runner.invoke(app, ["scan", str(file_with_key)])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Tests: --install-hook
# ---------------------------------------------------------------------------


class TestScanInstallHook:
    """Tests for --install-hook."""

    def test_install_hook_creates_executable(self, tmp_path: Path) -> None:
        """--install-hook should create .git/hooks/pre-commit."""
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        result = runner.invoke(
            app,
            ["scan", "--install-hook"],
            env={"GIT_DIR": str(tmp_path / ".git")},
            catch_exceptions=False,
        )
        hook = tmp_path / ".git" / "hooks" / "pre-commit"
        assert hook.exists(), f"stdout={result.stdout}\nstderr={result.stderr}"
        assert os.access(str(hook), os.X_OK)
        content = hook.read_text()
        assert "worthless scan" in content

    def test_install_hook_appends_to_existing(self, tmp_path: Path) -> None:
        """--install-hook should not overwrite existing hook."""
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)
        hook = git_dir / "pre-commit"
        hook.write_text("#!/bin/sh\necho existing\n")
        hook.chmod(0o755)

        runner.invoke(
            app,
            ["scan", "--install-hook"],
            env={"GIT_DIR": str(tmp_path / ".git")},
            catch_exceptions=False,
        )
        content = hook.read_text()
        assert "echo existing" in content
        assert "worthless scan" in content


# ---------------------------------------------------------------------------
# Tests: --pre-commit mode
# ---------------------------------------------------------------------------


class TestScanPrecommit:
    """Tests for --pre-commit mode (filenames passed as args)."""

    def test_precommit_processes_passed_files(self, file_with_key: Path, env_clean: Path) -> None:
        """--pre-commit should scan only the files passed as args."""
        result = runner.invoke(app, ["scan", "--pre-commit", str(file_with_key), str(env_clean)])
        assert result.exit_code == 1  # file_with_key has unprotected

    def test_precommit_clean_files_exit_0(self, env_clean: Path) -> None:
        """--pre-commit with clean files -> exit 0."""
        result = runner.invoke(app, ["scan", "--pre-commit", str(env_clean)])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Tests: provider diversity
# ---------------------------------------------------------------------------


class TestScanProviders:
    """Scan must detect keys from multiple providers, not just OpenAI."""

    def test_scan_detects_anthropic_key(self, tmp_path: Path) -> None:
        f = tmp_path / ".env"
        f.write_text(f"ANTHROPIC_API_KEY={_fake_anthropic_key()}\n")
        result = runner.invoke(app, ["scan", str(f)])
        assert result.exit_code == 1, f"stdout={result.stdout}\nstderr={result.stderr}"
        assert "anthropic" in result.stderr.lower()


# ---------------------------------------------------------------------------
# Tests: entropy filtering
# ---------------------------------------------------------------------------


class TestScanEntropy:
    """Placeholder values should be filtered by entropy."""

    def test_placeholder_skipped(self, tmp_path: Path) -> None:
        """Low-entropy placeholder value should not be reported."""
        f = tmp_path / ".env"
        f.write_text("OPENAI_API_KEY=sk-proj-your-key-here-your-key-here-your-key-here\n")
        result = runner.invoke(app, ["scan", str(f)])
        # Low-entropy placeholder should be skipped -> clean
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Tests: deep scan mode (WOR-45)
# ---------------------------------------------------------------------------


class TestScanDeep:
    """Tests for --deep scan mode: env dump + config file glob."""

    def test_deep_scan_finds_env_file_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deep scan should find keys in .env files."""
        env_file = tmp_path / ".env"
        env_file.write_text(f"OPENAI_API_KEY={_fake_openai_key()}\n")
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scan", "--deep"])
        assert result.exit_code == 1, f"stdout={result.stdout}\nstderr={result.stderr}"

    def test_deep_scan_finds_yml_config_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deep scan should glob *.yml and find keys inside."""
        yml = tmp_path / "config.yml"
        yml.write_text(f"api_key: {_fake_openai_key()}\n")
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scan", "--deep"])
        assert result.exit_code == 1, f"stdout={result.stdout}\nstderr={result.stderr}"

    def test_deep_scan_env_var_dump(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Deep scan dumps os.environ to temp file and scans it."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("MY_OPENAI_KEY", _fake_openai_key())
        result = runner.invoke(app, ["scan", "--deep"])
        # The env dump should catch the key in environment
        assert result.exit_code == 1, f"stdout={result.stdout}\nstderr={result.stderr}"

    def test_deep_scan_clean_dir_exits_0(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deep scan on a dir with no keys -> exit 0."""
        (tmp_path / "config.yml").write_text("database: postgres\n")
        (tmp_path / ".env").write_text("APP_NAME=myapp\n")
        monkeypatch.chdir(tmp_path)
        _strip_env_secrets(monkeypatch)
        result = runner.invoke(app, ["scan", "--deep"])
        assert result.exit_code == 0

    def test_deep_scan_cleans_up_temp_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deep scan should clean up its env dump temp file."""
        monkeypatch.chdir(tmp_path)
        # Isolate temp dir so xdist workers don't interfere with glob
        iso_tmp = tmp_path / "tmpdir"
        iso_tmp.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(iso_tmp))
        runner.invoke(app, ["scan", "--deep"])
        leaked = list(iso_tmp.glob("worthless-env-*"))
        assert len(leaked) == 0, f"Leaked temp files: {leaked}"


# ---------------------------------------------------------------------------
# Tests: --install-hook edge cases (WOR-45)
# ---------------------------------------------------------------------------


class TestScanInstallHookEdgeCases:
    """Additional edge cases for --install-hook."""

    def test_install_hook_idempotent(self, tmp_path: Path) -> None:
        """Running --install-hook twice should not duplicate the snippet."""
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        for _ in range(2):
            runner.invoke(
                app,
                ["scan", "--install-hook"],
                env={"GIT_DIR": str(tmp_path / ".git")},
                catch_exceptions=False,
            )
        content = (tmp_path / ".git" / "hooks" / "pre-commit").read_text()
        assert content.count("worthless scan") == 1

    def test_install_hook_no_git_dir_exits_2(self, tmp_path: Path) -> None:
        """--install-hook with no .git dir should exit 2."""
        result = runner.invoke(
            app,
            ["scan", "--install-hook"],
            env={"GIT_DIR": str(tmp_path / "nonexistent")},
            catch_exceptions=False,
        )
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# Tests: --pre-commit edge cases (WOR-45)
# ---------------------------------------------------------------------------


class TestScanPrecommitEdgeCases:
    """Additional edge cases for --pre-commit mode."""

    def test_precommit_no_files_exits_0(self) -> None:
        """--pre-commit with no files at all -> exit 0."""
        result = runner.invoke(app, ["scan", "--pre-commit"])
        assert result.exit_code == 0

    def test_precommit_nonexistent_file_exits_0(self, tmp_path: Path) -> None:
        """--pre-commit with a nonexistent staged file should not crash."""
        result = runner.invoke(app, ["scan", "--pre-commit", str(tmp_path / "gone.py")])
        assert result.exit_code == 0

    def test_precommit_mixed_files(self, env_clean: Path, file_with_key: Path) -> None:
        """--pre-commit with mix of clean and dirty files -> exit 1."""
        result = runner.invoke(
            app,
            ["scan", "--pre-commit", str(env_clean), str(file_with_key)],
        )
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Tests: --show-suffix output format (WOR-45)
# ---------------------------------------------------------------------------


class TestScanShowSuffixFormat:
    """Detailed tests for --show-suffix output formatting."""

    def test_show_suffix_contains_dots_separator(self, file_with_key: Path) -> None:
        """--show-suffix output should use '...' before the suffix."""
        result = runner.invoke(app, ["scan", "--show-suffix", str(file_with_key)])
        assert result.exit_code == 1
        assert "..." in result.stderr

    def test_show_suffix_with_clean_file_no_suffix(self, env_clean: Path) -> None:
        """--show-suffix with no keys found -> no suffix in output."""
        result = runner.invoke(app, ["scan", "--show-suffix", str(env_clean)])
        assert result.exit_code == 0

    def test_show_suffix_combined_with_json(self, file_with_key: Path) -> None:
        """--show-suffix with --json produces valid JSON object (HF5 shape)."""
        result = runner.invoke(app, ["scan", "--show-suffix", "--json", str(file_with_key)])
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert isinstance(data, dict)
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) >= 1


# ---------------------------------------------------------------------------
# Tests: _find_git_dir CWD traversal (WOR-45 coverage)
# ---------------------------------------------------------------------------


class TestScanFindGitDir:
    """Test _find_git_dir path: GIT_DIR unset, walks up CWD parents."""

    def test_install_hook_finds_git_from_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--install-hook without GIT_DIR should find .git by walking CWD."""
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)
        subdir = tmp_path / "src" / "pkg"
        subdir.mkdir(parents=True)
        monkeypatch.chdir(subdir)
        # Unset GIT_DIR so _find_git_dir walks parents
        monkeypatch.delenv("GIT_DIR", raising=False)
        result = runner.invoke(app, ["scan", "--install-hook"], catch_exceptions=False)
        hook = tmp_path / ".git" / "hooks" / "pre-commit"
        assert hook.exists(), f"stdout={result.stdout}\nstderr={result.stderr}"

    def test_install_hook_no_git_anywhere_exits_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """--install-hook with no .git anywhere in parents -> exit 2."""
        # Use /tmp which has no .git in any parent
        monkeypatch.chdir("/tmp")  # noqa: S108
        monkeypatch.delenv("GIT_DIR", raising=False)
        result = runner.invoke(app, ["scan", "--install-hook"], catch_exceptions=False)
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# Tests: error handlers and format validation (WOR-45 coverage)
# ---------------------------------------------------------------------------


class TestScanErrorPaths:
    """Test error handler branches in scan command."""

    def test_unknown_format_exits_2(self, file_with_key: Path) -> None:
        """--format with unknown value should exit 2."""
        result = runner.invoke(app, ["scan", "--format", "xml", str(file_with_key)])
        assert result.exit_code == 2

    def test_scan_non_tty_output(self, file_with_key: Path) -> None:
        """Scan with unprotected key in non-TTY context."""
        result = runner.invoke(app, ["scan", str(file_with_key)])
        assert result.exit_code == 1
        # Non-TTY should suggest docs URL instead of "Run: worthless lock"
        # CliRunner is non-TTY by default
        assert "unprotected" in result.stderr.lower() or "UNPROTECTED" in result.stderr

    def test_scan_protected_key_count(self, file_with_key: Path, env_clean: Path) -> None:
        """Scan with findings should report count in human output."""
        result = runner.invoke(app, ["scan", str(file_with_key), str(env_clean)])
        assert result.exit_code == 1
        assert "Found" in result.stderr
        assert "1 unprotected" in result.stderr

    def test_scan_files_exception_exits_2(self, file_with_key: Path) -> None:
        """Generic exception during scan_files -> exit 2."""

        with patch(
            "worthless.cli.commands.scan.scan_files",
            side_effect=RuntimeError("boom"),
        ):
            result = runner.invoke(app, ["scan", str(file_with_key)])
        assert result.exit_code == 2

    def test_scan_files_exception_quiet(self, file_with_key: Path) -> None:
        """Generic exception in quiet mode -> exit 2, sanitized error on stderr."""

        with patch(
            "worthless.cli.commands.scan.scan_files",
            side_effect=RuntimeError("boom"),
        ):
            result = runner.invoke(app, ["-q", "scan", str(file_with_key)])
        assert result.exit_code == 2
        # Errors are always shown (even in quiet mode) but must be sanitized
        assert "WRTLS-199" in result.stderr
        assert "boom" not in result.stderr  # raw exception must not leak

    def test_worthless_error_during_scan_exits_2(self, file_with_key: Path) -> None:
        """WorthlessError during scan -> exit 2 with error message."""

        from worthless.cli.errors import ErrorCode, WorthlessError

        with patch(
            "worthless.cli.commands.scan.scan_files",
            side_effect=WorthlessError(ErrorCode.SCAN_ERROR, "test error", exit_code=2),
        ):
            result = runner.invoke(app, ["scan", str(file_with_key)])
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# Tests: _collect_deep_paths edge cases (coverage completeness)
# ---------------------------------------------------------------------------


class TestCollectDeepPaths:
    """Exercise _collect_deep_paths branches for full coverage."""

    def test_deep_scan_empty_dir_no_config_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deep scan in dir with no .yml/.yaml/.toml/.json -> still works."""
        monkeypatch.chdir(tmp_path)
        _strip_env_secrets(monkeypatch)
        result = runner.invoke(app, ["scan", "--deep"])
        assert result.exit_code == 0

    def test_deep_scan_tempfile_write_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If tempfile write fails, deep scan still works (skips env dump)."""
        monkeypatch.chdir(tmp_path)

        with patch("worthless.cli.commands.scan.os.write", side_effect=OSError("disk full")):
            result = runner.invoke(app, ["scan", "--deep"])
        # Should not crash — exception is caught
        assert result.exit_code in (0, 1)

    def test_deep_scan_explicit_path_deduped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Explicit path that's also a .env should not be scanned twice."""
        env_file = tmp_path / ".env"
        env_file.write_text(f"OPENAI_API_KEY={_fake_openai_key()}\n")
        monkeypatch.chdir(tmp_path)
        # Pass .env explicitly — _collect_fast_paths adds it too
        result = runner.invoke(app, ["scan", "--deep", str(env_file)])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Tests: _format_human branch coverage
# ---------------------------------------------------------------------------


class TestFormatHumanBranches:
    """Cover remaining branches in _format_human."""

    def test_show_suffix_file_read_error(self, tmp_path: Path) -> None:
        """If file can't be re-read during show_suffix, gracefully skip."""
        f = tmp_path / "config.py"
        f.write_text(f'KEY = "{_fake_openai_key()}"\n')
        result = runner.invoke(app, ["scan", "--show-suffix", str(f)])
        assert result.exit_code == 1
        # Now delete the file and scan with a mocked finding

        from worthless.cli.scanner import ScanFinding

        fake_finding = ScanFinding(
            file=str(tmp_path / "gone.py"),
            line=1,
            var_name="KEY",
            provider="openai",
            is_protected=False,
            value_preview="sk-p****",
        )
        with patch("worthless.cli.commands.scan.scan_files", return_value=[fake_finding]):
            result = runner.invoke(app, ["scan", "--show-suffix", str(tmp_path / "gone.py")])
        assert result.exit_code == 1

    def test_protected_finding_count(self, tmp_path: Path) -> None:
        """Protected findings should be counted and displayed."""

        from worthless.cli.scanner import ScanFinding

        findings = [
            ScanFinding(
                file=str(tmp_path / "x.env"),
                line=1,
                var_name="KEY",
                provider="openai",
                is_protected=True,
                value_preview="sk-p****",
            ),
            ScanFinding(
                file=str(tmp_path / "x.env"),
                line=2,
                var_name="KEY2",
                provider="openai",
                is_protected=False,
                value_preview="sk-p****",
            ),
        ]
        with patch("worthless.cli.commands.scan.scan_files", return_value=findings):
            result = runner.invoke(app, ["scan", str(tmp_path / "x.env")])
        assert result.exit_code == 1
        assert "1 protected" in result.stderr
        assert "1 unprotected" in result.stderr

    def test_tty_output_suggests_lock_command(self) -> None:
        """In TTY context, unprotected findings should suggest 'worthless lock'."""
        from worthless.cli.commands.scan import _format_human
        from worthless.cli.scanner import ScanFinding

        finding = ScanFinding(
            file="/tmp/x.env",  # noqa: S108
            line=1,
            var_name="KEY",
            provider="openai",
            is_protected=False,
            value_preview="sk-p****",
        )
        output = _format_human([finding], show_suffix=False, is_tty=True)
        assert "Run: worthless lock" in output

    def test_non_tty_output_suggests_docs(self) -> None:
        """In non-TTY context, should suggest docs URL."""
        from worthless.cli.commands.scan import _format_human
        from worthless.cli.scanner import ScanFinding

        finding = ScanFinding(
            file="/tmp/x.env",  # noqa: S108
            line=1,
            var_name="KEY",
            provider="openai",
            is_protected=False,
            value_preview="sk-p****",
        )
        output = _format_human([finding], show_suffix=False, is_tty=False)
        assert "docs.worthless.dev" in output

    def test_deep_scan_tempfile_close_also_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If both write and close fail in _collect_deep_paths, don't crash."""
        monkeypatch.chdir(tmp_path)

        call_count = 0

        def _failing_write(fd, data):
            raise OSError("disk full")

        def _failing_close(fd):
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                raise OSError("already closed")
            # Let other close calls through (e.g. tempfile's fd)

        with (
            patch("worthless.cli.commands.scan.os.write", _failing_write),
            patch("worthless.cli.commands.scan.os.close", _failing_close),
        ):
            result = runner.invoke(app, ["scan", "--deep"])
        assert result.exit_code in (0, 1)
