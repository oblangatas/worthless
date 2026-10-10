"""Tests for the scan CLI command."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.scan import _format_human
from worthless.cli.key_patterns import KEY_PATTERN
from worthless.cli import scanner as scanner_mod
from worthless.cli.scanner import ScanFinding, format_sarif, scan_files

from tests.helpers import fake_key
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


runner = CliRunner()


def _git_commit(repo: Path, name: str) -> None:
    """Init *repo* and really commit *name* — hermetic: no signing, no hooks,
    no reliance on the machine's git identity."""
    git = ["git", "-C", str(repo)]
    cfg = ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)  # noqa: S607
    subprocess.run([*git, "add", name], check=True)  # noqa: S607
    subprocess.run(  # noqa: S607
        [*git, *cfg, "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "x"], check=True
    )


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

    def test_format_json_never_contains_raw_key_value(self, file_with_key: Path) -> None:
        """WOR-277 success criterion: scan --json findings carry only a
        {prefix}...{suffix} preview — the raw matched key must never
        appear anywhere in the JSON output."""
        secret = _fake_openai_key()
        result = runner.invoke(app, ["scan", "--json", str(file_with_key)])
        assert result.exit_code == 1
        assert secret not in result.stdout
        data = json.loads(result.stdout)
        assert secret not in json.dumps(data)
        preview = data["findings"][0]["value_preview"]
        assert preview != secret
        assert "*" in preview, f"expected a masked preview, got {preview!r}"
        assert len(preview) < len(secret)

    def test_format_sarif_never_contains_raw_key_value(self, file_with_key: Path) -> None:
        """WOR-277 success criterion: scan --format sarif must never emit
        the raw matched key value anywhere in the SARIF document."""
        secret = _fake_openai_key()
        result = runner.invoke(app, ["scan", "--format", "sarif", str(file_with_key)])
        assert result.exit_code == 1
        assert secret not in result.stdout
        sarif = json.loads(result.stdout)
        assert secret not in json.dumps(sarif)

    def test_quiet_suppresses_output(self, file_with_key: Path) -> None:
        """--quiet should produce no stderr output (exit code only)."""
        result = runner.invoke(app, ["-q", "scan", str(file_with_key)])
        assert result.exit_code == 1
        assert result.stderr.strip() == ""

    def test_show_suffix_shows_fingerprint_not_real_bytes(self, file_with_key: Path) -> None:
        """SR-04 (WOR-655): --show-suffix shows a non-secret sha256[:8]
        fingerprint so a human can tell keys apart — NEVER the real last 4
        chars of the key (the previous, leaky behaviour)."""
        import hashlib

        key = _fake_openai_key()
        result = runner.invoke(app, ["scan", "--show-suffix", str(file_with_key)])
        assert result.exit_code == 1
        assert key[-4:] not in result.stderr
        fingerprint = hashlib.sha256(key.encode()).hexdigest()[:8]
        assert fingerprint in result.stderr


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

    def test_precommit_no_files_fails_closed(self) -> None:
        """--pre-commit with no files at all -> exit 2, never a clean verdict.

        Was ``test_precommit_no_files_exits_0``, added by a coverage-gap pass
        (WOR-45) that pinned the behaviour rather than the contract. That exit 0
        WAS the bug (worthless-2kuy): git invokes pre-commit hooks with zero
        arguments, so the installed hook inspected nothing, printed "No API keys
        found." and let a real key commit clean.

        Step 2 will revisit this: once scan collects staged files itself, an
        empty staged set becomes legitimate (empty/merge commit) and exit 0 is
        correct again — for a different reason. Until then, no files can only
        mean the hook is broken.
        """
        result = runner.invoke(app, ["scan", "--pre-commit"])
        assert result.exit_code == 2
        assert "No API keys found" not in result.stdout + result.stderr

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

    def test_show_suffix_uses_fingerprint_parens_format(self, file_with_key: Path) -> None:
        """SR-04 (WOR-655): --show-suffix renders '**** (<8-hex>)', replacing
        the old 'sk-a...wXyZ' prefix+suffix leak. No '...' separator, no real
        bytes."""
        import hashlib

        key = _fake_openai_key()
        result = runner.invoke(app, ["scan", "--show-suffix", str(file_with_key)])
        assert result.exit_code == 1
        fingerprint = hashlib.sha256(key.encode()).hexdigest()[:8]
        assert f"**** ({fingerprint})" in result.stderr

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

    def test_deep_scan_tempfile_write_failure_unlinks_orphan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WOR-277: a write failure must not orphan the env-dump tempfile.

        Before the fix, ``mkstemp`` had already created the file on disk
        when ``os.write`` raised; the except-branch closed the fd but never
        unlinked it, leaking a (possibly partially written) plaintext env
        dump forever. Spy on ``tempfile.mkstemp`` to learn the exact path
        it created, then assert it's gone once ``_collect_deep_paths``
        returns.
        """
        monkeypatch.chdir(tmp_path)
        _strip_env_secrets(monkeypatch)
        monkeypatch.setenv("WORTHLESS_TEST_ENV_LEAK_PROBE", "sentinel-value")

        created_paths: list[str] = []
        real_mkstemp = tempfile.mkstemp

        def _spy_mkstemp(*args, **kwargs):
            fd, path = real_mkstemp(*args, **kwargs)
            created_paths.append(path)
            return fd, path

        with (
            patch("worthless.cli.commands.scan.tempfile.mkstemp", _spy_mkstemp),
            patch("worthless.cli.commands.scan.os.write", side_effect=OSError("disk full")),
        ):
            result = runner.invoke(app, ["scan", "--deep"])
        assert result.exit_code in (0, 1)
        assert created_paths, "mkstemp should have been called for the env dump"
        assert not Path(created_paths[0]).exists(), (
            f"orphaned env-dump tempfile leaked at {created_paths[0]!r}"
        )

    def test_mkstemp_never_opens_through_a_preexisting_symlink(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WOR-277 ('refuse if a symlink pre-exists'): ``mkstemp``'s
        O_CREAT|O_EXCL contract means a pre-planted symlink at a candidate
        path is a collision, not a target — it retries the next candidate
        name rather than opening through the link. This is why
        ``_collect_deep_paths`` needs no hand-rolled symlink check of its
        own; it inherits the guarantee from ``tempfile.mkstemp`` directly.
        """
        attacker_target = tmp_path / "attacker-owned-file"
        attacker_target.write_text("not the env dump\n")

        poisoned_name = "poisoned0000000000000000000000"
        fresh_name = "freshname0000000000000000000000"
        (tmp_path / f"worthless-env-{poisoned_name}.env").symlink_to(attacker_target)

        names = iter([poisoned_name, fresh_name])
        monkeypatch.setattr(tempfile, "_get_candidate_names", lambda: names)

        fd, path = tempfile.mkstemp(prefix="worthless-env-", suffix=".env", dir=str(tmp_path))
        try:
            os.close(fd)
            created = Path(path)
            assert created.name == f"worthless-env-{fresh_name}.env"
            assert not created.is_symlink()
            assert attacker_target.read_text() == "not the env dump\n", (
                "mkstemp wrote through the pre-planted symlink instead of skipping it"
            )
        finally:
            Path(path).unlink(missing_ok=True)

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

        finding = ScanFinding(
            file="/tmp/.env",  # noqa: S108 — must be a real .env basename: lock's
            # allowlist refuses "x.env", so scan would (correctly) not
            # suggest lock for it.
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

        finding = ScanFinding(
            file="/tmp/.env",  # noqa: S108 — must be a real .env basename: lock's
            # allowlist refuses "x.env", so scan would (correctly) not
            # suggest lock for it.
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


class TestScanVerdictNamesTheRealFile:
    """The verdict line must describe the file it actually scanned.

    ``_scan_verdict_line`` hardcoded ".env" and "Run `worthless lock`". That was
    survivable while scan mostly looked at ``.env`` files. Once the pre-commit
    hook began scanning STAGED SOURCE FILES (worthless-2kuy), the common case
    became a key in ``app.py`` — reported as "exposed in .env", sending the user
    to look in the wrong file, and then to a command that cannot help: lock's
    basename allowlist accepts only the 9 ``.env``-family names, so
    ``worthless lock --env app.py`` is refused by design.
    """

    def test_source_file_verdict_does_not_say_dotenv(self, tmp_path: Path) -> None:
        leaky = tmp_path / "app.py"
        leaky.write_text(f'OPENAI_API_KEY = "{_fake_openai_key()}"\n')

        result = runner.invoke(app, ["scan", str(leaky)])
        out = " ".join((result.stdout + result.stderr).split())

        # Not vacuous: the key really was found.
        assert "app.py" in out, f"scan must report the file it scanned; output:\n{out}"

        assert "exposed in .env" not in out, (
            f"scan reported a key in app.py as exposed in .env, sending the user "
            f"to a file that does not contain it; output:\n{out}"
        )

    def test_source_file_is_not_sent_to_lock(self, tmp_path: Path) -> None:
        leaky = tmp_path / "app.py"
        leaky.write_text(f'OPENAI_API_KEY = "{_fake_openai_key()}"\n')

        result = runner.invoke(app, ["scan", str(leaky)])
        out = " ".join((result.stdout + result.stderr).split()).lower()

        # lock's basename allowlist refuses anything outside the .env family, so
        # "run lock on this file" cannot be carried out. Advice that names the
        # move first IS followable, so assert the guidance is right rather than
        # banning the word — absence alone would also pass on silence.
        assert "move it to a .env file" in out, (
            f"scan must tell the user how to make this actionable; output:\n{out}"
        )
        assert "run: worthless lock" not in out, (
            f"scan issued the bare instruction to run lock on a file lock "
            f"refuses by design; output:\n{out}"
        )

    def test_dotenv_verdict_is_unchanged(self, tmp_path: Path) -> None:
        # The .env path is the one where the existing wording is correct and the
        # advice is followable. It must keep both.
        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={_fake_openai_key()}\n")

        result = runner.invoke(app, ["scan", str(env)])
        out = " ".join((result.stdout + result.stderr).split()).lower()

        assert "worthless lock" in out, (
            f"a .env with an exposed key must still point at lock; output:\n{out}"
        )


class TestInstallHookIntoExistingExecHook:
    """worthless-2kuy step 3: never append below an ``exec``.

    The pre-commit FRAMEWORK's generated hook ends with an ``exec ... hook-impl``
    line. ``exec`` replaces the shell process, so anything appended after it is
    unreachable. The installer's marker check only prevents double-installs, not
    dead placement — so for users already running pre-commit (the most
    hook-literate ones), worthless's line was installed and never ran.
    """

    def _framework_hook(self) -> str:
        # Shape of the real pre-commit framework template.
        return (
            "#!/usr/bin/env bash\n"
            "# start templated\n"
            "INSTALL_PYTHON=/usr/bin/python3\n"
            "ARGS=(hook-impl --config=.pre-commit-config.yaml --hook-type=pre-commit)\n"
            "# end templated\n"
            'exec "$INSTALL_PYTHON" -mpre_commit "${ARGS[@]}"\n'
        )

    def test_worthless_line_is_reachable_after_install(self, tmp_path: Path) -> None:
        git_dir = tmp_path / ".git"
        (git_dir / "hooks").mkdir(parents=True)
        hook = git_dir / "hooks" / "pre-commit"
        hook.write_text(self._framework_hook())

        result = runner.invoke(app, ["scan", "--install-hook"], env={"GIT_DIR": str(git_dir)})
        assert result.exit_code == 0, f"{result.stdout}{result.stderr}"

        content = hook.read_text()
        lines = [ln.strip() for ln in content.splitlines()]
        exec_idx = next((i for i, ln in enumerate(lines) if ln.startswith("exec ")), None)
        worthless_idx = next(
            (i for i, ln in enumerate(lines) if "worthless scan --pre-commit" in ln), None
        )

        if worthless_idx is not None and exec_idx is not None:
            assert worthless_idx < exec_idx, (
                "worthless's hook line was installed AFTER an `exec`, so it can "
                "never run — the user believes they are protected and is not.\n"
                f"hook contents:\n{content}"
            )
        else:
            # The other acceptable outcome: refuse to append and tell the user
            # to add worthless to .pre-commit-config.yaml instead.
            out = (result.stdout + result.stderr).lower()
            assert "pre-commit-config" in out or "already" in out, (
                "installer neither placed the line reachably nor told the user "
                f"how to wire it up; output:\n{result.stdout}{result.stderr}"
            )


class TestScanAgreesWithLockOnOAuthTokens:
    """worthless-p55g: scan and lock must not send the user in a circle.

    ``lock`` deliberately refuses to shard a Claude Code OAuth token — sharding
    rewrites the ``sk-ant-oat`` marker Claude Code is recognised by. ``scan``
    had no matching filter, so it reported the token UNPROTECTED and told the
    user to run ``lock``; ``lock`` declined and reported nothing was locked.
    CI stayed red permanently with no remediation available.

    The fix gives these tokens their own verdict — "can't protect" — in text,
    JSON and SARIF together, so no format contradicts another. Files live in a
    subdirectory: this module's autouse fixture chdirs into tmp_path and scan
    always adds ./.env, so a tmp_path/.env would be counted twice
    (worthless-vab1).
    """

    @staticmethod
    def _env(tmp_path: Path, *lines: str) -> Path:
        env = tmp_path / "proj" / ".env"
        env.parent.mkdir()
        env.write_text("".join(f"{line}\n" for line in lines))
        return env

    @staticmethod
    def _oauth(seed: str) -> str:
        return f"ANTHROPIC_API_KEY={fake_key('sk-ant-oat01-', seed)}"

    @staticmethod
    def _flat(result) -> str:  # noqa: ANN001 - click Result
        return " ".join((result.stdout + result.stderr).split())

    def test_oauth_only_file_passes_the_scan(self, tmp_path: Path) -> None:
        env = self._env(tmp_path, self._oauth("p55g-exit"))

        result = runner.invoke(app, ["scan", str(env)])

        # Exit 1 means "you have leaks, go run lock". lock refuses this token,
        # so 1 strands CI with no way to go green. Exactly 0, not merely "not
        # 1": exit 2 means the scan itself broke or was incomplete.
        assert result.exit_code == 0, self._flat(result)

    def test_oauth_only_file_says_cant_protect_and_names_a_real_fix(self, tmp_path: Path) -> None:
        env = self._env(tmp_path, self._oauth("p55g-verdict"))

        result = runner.invoke(app, ["scan", str(env)])
        out = self._flat(result)
        low = out.lower()

        # Not vacuous: scan really did see the token.
        assert "anthropic_api_key" in low, out
        # The false instruction: lock refuses this token by design, so
        # "UNPROTECTED ... run worthless lock" cannot be followed.
        assert "UNPROTECTED" not in out, out
        assert "still exposed" not in low, out
        assert "run `worthless lock`" not in low, out
        assert "run worthless lock" not in low, out
        # The positive spec: name the category, stay honest that the token is
        # still sitting there, and name a fix that exists.
        assert "can't protect" in low, out
        assert "plain text" in low, out
        assert "sk-ant-api03" in low, out
        # Never "0 unprotected" next to a live plaintext token.
        assert "0 unprotected" not in low, out

    def test_sarif_keeps_a_protected_key_as_a_warning(self) -> None:
        # Pre-existing behaviour, moved into _sarif_verdict by this PR: a key
        # worthless protects is reported at "warning", never as a login token.
        protected = ScanFinding(
            file="/p/.env",
            line=1,
            var_name="OPENAI_API_KEY",
            provider="openai",
            is_protected=True,
            value_preview="****",
        )

        [res] = format_sarif([protected], "0")["runs"][0]["results"]

        assert res["level"] == "warning", res
        assert res["ruleId"] == "worthless/exposed-api-key", res
        assert "(protected by worthless)" in res["message"]["text"], res

    def test_a_file_with_an_unprotectable_token_never_reads_as_clean(self) -> None:
        findings = [
            ScanFinding(
                file="/p/.env",
                line=1,
                var_name="OPENAI_API_KEY",
                provider="openai",
                is_protected=True,
                value_preview="****",
            ),
            ScanFinding(
                file="/p/.env",
                line=2,
                var_name="ANTHROPIC_API_KEY",
                provider="anthropic",
                is_protected=False,
                value_preview="****",
                is_login_token=True,
            ),
        ]

        low = " ".join(_format_human(findings, is_tty=False).split()).lower()

        # Everything lock CAN act on is protected — but a live token is still
        # in the file, so "a leaked .env is worthless" would be false comfort.
        assert "worthless to an attacker" not in low, low
        assert "1 of 2 keys protected" in low, low
        assert "can't protect" in low, low

    def test_json_agrees_with_the_text(self, tmp_path: Path) -> None:
        env = self._env(tmp_path, self._oauth("p55g-json"))

        result = runner.invoke(app, ["scan", str(env), "--json"])

        assert result.exit_code == 0, self._flat(result)
        data = json.loads(result.stdout)
        # Additive field, so no bump (docs/install/agent-schema.md).
        assert data["schema_version"] == 2
        [finding] = data["findings"]
        assert finding["is_protected"] is False
        assert finding["is_unshardable"] is True, finding
        assert "sk-ant-api03" in finding["remediation"], finding
        assert finding["exposure"] == "local", finding

    def test_sarif_is_a_note_under_its_own_rule(self, tmp_path: Path) -> None:
        env = self._env(tmp_path, self._oauth("p55g-sarif"))

        result = runner.invoke(app, ["scan", str(env), "--format", "sarif"])

        assert result.exit_code == 0, self._flat(result)
        run = json.loads(result.stdout)["runs"][0]
        [res] = run["results"]
        # GitHub code scanning reads the level, not the exit code: "error"
        # keeps the gate red even when scan exits 0.
        assert res["level"] == "note", res
        assert res["ruleId"] == "worthless/unshardable-oauth-token", res
        assert "sk-ant-api03" in res["message"]["text"], res
        assert res["ruleId"] in {r["id"] for r in run["tool"]["driver"]["rules"]}

    def test_quiet_still_says_why(self, tmp_path: Path) -> None:
        env = self._env(tmp_path, self._oauth("p55g-quiet"))

        result = runner.invoke(app, ["--quiet", "scan", str(env)])
        low = self._flat(result).lower()

        assert result.exit_code == 0, low
        # --quiet hides chatter, not the one thing the user cannot learn any
        # other way. Today it prints nothing at all.
        assert "can't protect" in low, low
        assert "sk-ant-api03" in low, low

    def test_mixed_file_fails_only_for_the_key_lock_can_fix(self, tmp_path: Path) -> None:
        env = self._env(tmp_path, self._oauth("p55g-mixed"), f"OPENAI_API_KEY={_fake_openai_key()}")

        result = runner.invoke(app, ["scan", str(env)])
        low = self._flat(result).lower()

        # The OpenAI key IS fixable, so the build still fails — counted once.
        assert result.exit_code == 1, low
        assert "1 still exposed" in low, low
        assert "1 can't protect" in low, low

        sarif = runner.invoke(app, ["scan", str(env), "--format", "sarif"])
        levels = sorted(r["level"] for r in json.loads(sarif.stdout)["runs"][0]["results"])
        assert levels == ["error", "note"], levels

        data = json.loads(runner.invoke(app, ["scan", str(env), "--json"]).stdout)
        flags = sorted((f["var_name"], f["is_unshardable"]) for f in data["findings"])
        assert flags == [("ANTHROPIC_API_KEY", True), ("OPENAI_API_KEY", False)], flags

    def test_a_token_outside_the_env_family_still_fails(self, tmp_path: Path) -> None:
        # The pass exists because lock can't fix a token in a .env file and
        # failing forever there has no way out. In any other file a fix does
        # exist — take it out of the file (and rotate it if it was committed) —
        # so it fails like any other key. A refresh token in source is the worst
        # case: long-lived, and in CI already in git history.
        leak = tmp_path / "proj" / "settings.py"
        leak.parent.mkdir()
        leak.write_text(f'REFRESH = "{fake_key("sk-ant-ort01-", "p55g-source")}"\n')

        result = runner.invoke(app, ["scan", str(leak)])
        out = self._flat(result)

        assert result.exit_code == 1, out
        assert "UNPROTECTED" in out, out
        assert "can't protect" not in out.lower(), out
        sarif = json.loads(runner.invoke(app, ["scan", str(leak), "--format", "sarif"]).stdout)
        assert [r["level"] for r in sarif["runs"][0]["results"]] == ["error"], sarif
        # Still the p55g dead end if it says "run lock": lock refuses this
        # token wherever it sits. The fix that exists is to revoke it.
        assert "run `worthless lock`" not in out.lower(), out
        assert "revoke" in out.lower(), out
        # Says exactly why, not a list of guesses.
        assert "isn't a .env file" in out.lower(), out

    def test_a_token_in_a_committed_env_still_fails(self, tmp_path: Path) -> None:
        # A .env in git is a leak, and in CI the scan is the backstop for
        # people who never installed the hook. Main failed it; the pass must
        # not cover it. The fix that exists: revoke it, take it out of git.
        env = self._env(tmp_path, self._oauth("p55g-committed"))
        _git_commit(env.parent, ".env")

        result = runner.invoke(app, ["scan", str(env)])
        low = self._flat(result).lower()

        assert result.exit_code == 1, low
        assert "revoke" in low, low
        assert "run `worthless lock`" not in low, low
        # The exact problem, in plain words — not "it can leave the machine".
        assert "this .env file is committed to git" in low, low
        assert f"git rm --cached {str(env).lower()}" in low, low
        data = json.loads(runner.invoke(app, ["scan", str(env), "--json"]).stdout)
        [finding] = data["findings"]
        assert finding["is_unshardable"] is False, data
        assert finding["exposure"] == "committed", data
        assert "committed to git" in finding["remediation"].lower(), data
        sarif = json.loads(runner.invoke(app, ["scan", str(env), "--format", "sarif"]).stdout)
        [res] = sarif["runs"][0]["results"]
        assert res["level"] == "error", res
        assert "committed to git" in res["message"]["text"].lower(), res

    def test_a_staged_env_is_not_called_committed(self, tmp_path: Path) -> None:
        # `git add` alone puts the file in git's index, not in its history.
        # Saying "already in your git history" would be false, and this is
        # exactly what the pre-commit-framework hook sees.
        env = self._env(tmp_path, self._oauth("p55g-staged"))
        subprocess.run(["git", "init", "-q", str(env.parent)], check=True)  # noqa: S607
        subprocess.run(["git", "-C", str(env.parent), "add", ".env"], check=True)  # noqa: S607

        result = runner.invoke(app, ["scan", str(env)])
        low = self._flat(result).lower()

        assert result.exit_code == 1, low
        assert "staged in git but not committed yet" in low, low
        assert "already in your git history" not in low, low
        assert "committed to git" not in low, low
        data = json.loads(runner.invoke(app, ["scan", str(env), "--json"]).stdout)
        assert data["findings"][0]["exposure"] == "staged", data

    def test_untracking_a_committed_env_without_committing_still_fails(
        self, tmp_path: Path
    ) -> None:
        # `git rm --cached` takes the file out of git's index, so git calls it
        # untracked — but until that is committed, the token is still in the
        # latest commit. Doing half of the committed advice must not go green.
        env = self._env(tmp_path, self._oauth("p55g-untracked-in-head"))
        _git_commit(env.parent, ".env")
        subprocess.run(
            ["git", "-C", str(env.parent), "rm", "-q", "--cached", ".env"],  # noqa: S607
            check=True,
        )

        result = runner.invoke(app, ["scan", str(env)])
        low = self._flat(result).lower()

        assert result.exit_code == 1, low
        assert "this .env file is committed to git" in low, low
        sarif = json.loads(runner.invoke(app, ["scan", str(env), "--format", "sarif"]).stdout)
        [res] = sarif["runs"][0]["results"]
        assert res["level"] == "error", res

    def test_a_mixed_committed_env_headline_doesnt_send_the_token_to_lock(
        self, tmp_path: Path
    ) -> None:
        # The OpenAI key is fixable by lock; the login token is not. The
        # headline must not lump the token in with "Run `worthless lock`".
        env = self._env(
            tmp_path, self._oauth("p55g-mixed-committed"), f"OPENAI_API_KEY={_fake_openai_key()}"
        )
        _git_commit(env.parent, ".env")

        result = runner.invoke(app, ["scan", str(env)])
        headline = (result.stdout + result.stderr).splitlines()[0].lower()

        assert result.exit_code == 1, headline
        assert "login token" in headline and "see below" in headline, headline

    def test_tokens_in_one_file_get_one_explanation(self, tmp_path: Path) -> None:
        # Two tokens, same file, same reason: one paragraph, not two. A token
        # with no variable name is labelled by its line, not the provider name.
        cfg = tmp_path / "proj" / "config.yaml"
        cfg.parent.mkdir()
        cfg.write_text(
            f"a: {fake_key('sk-ant-oat01-', 'p55g-one')}\n"
            f"b: {fake_key('sk-ant-oat01-', 'p55g-two')}\n"
        )

        result = runner.invoke(app, ["scan", str(cfg)])
        low = self._flat(result).lower()

        assert result.exit_code == 1, low
        assert low.count("isn't a .env file") == 1, low
        assert "line 1" in low and "line 2" in low, low

    def test_git_is_asked_in_english(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # The "not a git repository" check reads git's English message; a
        # translated git (e.g. LANG=de_DE) would otherwise fail a plain .env.
        env = self._env(tmp_path, self._oauth("p55g-lang"))
        envs: list[dict] = []

        def fake_git(cmd, **kwargs):  # noqa: ANN001, ANN202
            envs.append(kwargs.get("env") or {})
            return subprocess.CompletedProcess(cmd, 128, b"", b"fatal: not a git repository")

        monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
        monkeypatch.setattr(scanner_mod.subprocess, "run", fake_git)

        [finding] = scan_files([env])

        assert finding.is_unshardable is True
        assert envs and all(e.get("LC_ALL") == "C" for e in envs), envs

    def test_the_cli_says_when_git_couldnt_answer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env = self._env(tmp_path, self._oauth("p55g-unknown-cli"))

        def refusing_git(cmd, **_kwargs):  # noqa: ANN001, ANN202
            return subprocess.CompletedProcess(cmd, 128, b"", b"fatal: detected dubious ownership")

        monkeypatch.setattr(scanner_mod.subprocess, "run", refusing_git)

        result = runner.invoke(app, ["scan", str(env)])
        low = self._flat(result).lower()

        assert result.exit_code == 1, low
        assert "couldn't ask git" in low, low
        assert "committed to git" not in low, low

    def test_an_inherited_git_dir_cannot_fool_the_check(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Git sets GIT_DIR for hooks run in a linked worktree. Inherited, it
        # makes `git -C proj ls-files` ask some OTHER repo, which answers "not
        # tracked" for a .env this repo has committed — and the token passes.
        env = self._env(tmp_path, self._oauth("p55g-git-dir"))
        subprocess.run(["git", "init", "-q", str(env.parent)], check=True)  # noqa: S607
        subprocess.run(["git", "-C", str(env.parent), "add", ".env"], check=True)  # noqa: S607
        other = tmp_path / "other"
        subprocess.run(["git", "init", "-q", str(other)], check=True)  # noqa: S607
        monkeypatch.setenv("GIT_DIR", str(other / ".git"))

        [finding] = scan_files([env])

        assert finding.is_unshardable is False

    def test_a_token_in_the_environment_is_not_told_to_revoke(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # --deep scans the environment through a temp dump file. A CI secret
        # held there is where it belongs, not leaked: "revoke it" would kill a
        # working token and the next run would be red again. It still fails, as
        # every environment key does under --deep (worthless-07st), but the
        # advice must fit — and never say lock.
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", fake_key("sk-ant-oat01-", "p55g-env"))

        result = runner.invoke(app, ["scan", "--deep", "--json"])

        assert result.exit_code == 1, result.stdout  # still fails, as on main
        findings = [
            f
            for f in json.loads(result.stdout)["findings"]
            if f["var_name"] == "CLAUDE_CODE_OAUTH_TOKEN"
        ]
        assert len(findings) == 1, findings
        assert findings[0]["is_unshardable"] is False, findings
        assert findings[0]["exposure"] == "environment", findings
        remedy = findings[0]["remediation"].lower()
        assert "environment" in remedy, findings
        assert "revoke" not in remedy, findings
        assert "worthless lock" not in remedy, findings

    def test_a_token_in_a_committed_template_still_fails(self, tmp_path: Path) -> None:
        # .env.example and friends are templates meant to be committed, so they
        # are not in lock's .env family: a real token there is exposed.
        example = tmp_path / "proj" / ".env.example"
        example.parent.mkdir()
        example.write_text(f"{self._oauth('p55g-example')}\n")

        result = runner.invoke(app, ["scan", str(example)])

        assert result.exit_code == 1, self._flat(result)
        assert "revoke" in self._flat(result).lower(), self._flat(result)
        assert "isn't a .env file" in self._flat(result).lower(), self._flat(result)

    @pytest.mark.parametrize("git_answer", ["no-git", "timeout", "dubious-ownership"])
    def test_an_unknown_git_answer_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_answer: str
    ) -> None:
        # The pass needs git to say "not tracked". If git can't answer — not
        # installed, hung, or refusing a checkout it doesn't own (common in CI
        # containers) — the token must not pass because the check couldn't run.
        env = self._env(tmp_path, self._oauth(f"p55g-{git_answer}"))

        def fake_git(cmd, **_kwargs):  # noqa: ANN001, ANN202
            if git_answer == "no-git":
                raise FileNotFoundError("git")
            if git_answer == "timeout":
                raise subprocess.TimeoutExpired(cmd, 10)
            return subprocess.CompletedProcess(
                cmd, 128, b"", b"fatal: detected dubious ownership in repository at '/x'"
            )

        monkeypatch.setattr(scanner_mod.subprocess, "run", fake_git)

        [finding] = scan_files([env])

        assert finding.is_login_token is True
        assert finding.is_unshardable is False
        # Honest about why: it didn't see the file in git, it couldn't ask.
        remedy = scanner_mod.remediation_for(finding) or ""
        assert "couldn't ask git" in remedy, remedy
        assert "is in git" not in remedy, remedy

    def test_a_gitignored_env_in_a_repo_passes(self, tmp_path: Path) -> None:
        # The everyday local setup: a project repo whose .env is gitignored.
        env = self._env(tmp_path, self._oauth("p55g-gitignored"))
        subprocess.run(["git", "init", "-q", str(env.parent)], check=True)  # noqa: S607
        (env.parent / ".gitignore").write_text(".env\n")

        [finding] = scan_files([env])

        assert finding.is_unshardable is True

    @pytest.mark.parametrize(
        ("returncode", "stderr"),
        [(1, b"error: pathspec '.env' did not match"), (128, b"fatal: not a git repository")],
        ids=["untracked-in-repo", "not-a-repo"],
    )
    def test_a_clear_untracked_answer_lets_the_token_pass(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        returncode: int,
        stderr: bytes,
    ) -> None:
        # Only these two answers mean "not in git". Pinned with a simulated git,
        # so the test doesn't depend on whether TMPDIR sits inside a repo.
        env = self._env(tmp_path, self._oauth(f"p55g-clear-{returncode}"))

        def fake_git(cmd, **_kwargs):  # noqa: ANN001, ANN202
            return subprocess.CompletedProcess(cmd, returncode, b"", stderr)

        monkeypatch.setattr(scanner_mod.subprocess, "run", fake_git)

        [finding] = scan_files([env])

        assert finding.is_unshardable is True

    def test_git_is_asked_once_per_file_not_once_per_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The pre-commit hook runs under a time budget; one git call per token
        # (each with its own timeout) could blow it on a .env full of tokens.
        env = self._env(tmp_path, *(self._oauth(f"p55g-many-{i}") for i in range(3)))
        calls: list[Path] = []

        def counting(path: Path) -> str:
            calls.append(path)
            return "untracked"

        monkeypatch.setattr(scanner_mod, "_git_state", counting)

        findings = scan_files([env])

        assert len(findings) == 3
        assert all(f.is_unshardable for f in findings)
        assert len(calls) == 1, calls

    def test_a_symlinked_env_still_fails(self, tmp_path: Path) -> None:
        # Lock refuses symlinks outright, so "a .env file lock manages" is false
        # for a .env that points at some other (possibly committed) file.
        target = tmp_path / "proj" / "prod.secrets"
        target.parent.mkdir()
        target.write_text(f"{self._oauth('p55g-symlink')}\n")
        link = tmp_path / "proj" / ".env"
        link.symlink_to(target)

        result = runner.invoke(app, ["scan", str(link)])

        assert result.exit_code == 1, self._flat(result)
        assert "can't protect" not in self._flat(result).lower(), self._flat(result)
        assert "this .env file is a symlink" in self._flat(result).lower(), self._flat(result)

    def test_a_login_token_is_never_counted_as_protected(self, tmp_path: Path) -> None:
        # Protection is looked up by variable name and file. If ANTHROPIC_API_KEY
        # was locked earlier and a login token was then pasted over it, the name
        # still matches. But lock never shards these tokens, so this value cannot
        # be a worthless shard — calling it protected printed the all-clear.
        env = self._env(tmp_path, self._oauth("p55g-overwrite"))

        [finding] = scan_files(
            [env], enrolled_locations={("ANTHROPIC_API_KEY", str(env.resolve()))}
        )

        assert finding.is_protected is False
        assert finding.is_unshardable is True
        low = " ".join(_format_human([finding], is_tty=False).split()).lower()
        assert "worthless to an attacker" not in low, low

    def test_quiet_never_points_at_the_wrong_key(self, tmp_path: Path) -> None:
        # Mixed file under --quiet: the build fails because of the OpenAI key.
        # Printing only the token's note would send a CI reader to delete the
        # wrong line and stay red. Quiet stays silent on a failing scan, as it
        # always has.
        env = self._env(
            tmp_path, self._oauth("p55g-quiet-mixed"), f"OPENAI_API_KEY={_fake_openai_key()}"
        )

        result = runner.invoke(app, ["--quiet", "scan", str(env)])

        assert result.exit_code == 1, self._flat(result)
        assert "can't protect" not in self._flat(result).lower(), self._flat(result)

    def test_following_scans_advice_ends_in_a_green_build(
        self, tmp_path: Path, home_dir: WorthlessHome
    ) -> None:
        """The loop itself: scan says run lock, lock runs, scan goes green.

        Before the fix the last step failed forever: lock protected the OpenAI
        key and skipped the token, and scan still failed the build over it.
        """
        env = self._env(
            tmp_path, self._oauth("p55g-journey"), f"OPENAI_API_KEY={_fake_openai_key()}"
        )
        home = {"WORTHLESS_HOME": str(home_dir.base_dir)}

        before = runner.invoke(app, ["scan", str(env)], env=home)
        assert before.exit_code == 1, self._flat(before)
        assert "run `worthless lock`" in self._flat(before).lower()

        locked = runner.invoke(app, ["lock", "--env", str(env)], env=home)
        assert locked.exit_code == 0, locked.output

        after = runner.invoke(app, ["scan", str(env)], env=home)
        low = self._flat(after).lower()
        assert after.exit_code == 0, low
        # Green, but not falsely clean: the token is still named.
        assert "can't protect" in low, low
        assert "worthless to an attacker" not in low, low
