"""CLI integration tests for ``worthless scan --code`` (worthless-7sl9).

These exercise the typer wiring + output formatting + the AI-agent prompt
block. Pure scanner correctness lives in test_code_scanner.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app

runner = CliRunner(mix_stderr=False)


@pytest.fixture
def project_with_hardcoded_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create a tmp project containing one hardcoded OpenAI URL, cd into it."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "client.py").write_text(
        'from openai import OpenAI\nclient = OpenAI(base_url="https://api.openai.com/v1")\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestScanCodeHappyFlow:
    def test_emits_finding_with_file_line_provider(self, project_with_hardcoded_url: Path) -> None:
        result = runner.invoke(app, ["scan", "--code", "--no-ai-prompt"])
        # Findings exit 0 — warn-only contract.
        assert result.exit_code == 0
        # Path appears in human output (stderr, like the .env scanner).
        assert "client.py" in result.stderr
        assert "https://api.openai.com/v1" in result.stderr
        assert "openai" in result.stderr.lower()
        assert "OPENAI_BASE_URL" in result.stderr
        # Source line snippet must be present (→ prefix from _format_code_findings_human).
        assert "→" in result.stderr

    def test_ai_prompt_block_emitted_by_default(self, project_with_hardcoded_url: Path) -> None:
        result = runner.invoke(app, ["scan", "--code"])
        assert result.exit_code == 0
        assert "COPY THIS TO YOUR AI AGENT" in result.stderr
        assert "OPENAI_BASE_URL" in result.stderr

    def test_ai_prompt_suppressed_with_flag(self, project_with_hardcoded_url: Path) -> None:
        result = runner.invoke(app, ["scan", "--code", "--no-ai-prompt"])
        assert result.exit_code == 0
        assert "COPY THIS TO YOUR AI AGENT" not in result.stderr

    def test_honesty_footer_present(self, project_with_hardcoded_url: Path) -> None:
        result = runner.invoke(app, ["scan", "--code", "--no-ai-prompt"])
        # Honest framing per feedback_honest_framing_audit.md — check specific bypass classes.
        assert "does NOT" in result.stderr
        assert "runtime-composed" in result.stderr
        assert "IP literals" in result.stderr

    def test_json_output_has_code_findings_key(self, project_with_hardcoded_url: Path) -> None:
        result = runner.invoke(app, ["scan", "--code", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "code_findings" in data
        assert len(data["code_findings"]) == 1
        f = data["code_findings"][0]
        assert f["provider_name"] == "openai"
        assert f["suggested_env_var"] == "OPENAI_BASE_URL"
        assert f["matched_url"] == "https://api.openai.com/v1"
        assert f["line"] == 2

    def test_json_output_excludes_ai_prompt(self, project_with_hardcoded_url: Path) -> None:
        result = runner.invoke(app, ["scan", "--code", "--json"])
        assert "COPY THIS TO YOUR AI AGENT" not in result.stdout


class TestScanCodeOptOut:
    def test_scan_without_code_flag_skips_code_scan(self, project_with_hardcoded_url: Path) -> None:
        # Plain ``worthless scan`` must NOT scan source — only .env.
        result = runner.invoke(app, ["scan"])
        # No .env present so exit 0; no code findings printed.
        assert "client.py" not in result.stderr
        assert "COPY THIS TO YOUR AI AGENT" not in result.stderr


class TestScanCodeBadFlow:
    def test_clean_project_zero_findings(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "app.py").write_text(
            'import os\nurl = os.environ["OPENAI_BASE_URL"]\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scan", "--code", "--no-ai-prompt"])
        assert result.exit_code == 0
        assert "No hardcoded provider URLs" in result.stderr

    def test_nonexistent_path_errors_cleanly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scan", "--code", "/does/not/exist"])
        assert result.exit_code != 0
        # No raw Python traceback leaking to the user.
        assert "Traceback" not in result.stderr


class TestScanCodeEdges:
    """Edges from the manual coverage audit — AI prompt suppression on
    zero-findings, and the documented SARIF-doesn't-include-code-findings
    contract."""

    def test_ai_prompt_block_not_emitted_when_zero_findings(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Clean project + --code (with default --ai-prompt ON) should NOT
        # emit the COPY-THIS-TO-YOUR-AI-AGENT block. The block is for
        # actionable findings; on a clean run it would be noise.
        (tmp_path / "ok.py").write_text(
            'import os\nurl = os.environ.get("OPENAI_BASE_URL")\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["scan", "--code"])
        assert result.exit_code == 0
        assert "COPY THIS TO YOUR AI AGENT" not in result.stderr

    def test_wsl_env_var_emits_performance_warning(
        self, project_with_hardcoded_url: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Simulate WSL by setting the canonical env var (WSL_DISTRO_NAME for
        # WSL2). The warning fires before the scan so the user knows a slow
        # scan is expected, not a hang.
        monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")
        result = runner.invoke(app, ["scan", "--code", "--no-ai-prompt"])
        assert result.exit_code == 0
        assert "WSL" in result.stderr

    def test_wsl_warning_suppressed_in_json_mode(
        self, project_with_hardcoded_url: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")
        result = runner.invoke(app, ["scan", "--code", "--json"])
        assert result.exit_code == 0
        assert "WSL" not in result.stdout
        assert "WSL" not in result.stderr

    def test_sarif_format_does_not_include_code_findings_by_design(
        self, project_with_hardcoded_url: Path
    ) -> None:
        # Documented limit: SARIF output is for .env key findings only.
        # Code findings live in the text + JSON envelopes. If a future
        # ticket wants code findings in SARIF, that's a deliberate
        # additive change, not a silent bug.
        import json

        result = runner.invoke(app, ["scan", "--code", "--format", "sarif"])
        assert result.exit_code == 0
        sarif = json.loads(result.stdout)
        # SARIF shape: {"runs": [{"results": [...]}]}; assert no
        # result is the new hardcoded-provider-url rule.
        all_rule_ids: set[str] = set()
        for run in sarif.get("runs", []):
            for r in run.get("results", []):
                if r.get("ruleId"):
                    all_rule_ids.add(r["ruleId"])
        assert "hardcoded-provider-url" not in all_rule_ids


class TestScanCodeAdversarialRace:
    """worthless-nxyz: a single file failing to stat mid-scan must not crash
    the entire CLI invocation. Unit coverage in test_code_scanner pins the
    library contract; this test pins the FULL CLI flow — typer wiring + output
    formatters + exit code — against the same race so a future refactor that
    re-introduces the crash in a downstream formatter still fails loudly."""

    def test_racy_file_in_git_branch_does_not_crash_cli(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import subprocess

        # Build a real git repo so the scan goes through ``_list_files_git``
        # (the branch with the new OSError guard). Two files: one will trip
        # ``Path.is_symlink`` with OSError, the other is a clean finding.
        (tmp_path / "racy.py").write_text(
            'client = OpenAI(base_url="https://api.openai.com/v1")\n', encoding="utf-8"
        )
        (tmp_path / "ok.py").write_text(
            'client = Anthropic(base_url="https://api.anthropic.com/v1")\n', encoding="utf-8"
        )
        subprocess.run(
            ["git", "init", "--quiet", "--initial-branch=main"],  # noqa: S607
            cwd=tmp_path,
            check=True,
        )
        subprocess.run(
            ["git", "add", "-A"],  # noqa: S607
            cwd=tmp_path,
            check=True,
        )
        subprocess.run(
            [  # noqa: S607
                "git",
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "--quiet",
                "-m",
                "init",
            ],
            cwd=tmp_path,
            check=True,
        )

        # Patch ``Path.is_symlink`` to raise OSError on racy.py. Hits the
        # exact call site the production fix guards.
        real_is_symlink = Path.is_symlink

        def fake_is_symlink(self: Path) -> bool:
            if self.name == "racy.py":
                raise OSError("simulated mid-scan stat failure")
            return real_is_symlink(self)

        monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)
        monkeypatch.chdir(tmp_path)

        # Full CLI invocation — exit code, JSON envelope, no traceback.
        result = runner.invoke(app, ["scan", "--code", "--json"])

        assert result.exit_code == 0, (
            f"CLI must NOT crash on a single racy file. "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        assert "Traceback" not in result.stderr
        assert "Traceback" not in result.stdout

        payload = json.loads(result.stdout)
        assert "code_findings" in payload
        finding_files = {Path(f["file"]).name for f in payload["code_findings"]}
        assert "racy.py" not in finding_files, "OSError-raising file must be silently dropped"
        assert "ok.py" in finding_files, "clean file in the same scan must still be reported"
