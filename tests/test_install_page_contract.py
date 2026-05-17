"""Docs-as-contract tests for the install page E2E journey (WOR-502).

These tests pin the relationship between what the install pages claim and what
the CLI actually does. A failing test here means either the docs are lying or
the CLI regressed — both need fixing.
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

runner = CliRunner(mix_stderr=False)

_INSTALL_PAGES = [
    "website/install-solo.md",
    "website/install-mcp.md",
    "website/install-openclaw.md",
    "website/install-self-hosted.md",
]

_PLACEHOLDER_PHRASES = [
    "not yet available",
    "coming soon",
    "not yet streamlined",
]

_REPO_ROOT = Path(__file__).parent.parent


class TestInstallPageContract:
    """Contract tests: install pages match real CLI behaviour."""

    def test_no_placeholder_language(self) -> None:
        """Install pages must not contain stale placeholder language."""
        violations: list[str] = []
        for rel in _INSTALL_PAGES:
            path = _REPO_ROOT / rel
            text = path.read_text().lower()
            for phrase in _PLACEHOLDER_PHRASES:
                if phrase in text:
                    violations.append(f"{rel}: contains '{phrase}'")
        assert not violations, "Placeholder language found:\n" + "\n".join(violations)

    def test_worthless_status_shows_protected(self, home_with_key: WorthlessHome) -> None:
        """worthless status shows PROTECTED and proxy running — as documented."""
        pid_file = home_with_key.base_dir / "proxy.pid"
        pid_file.write_text("99999\n8787\n")

        class _MockResponse:
            status_code = 200

            def json(self):
                return {"status": "ok", "mode": "up"}

        with patch("worthless.cli.process.httpx") as mock_httpx:
            mock_httpx.get.return_value = _MockResponse()
            result = runner.invoke(
                app,
                ["status"],
                env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
            )

        assert result.exit_code == 0
        output = result.stderr + result.stdout
        assert "PROTECTED" in output, "status must show PROTECTED for enrolled key"
        assert "running" in output.lower(), "status must show proxy running"

    def test_worthless_lock_output_matches_docs(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """worthless lock output matches the terminal block shown in install-solo.md."""
        from tests.helpers import fake_openai_key

        key = fake_openai_key()
        env_file = tmp_path / ".env"
        env_file.write_text(f"OPENAI_API_KEY={key}\n")

        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

        # Normalize Rich line-wrapping before asserting on multi-word phrases.
        output = " ".join((result.stderr + result.stdout).split())
        assert "key(s) split" in output or "key split" in output, (
            "lock output must confirm key was split (docs claim this)"
        )
        assert "no longer contains a usable secret" in output, (
            "lock output must confirm .env no longer contains the real key"
        )

    def test_worthless_version_is_current(self) -> None:
        """worthless --version output contains the installed package version."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        expected = importlib.metadata.version("worthless")
        output = result.stderr + result.stdout
        assert expected in output, f"--version output must contain package version {expected!r}"
