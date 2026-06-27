"""Windows fail-fast guard for ``up``, ``wrap``, and the default command."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app

runner = CliRunner()


_EXPECTED_MESSAGE = "Native Windows is not supported"
_EXPECTED_LINK = "github.com/shacharm2/worthless#platforms"


@pytest.fixture()
def fake_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch ``IS_WINDOWS`` at the definition site so the helper sees ``True``."""
    monkeypatch.setattr("worthless.cli.platform.IS_WINDOWS", True)


@pytest.fixture()
def home_dir(tmp_path: Path) -> Path:
    """Minimal WORTHLESS_HOME for CLI invocations that otherwise need one."""
    base = tmp_path / ".worthless"
    base.mkdir()
    (base / "fernet.key").write_bytes(b"dummykey")
    return base


class TestUpRefusesOnWindows:
    def test_up_foreground(self, fake_windows: None, home_dir: Path) -> None:
        result = runner.invoke(app, ["up"], env={"WORTHLESS_HOME": str(home_dir)})
        assert result.exit_code == 1, result.output
        assert _EXPECTED_MESSAGE in result.output
        assert _EXPECTED_LINK in result.output

    def test_up_daemon(self, fake_windows: None, home_dir: Path) -> None:
        result = runner.invoke(app, ["up", "--daemon"], env={"WORTHLESS_HOME": str(home_dir)})
        assert result.exit_code == 1, result.output
        assert _EXPECTED_MESSAGE in result.output


class TestWrapRefusesOnWindows:
    def test_wrap(self, fake_windows: None, home_dir: Path) -> None:
        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_dir)},
        )
        assert result.exit_code == 1, result.output
        assert _EXPECTED_MESSAGE in result.output
        assert _EXPECTED_LINK in result.output


class TestDefaultCommandRefusesOnWindows:
    def test_bare_invocation(self, fake_windows: None, home_dir: Path) -> None:
        """``worthless`` with no subcommand triggers the default pipeline and must refuse."""
        result = runner.invoke(app, ["--yes"], env={"WORTHLESS_HOME": str(home_dir)})
        assert result.exit_code == 1, result.output
        assert _EXPECTED_MESSAGE in result.output


class TestDownExemptOnWindows:
    """``worthless down`` is deliberately exempt — users need an escape hatch."""

    def test_down_does_not_refuse(self, fake_windows: None, home_dir: Path) -> None:
        # No proxy running — down should exit 0 ("not running") without
        # invoking the Windows guard.
        result = runner.invoke(app, ["down"], env={"WORTHLESS_HOME": str(home_dir)})
        assert _EXPECTED_MESSAGE not in result.output, (
            "down must not trip the Windows fail-fast guard"
        )
        assert result.exit_code == 0, result.output

    def test_down_still_emits_soft_warning(
        self, fake_windows: None, home_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Positive proof: ``down`` must still call ``warn_windows_once``.

        Asserting "no fail-fast message" alone would pass if a future refactor
        silently dropped the warning too. Verify the warn is actively invoked.
        """
        called: list[bool] = []
        monkeypatch.setattr(
            "worthless.cli.commands.down.warn_windows_once",
            lambda *_a, **_kw: called.append(True),
        )
        result = runner.invoke(app, ["down"], env={"WORTHLESS_HOME": str(home_dir)})
        assert result.exit_code == 0, result.output
        assert called, "warn_windows_once was not called on down path"


class TestErrorMessageContract:
    """The error message is a contract: code, link, and no-bypass notice."""

    def test_error_carries_structured_code(self, fake_windows: None, home_dir: Path) -> None:
        """Pin WRTLS-110 so silent ErrorCode swaps break the tests, not prod."""
        result = runner.invoke(app, ["up"], env={"WORTHLESS_HOME": str(home_dir)})
        assert "WRTLS-110" in result.output, result.output

    def test_error_names_the_ineffective_env_var(self, fake_windows: None, home_dir: Path) -> None:
        """``WORTHLESS_WINDOWS_ACK`` silences the soft warning on ``down``; on
        the hard-fail path it's a no-op. The message must name the variable
        explicitly so users who try to set it don't file confused bug reports.
        """
        result = runner.invoke(app, ["up"], env={"WORTHLESS_HOME": str(home_dir)})
        collapsed = " ".join(result.output.split()).lower()
        assert "worthless_windows_ack" in collapsed, collapsed
        assert "does not honor" in collapsed, collapsed


class TestErrorLinkTargetExists:
    """The error message points at a README anchor — that anchor must exist.

    Substring-matching alone (``"## Platforms" in content``) passes for
    ``## Platforms (deprecated)``, ``## Platforms Are Great``, etc. — which
    would silently shift the GitHub slug and break the link. Pin the exact
    heading with a regex, then derive the expected slug and confirm it
    matches the fragment in ``PLATFORMS_URL``.
    """

    def test_readme_has_exact_platforms_heading(self) -> None:
        import re

        readme = Path(__file__).resolve().parents[1] / "README.md"
        content = readme.read_text(encoding="utf-8")
        assert re.search(r"^## Platforms\s*$", content, flags=re.MULTILINE), (
            "README must have an exact '## Platforms' heading (no suffix) — "
            "error message fragment '#platforms' depends on it"
        )

    def test_platforms_url_fragment_matches_readme_slug(self) -> None:
        """``PLATFORMS_URL``'s fragment must equal the slug GitHub will generate
        from the ``## Platforms`` heading. GitHub's rule: lowercase, punctuation
        stripped, spaces → dashes. For an exact ``## Platforms`` the slug is
        ``platforms``; pin the contract so a future URL rename is caught here.
        """
        from urllib.parse import urlparse

        from worthless.cli.platform import PLATFORMS_URL

        fragment = urlparse(PLATFORMS_URL).fragment
        expected_slug = "platforms"  # slugify("Platforms")
        assert fragment == expected_slug, (
            f"PLATFORMS_URL fragment is '{fragment}', but the README heading "
            f"'## Platforms' generates the GitHub slug '{expected_slug}'"
        )
