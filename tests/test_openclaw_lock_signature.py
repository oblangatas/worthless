"""OpenClaw + lock insulation tests (worthless-7sl9).

The scan --code work explicitly does NOT touch lock.py or openclaw/*.
These tests are the tripwire that proves it stays that way:

- ``apply_lock`` signature is pinned (kwarg names + return type).
- ``worthless lock --help`` does not expose any --code option.
- Lock end-to-end never invokes the new scanner.
- A self-scan of the openclaw skill assets produces zero findings
  (sanity: OpenClaw itself does not contain any provider URLs that
  would self-trigger the rule).
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.code_scanner import scan_for_hardcoded_provider_urls
from worthless.openclaw.integration import OpenclawApplyResult, apply_lock

runner = CliRunner(mix_stderr=False)


def _strip_ansi(s: str) -> str:
    """Remove ANSI escape codes for plain-text assertions.

    GitHub CI runners set FORCE_COLOR=1; Rich then wraps individual
    hyphens (e.g. --code → \\x1b[..m-\\x1b[0m\\x1b[..m-code\\x1b[0m)
    which breaks simple substring search.
    """
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


class TestOpenClawSignaturePinned:
    def test_apply_lock_accepts_planned_updates_and_proxy_base_url(self) -> None:
        sig = inspect.signature(apply_lock)
        params = sig.parameters

        assert "planned_updates" in params
        assert "proxy_base_url" in params
        # proxy_base_url is keyword-only with a default of None.
        assert params["proxy_base_url"].kind == inspect.Parameter.KEYWORD_ONLY
        assert params["proxy_base_url"].default is None

    def test_apply_lock_returns_openclaw_apply_result(self) -> None:
        # ``from __future__ import annotations`` in integration.py keeps
        # type hints as strings, so compare against the name. Sanity:
        # the class still exists and is importable.
        sig = inspect.signature(apply_lock)
        assert sig.return_annotation == "OpenclawApplyResult"
        assert OpenclawApplyResult.__name__ == "OpenclawApplyResult"


class TestLockCliUntouched:
    def test_lock_help_does_not_mention_code_scan(self) -> None:
        result = runner.invoke(app, ["lock", "--help"])
        assert result.exit_code == 0
        # The --code flag belongs on scan, not lock.
        assert "--code" not in _strip_ansi(result.stdout)

    def test_scan_help_documents_code_flag(self) -> None:
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--code" in _strip_ansi(result.stdout)


class TestLockDoesNotInvokeCodeScanner:
    def test_lock_never_calls_scan_for_hardcoded_provider_urls(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Even with a hardcoded URL in source, lock must not invoke the
        new code scanner. Lock-side coupling is explicitly deferred
        (worthless-8a5d parked, depends on 7sl9)."""
        (tmp_path / "app.py").write_text(
            'client = OpenAI(base_url="https://api.openai.com/v1")\n', encoding="utf-8"
        )
        # Empty .env so lock will exit "no unprotected keys" rather than
        # do real DB writes — we only care that the scanner wasn't called.
        (tmp_path / ".env").write_text("# empty\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        with patch("worthless.cli.code_scanner.scan_for_hardcoded_provider_urls") as mock_scan:
            runner.invoke(app, ["lock", "--env", str(tmp_path / ".env")])
            assert mock_scan.call_count == 0, (
                "lock invoked code_scanner — lock/scan coupling is forbidden "
                "until worthless-8a5d is revived"
            )


class TestOpenClawAssetsAreClean:
    def test_skill_assets_dir_has_no_provider_url_findings(self) -> None:
        # Sanity: scanning OpenClaw's own bundled assets produces zero
        # findings. If this ever fails, OpenClaw started shipping with a
        # hardcoded provider URL — which would self-trigger the rule for
        # every user.
        from worthless import openclaw as openclaw_pkg

        assets_dir = Path(openclaw_pkg.__file__).parent / "skill_assets"
        if not assets_dir.exists():
            return  # nothing to check

        findings = scan_for_hardcoded_provider_urls([assets_dir])
        assert findings == [], f"OpenClaw skill assets contain hardcoded provider URLs: {findings}"
