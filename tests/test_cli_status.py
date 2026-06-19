"""Tests for the status CLI command."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

runner = CliRunner(mix_stderr=False)

# home_with_key fixture is in conftest.py


# ---------------------------------------------------------------------------
# Tests: no enrollment
# ---------------------------------------------------------------------------


class TestStatusNoEnrollment:
    """Tests for status with no enrolled keys."""

    def test_status_no_keys_shows_message(self, home_dir: WorthlessHome) -> None:
        """Status with no enrollment shows 'No keys enrolled'."""
        result = runner.invoke(
            app,
            ["status"],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        assert (
            "no keys enrolled" in result.stderr.lower()
            or "no keys enrolled" in result.stdout.lower()
        )

    def test_status_json_no_keys(self, home_dir: WorthlessHome) -> None:
        """Status --json with no enrollment returns empty keys array."""
        result = runner.invoke(
            app,
            ["--json", "status"],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["keys"] == []


# ---------------------------------------------------------------------------
# Tests: with enrollment
# ---------------------------------------------------------------------------


class TestStatusWithKeys:
    """Tests for status with enrolled keys."""

    def test_status_shows_aliases_and_providers(self, home_with_key: WorthlessHome) -> None:
        """Status with enrolled key shows alias and provider."""
        result = runner.invoke(
            app,
            ["status"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 0
        output = result.stderr + result.stdout
        assert "openai-a1b2c3d4" in output
        assert "openai" in output

    def test_status_json_with_keys(self, home_with_key: WorthlessHome) -> None:
        """Status --json outputs valid JSON with keys array."""
        result = runner.invoke(
            app,
            ["--json", "status"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert isinstance(data["keys"], list)
        assert len(data["keys"]) >= 1
        key_entry = data["keys"][0]
        assert "alias" in key_entry
        assert "provider" in key_entry


# ---------------------------------------------------------------------------
# Tests: proxy health
# ---------------------------------------------------------------------------


class TestStatusProxy:
    """Tests for proxy health check in status."""

    def test_status_unreachable_proxy_shows_not_running(self, home_with_key: WorthlessHome) -> None:
        """Status with no proxy running shows 'not running'."""
        result = runner.invoke(
            app,
            ["status"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 0
        output = result.stderr + result.stdout
        assert "not running" in output.lower()

    def test_status_json_unreachable_proxy(self, home_with_key: WorthlessHome) -> None:
        """Status --json with no proxy shows proxy.healthy=false."""
        result = runner.invoke(
            app,
            ["--json", "status"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["proxy"]["healthy"] is False
        assert data["proxy"]["port"] is None

    def test_status_mock_healthy_proxy(self, home_with_key: WorthlessHome, tmp_path: Path) -> None:
        """Status with mock healthy proxy shows 'running'."""
        # Write a PID file to indicate proxy is running on port 18787
        pid_file = home_with_key.base_dir / "proxy.pid"
        pid_file.write_text("99999\n18787\n")

        # Mock httpx.get to return healthy response

        class MockResponse:
            status_code = 200

            def json(self):
                return {"status": "ok", "mode": "up"}

        with patch("worthless.cli.process.httpx") as mock_httpx:
            mock_httpx.get.return_value = MockResponse()
            result = runner.invoke(
                app,
                ["status"],
                env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
            )

        assert result.exit_code == 0
        output = result.stderr + result.stdout
        assert "running" in output.lower() or "18787" in output

    def test_status_json_healthy_proxy(self, home_with_key: WorthlessHome, tmp_path: Path) -> None:
        """Status --json with mock proxy shows port and mode."""
        pid_file = home_with_key.base_dir / "proxy.pid"
        pid_file.write_text("99999\n18787\n")

        class MockResponse:
            status_code = 200

            def json(self):
                return {"status": "ok", "mode": "up"}

        with patch("worthless.cli.process.httpx") as mock_httpx:
            mock_httpx.get.return_value = MockResponse()
            result = runner.invoke(
                app,
                ["--json", "status"],
                env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
            )

        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["proxy"]["healthy"] is True
        assert data["proxy"]["port"] == 18787
        assert data["proxy"]["mode"] == "up"


# ---------------------------------------------------------------------------
# Tests: requests_proxied in status
# ---------------------------------------------------------------------------


class TestStatusRequestsProxied:
    """Tests for requests_proxied display in status output."""

    def test_status_shows_requests_proxied(self, home_with_key: WorthlessHome) -> None:
        """Status with healthy proxy shows 'Requests proxied: N'."""
        pid_file = home_with_key.base_dir / "proxy.pid"
        pid_file.write_text("99999\n18787\n")

        class MockResponse:
            status_code = 200

            def json(self):
                return {"status": "ok", "mode": "up", "requests_proxied": 42}

        with patch("worthless.cli.process.httpx") as mock_httpx:
            mock_httpx.get.return_value = MockResponse()
            result = runner.invoke(
                app,
                ["status"],
                env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
            )

        assert result.exit_code == 0
        output = result.stderr + result.stdout
        assert "42" in output
        assert "proxied" in output.lower()

    def test_status_json_includes_requests_proxied(self, home_with_key: WorthlessHome) -> None:
        """Status --json includes requests_proxied from proxy health."""
        pid_file = home_with_key.base_dir / "proxy.pid"
        pid_file.write_text("99999\n18787\n")

        class MockResponse:
            status_code = 200

            def json(self):
                return {"status": "ok", "mode": "up", "requests_proxied": 7}

        with patch("worthless.cli.process.httpx") as mock_httpx:
            mock_httpx.get.return_value = MockResponse()
            result = runner.invoke(
                app,
                ["--json", "status"],
                env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
            )

        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["proxy"]["requests_proxied"] == 7

    def test_status_zero_requests_proxied(self, home_with_key: WorthlessHome) -> None:
        """Status shows 0 requests when proxy has no spend_log entries."""
        pid_file = home_with_key.base_dir / "proxy.pid"
        pid_file.write_text("99999\n18787\n")

        class MockResponse:
            status_code = 200

            def json(self):
                return {"status": "ok", "mode": "up", "requests_proxied": 0}

        with patch("worthless.cli.process.httpx") as mock_httpx:
            mock_httpx.get.return_value = MockResponse()
            result = runner.invoke(
                app,
                ["status"],
                env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
            )

        assert result.exit_code == 0
        output = result.stderr + result.stdout
        assert "0" in output


# ---------------------------------------------------------------------------
# WOR-658: status surfaces bind_confirmation state from the sentinel.
#
# Lock writes a ``bind_confirmation`` block into the sentinel after the
# OpenClaw rewrite (pass / fail / skipped + reason). The whole point of
# persisting it is so ``worthless status`` can show the user DEGRADED with
# an actionable reason across terminal sessions — the original lock exit
# code is long gone by the time the user runs status. Without these tests
# the feature is silent and the user has no cue that routing isn't proven.
# ---------------------------------------------------------------------------


class TestStatusSurfacesBindConfirmation:
    """The status command MUST read bind_confirmation from the sentinel and
    show the user a human-readable reason — not just generic DEGRADED."""

    def _write_sentinel(self, home: WorthlessHome, payload: dict) -> None:
        from worthless.cli.sentinel import sentinel_path

        sentinel_path(home.base_dir).write_text(json.dumps(payload, sort_keys=True))

    def test_status_shows_bind_fail_reason_in_human_output(
        self, home_with_key: WorthlessHome
    ) -> None:
        """bind_confirmation.status == 'fail' → human output names the cause."""
        self._write_sentinel(
            home_with_key,
            {
                "ts": "2026-06-15T00:00:00+00:00",
                "status": "partial",
                "openclaw": "failed",
                "alias_count": 1,
                "events": [],
                "bind_confirmation": {
                    "status": "fail",
                    "delta": 0,
                    "reached": 1,
                    "aliases": ["openai-abc"],
                },
            },
        )

        result = runner.invoke(
            app,
            ["status"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        out = result.stderr + result.stdout
        assert "routing" in out.lower() or "not reach" in out.lower(), (
            f"status must explain WHY DEGRADED on bind-fail. Got:\n{out}"
        )
        assert result.exit_code != 0

    def test_status_names_squatter_reason_in_human_output(
        self, home_with_key: WorthlessHome
    ) -> None:
        """proxy_unrecognised → human output points at the unrecognised peer."""
        self._write_sentinel(
            home_with_key,
            {
                "ts": "2026-06-15T00:00:00+00:00",
                "status": "ok",
                "openclaw": "ok",
                "alias_count": 1,
                "events": [],
                "bind_confirmation": {
                    "status": "skipped",
                    "reason": "proxy_unrecognised",
                    "delta": 0,
                    "reached": 0,
                    "aliases": ["openai-abc"],
                },
            },
        )

        result = runner.invoke(
            app,
            ["status"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        out = result.stderr + result.stdout
        assert "unrecogn" in out.lower() or "worthless proxy" in out.lower(), (
            f"skipped/unrecognised must surface a distinct message. Got:\n{out}"
        )
        # CodeRabbit gate-10: pin the exit contract. skipped/unrecognised is
        # NOT a degraded state (status=ok, openclaw=ok) — it's inconclusive,
        # so status must exit 0, not the 73 reserved for true DEGRADED.
        assert result.exit_code == 0, (
            f"skipped/unrecognised is inconclusive, not DEGRADED — must exit 0. "
            f"Got {result.exit_code}"
        )

    def test_status_quiet_when_bind_confirmation_passes(self, home_with_key: WorthlessHome) -> None:
        """status=ok + bind=pass → no DEGRADED, no [WARN]."""
        self._write_sentinel(
            home_with_key,
            {
                "ts": "2026-06-15T00:00:00+00:00",
                "status": "ok",
                "openclaw": "ok",
                "alias_count": 1,
                "events": [],
                "bind_confirmation": {
                    "status": "pass",
                    "delta": 1,
                    "reached": 1,
                    "aliases": ["openai-abc"],
                },
            },
        )

        result = runner.invoke(
            app,
            ["status"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        out = result.stderr + result.stdout
        assert "[WARN]" not in out
        assert "DEGRADED" not in out.upper()
        assert result.exit_code == 0

    # Fix 13: backward-compat — old sentinels lack bind_confirmation field.
    def test_status_tolerates_old_sentinel_without_bind_confirmation(
        self, home_with_key: WorthlessHome
    ) -> None:
        """Sentinel written by a pre-WOR-658 lock has no bind_confirmation key.
        Status must read it cleanly (no KeyError, no crash)."""
        self._write_sentinel(
            home_with_key,
            {
                "ts": "2026-06-15T00:00:00+00:00",
                "status": "ok",
                "openclaw": "ok",
                "alias_count": 1,
                "events": [],
                # bind_confirmation intentionally absent
            },
        )

        result = runner.invoke(
            app,
            ["status"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 0
        assert "Traceback" not in (result.stderr + result.stdout)
