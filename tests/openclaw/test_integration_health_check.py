"""Phase 2.d — ``integration.health_check()`` unit tests.

Spec: ``engineering/research/openclaw/WOR-431-phase-2-spec.md`` §"Phase 2.d"
and AC4 (doctor surfaces OpenClaw status with traffic lights).

``health_check(state, *, expected_providers, proxy_port)`` is the read-only
check that ``worthless doctor`` delegates to. It reads ``openclaw.json`` and
compares each ``worthless-<provider>`` entry's ``baseUrl`` against the
expected proxy URL, returning a structured :class:`OpenclawHealthReport`.

WOR-477 gap 1: ``health_check()`` and ``OpenclawHealthReport`` were listed
in the spec but never implemented. These tests drive the Phase 2.d addition.
"""

from __future__ import annotations

import json
from pathlib import Path

from worthless.openclaw.integration import IntegrationState, OpenclawHealthReport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_state(
    *,
    present: bool = True,
    config_path: Path | None = None,
    workspace_path: Path | None = None,
    skill_path: Path | None = None,
    home_dir: Path | None = None,
    notes: tuple[str, ...] = (),
    home_mismatch: bool = False,
) -> IntegrationState:
    return IntegrationState(
        present=present,
        config_path=config_path,
        workspace_path=workspace_path,
        skill_path=skill_path,
        home_dir=home_dir,
        notes=notes,
        home_mismatch=home_mismatch,
    )


def _write_config(path: Path, providers: dict) -> None:
    path.write_text(
        json.dumps({"models": {"providers": providers}}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# HC-01: config_path is None → all providers missing
# ---------------------------------------------------------------------------


class TestHealthCheckNoConfig:
    """HC-01: no openclaw.json path → all providers in providers_missing."""

    def test_no_config_all_missing(self) -> None:
        from worthless.openclaw.integration import health_check

        state = _make_state(present=True, config_path=None)
        report = health_check(
            state,
            expected_providers=[("openai", "openai-aaaa1111")],
            proxy_port=8787,
        )

        assert report.providers_missing == ("worthless-openai",)
        assert report.providers_ok == ()
        assert report.providers_drifted == ()
        assert report.config_unreadable is False
        assert report.healthy is False

    def test_no_config_multiple_providers_all_missing(self) -> None:
        from worthless.openclaw.integration import health_check

        state = _make_state(present=True, config_path=None)
        report = health_check(
            state,
            expected_providers=[
                ("openai", "openai-aaaa1111"),
                ("anthropic", "anthropic-bbbb2222"),
            ],
            proxy_port=8787,
        )

        assert set(report.providers_missing) == {"worthless-openai", "worthless-anthropic"}
        assert report.healthy is False

    def test_no_providers_empty_report(self) -> None:
        from worthless.openclaw.integration import health_check

        state = _make_state(present=True, config_path=None)
        report = health_check(state, expected_providers=[], proxy_port=8787)

        assert report.providers_missing == ()
        assert report.healthy is True


# ---------------------------------------------------------------------------
# HC-02: provider correctly wired → providers_ok
# ---------------------------------------------------------------------------


class TestHealthCheckProviderOk:
    """HC-02: provider entry present with matching baseUrl → providers_ok."""

    def test_provider_wired_correctly(self, tmp_path: Path) -> None:
        from worthless.openclaw.integration import health_check

        config = tmp_path / "openclaw.json"
        _write_config(
            config,
            {
                "worthless-openai": {
                    "baseUrl": "http://127.0.0.1:8787/openai-aaaa1111/v1",
                    "apiKey": "sk-shard-a",
                    "api": "openai-completions",
                    "models": [],
                }
            },
        )
        state = _make_state(config_path=config)
        report = health_check(
            state,
            expected_providers=[("openai", "openai-aaaa1111")],
            proxy_port=8787,
            proxy_base_url="http://127.0.0.1:8787",  # pin host; skip Docker detection
        )

        assert report.providers_ok == ("worthless-openai",)
        assert report.providers_missing == ()
        assert report.providers_drifted == ()
        assert report.healthy is True

    def test_non_default_port_wired_correctly(self, tmp_path: Path) -> None:
        from worthless.openclaw.integration import health_check

        config = tmp_path / "openclaw.json"
        _write_config(
            config,
            {
                "worthless-openai": {
                    "baseUrl": "http://127.0.0.1:9090/openai-abc/v1",
                    "apiKey": "sk-shard-a",
                    "api": "openai-completions",
                    "models": [],
                }
            },
        )
        state = _make_state(config_path=config)
        report = health_check(
            state,
            expected_providers=[("openai", "openai-abc")],
            proxy_port=9090,
            proxy_base_url="http://127.0.0.1:9090",  # pin host; skip Docker detection
        )

        assert report.healthy is True
        assert "worthless-openai" in report.providers_ok


# ---------------------------------------------------------------------------
# HC-03: provider absent from config → providers_missing
# ---------------------------------------------------------------------------


class TestHealthCheckProviderMissing:
    """HC-03: provider entry absent from openclaw.json → providers_missing."""

    def test_provider_not_in_config(self, tmp_path: Path) -> None:
        from worthless.openclaw.integration import health_check

        config = tmp_path / "openclaw.json"
        _write_config(config, {})  # empty providers
        state = _make_state(config_path=config)
        report = health_check(
            state,
            expected_providers=[("openai", "openai-aaaa1111")],
            proxy_port=8787,
        )

        assert report.providers_missing == ("worthless-openai",)
        assert report.healthy is False

    def test_one_present_one_missing(self, tmp_path: Path) -> None:
        from worthless.openclaw.integration import health_check

        config = tmp_path / "openclaw.json"
        _write_config(
            config,
            {
                "worthless-openai": {
                    "baseUrl": "http://127.0.0.1:8787/openai-aaaa1111/v1",
                    "apiKey": "sk-a",
                    "api": "openai-completions",
                    "models": [],
                }
            },
        )
        state = _make_state(config_path=config)
        report = health_check(
            state,
            expected_providers=[
                ("openai", "openai-aaaa1111"),
                ("anthropic", "anthropic-bbbb2222"),
            ],
            proxy_port=8787,
            proxy_base_url="http://127.0.0.1:8787",  # pin host; skip Docker detection
        )

        assert "worthless-openai" in report.providers_ok
        assert "worthless-anthropic" in report.providers_missing
        assert report.healthy is False


# ---------------------------------------------------------------------------
# HC-04: baseUrl mismatch → providers_drifted
# ---------------------------------------------------------------------------


class TestHealthCheckProviderDrifted:
    """HC-04: entry exists but baseUrl is wrong → providers_drifted."""

    def test_wrong_port_detected(self, tmp_path: Path) -> None:
        from worthless.openclaw.integration import health_check

        config = tmp_path / "openclaw.json"
        wrong_url = "http://127.0.0.1:9999/openai-aaaa1111/v1"
        _write_config(
            config,
            {
                "worthless-openai": {
                    "baseUrl": wrong_url,
                    "apiKey": "sk-a",
                    "api": "openai-completions",
                    "models": [],
                }
            },
        )
        state = _make_state(config_path=config)
        report = health_check(
            state,
            expected_providers=[("openai", "openai-aaaa1111")],
            proxy_port=8787,
            proxy_base_url="http://127.0.0.1:8787",  # pin host; skip Docker detection
        )

        assert len(report.providers_drifted) == 1
        name, actual, expected = report.providers_drifted[0]
        assert name == "worthless-openai"
        assert actual == wrong_url
        assert expected == "http://127.0.0.1:8787/openai-aaaa1111/v1"
        assert report.healthy is False

    def test_wrong_alias_detected(self, tmp_path: Path) -> None:
        from worthless.openclaw.integration import health_check

        config = tmp_path / "openclaw.json"
        _write_config(
            config,
            {
                "worthless-openai": {
                    "baseUrl": "http://127.0.0.1:8787/stale-alias/v1",
                    "apiKey": "sk-a",
                    "api": "openai-completions",
                    "models": [],
                }
            },
        )
        state = _make_state(config_path=config)
        report = health_check(
            state,
            expected_providers=[("openai", "openai-fresh-alias")],
            proxy_port=8787,
        )

        assert len(report.providers_drifted) == 1
        _name, actual, expected = report.providers_drifted[0]
        assert "stale-alias" in actual
        assert "openai-fresh-alias" in expected


# ---------------------------------------------------------------------------
# HC-05: config unreadable → config_unreadable=True
# ---------------------------------------------------------------------------


class TestHealthCheckConfigUnreadable:
    """HC-05: malformed config → config_unreadable=True, bail early."""

    def test_malformed_json(self, tmp_path: Path) -> None:
        from worthless.openclaw.integration import health_check

        config = tmp_path / "openclaw.json"
        config.write_text("not-valid-json\n", encoding="utf-8")
        state = _make_state(config_path=config)
        report = health_check(
            state,
            expected_providers=[("openai", "openai-aaaa1111")],
            proxy_port=8787,
        )

        assert report.config_unreadable is True
        assert report.healthy is False

    def test_unreadable_bails_early_without_crashing(self, tmp_path: Path) -> None:
        from worthless.openclaw.integration import health_check

        config = tmp_path / "openclaw.json"
        config.write_text("not-valid-json\n", encoding="utf-8")
        state = _make_state(config_path=config)

        # Must not raise — errors surface as config_unreadable=True.
        report = health_check(
            state,
            expected_providers=[
                ("openai", "openai-aaaa1111"),
                ("anthropic", "anthropic-bbbb2222"),
            ],
            proxy_port=8787,
        )

        assert report.config_unreadable is True


# ---------------------------------------------------------------------------
# HC-06: OpenclawHealthReport.healthy property
# ---------------------------------------------------------------------------


class TestHealthReportHealthy:
    """HC-06: ``OpenclawHealthReport.healthy`` reflects combined verdict."""

    def test_all_ok_is_healthy(self) -> None:
        r = OpenclawHealthReport(providers_ok=("worthless-openai",))
        assert r.healthy is True

    def test_missing_provider_not_healthy(self) -> None:
        r = OpenclawHealthReport(providers_missing=("worthless-openai",))
        assert r.healthy is False

    def test_drifted_provider_not_healthy(self) -> None:
        r = OpenclawHealthReport(providers_drifted=(("worthless-openai", "x", "y"),))
        assert r.healthy is False

    def test_unreadable_not_healthy(self) -> None:
        r = OpenclawHealthReport(config_unreadable=True)
        assert r.healthy is False

    def test_empty_report_is_healthy(self) -> None:
        """No expected providers → nothing to check → healthy by definition."""
        r = OpenclawHealthReport()
        assert r.healthy is True
