"""Unit tests for ``worthless verify`` (WOR-517, Phase 4 of the WOR-514 incident).

The contract these pin, from the pre-code expert review:

* GREEN is earned ONLY by a live bind-probe delta this instant — never by a
  cumulative counter. A healthy proxy whose probe counter does NOT move is RED
  (the silent-bypass class Ido hit).
* Proxy DOWN is the loud case: RED, non-zero exit, "exposed right now" framing,
  and a recovery hint that matches how the proxy is managed.
* verify's GREEN says the proxy is live and routing; it must SAY it does not
  prove OpenClaw isn't also bypassing on a cached token (the honesty line).

Collaborators are mocked at the ``verify`` module boundary so these stay
deterministic and CI-able (no proxy, no docker).
"""

from __future__ import annotations

import json
from unittest.mock import patch

from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.commands.service._common import ServiceState
from worthless.cli.commands.service.proxy_state import ProxyRuntimeState

runner = CliRunner(mix_stderr=False)


def _runtime(*, running: bool, service_state: ServiceState | None = None, port: int = 8787):
    return ProxyRuntimeState(
        running=running,
        pid=None,
        port=port,
        source="service" if service_state is not None else "health",
        service_state=service_state,
    )


def _invoke(args, *, runtime, confirm=None, aliases=("anthropic",)):
    """Invoke ``verify`` with the three collaborators mocked."""
    keys = [{"alias": a, "provider": "anthropic", "status": "PROTECTED"} for a in aliases]
    with (
        patch("worthless.cli.commands.verify._resolve_home_for_status", return_value=object()),
        patch("worthless.cli.commands.verify.detect_proxy_runtime", return_value=runtime),
        patch("worthless.cli.commands.verify._list_enrolled_keys", return_value=keys),
        patch("worthless.cli.commands.verify._confirm_bind_aliases", return_value=confirm),
    ):
        return runner.invoke(app, args)


# --------------------------------------------------------------------------
# Proxy DOWN — the Ido headline case
# --------------------------------------------------------------------------


def test_down_not_installed_is_red_and_points_at_install():
    result = _invoke(["verify"], runtime=_runtime(running=False, service_state=None))
    assert result.exit_code != 0, result.stdout + result.stderr
    out = (result.stdout + result.stderr).lower()
    assert "down" in out
    assert "in the clear right now" in out
    # Not service-managed → nudge to install (autostart) / up.
    assert "service install" in out or "worthless up" in out


def test_down_service_managed_points_at_restart():
    result = _invoke(
        ["verify"],
        runtime=_runtime(running=False, service_state=ServiceState.STOPPED),
    )
    assert result.exit_code != 0
    out = (result.stdout + result.stderr).lower()
    assert "service restart" in out


# --------------------------------------------------------------------------
# Up but nothing locked — YELLOW, not an error
# --------------------------------------------------------------------------


def test_up_no_aliases_is_yellow():
    result = _invoke(["verify"], runtime=_runtime(running=True), aliases=())
    out = (result.stdout + result.stderr).lower()
    assert "lock" in out  # nudge to `worthless lock`
    assert result.exit_code == 0


# --------------------------------------------------------------------------
# The honest core — a live delta earns GREEN
# --------------------------------------------------------------------------


def test_live_delta_is_green_with_honesty_line():
    confirm = {"status": "pass", "delta": 1, "aliases": ["anthropic"], "reached": 1}
    result = _invoke(["verify"], runtime=_runtime(running=True), confirm=confirm)
    assert result.exit_code == 0, result.stdout + result.stderr
    out = result.stdout + result.stderr
    assert "GREEN" in out or "green" in out.lower()
    # The mandatory honesty line — GREEN must not overclaim.
    assert "does not prove" in out.lower() or "does NOT prove" in out


def test_healthy_but_zero_delta_is_red():
    """Silent-bypass class: proxy answered the probe but did NOT count it."""
    confirm = {"status": "fail", "delta": 0, "aliases": ["anthropic"], "reached": 1}
    result = _invoke(["verify"], runtime=_runtime(running=True), confirm=confirm)
    assert result.exit_code != 0, result.stdout + result.stderr
    assert "red" in (result.stdout + result.stderr).lower()


def test_squatter_is_red():
    confirm = {
        "status": "skipped",
        "reason": "proxy_unrecognised",
        "delta": 0,
        "aliases": ["anthropic"],
        "reached": 0,
    }
    result = _invoke(["verify"], runtime=_runtime(running=True), confirm=confirm)
    assert result.exit_code != 0
    assert "red" in (result.stdout + result.stderr).lower()


def test_unreachable_probe_is_red():
    confirm = {
        "status": "skipped",
        "reason": "synthetic_unreachable",
        "delta": 0,
        "aliases": ["anthropic"],
        "reached": 0,
    }
    result = _invoke(["verify"], runtime=_runtime(running=True), confirm=confirm)
    assert result.exit_code != 0
    assert "red" in (result.stdout + result.stderr).lower()


# --------------------------------------------------------------------------
# JSON shape
# --------------------------------------------------------------------------


def test_json_shape_green():
    confirm = {"status": "pass", "delta": 1, "aliases": ["anthropic"], "reached": 1}
    result = _invoke(["verify", "--json"], runtime=_runtime(running=True), confirm=confirm)
    payload = json.loads(result.stdout)
    assert payload["verdict"] == "green"
    assert payload["healthy"] is True
    assert payload["aliases"] == [{"alias": "anthropic", "routed": True}]


def test_json_shape_down():
    result = _invoke(["verify", "--json"], runtime=_runtime(running=False, service_state=None))
    payload = json.loads(result.stdout)
    assert payload["verdict"] == "red"
    assert payload["healthy"] is False
    assert payload["reason"] == "proxy_down"
