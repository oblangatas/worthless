"""WOR-860: `status`, `verify` and the editor say whether protection survives a restart.

Before this, `worthless status` printed "🟢 You're protected" for a proxy started
by `worthless up` or plain `worthless`: true now, false after the next restart,
and nothing said so. Decision (WOR-860, option C): `status` and `verify` both
say it, from ONE function, so the two can't drift; the editor (MCP) gets the
same headline as `status` (WOR-820: one true answer on every surface).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.commands import status as status_mod
from worthless.cli.commands import verify as verify_mod
from worthless.cli.commands.service import proxy_state
from worthless.cli.commands.service._common import ServiceState, ServiceStatus

KEYS = [{"alias": "openai-1", "provider": "openai", "status": "PROTECTED"}]


def _note(*, survives: bool, backend: str = "launchd", wsl: bool = False) -> str:
    with (
        patch.object(proxy_state, "current_platform_backend_name", return_value=backend),
        patch.object(proxy_state, "is_wsl", return_value=wsl),
    ):
        return proxy_state.restart_note(survives)


class TestTheNoteItself:
    def test_without_a_service_it_says_not_after_a_restart_and_names_the_fix(self) -> None:
        note = _note(survives=False)
        assert "not after a restart" in note.lower()
        assert "worthless service install" in note

    def test_it_never_claims_the_terminal_kills_it(self) -> None:
        """Plain `worthless` starts a DETACHED proxy that outlives the terminal;
        only a restart is certain to end it, so only a restart is claimed."""
        assert "terminal" not in _note(survives=False).lower()

    @pytest.mark.parametrize(
        ("backend", "wsl", "phrase"),
        [
            ("launchd", False, "starts when you log in"),
            ("systemd", False, "starts when this computer starts"),
            ("systemd", True, "starts with this WSL distro"),
        ],
    )
    def test_with_a_service_it_says_when_it_starts_per_platform(
        self, backend: str, wsl: bool, phrase: str
    ) -> None:
        note = _note(survives=True, backend=backend, wsl=wsl)
        assert phrase in note
        assert "not after a restart" not in note.lower()

    def test_wsl_is_warned_that_it_still_stops_without_wslconfig(self) -> None:
        note = _note(survives=True, backend="systemd", wsl=True)
        assert "15 seconds" in note
        assert "instanceIdleTimeout=-1" in note

    def test_wsl_without_a_service_is_told_the_window_matters(self) -> None:
        """On WSL the distro stops ~15 s after the last WSL window closes, so for
        a non-service proxy, closing the window does end it."""
        note = _note(survives=False, backend="systemd", wsl=True)
        assert "last WSL window closes" in note
        assert "worthless service install" in note

    def test_linux_is_not_told_login(self) -> None:
        """systemd + lingering starts at boot, not at login."""
        assert "log in" not in _note(survives=True, backend="systemd", wsl=False)


class TestSurvivesRestart:
    @pytest.mark.parametrize(
        ("state", "expected"),
        [
            (ServiceState.RUNNING, True),
            (ServiceState.NOT_INSTALLED, False),
            (ServiceState.STOPPED, False),
            (ServiceState.FAILED, False),
        ],
    )
    def test_only_a_running_service_counts(self, state: ServiceState, expected: bool) -> None:
        st = ServiceStatus(state=state, unit_path=None, binary=None, port=8787, healthy=True)
        with (
            patch.object(proxy_state, "_service_port", return_value=8787),
            patch.object(proxy_state, "_detect_service_status", return_value=st),
        ):
            assert proxy_state.survives_restart(object(), 8787) is expected

    def test_no_service_backend_means_no(self) -> None:
        with (
            patch.object(proxy_state, "_service_port", return_value=8787),
            patch.object(proxy_state, "_detect_service_status", return_value=None),
        ):
            assert proxy_state.survives_restart(object(), 8787) is False

    def test_a_proxy_on_another_port_does_not_borrow_the_services_answer(self) -> None:
        """Service on 8787, user also runs `worthless up --port 9000`: only 8787
        comes back after a restart, so 9000 must not be promised survival."""
        running = ServiceStatus(
            state=ServiceState.RUNNING, unit_path=None, binary=None, port=9000, healthy=True
        )
        with (
            patch.object(proxy_state, "_service_port", return_value=8787),
            patch.object(proxy_state, "_detect_service_status", return_value=running),
        ):
            assert proxy_state.survives_restart(object(), 9000) is False

    @pytest.mark.parametrize(
        "error",
        [FileNotFoundError("systemctl"), PermissionError("launchctl"), ValueError("bad plist")],
        ids=["no-systemctl", "no-permission", "corrupt-unit"],
    )
    def test_a_broken_service_tool_means_no_not_a_crash(self, error: Exception) -> None:
        """status ran no subprocess before; now it asks launchctl/systemctl. A
        container or WSL without systemd must still get an answer."""
        backend = MagicMock()
        backend.installed_port.return_value = None
        backend.detect_status.side_effect = error
        with patch.object(proxy_state, "_backend", return_value=backend):
            assert proxy_state.survives_restart(object(), 8787) is False


class TestStatusSaysIt:
    def test_green_without_a_service_carries_the_note(self) -> None:
        verdict, header = status_mod._status_verdict(
            KEYS, True, False, True, survives_restart=False
        )
        assert verdict == "protected"
        assert header.startswith("🟢 You're protected now")
        assert _note(survives=False) in header

    def test_green_with_a_service_carries_the_service_note(self) -> None:
        with (
            patch.object(proxy_state, "current_platform_backend_name", return_value="launchd"),
            patch.object(proxy_state, "is_wsl", return_value=False),
        ):
            _, header = status_mod._status_verdict(KEYS, True, False, True, survives_restart=True)
        assert "starts when you log in" in header
        assert "not after a restart" not in header.lower()

    def test_the_default_is_the_cautious_answer(self) -> None:
        """A caller that doesn't say must not get a promise of survival."""
        _, header = status_mod._status_verdict(KEYS, True, False, True)
        assert "not after a restart" in header.lower()

    def test_non_green_verdicts_are_unchanged(self) -> None:
        verdict, header = status_mod._status_verdict(KEYS, False, False, True)
        assert verdict == "protected_at_rest"
        assert "restart" not in header.lower()

    def test_json_carries_the_fact(self, tmp_path: Path) -> None:
        home = MagicMock(name="WorthlessHome")
        home.base_dir = tmp_path
        with (
            patch.object(status_mod, "_resolve_home_for_status", return_value=home),
            patch.object(status_mod, "_list_enrolled_keys", return_value=KEYS),
            patch.object(status_mod, "_discover_proxy_port", return_value=8787),
            patch.object(
                status_mod,
                "_check_proxy_health",
                return_value={"healthy": True, "port": 8787, "mode": "up", "bind_probe_count": 0},
            ),
            patch.object(status_mod, "read_sentinel", return_value=None),
            patch.object(status_mod, "survives_restart", return_value=True),
        ):
            result = CliRunner().invoke(app, ["status", "--json"])
        assert json.loads(result.stdout)["survives_restart"] is True

    def test_a_squatter_on_the_port_is_never_promised_survival(self, tmp_path: Path) -> None:
        """Healthy but not identified as worthless: never `survives_restart: true`."""
        home = MagicMock(name="WorthlessHome")
        home.base_dir = tmp_path
        with (
            patch.object(status_mod, "_resolve_home_for_status", return_value=home),
            patch.object(status_mod, "_list_enrolled_keys", return_value=KEYS),
            patch.object(status_mod, "_discover_proxy_port", return_value=8787),
            patch.object(
                status_mod,
                "_check_proxy_health",
                return_value={"healthy": True, "port": 8787, "mode": "up"},
            ),
            patch.object(status_mod, "read_sentinel", return_value=None),
            patch.object(status_mod, "survives_restart", return_value=True),
        ):
            result = CliRunner().invoke(app, ["status", "--json"])
        payload = json.loads(result.stdout)
        assert payload["verdict"] == "proxy_unrecognised"
        assert payload["survives_restart"] is False


class TestVerifySaysTheSameThing:
    def test_green_prints_the_identical_note(self, capsys: pytest.CaptureFixture[str]) -> None:
        v = {
            "verdict": "green",
            "reason": "routed",
            "healthy": True,
            "aliases": [{"alias": "openai-1", "routed": True}],
            "service_managed": False,
            "survives_restart": False,
        }
        verify_mod._print_human(v)
        assert _note(survives=False) in capsys.readouterr().err

    @pytest.mark.parametrize(("survives", "lead"), [(False, "GREEN now —"), (True, "GREEN —")])
    def test_green_says_now_when_a_restart_ends_it(
        self, capsys: pytest.CaptureFixture[str], survives: bool, lead: str
    ) -> None:
        v = {
            "verdict": "green",
            "reason": "routed",
            "healthy": True,
            "aliases": [{"alias": "openai-1", "routed": True}],
            "service_managed": survives,
            "survives_restart": survives,
        }
        verify_mod._print_human(v)
        assert capsys.readouterr().err.startswith(lead)

    @pytest.mark.parametrize(
        ("probe", "survives", "expected"),
        [("pass", True, True), ("pass", False, False), ("fail", True, False)],
        ids=["routed+service", "routed-no-service", "not-routed"],
    )
    def test_evaluate_reports_survival_only_for_a_proxy_that_routed(
        self, probe: str, survives: bool, expected: bool
    ) -> None:
        """Real `_evaluate`: a proxy that failed the routing probe isn't proven
        ours, so it is never promised survival."""
        state = proxy_state.ProxyRuntimeState(
            running=True, pid=None, port=8787, source="service", service_state=None
        )
        with (
            patch.object(verify_mod, "detect_proxy_runtime", return_value=state),
            patch.object(verify_mod, "_list_enrolled_keys", return_value=KEYS),
            patch.object(verify_mod, "_confirm_bind_aliases", return_value={"status": probe}),
            patch.object(verify_mod, "survives_restart", return_value=survives),
        ):
            v = verify_mod._evaluate(MagicMock(name="WorthlessHome"))
        assert v["survives_restart"] is expected

    def test_json_carries_the_fact(self) -> None:
        v = {
            "verdict": "green",
            "reason": "routed",
            "healthy": True,
            "aliases": [],
            "service_managed": True,
            "survives_restart": True,
        }
        with patch.object(verify_mod, "_evaluate", return_value=v):
            result = CliRunner().invoke(app, ["verify", "--json"])
        assert json.loads(result.stdout)["survives_restart"] is True
