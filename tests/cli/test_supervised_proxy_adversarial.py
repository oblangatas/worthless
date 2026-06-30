"""Adversarial and stress tests for supervised proxy start and service detection.

Covers wave-3 gauntlet failures, STRESS_TEST_MATRIX proxy rows, and W3-ADV backlog
items on the integration lane (not full mutator guards). Linear: WOR-717 / WOR-723.
"""

from __future__ import annotations

import concurrent.futures
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from hypothesis import HealthCheck, assume, given, settings, strategies as st

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service import launchd, systemd, templates
from worthless.cli.commands.service._common import (
    ServiceState,
    ServiceStatus,
    unit_file_matches_home,
)
from worthless.cli.commands.service.proxy_state import ProxyRuntimeState, detect_proxy_runtime
from worthless.cli.commands.up import start_supervised_proxy
from worthless.cli.default_command import _ensure_proxy_running
from worthless.cli.errors import WorthlessError

from tests.fixtures.dirty_home import make_bootstrapped_home
from tests.helpers import fake_openai_key


@pytest.fixture()
def home(tmp_path: Path) -> WorthlessHome:
    return make_bootstrapped_home(tmp_path / ".worthless")


@pytest.mark.adversarial
class TestUnitFileMatchesHomeAdversarial:
    """``unit_file_matches_home`` must not trust substring accidents or foreign homes."""

    def test_rejects_foreign_home_plist(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = tmp_path / "dev.worthless.proxy.plist"
        plist.write_text(
            templates.render_launchd_plist(
                binary="/usr/local/bin/worthless",
                worthless_home=str(tmp_path / "other-home"),
                log_path=str(tmp_path / "other-home" / "proxy.log"),
            )
        )
        assert unit_file_matches_home(plist, home) is False

    def test_rejects_plist_that_only_mentions_home_in_unrelated_field(
        self, home: WorthlessHome, tmp_path: Path
    ) -> None:
        """A comment-like string must not satisfy ownership without WORTHLESS_HOME key."""
        plist = tmp_path / "dev.worthless.proxy.plist"
        plist.write_text(
            "<!-- WORTHLESS_HOME="
            + str(home.base_dir)
            + " -->\n"
            + templates.render_launchd_plist(
                binary="/usr/local/bin/worthless",
                worthless_home=str(tmp_path / "decoy-home"),
                log_path=str(tmp_path / "decoy-home" / "proxy.log"),
            )
        )
        assert unit_file_matches_home(plist, home) is False

    def test_accepts_symlinked_install_path(self, tmp_path: Path) -> None:
        real_home = tmp_path / "real-home"
        real_home.mkdir()
        link_home = tmp_path / "link-home"
        link_home.symlink_to(real_home, target_is_directory=True)
        home = WorthlessHome(base_dir=link_home)

        unit = tmp_path / "worthless-proxy.service"
        unit.write_text(
            templates.render_systemd_unit(
                binary="/usr/local/bin/worthless",
                worthless_home=str(link_home),
            )
        )
        assert unit_file_matches_home(unit, home) is True

    def test_rejects_missing_unit_file(self, home: WorthlessHome, tmp_path: Path) -> None:
        assert unit_file_matches_home(tmp_path / "missing.plist", home) is False

    def test_rejects_empty_unit_file(self, home: WorthlessHome, tmp_path: Path) -> None:
        empty = tmp_path / "empty.service"
        empty.write_text("")
        assert unit_file_matches_home(empty, home) is False

    @given(st.text(min_size=0, max_size=200))
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_random_text_without_embedded_home_is_not_owned(
        self, home: WorthlessHome, tmp_path: Path, noise: str
    ) -> None:
        assume(str(home.base_dir) not in noise)
        assume(str(home.base_dir.resolve()) not in noise)
        blob = tmp_path / "noise.service"
        blob.write_text(noise)
        assert unit_file_matches_home(blob, home) is False

    def test_concurrent_reads_do_not_crash(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = tmp_path / "dev.worthless.proxy.plist"
        plist.write_text(
            templates.render_launchd_plist(
                binary="/usr/local/bin/worthless",
                worthless_home=str(home.base_dir),
                log_path=str(home.base_dir / "proxy.log"),
            )
        )

        def _check() -> bool:
            return unit_file_matches_home(plist, home)

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: _check(), range(64)))
        assert all(results)


@pytest.mark.adversarial
class TestDetectProxyRuntimeAdversarial:
    """Ordering and stale-state behavior for unified runtime detection."""

    def test_stale_pidfile_removed_when_process_dead(
        self, home: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from worthless.cli.process import pid_path, write_pid

        pf = pid_path(home)
        write_pid(pf, 999999, 8787)
        monkeypatch.setattr(
            "worthless.cli.commands.service.proxy_state.check_pid",
            lambda pid: False,
        )
        monkeypatch.setattr(
            "worthless.cli.commands.service.proxy_state.poll_health",
            lambda port, timeout=1.0: False,
        )
        monkeypatch.setattr(
            "worthless.cli.commands.service.proxy_state.current_platform_backend_name",
            lambda: "launchd",
        )
        monkeypatch.setattr(
            launchd,
            "detect_status",
            lambda h, p: ServiceStatus(
                state=ServiceState.NOT_INSTALLED,
                unit_path=None,
                binary=None,
                port=p,
                healthy=False,
            ),
        )

        state = detect_proxy_runtime(home)
        assert state.running is False
        assert not pf.exists()

    def test_health_probe_wins_when_no_pidfile(
        self, home: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Foreign listener on configured port: treated as running (spawn skipped)."""
        monkeypatch.setattr(
            "worthless.cli.commands.service.proxy_state.poll_health",
            lambda port, timeout=1.0: True,
        )
        state = detect_proxy_runtime(home)
        assert state.running is True
        assert state.source == "health"

        supervised_calls: list[int] = []
        runtime = ProxyRuntimeState(
            running=True,
            pid=None,
            port=state.port,
            source="health",
        )

        with (
            patch(
                "worthless.cli.default_command.detect_proxy_runtime",
                return_value=runtime,
            ),
            patch(
                "worthless.cli.default_command.start_supervised_proxy",
                side_effect=lambda *a, **k: supervised_calls.append(1) or 1,
            ),
        ):
            running, _pid, port = _ensure_proxy_running(home, MagicMock())

        assert running is True
        assert port == state.port
        assert not supervised_calls

    def test_service_stopped_does_not_report_running(
        self, home: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "worthless.cli.commands.service.proxy_state.poll_health",
            lambda port, timeout=1.0: False,
        )
        monkeypatch.setattr(
            "worthless.cli.commands.service.proxy_state.current_platform_backend_name",
            lambda: "systemd",
        )

        def _stopped(h: WorthlessHome, port: int) -> ServiceStatus:
            return ServiceStatus(
                state=ServiceState.STOPPED,
                unit_path=tmp_path / "worthless-proxy.service",
                binary="/usr/bin/worthless",
                port=port,
                healthy=False,
            )

        monkeypatch.setattr(systemd, "detect_status", _stopped)
        state = detect_proxy_runtime(home)
        assert state.running is False
        assert state.service_state == ServiceState.STOPPED


@pytest.mark.adversarial
class TestStartSupervisedProxyAdversarial:
    """Spawn failure hygiene and env inheritance (scrub gap anchor for #292)."""

    def test_popen_failure_does_not_leak_exception_secrets_in_console(
        self, home: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = fake_openai_key()
        errors: list[str] = []

        class FakeConsole:
            def print_error(self, err: WorthlessError) -> None:
                errors.append(str(err))

        def boom(*args, **kwargs):
            raise OSError(f"spawn failed with {secret}")

        binary = tmp_path / "worthless-bin"
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        binary.chmod(0o755)

        with (
            patch("worthless.cli.commands.up.subprocess.Popen", boom),
            patch(
                "worthless.cli.commands.service._common.resolve_worthless_binary",
                return_value=binary,
            ),
            pytest.raises(typer.Exit),
        ):
            start_supervised_proxy(
                home,
                8787,
                home.base_dir / "proxy.log",
                FakeConsole(),
            )

        combined = " ".join(errors)
        assert secret not in combined
        assert "spawn failed" not in combined.lower() or secret not in combined

    def test_supervised_spawn_inherits_parent_provider_env_documented_gap(
        self, home: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Anchor: full ``os.environ.copy()`` forwards provider keys until #292 scrubs."""
        provider_key = fake_openai_key()
        monkeypatch.setenv("OPENAI_API_KEY", provider_key)
        captured: dict = {}

        def fake_popen(cmd, **kwargs):
            captured["env"] = dict(kwargs["env"])
            return MagicMock(pid=99999)

        binary = tmp_path / "worthless-bin"
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        binary.chmod(0o755)

        with (
            patch("worthless.cli.commands.up.subprocess.Popen", fake_popen),
            patch(
                "worthless.cli.commands.service._common.resolve_worthless_binary",
                return_value=binary,
            ),
            patch("worthless.cli.commands.up.poll_health_pid", return_value=4242),
            patch("worthless.cli.commands.up.os.open", return_value=3),
            patch("worthless.cli.commands.up.os.close"),
        ):
            start_supervised_proxy(home, 8787, home.base_dir / "proxy.log", MagicMock())

        assert captured["env"]["WORTHLESS_HOME"] == str(home.base_dir)
        assert captured["env"]["OPENAI_API_KEY"] == provider_key  # flip when scrub lands


@pytest.mark.adversarial
class TestDefaultCommandStress:
    """Chaos-lite: rapid phase-2 calls must not double-spawn under mocked runtime."""

    def test_ensure_proxy_running_skips_spawn_when_health_reports_running(
        self, home: WorthlessHome
    ) -> None:
        """Regression: health source must short-circuit before start_supervised_proxy."""
        runtime = ProxyRuntimeState(
            running=True,
            pid=None,
            port=8787,
            source="health",
        )
        supervised_calls: list[int] = []

        with (
            patch(
                "worthless.cli.default_command.detect_proxy_runtime",
                return_value=runtime,
            ),
            patch(
                "worthless.cli.default_command.start_supervised_proxy",
                side_effect=lambda *a, **k: supervised_calls.append(1) or 1,
            ),
        ):
            running, pid, port = _ensure_proxy_running(home, MagicMock())

        assert running is True
        assert pid is None
        assert port == 8787
        assert not supervised_calls

    def test_ensure_proxy_running_exits_2_when_service_stopped(self, home: WorthlessHome) -> None:
        runtime = ProxyRuntimeState(
            running=False,
            pid=None,
            port=8787,
            source="service",
            service_state=ServiceState.STOPPED,
        )

        with (
            patch(
                "worthless.cli.default_command.detect_proxy_runtime",
                return_value=runtime,
            ),
            patch("worthless.cli.default_command.start_supervised_proxy") as mock_spawn,
            pytest.raises(typer.Exit) as exc_info,
        ):
            _ensure_proxy_running(home, MagicMock())

        assert exc_info.value.exit_code == 2
        mock_spawn.assert_not_called()

    def test_rapid_ensure_proxy_running_idempotent(
        self, home: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runtime = ProxyRuntimeState(
            running=True,
            pid=4242,
            port=8787,
            source="service",
            service_state=ServiceState.RUNNING,
        )
        spawn_count = 0

        def fake_supervised(*_a, **_k):
            nonlocal spawn_count
            spawn_count += 1
            return 4242

        monkeypatch.setattr(
            "worthless.cli.default_command.detect_proxy_runtime",
            lambda home: runtime,
        )
        monkeypatch.setattr(
            "worthless.cli.default_command.start_supervised_proxy",
            fake_supervised,
        )

        for _ in range(32):
            running, _pid, port = _ensure_proxy_running(home, MagicMock())
            assert running is True
            assert port == 8787

        assert spawn_count == 0
