"""Integration tests for ``start_supervised_proxy`` and default-command proxy phase.

Linear: WOR-717 (supervised default start).
"""

from __future__ import annotations

from importlib.metadata import version as pkg_version

import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service._common import ServiceState
from worthless.cli.commands.service.proxy_state import ProxyRuntimeState
from worthless.cli.commands.up import start_daemon, start_supervised_proxy
from worthless.cli.default_command import _ensure_proxy_running


class TestStartSupervisedProxyIntegration:
    """``start_supervised_proxy`` spawns detached ``worthless up``, not ``start_daemon``."""

    def test_spawns_detached_worthless_up_with_home_and_port(
        self,
        home_with_key: WorthlessHome,
        tmp_path,
    ) -> None:
        captured: dict = {}

        def fake_popen(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs
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
            console = MagicMock()
            log_file = home_with_key.base_dir / "proxy.log"
            pid = start_supervised_proxy(home_with_key, 8787, log_file, console)

        # worthless-l0s1: this interpreter's worthless, never whichever is on PATH.
        assert captured["cmd"] == [sys.executable, "-m", "worthless", "up", "--port", "8787"]
        assert captured["kwargs"]["start_new_session"] is True
        assert captured["kwargs"]["env"]["WORTHLESS_HOME"] == str(home_with_key.base_dir)
        assert captured["kwargs"]["env"]["WORTHLESS_PORT"] == "8787"
        assert pid == 4242

    def test_never_invokes_start_daemon(
        self,
        home_with_key: WorthlessHome,
        tmp_path,
    ) -> None:
        daemon_called = False

        def fake_daemon(*args, **kwargs):
            nonlocal daemon_called
            daemon_called = True
            return 1

        def fake_popen(cmd, **kwargs):
            return MagicMock(pid=1)

        binary = tmp_path / "worthless-bin"
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        binary.chmod(0o755)

        with (
            patch("worthless.cli.commands.up.subprocess.Popen", fake_popen),
            patch(
                "worthless.cli.commands.service._common.resolve_worthless_binary",
                return_value=binary,
            ),
            patch("worthless.cli.commands.up.start_daemon", fake_daemon),
            patch("worthless.cli.commands.up.poll_health_pid", return_value=42),
            patch("worthless.cli.commands.up.os.open", return_value=3),
            patch("worthless.cli.commands.up.os.close"),
        ):
            start_supervised_proxy(
                home_with_key,
                8787,
                home_with_key.base_dir / "proxy.log",
                MagicMock(),
            )

        assert not daemon_called
        assert start_daemon is not None  # legacy escape hatch remains importable


class TestDefaultProxyPhaseIntegration:
    """Default command proxy phase must respect unified runtime detection."""

    @pytest.mark.integration
    def test_skips_supervised_start_when_service_reports_healthy(
        self,
        home_with_key: WorthlessHome,
    ) -> None:
        supervised_called = False

        def fake_supervised(*args, **kwargs):
            nonlocal supervised_called
            supervised_called = True
            return 1

        runtime = ProxyRuntimeState(
            running=True,
            pid=None,
            port=8787,
            source="service",
            service_state=ServiceState.RUNNING,
        )

        with (
            patch(
                "worthless.cli.default_command.detect_proxy_runtime",
                return_value=runtime,
            ),
            patch(
                "worthless.cli.default_command.start_supervised_proxy",
                fake_supervised,
            ),
        ):
            running, _pid, port = _ensure_proxy_running(home_with_key, MagicMock())

        assert running is True
        assert port == 8787
        assert not supervised_called


class TestServiceManagedLockIdempotency:
    """Lock + service-managed proxy: repeat ``--yes`` must not double-enroll."""

    def test_second_yes_with_service_proxy_skips_supervised_start(
        self,
        home_with_key,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from typer.testing import CliRunner

        from tests.helpers import fake_openai_key
        from tests.user_flows.helpers import scrubbed_cli_env
        from worthless.cli.app import app
        from tests.cli.conftest import list_enrollments

        project = tmp_path / "project"
        project.mkdir()
        env_file = project / ".env"
        env_file.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
        monkeypatch.chdir(project)

        runner = CliRunner()
        env = scrubbed_cli_env(home_with_key.base_dir)

        supervised_calls: list[int] = []
        proxy_checks = {"count": 0}

        def fake_supervised(*_a, **_kw) -> int:
            supervised_calls.append(1)
            return 4242

        def mock_detect_proxy_runtime(
            _home: WorthlessHome, *, port: int | None = None
        ) -> ProxyRuntimeState:
            if proxy_checks["count"] == 0:
                proxy_checks["count"] += 1
                return ProxyRuntimeState(
                    running=False,
                    pid=None,
                    port=8787,
                    source="none",
                )
            return ProxyRuntimeState(
                running=True,
                pid=4242,
                port=8787,
                source="health",
            )

        monkeypatch.setattr(
            "worthless.cli.default_command.detect_proxy_runtime",
            mock_detect_proxy_runtime,
        )
        monkeypatch.setattr(
            "worthless.cli.default_command.start_supervised_proxy",
            fake_supervised,
        )
        monkeypatch.setattr("worthless.cli.default_command.poll_health", lambda *a, **kw: True)

        first = runner.invoke(app, ["--yes"], env=env)
        assert first.exit_code == 0, first.stdout + first.stderr
        first_count = len(list_enrollments(home_with_key))
        assert first_count >= 1
        assert len(supervised_calls) == 1

        second = runner.invoke(app, ["--yes"], env=env)
        combined = second.stdout + second.stderr
        assert second.exit_code == 0, combined
        assert len(supervised_calls) == 1, combined
        assert len(list_enrollments(home_with_key)) == first_count


class TestSupervisedUpSidecarContract:
    """WOR-717 delegates to ``worthless up``, which owns sidecar IPC (see test_up_with_sidecar)."""

    def test_supervised_spawn_argv_is_foreground_up(self, home_with_key, tmp_path) -> None:
        """Regression guard: supervised path must not resurrect daemon/sidecar-less start."""
        captured: dict = {}

        def fake_popen(cmd, **kwargs):
            captured["cmd"] = cmd
            return MagicMock(pid=1)

        binary = tmp_path / "worthless-bin"
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        binary.chmod(0o755)

        with (
            patch("worthless.cli.commands.up.subprocess.Popen", fake_popen),
            patch(
                "worthless.cli.commands.service._common.resolve_worthless_binary",
                return_value=binary,
            ),
            patch("worthless.cli.commands.up.poll_health_pid", return_value=42),
            patch("worthless.cli.commands.up.os.open", return_value=3),
            patch("worthless.cli.commands.up.os.close"),
        ):
            start_supervised_proxy(
                home_with_key,
                8787,
                home_with_key.base_dir / "proxy.log",
                MagicMock(),
            )

        assert captured["cmd"][3:6] == ["up", "--port", "8787"]


class TestTheDefaultCommandStartsItself:
    """worthless-l0s1: plain `worthless` spawned whichever `worthless` was first on
    PATH. A dev run picked up an older install, which answered /healthz 200 on a
    stale key and turned status green — the new code never ran."""

    def test_never_asks_path_which_worthless_to_run(self, home_with_key, tmp_path) -> None:
        captured: dict = {}

        def fake_popen(cmd, **kwargs):
            captured["cmd"] = cmd
            return MagicMock(pid=1)

        with (
            patch("worthless.cli.commands.up.subprocess.Popen", fake_popen),
            patch(
                "worthless.cli.commands.service._common.resolve_worthless_binary",
                side_effect=AssertionError("looked up worthless on PATH"),
            ),
            patch("worthless.cli.commands.up.poll_health_pid", return_value=42),
            patch("worthless.cli.commands.up.os.open", return_value=3),
            patch("worthless.cli.commands.up.os.close"),
        ):
            start_supervised_proxy(
                home_with_key, 8787, home_with_key.base_dir / "proxy.log", MagicMock()
            )
        assert captured["cmd"][:3] == [sys.executable, "-m", "worthless"]

    def test_python_dash_m_worthless_really_runs(self) -> None:
        """The spawn above is only real if `python -m worthless` is an entry point."""
        out = subprocess.run(
            [sys.executable, "-m", "worthless", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert out.returncode == 0, out.stderr
        assert out.stdout.split()[-1] == pkg_version("worthless"), "the child is this install"

    def test_a_worthless_package_in_the_project_cannot_stand_in_for_the_proxy(
        self, home_with_key, tmp_path, monkeypatch
    ) -> None:
        """PR #767 security review: `python -m` puts the cwd first on sys.path, and
        plain `worthless` runs in the user's project. A cloned repo with its own
        `worthless/` package would run as the proxy, with WORTHLESS_HOME in hand.
        Run the exact spawn (argv + cwd) with --version and see who answers."""
        project = tmp_path / "cloned-repo"
        (project / "worthless").mkdir(parents=True)
        (project / "worthless" / "__init__.py").write_text("")
        (project / "worthless" / "__main__.py").write_text("print('HIJACKED')\n")
        monkeypatch.chdir(project)
        captured: dict = {}

        def fake_popen(cmd, **kwargs):
            captured.update(cmd=cmd, cwd=kwargs.get("cwd"))
            return MagicMock(pid=1)

        with (
            patch("worthless.cli.commands.up.subprocess.Popen", fake_popen),
            patch("worthless.cli.commands.up.poll_health_pid", return_value=42),
            patch("worthless.cli.commands.up.os.open", return_value=3),
            patch("worthless.cli.commands.up.os.close"),
        ):
            start_supervised_proxy(
                home_with_key, 8787, home_with_key.base_dir / "proxy.log", MagicMock()
            )
        argv = captured["cmd"][: captured["cmd"].index("worthless") + 1] + ["--version"]
        out = subprocess.run(
            argv, cwd=captured["cwd"], capture_output=True, text=True, timeout=30, check=False
        )
        assert "HIJACKED" not in out.stdout
        assert out.returncode == 0 and "worthless" in out.stdout.lower(), out.stderr
