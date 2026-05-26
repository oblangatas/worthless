"""Tests for process lifecycle module — pipe death detection, PID files, signal forwarding."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from tests._fakes import WOR309_SUBPROCESS_FOLLOWUP


class TestCreateLivenessPipe:
    """Test create_liveness_pipe returns two valid fds."""

    def test_returns_two_fds(self):
        from worthless.cli.process import create_liveness_pipe

        read_fd, write_fd = create_liveness_pipe()
        try:
            # Both should be valid file descriptors
            os.fstat(read_fd)
            os.fstat(write_fd)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_write_end_eof_on_close(self):
        from worthless.cli.process import create_liveness_pipe

        read_fd, write_fd = create_liveness_pipe()
        os.close(write_fd)
        # Reading from read_fd should get EOF (empty bytes)
        data = os.read(read_fd, 1)
        assert data == b""
        os.close(read_fd)


class TestPidFiles:
    """Test write_pid, read_pid, check_pid, cleanup_stale_pid."""

    def test_write_read_roundtrip(self, tmp_path: Path):
        from worthless.cli.process import read_pid, write_pid

        pid_path = tmp_path / "proxy.pid"
        write_pid(pid_path, 12345, 8787)
        result = read_pid(pid_path)
        assert result == (12345, 8787)

    def test_concurrent_write_pid_does_not_clobber_tmp(self, tmp_path: Path):
        """Two concurrent writers must not race on a shared tmp file.

        Before the fix, every call used ``proxy.pid.tmp`` — two threads
        calling ``write_pid`` simultaneously could leave the final
        ``proxy.pid`` with a mangled body or even a bare ``proxy.pid.tmp``
        dangling in the directory. Unique per-caller tmp names close the
        gap; the final pidfile always parses to one of the two writes.
        """
        import threading

        from worthless.cli.process import read_pid, write_pid

        pid_path = tmp_path / "proxy.pid"
        errors: list[BaseException] = []

        def _write(pid: int) -> None:
            try:
                for _ in range(20):
                    write_pid(pid_path, pid, 8787)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        t1 = threading.Thread(target=_write, args=(11111,))
        t2 = threading.Thread(target=_write, args=(22222,))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert not errors, f"concurrent writes raised: {errors!r}"
        info = read_pid(pid_path)
        assert info is not None, "pidfile unreadable — torn or missing"
        assert info == (11111, 8787) or info == (22222, 8787), (
            f"pidfile content is not from either writer: {info!r}"
        )
        # No dangling shared tmp file.
        leftovers = [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
        assert not leftovers, f"tmp files leaked: {leftovers}"

    def test_read_missing_file(self, tmp_path: Path):
        from worthless.cli.process import read_pid

        pid_path = tmp_path / "nonexistent.pid"
        assert read_pid(pid_path) is None

    def test_read_corrupt_file(self, tmp_path: Path):
        from worthless.cli.process import read_pid

        pid_path = tmp_path / "corrupt.pid"
        pid_path.write_text("garbage")
        assert read_pid(pid_path) is None

    def test_check_pid_current_process(self):
        from worthless.cli.process import check_pid

        assert check_pid(os.getpid()) is True

    def test_check_pid_nonexistent(self):
        from worthless.cli.process import check_pid

        # PID 99999999 almost certainly doesn't exist
        assert check_pid(99999999) is False

    def test_cleanup_stale_pid_dead_process(self, tmp_path: Path):
        from worthless.cli.process import cleanup_stale_pid, write_pid

        pid_path = tmp_path / "proxy.pid"
        # Use a PID that doesn't exist
        write_pid(pid_path, 99999999, 8787)
        assert cleanup_stale_pid(pid_path) is True
        assert not pid_path.exists()

    def test_cleanup_stale_pid_live_process(self, tmp_path: Path):
        from worthless.cli.process import cleanup_stale_pid, write_pid

        pid_path = tmp_path / "proxy.pid"
        write_pid(pid_path, os.getpid(), 8787)
        assert cleanup_stale_pid(pid_path) is False
        assert pid_path.exists()

    def test_cleanup_stale_pid_missing_file(self, tmp_path: Path):
        from worthless.cli.process import cleanup_stale_pid

        pid_path = tmp_path / "nonexistent.pid"
        assert cleanup_stale_pid(pid_path) is True


class TestDisableCoreDumps:
    """Test disable_core_dumps doesn't raise."""

    def test_no_exception(self):
        from worthless.cli.process import disable_core_dumps

        # Should not raise on any platform
        disable_core_dumps()


class TestForwardSignals:
    """Test signal handler registration (not full signal delivery)."""

    def test_registers_handlers(self):
        from worthless.cli.process import forward_signals

        # Create mock processes
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            old_int = signal.getsignal(signal.SIGINT)
            old_term = signal.getsignal(signal.SIGTERM)

            forward_signals(proxy=proc, child=None)

            # Handlers should have changed
            new_int = signal.getsignal(signal.SIGINT)
            new_term = signal.getsignal(signal.SIGTERM)
            assert new_int != old_int or new_term != old_term
        finally:
            proc.terminate()
            proc.wait()
            # Restore default handlers
            signal.signal(signal.SIGINT, signal.default_int_handler)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)


@pytest.mark.integration
@pytest.mark.real_ipc
@pytest.mark.timeout(30)
@pytest.mark.skip(reason=WOR309_SUBPROCESS_FOLLOWUP)
class TestSpawnProxyIntegration:
    """Integration test: spawn real proxy and check health."""

    def test_spawn_and_health(self, tmp_path: Path):
        """Spawn proxy on random port, poll health, shut down."""
        from worthless.cli.process import poll_health, spawn_proxy

        # Set up minimal WorthlessHome
        from worthless.cli.bootstrap import ensure_home

        home = ensure_home(tmp_path / ".worthless")

        env = {
            "WORTHLESS_DB_PATH": str(home.db_path),
            "WORTHLESS_FERNET_KEY": home.fernet_key.decode(),
            "WORTHLESS_ALLOW_INSECURE": "true",
        }

        proc, port = spawn_proxy(env, port=0)
        try:
            assert port > 0
            assert proc.poll() is None  # Still running

            healthy = poll_health(port, timeout=15.0)
            assert healthy is True
        finally:
            proc.terminate()
            proc.wait(timeout=5)


class TestProxyCmdShape:
    """``proxy_cmd`` must stay a single-process uvicorn launch.

    Tripwire for the PID-authority assumption in ``poll_health_pid``:
    ``os.getpid()`` inside the ``/healthz`` handler equals the process
    bound to the port *only* when uvicorn runs as a single process. With
    ``--reload`` (supervisor above uvicorn) or ``--workers N>1`` (pool
    of accepting processes) the listening PID is not necessarily the
    one answering ``/healthz`` — the authority logic would need
    revisiting.
    """

    def test_proxy_cmd_has_no_workers_or_reload_flags(self):
        from worthless.cli.process import proxy_cmd

        cmd = proxy_cmd(port=0)
        forbidden = {
            "--workers",
            "--reload",
            "--reload-dir",
            "--reload-include",
            "--reload-exclude",
            "--reload-delay",
        }
        present = forbidden.intersection(cmd)
        assert not present, (
            f"proxy_cmd now includes {sorted(present)} — these break the "
            "single-process assumption poll_health_pid relies on. Revisit "
            "the PID-authority logic before shipping."
        )

    def test_proxy_cmd_passes_host_to_uvicorn(self):
        """proxy_cmd must forward its host arg to uvicorn --host.

        The host is now an explicit parameter — callers derive it from
        build_proxy_env()["WORTHLESS_HOST"] so the env dict is the
        single source of truth.
        """
        from worthless.cli.process import proxy_cmd

        cmd = proxy_cmd(port=8787, host="0.0.0.0")  # noqa: S104
        host_idx = cmd.index("--host")
        assert cmd[host_idx + 1] == "0.0.0.0"  # noqa: S104

    def test_proxy_cmd_defaults_to_loopback(self):
        """Default host arg is loopback-safe."""
        from worthless.cli.process import proxy_cmd

        cmd = proxy_cmd(port=8787)
        host_idx = cmd.index("--host")
        assert cmd[host_idx + 1] == "127.0.0.1"

    def test_build_proxy_env_sets_worthless_host_for_lan(self, monkeypatch, tmp_path):
        """build_proxy_env must populate WORTHLESS_HOST for LAN mode.

        Regression guard: previously WORTHLESS_HOST was never written into the
        env dict — it only reached the child via os.environ bleed-through in
        prepare_proxy_env. A systemd unit or any non-shell spawn that sets
        WORTHLESS_DEPLOY_MODE=lan but not WORTHLESS_HOST would silently bind
        loopback, defeating the entire deploy mode.
        """
        from unittest.mock import MagicMock

        from worthless.cli.process import build_proxy_env

        monkeypatch.setenv("WORTHLESS_DEPLOY_MODE", "lan")
        monkeypatch.delenv("WORTHLESS_HOST", raising=False)

        home = MagicMock()
        home.db_path = tmp_path / "worthless.db"
        home.base_dir = tmp_path
        home.fernet_key = b"fake-key"

        env = build_proxy_env(home)
        got = env.get("WORTHLESS_HOST")
        assert got == "0.0.0.0", (  # noqa: S104
            f"Expected WORTHLESS_HOST=0.0.0.0 in env dict for LAN mode, got {got!r}"
        )


class TestPrepareProxyEnv:
    """``prepare_proxy_env`` propagates env vars to the child process correctly."""

    def test_worthless_host_forwarded_from_os_environ(self, monkeypatch):
        """WORTHLESS_HOST set in parent shell reaches the spawned proxy.

        Even though ``proxy_cmd`` now takes ``host`` as an explicit param,
        the child process env must also carry ``WORTHLESS_HOST`` so uvicorn
        can be restarted in-process or inspected via env introspection.
        """
        from worthless.cli.process import prepare_proxy_env

        monkeypatch.setenv("WORTHLESS_HOST", "0.0.0.0")  # noqa: S104
        env = prepare_proxy_env({}, fernet_fd=None)
        assert env.get("WORTHLESS_HOST") == "0.0.0.0"  # noqa: S104

    def test_fernet_key_scrubbed_from_child_env(self, monkeypatch):
        """WORTHLESS_FERNET_KEY must never leak into child env via os.environ bleed."""
        from worthless.cli.process import prepare_proxy_env

        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "secret-should-not-leak")
        env = prepare_proxy_env({}, fernet_fd=None)
        assert "WORTHLESS_FERNET_KEY" not in env
