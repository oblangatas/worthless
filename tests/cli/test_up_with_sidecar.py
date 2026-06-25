"""Phase D — wire sidecar lifecycle into ``worthless up`` (foreground).

Covers:

* D1 — sidecar spawns before the proxy, and the proxy env carries
  ``WORTHLESS_SIDECAR_SOCKET``.
* D2 — clean shutdown terminates the proxy first, then the sidecar.
* D3 — sidecar crash mid-session surfaces as WRTLS-113 SIDECAR_CRASHED.
* D4 — orphan cleanup if proxy spawn raises after sidecar is up.
* D5 — daemon mode (``-d``) is rejected with a clear error.
* D6 — error-code numbering: 111 < 112 < 113.

Tests deliberately drive ``_start_foreground`` directly (lifted to module
scope in Phase D) rather than going through the Typer CLI, because the
poll loop and shutdown ordering are the surface under test — Typer
runner integration is covered by the existing ``test_cli_up.py``.
"""

from __future__ import annotations

import collections
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import typer

from tests.fixtures.dirty_home import write_secure_fernet_key
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.sidecar_lifecycle import ShareFiles, SidecarHandle


# ---------------------------------------------------------------------------
# Test fixtures and fakes
# ---------------------------------------------------------------------------


class _FakeProxyProc:
    """Fake proxy ``Popen``. ``poll()`` returns *poll_sequence* in order."""

    def __init__(
        self,
        pid: int = 22222,
        poll_sequence: list[int | None] | None = None,
    ) -> None:
        self.pid = pid
        # Default: proxy stays alive forever until terminated.
        self._poll_sequence = list(poll_sequence) if poll_sequence else None
        self._exit_code: int | None = None
        self.terminate_called = False
        self.kill_called = False
        self.terminated_at: int | None = None  # event-order counter
        self._poll_call_idx = 0

    def poll(self) -> int | None:
        if self._exit_code is not None:
            return self._exit_code
        if self._poll_sequence is not None:
            if self._poll_call_idx < len(self._poll_sequence):
                value = self._poll_sequence[self._poll_call_idx]
                self._poll_call_idx += 1
                if value is not None:
                    self._exit_code = value
                return value
            return self._exit_code
        return None

    def terminate(self) -> None:
        self.terminate_called = True
        if self._exit_code is None:
            self._exit_code = 0

    def kill(self) -> None:
        self.kill_called = True
        self._exit_code = -9

    def wait(self, timeout: float | None = None) -> int:
        if self._exit_code is None:
            self._exit_code = 0
        return self._exit_code


class _FakeSidecarProc:
    """Fake sidecar ``Popen`` — tracks lifecycle for assertions."""

    def __init__(
        self,
        pid: int = 11111,
        crash_after_polls: int | None = None,
    ) -> None:
        self.pid = pid
        self._exit_code: int | None = None
        self._poll_count = 0
        self._crash_after = crash_after_polls
        self.terminate_called = False

    def poll(self) -> int | None:
        self._poll_count += 1
        if self._crash_after is not None and self._poll_count > self._crash_after:
            self._exit_code = 7  # arbitrary non-zero
        return self._exit_code

    def terminate(self) -> None:
        self.terminate_called = True
        if self._exit_code is None:
            self._exit_code = 0

    def kill(self) -> None:
        self._exit_code = -9

    def wait(self, timeout: float | None = None) -> int:
        if self._exit_code is None:
            self._exit_code = 0
        return self._exit_code


def _make_share_files(run_dir: Path) -> ShareFiles:
    """Build a ``ShareFiles`` with real paths under *run_dir*. Files don't
    need to exist — Phase D tests stub ``shutdown_sidecar`` so the unlink
    code path isn't exercised here."""
    run_dir.mkdir(parents=True, exist_ok=True)
    return ShareFiles(
        share_a_path=run_dir / "share_a.bin",
        share_b_path=run_dir / "share_b.bin",
        shard_a=bytearray(b"\x00" * 22),
        shard_b=bytearray(b"\x00" * 22),
        run_dir=run_dir,
    )


def _make_handle(sidecar_proc: _FakeSidecarProc, run_dir: Path) -> SidecarHandle:
    return SidecarHandle(
        proc=sidecar_proc,  # type: ignore[arg-type]
        socket_path=run_dir / "sidecar.sock",
        shares=_make_share_files(run_dir),
        allowed_uid=1000,
        drain_timeout=5.0,
        stderr_buf=collections.deque(),
    )


@pytest.fixture
def home(tmp_path: Path) -> WorthlessHome:
    base = tmp_path / ".worthless"
    base.mkdir()
    # Plant a 44-byte fernet key so build_proxy_env / split_to_tmpfs work
    # under the keyring-unavailable code path.
    write_secure_fernet_key(base / "fernet.key", b"A" * 44)
    return WorthlessHome(base_dir=base)


# ---------------------------------------------------------------------------
# D1 — sidecar spawns before proxy, env carries the socket path
# ---------------------------------------------------------------------------


class TestSidecarBeforeProxy:
    def test_up_spawns_sidecar_before_proxy(self, home: WorthlessHome) -> None:
        """spawn_sidecar must be called BEFORE spawn_proxy, and the proxy
        env passed to spawn_proxy must contain WORTHLESS_SIDECAR_SOCKET."""
        # Lazy import — module is being edited as part of Phase D.
        from worthless.cli.commands import up as up_mod

        order: list[str] = []
        captured_proxy_env: dict[str, str] = {}
        sidecar_proc = _FakeSidecarProc()

        def fake_spawn_sidecar(
            socket_path: Path,
            shares: ShareFiles,
            allowed_uid: int,
            **_: Any,
        ) -> SidecarHandle:
            order.append("sidecar")
            return _make_handle(sidecar_proc, shares.run_dir)

        proxy_proc = _FakeProxyProc(poll_sequence=[None, 0])

        def fake_spawn_proxy(*, env: dict[str, str], port: int) -> tuple[_FakeProxyProc, int]:
            order.append("proxy")
            captured_proxy_env.update(env)
            return proxy_proc, port

        with (
            patch.object(up_mod, "spawn_sidecar", fake_spawn_sidecar),
            patch.object(up_mod, "spawn_proxy", fake_spawn_proxy),
            patch.object(up_mod, "poll_health_pid", return_value=proxy_proc.pid),
            patch.object(up_mod, "write_pid"),
            patch.object(up_mod, "_upgrade_pidfile_if_trusted", return_value=proxy_proc.pid),
            patch.object(up_mod, "shutdown_sidecar"),
        ):
            up_mod._start_foreground(
                home=home,
                proxy_env={"WORTHLESS_DB_PATH": "x", "WORTHLESS_HOME": str(home.base_dir)},
                port=8787,
                pid_file=home.base_dir / "proxy.pid",
                console=MagicMock(),
            )

        assert order == ["sidecar", "proxy"], f"sidecar must be spawned first, got {order!r}"
        assert "WORTHLESS_SIDECAR_SOCKET" in captured_proxy_env
        assert captured_proxy_env["WORTHLESS_SIDECAR_SOCKET"].endswith("sidecar.sock")


# ---------------------------------------------------------------------------
# D2 — clean shutdown: proxy first, then sidecar
# ---------------------------------------------------------------------------


class TestShutdownOrdering:
    def test_up_shuts_down_proxy_then_sidecar_on_clean_exit(self, home: WorthlessHome) -> None:
        from worthless.cli.commands import up as up_mod

        events: list[str] = []
        sidecar_proc = _FakeSidecarProc()
        proxy_proc = _FakeProxyProc(poll_sequence=[None, 0])

        # Wire ordering hooks into terminate() and shutdown_sidecar().
        original_terminate = proxy_proc.terminate

        def proxy_terminate_with_event() -> None:
            events.append("proxy.terminate")
            original_terminate()

        proxy_proc.terminate = proxy_terminate_with_event  # type: ignore[method-assign]

        def fake_shutdown_sidecar(handle: SidecarHandle) -> None:
            events.append("shutdown_sidecar")

        def fake_spawn_sidecar(
            socket_path: Path, shares: ShareFiles, allowed_uid: int, **_: Any
        ) -> SidecarHandle:
            return _make_handle(sidecar_proc, shares.run_dir)

        def fake_spawn_proxy(*, env: dict[str, str], port: int) -> tuple[_FakeProxyProc, int]:
            return proxy_proc, port

        with (
            patch.object(up_mod, "spawn_sidecar", fake_spawn_sidecar),
            patch.object(up_mod, "spawn_proxy", fake_spawn_proxy),
            patch.object(up_mod, "poll_health_pid", return_value=proxy_proc.pid),
            patch.object(up_mod, "write_pid"),
            patch.object(up_mod, "_upgrade_pidfile_if_trusted", return_value=proxy_proc.pid),
            patch.object(up_mod, "shutdown_sidecar", fake_shutdown_sidecar),
        ):
            up_mod._start_foreground(
                home=home,
                proxy_env={"WORTHLESS_DB_PATH": "x", "WORTHLESS_HOME": str(home.base_dir)},
                port=8787,
                pid_file=home.base_dir / "proxy.pid",
                console=MagicMock(),
            )

        assert events == ["proxy.terminate", "shutdown_sidecar"], (
            f"proxy must terminate before sidecar shutdown, got {events!r}"
        )


# ---------------------------------------------------------------------------
# D3 — sidecar crash mid-session → WRTLS-113
# ---------------------------------------------------------------------------


class TestSidecarCrashDetected:
    def test_up_exits_with_wrtls_113_when_sidecar_crashes_midsession(
        self, home: WorthlessHome
    ) -> None:
        from worthless.cli.commands import up as up_mod

        events: list[str] = []
        # Sidecar reports alive on the first poll, then dead.
        sidecar_proc = _FakeSidecarProc(crash_after_polls=1)
        # Proxy stays alive — only the sidecar dies.
        proxy_proc = _FakeProxyProc(poll_sequence=[None, None, None])

        original_terminate = proxy_proc.terminate

        def proxy_terminate_with_event() -> None:
            events.append("proxy.terminate")
            original_terminate()

        proxy_proc.terminate = proxy_terminate_with_event  # type: ignore[method-assign]

        def fake_shutdown_sidecar(handle: SidecarHandle) -> None:
            events.append("shutdown_sidecar")

        def fake_spawn_sidecar(
            socket_path: Path, shares: ShareFiles, allowed_uid: int, **_: Any
        ) -> SidecarHandle:
            return _make_handle(sidecar_proc, shares.run_dir)

        def fake_spawn_proxy(*, env: dict[str, str], port: int) -> tuple[_FakeProxyProc, int]:
            return proxy_proc, port

        with (
            patch.object(up_mod, "spawn_sidecar", fake_spawn_sidecar),
            patch.object(up_mod, "spawn_proxy", fake_spawn_proxy),
            patch.object(up_mod, "poll_health_pid", return_value=proxy_proc.pid),
            patch.object(up_mod, "write_pid"),
            patch.object(up_mod, "_upgrade_pidfile_if_trusted", return_value=proxy_proc.pid),
            patch.object(up_mod, "shutdown_sidecar", fake_shutdown_sidecar),
            patch("time.sleep"),  # Don't burn real seconds in the poll loop.
        ):
            with pytest.raises(WorthlessError) as excinfo:
                up_mod._start_foreground(
                    home=home,
                    proxy_env={"WORTHLESS_DB_PATH": "x", "WORTHLESS_HOME": str(home.base_dir)},
                    port=8787,
                    pid_file=home.base_dir / "proxy.pid",
                    console=MagicMock(),
                )

        assert excinfo.value.code == ErrorCode.SIDECAR_CRASHED
        assert "proxy.terminate" in events
        assert "shutdown_sidecar" in events
        # Proxy must be torn down BEFORE the error escapes.
        assert events.index("proxy.terminate") < events.index("shutdown_sidecar")

    def test_sidecar_crash_during_health_poll_surfaces_wrtls_113_not_104(
        self, home: WorthlessHome
    ) -> None:
        """Jenny REJECT #1: if the sidecar dies during the 15-second
        ``poll_health_pid`` window (between proxy spawn and the supervisor
        loop start), the OLD code raised ``WRTLS-104 PROXY_UNREACHABLE``
        — wrong direction for the user's debug effort.

        The fix: before declaring the proxy unreachable, check
        ``handle.proc.poll() is not None``. If the sidecar is the dead
        party, surface ``WRTLS-113 SIDECAR_CRASHED`` instead.
        """
        from worthless.cli.commands import up as up_mod

        # Proxy looks alive (no crash on the proxy side); sidecar is DEAD.
        proxy_proc = _FakeProxyProc(poll_sequence=[None, None])
        sidecar_proc = _FakeSidecarProc()
        sidecar_proc._exit_code = 7  # type: ignore[attr-defined]  # sidecar crashed

        def fake_spawn_sidecar(
            socket_path: Path, shares: ShareFiles, allowed_uid: int, **_: Any
        ) -> SidecarHandle:
            return _make_handle(sidecar_proc, shares.run_dir)

        with (
            patch.object(up_mod, "spawn_sidecar", fake_spawn_sidecar),
            patch.object(up_mod, "spawn_proxy", lambda *, env, port: (proxy_proc, port)),
            # poll_health_pid returns None — proxy never became healthy.
            # Pre-fix: this triggers WRTLS-104. Post-fix: we check the
            # sidecar first, see it's dead, and raise WRTLS-113 instead.
            patch.object(up_mod, "poll_health_pid", return_value=None),
            patch.object(up_mod, "write_pid"),
            patch.object(up_mod, "shutdown_sidecar"),
            patch("time.sleep"),
        ):
            with pytest.raises(WorthlessError) as excinfo:
                up_mod._start_foreground(
                    home=home,
                    proxy_env={"WORTHLESS_DB_PATH": "x", "WORTHLESS_HOME": str(home.base_dir)},
                    port=8787,
                    pid_file=home.base_dir / "proxy.pid",
                    console=MagicMock(),
                )

        assert excinfo.value.code == ErrorCode.SIDECAR_CRASHED, (
            f"sidecar-died-during-health-poll must surface WRTLS-113, "
            f"got {excinfo.value.code.name} (WRTLS-{excinfo.value.code.value})"
        )


# ---------------------------------------------------------------------------
# D4 — orphan cleanup if proxy spawn fails after sidecar is up
# ---------------------------------------------------------------------------


class TestOrphanCleanupOnInitFailure:
    def test_up_cleans_up_orphan_state_when_init_fails_post_spawn(
        self, home: WorthlessHome
    ) -> None:
        """Jenny REJECT #2: the original D4 only asserted
        ``len(shutdown_calls) == 1``. A buggy ``shutdown_sidecar(None)``
        call would have passed. This tightened version asserts:

        1. ``shutdown_sidecar`` is called EXACTLY once.
        2. It receives the SAME handle ``spawn_sidecar`` returned (identity
           check, not just truthiness).
        3. The cleanup actually removes the run dir on disk (not just
           records the function call) — the fake ``shutdown_sidecar``
           performs a real ``rmtree`` so the assertion is observable.
        """
        from worthless.cli.commands import up as up_mod

        sidecar_proc = _FakeSidecarProc()
        spawned_handles: list[SidecarHandle] = []

        def fake_spawn_sidecar(
            socket_path: Path, shares: ShareFiles, allowed_uid: int, **_: Any
        ) -> SidecarHandle:
            handle = _make_handle(sidecar_proc, shares.run_dir)
            spawned_handles.append(handle)
            return handle

        def fake_spawn_proxy(*, env: dict[str, str], port: int) -> tuple[Any, int]:
            raise RuntimeError("simulated proxy spawn failure")

        shutdown_calls: list[SidecarHandle] = []

        def fake_shutdown_sidecar(handle: SidecarHandle) -> None:
            shutdown_calls.append(handle)
            # Perform REAL cleanup so the run-dir-gone assertion below is
            # not vacuous — a buggy production path that skipped the call
            # entirely would leave the dir in place and the assertion
            # would catch it.
            import shutil as _shutil

            _shutil.rmtree(handle.shares.run_dir, ignore_errors=True)

        with (
            patch.object(up_mod, "spawn_sidecar", fake_spawn_sidecar),
            patch.object(up_mod, "spawn_proxy", fake_spawn_proxy),
            patch.object(up_mod, "shutdown_sidecar", fake_shutdown_sidecar),
        ):
            with pytest.raises(typer.Exit) as excinfo:
                up_mod._start_foreground(
                    home=home,
                    proxy_env={"WORTHLESS_DB_PATH": "x", "WORTHLESS_HOME": str(home.base_dir)},
                    port=8787,
                    pid_file=home.base_dir / "proxy.pid",
                    console=MagicMock(),
                )

        assert excinfo.value.exit_code == 1
        cause = excinfo.value.__cause__
        assert isinstance(cause, RuntimeError)
        assert "simulated proxy spawn failure" in str(cause)

        # 1. Exactly one shutdown call.
        assert len(shutdown_calls) == 1, (
            f"shutdown_sidecar must be invoked exactly once, got {len(shutdown_calls)}"
        )
        # 2. With the SAME handle spawn_sidecar returned (identity, not equality).
        assert len(spawned_handles) == 1
        assert shutdown_calls[0] is spawned_handles[0], (
            "shutdown_sidecar was called with a different handle than the one "
            "spawn_sidecar returned — the cleanup path lost track of the live "
            "subprocess"
        )
        # 3. The cleanup actually removed the run dir on disk.
        assert not spawned_handles[0].shares.run_dir.exists(), (
            f"run dir {spawned_handles[0].shares.run_dir} survived shutdown — "
            "cleanup is recording the call but not performing it"
        )


# ---------------------------------------------------------------------------
# D5 — daemon mode rejected
# ---------------------------------------------------------------------------


class TestDaemonModeRejected:
    def test_up_rejects_daemon_mode_with_clear_error(self, home: WorthlessHome) -> None:
        from typer.testing import CliRunner

        from worthless.cli.app import app

        runner = CliRunner()

        with patch("worthless.cli.commands.up.get_home", return_value=home):
            result = runner.invoke(app, ["up", "-d"])

        assert result.exit_code != 0
        out = (result.stdout or "") + (str(result.exception) if result.exception else "")
        # Must mention daemon and foreground in some form.
        assert "daemon" in out.lower()
        assert "foreground" in out.lower()
        # WOR-384 fix-11/11: pin the numeric error code so a future change
        # to the rejection's ErrorCode surfaces explicitly. Was substring-
        # only before — would silently couple to the wrong code (Jenny CONCERN #4).
        assert "WRTLS-115" in out, f"Expected WRTLS-115 (DAEMON_NOT_SUPPORTED), got: {out!r}"


# ---------------------------------------------------------------------------
# D6 — error code ordering
# ---------------------------------------------------------------------------


class TestErrorCodeOrdering:
    def test_error_code_sidecar_crashed_is_113(self) -> None:
        assert ErrorCode.SIDECAR_CRASHED == 113
        assert (
            int(ErrorCode.UNSAFE_REWRITE_REFUSED)
            < int(ErrorCode.SIDECAR_CRASHED)
            < int(ErrorCode.SIDECAR_NOT_READY)
        )


# ---------------------------------------------------------------------------
# SR-02 — Fernet key zeroed after split_to_tmpfs (security expert audit)
# ---------------------------------------------------------------------------


class TestFernetKeyZeroedAfterSplit:
    def test_fernet_key_zeroed_after_split_to_tmpfs(self, home: WorthlessHome) -> None:
        """SR-02 must-fix: the Fernet key bytearray returned by
        ``home.fernet_key`` must be zeroed after ``split_to_tmpfs`` consumes
        it. Plaintext key is not needed in ``up`` after the shares are on
        disk; leaving it in memory for the entire session is unnecessary
        retention of secret material.
        """
        from worthless.cli.commands import up as up_mod

        captured_keys: list[bytearray] = []
        sidecar_proc = _FakeSidecarProc()

        def fake_split_to_tmpfs(fernet_key: bytearray, home_dir: Path) -> ShareFiles:
            # Capture the bytearray reference so we can assert post-call
            # state. The reference must point at the same object the
            # production code is responsible for zeroing.
            captured_keys.append(fernet_key)
            run_dir = home_dir / "run" / str(os.getpid())
            run_dir.mkdir(parents=True, exist_ok=True)
            return _make_share_files(run_dir)

        proxy_proc = _FakeProxyProc(poll_sequence=[None, 0])

        with (
            patch.object(up_mod, "split_to_tmpfs", fake_split_to_tmpfs),
            patch.object(
                up_mod,
                "spawn_sidecar",
                lambda socket_path, shares, allowed_uid, **_: _make_handle(
                    sidecar_proc, shares.run_dir
                ),
            ),
            patch.object(
                up_mod,
                "spawn_proxy",
                lambda *, env, port: (proxy_proc, port),
            ),
            patch.object(up_mod, "poll_health_pid", return_value=proxy_proc.pid),
            patch.object(up_mod, "write_pid"),
            patch.object(up_mod, "_upgrade_pidfile_if_trusted", return_value=proxy_proc.pid),
            patch.object(up_mod, "shutdown_sidecar"),
        ):
            up_mod._start_foreground(
                home=home,
                proxy_env={"WORTHLESS_DB_PATH": "x", "WORTHLESS_HOME": str(home.base_dir)},
                port=8787,
                pid_file=home.base_dir / "proxy.pid",
                console=MagicMock(),
            )

        assert len(captured_keys) == 1, (
            f"split_to_tmpfs called {len(captured_keys)} times, expected 1"
        )
        captured = captured_keys[0]
        assert len(captured) == 44, f"unexpected key length {len(captured)}"
        assert all(b == 0 for b in captured), (
            f"SR-02 violation: fernet_key still contains plaintext after split: "
            f"first byte = {captured[0]}"
        )

    def test_shares_zeroed_when_spawn_sidecar_fails(self, home: WorthlessHome) -> None:
        """SR-02 nice-to-have: when ``spawn_sidecar`` raises (handle is
        None), the failure-path cleanup unlinks the share files from disk
        but the bytearrays in the captured ``ShareFiles`` object are still
        on the stack with plaintext shard material. They must be zeroed
        before the exception propagates — otherwise a transient sidecar
        spawn failure leaks half the key in process memory.

        Mirrors what ``shutdown_sidecar`` does on the success path (Phase C
        zeroing); this fix extends the same guarantee to the spawn-failure
        fallback that runs BEFORE a handle exists.
        """
        from worthless.cli.commands import up as up_mod

        captured_shares: list[ShareFiles] = []

        def fake_split(fernet_key: bytearray, home_dir: Path) -> ShareFiles:
            run_dir = home_dir / "run" / str(os.getpid())
            run_dir.mkdir(parents=True, exist_ok=True)
            shares = ShareFiles(
                share_a_path=run_dir / "share_a.bin",
                share_b_path=run_dir / "share_b.bin",
                shard_a=bytearray(b"\xab" * 22),  # non-zero
                shard_b=bytearray(b"\xcd" * 22),  # non-zero
                run_dir=run_dir,
            )
            captured_shares.append(shares)
            return shares

        def fake_spawn_raises(
            socket_path: Path,
            shares: ShareFiles,
            allowed_uid: int,
            **_: Any,
        ) -> SidecarHandle:
            raise WorthlessError(
                ErrorCode.SIDECAR_NOT_READY,
                "test: simulated spawn failure",
            )

        with (
            patch.object(up_mod, "split_to_tmpfs", fake_split),
            patch.object(up_mod, "spawn_sidecar", fake_spawn_raises),
        ):
            with pytest.raises(WorthlessError) as exc_info:
                up_mod._start_foreground(
                    home=home,
                    proxy_env={
                        "WORTHLESS_DB_PATH": "x",
                        "WORTHLESS_HOME": str(home.base_dir),
                    },
                    port=8787,
                    pid_file=home.base_dir / "proxy.pid",
                    console=MagicMock(),
                )

        assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
        assert len(captured_shares) == 1
        shares = captured_shares[0]
        assert all(b == 0 for b in shares.shard_a), (
            f"SR-02 violation: shard_a not zeroed on spawn failure: "
            f"first byte = {shares.shard_a[0]:02x}"
        )
        assert all(b == 0 for b in shares.shard_b), (
            f"SR-02 violation: shard_b not zeroed on spawn failure: "
            f"first byte = {shares.shard_b[0]:02x}"
        )

    def test_fernet_key_zeroed_even_when_split_to_tmpfs_raises(self, home: WorthlessHome) -> None:
        """SR-02: the zeroing must run on the failure path too. If
        ``split_to_tmpfs`` raises (e.g., disk full mid-write), the original
        Fernet key bytearray must still be wiped before the exception
        propagates — otherwise a transient disk error leaves plaintext key
        material in process memory for the rest of the session.

        Regression guard: protects against a future refactor that moves the
        wipe out of the ``finally`` block.
        """
        from worthless.cli.commands import up as up_mod

        captured_keys: list[bytearray] = []

        def fake_split_raises(fernet_key: bytearray, home_dir: Path) -> ShareFiles:
            captured_keys.append(fernet_key)
            raise OSError(28, "No space left on device")

        with (
            patch.object(up_mod, "split_to_tmpfs", fake_split_raises),
            # Other patches don't matter — we never get past split_to_tmpfs.
        ):
            with pytest.raises(OSError, match="No space left"):
                up_mod._start_foreground(
                    home=home,
                    proxy_env={
                        "WORTHLESS_DB_PATH": "x",
                        "WORTHLESS_HOME": str(home.base_dir),
                    },
                    port=8787,
                    pid_file=home.base_dir / "proxy.pid",
                    console=MagicMock(),
                )

        assert len(captured_keys) == 1
        captured = captured_keys[0]
        assert all(b == 0 for b in captured), (
            "SR-02 violation: fernet_key not zeroed when split_to_tmpfs raised"
        )


# ---------------------------------------------------------------------------
# QA #7 — Signal handlers must be installed BEFORE spawn (no orphan on
# SIGTERM during spawn window)
# ---------------------------------------------------------------------------


class TestSignalHandlersBeforeSpawn:
    def test_sigterm_handler_installed_before_spawn_sidecar(self, home: WorthlessHome) -> None:
        """If SIGTERM arrives during ``spawn_sidecar``, the parent must NOT
        get terminated by Python's default signal action (which would
        orphan the spawned subprocess). The fix: install our SIGTERM
        handler in ``_start_foreground`` BEFORE ``spawn_sidecar`` runs,
        rather than waiting until ``_supervise_proxy_with_sidecar``.

        Regression guard: capture the SIGTERM handler at the moment
        ``spawn_sidecar`` is invoked. Must not be ``signal.SIG_DFL`` (the
        default 'terminate process' behavior) — must already be our
        custom handler.
        """
        import signal as signal_mod  # local alias to avoid shadowing

        from worthless.cli.commands import up as up_mod

        # Reset SIGTERM to default so the test sees a known baseline if
        # nothing in the production code installs a handler.
        prev_sigterm = signal_mod.signal(signal_mod.SIGTERM, signal_mod.SIG_DFL)

        captured_handler_at_spawn: list[Any] = []
        sidecar_proc = _FakeSidecarProc()

        def fake_spawn_sidecar(
            socket_path: Path,
            shares: ShareFiles,
            allowed_uid: int,
            **_: Any,
        ) -> SidecarHandle:
            # Capture the SIGTERM handler at the moment of spawn.
            captured_handler_at_spawn.append(signal_mod.getsignal(signal_mod.SIGTERM))
            return _make_handle(sidecar_proc, shares.run_dir)

        proxy_proc = _FakeProxyProc(poll_sequence=[None, 0])

        try:
            with (
                patch.object(up_mod, "spawn_sidecar", fake_spawn_sidecar),
                patch.object(
                    up_mod,
                    "spawn_proxy",
                    lambda *, env, port: (proxy_proc, port),
                ),
                patch.object(up_mod, "poll_health_pid", return_value=proxy_proc.pid),
                patch.object(up_mod, "write_pid"),
                patch.object(
                    up_mod,
                    "_upgrade_pidfile_if_trusted",
                    return_value=proxy_proc.pid,
                ),
                patch.object(up_mod, "shutdown_sidecar"),
            ):
                up_mod._start_foreground(
                    home=home,
                    proxy_env={
                        "WORTHLESS_DB_PATH": "x",
                        "WORTHLESS_HOME": str(home.base_dir),
                    },
                    port=8787,
                    pid_file=home.base_dir / "proxy.pid",
                    console=MagicMock(),
                )
        finally:
            # Restore the handler the test environment had before us.
            signal_mod.signal(signal_mod.SIGTERM, prev_sigterm)

        assert len(captured_handler_at_spawn) == 1
        handler = captured_handler_at_spawn[0]
        # Must NOT be the default — that's the orphan-creating behavior.
        assert handler is not signal_mod.SIG_DFL, (
            "SIGTERM handler is signal.SIG_DFL at spawn_sidecar time; SIGTERM "
            "during spawn would terminate parent and orphan the sidecar PID"
        )


# ---------------------------------------------------------------------------
# QA #4 — Concurrent ``worthless up`` invocations must serialize via flock,
# not race on the pidfile (where the second invocation could overwrite the
# first's PID, then unlink it on its own cleanup, leaving the first running
# without a pidfile).
# ---------------------------------------------------------------------------


class TestConcurrentUpLock:
    def test_concurrent_up_fails_fast_when_lock_held(self, home: WorthlessHome) -> None:
        """Pre-acquire ``~/.worthless/.up.lock`` from the test process via
        ``fcntl.flock``, then call ``_start_foreground``. It must NOT
        spawn anything — must fail fast with ``WRTLS-105 LOCK_IN_PROGRESS``
        and a clear "another worthless up in progress" message.

        flock semantics on Linux + macOS: separate ``open()`` calls within
        the same process produce distinct open file descriptions, so
        contention IS detected even though the lock holder and the would-
        be acquirer share a PID.
        """
        import fcntl

        from worthless.cli.commands import up as up_mod

        lock_path = home.base_dir / ".up.lock"

        # Pre-acquire the lock from the test, simulating an in-flight
        # ``worthless up`` instance.
        with lock_path.open("a") as held_lock:
            fcntl.flock(held_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

            # The patches below would let _start_foreground succeed if the
            # lock didn't intervene — proves the failure is from the lock,
            # not from spawn errors.
            spawn_called: list[str] = []

            def _should_not_spawn(*args, **kwargs):
                spawn_called.append("sidecar")
                raise AssertionError(
                    "spawn_sidecar called despite held .up.lock — lock-fast-fail not in place"
                )

            with (
                patch.object(up_mod, "spawn_sidecar", _should_not_spawn),
                patch.object(up_mod, "spawn_proxy", _should_not_spawn),
            ):
                with pytest.raises(WorthlessError) as exc_info:
                    up_mod._start_foreground(
                        home=home,
                        proxy_env={
                            "WORTHLESS_DB_PATH": "x",
                            "WORTHLESS_HOME": str(home.base_dir),
                        },
                        port=8787,
                        pid_file=home.base_dir / "proxy.pid",
                        console=MagicMock(),
                    )

            assert exc_info.value.code == ErrorCode.LOCK_IN_PROGRESS
            msg = str(exc_info.value).lower()
            assert "in progress" in msg or "already" in msg or "lock" in msg, (
                f"Expected lock-held message, got: {exc_info.value!s}"
            )
            assert spawn_called == [], (
                "Lock check ran AFTER spawn — fast-fail must happen BEFORE any subprocess work"
            )

    def test_lock_released_after_normal_completion(self, home: WorthlessHome) -> None:
        """After ``_start_foreground`` returns normally (proxy stops),
        the .up.lock must be released so a subsequent ``worthless up``
        invocation can acquire it. Drives a fast clean exit (proxy
        ``poll_sequence=[None, 0]``) and asserts the lock is acquirable
        afterward.
        """
        import fcntl

        from worthless.cli.commands import up as up_mod

        sidecar_proc = _FakeSidecarProc()
        proxy_proc = _FakeProxyProc(poll_sequence=[None, 0])

        with (
            patch.object(
                up_mod,
                "spawn_sidecar",
                lambda socket_path, shares, allowed_uid, **_: _make_handle(
                    sidecar_proc, shares.run_dir
                ),
            ),
            patch.object(
                up_mod,
                "spawn_proxy",
                lambda *, env, port: (proxy_proc, port),
            ),
            patch.object(up_mod, "poll_health_pid", return_value=proxy_proc.pid),
            patch.object(up_mod, "write_pid"),
            patch.object(up_mod, "_upgrade_pidfile_if_trusted", return_value=proxy_proc.pid),
            patch.object(up_mod, "shutdown_sidecar"),
        ):
            up_mod._start_foreground(
                home=home,
                proxy_env={
                    "WORTHLESS_DB_PATH": "x",
                    "WORTHLESS_HOME": str(home.base_dir),
                },
                port=8787,
                pid_file=home.base_dir / "proxy.pid",
                console=MagicMock(),
            )

        # _start_foreground returned. Lock must be released.
        lock_path = home.base_dir / ".up.lock"
        assert lock_path.exists(), "lock file should still exist (only the lock is released)"

        # Should be able to acquire EX lock now — proves prior holder released.
        with lock_path.open("a") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


# ---------------------------------------------------------------------------
# Expert panel must-fix items
# ---------------------------------------------------------------------------


class TestExpertPanelMustFix:
    def test_sighup_handler_installed_alongside_sigint_sigterm(self, home: WorthlessHome) -> None:
        """Chaos panel #7: default SIGHUP terminates the parent → orphans.
        SIGHUP must be handled the same as SIGINT/SIGTERM (graceful shutdown).
        """
        import signal as signal_mod

        from worthless.cli.commands import up as up_mod

        prev_sighup = signal_mod.signal(signal_mod.SIGHUP, signal_mod.SIG_DFL)

        captured: list[Any] = []
        sidecar_proc = _FakeSidecarProc()

        def fake_spawn_sidecar(
            socket_path: Path, shares: ShareFiles, allowed_uid: int, **_: Any
        ) -> SidecarHandle:
            captured.append(signal_mod.getsignal(signal_mod.SIGHUP))
            return _make_handle(sidecar_proc, shares.run_dir)

        proxy_proc = _FakeProxyProc(poll_sequence=[None, 0])

        try:
            with (
                patch.object(up_mod, "spawn_sidecar", fake_spawn_sidecar),
                patch.object(up_mod, "spawn_proxy", lambda *, env, port: (proxy_proc, port)),
                patch.object(up_mod, "poll_health_pid", return_value=proxy_proc.pid),
                patch.object(up_mod, "write_pid"),
                patch.object(up_mod, "_upgrade_pidfile_if_trusted", return_value=proxy_proc.pid),
                patch.object(up_mod, "shutdown_sidecar"),
            ):
                up_mod._start_foreground(
                    home=home,
                    proxy_env={
                        "WORTHLESS_DB_PATH": "x",
                        "WORTHLESS_HOME": str(home.base_dir),
                    },
                    port=8787,
                    pid_file=home.base_dir / "proxy.pid",
                    console=MagicMock(),
                )
        finally:
            signal_mod.signal(signal_mod.SIGHUP, prev_sighup)

        assert len(captured) == 1
        handler = captured[0]
        assert handler is not signal_mod.SIG_DFL, (
            "SIGHUP handler is signal.SIG_DFL at spawn time — terminal hangup "
            "would terminate parent without cleanup"
        )

    def test_signal_handlers_installed_BEFORE_foreground_lock(self, home: WorthlessHome) -> None:
        """Security panel C-2: signal handlers must be installed BEFORE
        ``_foreground_lock`` acquisition. If SIGTERM arrives during the
        lock-acquire window with default SIG_DFL still active, the parent
        dies — closing the lockfile fd (releasing flock) but leaving the
        flow with no spawn-window protection. Move handlers to BEFORE the
        lock CM so the gap doesn't exist.
        """
        import signal as signal_mod

        from worthless.cli.commands import up as up_mod

        prev_sigterm = signal_mod.signal(signal_mod.SIGTERM, signal_mod.SIG_DFL)

        captured: list[Any] = []

        @contextmanager
        def spy_foreground_lock(home_dir: Path):
            # Capture the SIGTERM handler at the moment lock acquisition
            # would START. Pre-fix: handler is SIG_DFL here. Post-fix: it's
            # our spawn-window handler.
            captured.append(signal_mod.getsignal(signal_mod.SIGTERM))
            yield

        try:
            with patch.object(up_mod, "_foreground_lock", spy_foreground_lock):
                with patch.object(
                    up_mod,
                    "_start_foreground_locked",
                    lambda **kwargs: None,  # no-op; we only care about lock-time state
                ):
                    up_mod._start_foreground(
                        home=home,
                        proxy_env={
                            "WORTHLESS_DB_PATH": "x",
                            "WORTHLESS_HOME": str(home.base_dir),
                        },
                        port=8787,
                        pid_file=home.base_dir / "proxy.pid",
                        console=MagicMock(),
                    )
        finally:
            signal_mod.signal(signal_mod.SIGTERM, prev_sigterm)

        assert len(captured) == 1
        handler = captured[0]
        assert handler is not signal_mod.SIG_DFL, (
            "SIGTERM handler is signal.SIG_DFL at lock-acquisition time — "
            "the spawn-window handler isn't installed early enough"
        )


def test_run_parent_dir_has_0700_perms(tmp_path: Path) -> None:
    """Security panel C-1: ``~/.worthless/run/`` (the PARENT of the per-pid
    run dir) must be 0o700, not the umask-default 0o755. A world-traversable
    parent leaks live session PIDs to any local user — enabling targeted
    ptrace/proc-mem attacks on the sidecar (which holds plaintext shard B).
    """
    import stat as stat_mod

    from worthless.cli.sidecar_lifecycle import split_to_tmpfs

    home_dir = tmp_path / ".worthless"
    home_dir.mkdir()
    fernet_key = bytearray(b"A" * 44)

    split_to_tmpfs(fernet_key, home_dir)

    parent_run_dir = home_dir / "run"
    assert parent_run_dir.exists()
    parent_mode = stat_mod.S_IMODE(parent_run_dir.stat().st_mode)
    assert parent_mode == 0o700, (
        f"~/.worthless/run/ is mode {oct(parent_mode)}, expected 0o700. "
        "Parent dir leaks live session PIDs to other local users."
    )
