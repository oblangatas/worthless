"""WOR-309 Phase 5 slice 5.7 — GREEN integration tests against a real sidecar subprocess.

Tests #14-15 from ``.research/04-test-plan.md``. Both spawn the actual
``python -m worthless.sidecar`` binary via the ``subprocess_sidecar``
fixture and exercise the wire protocol end-to-end. Slow — kept tight.

Marked ``integration`` so the default test run can opt in/out per the
pyproject markers list. ``real_ipc`` opts out of the autouse Fake
supervisor injection (the proxy app is never built here, but the marker
keeps these tests on the same opt-out lane as the rest of the
"real subprocess" suite).
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from worthless.proxy.ipc_supervisor import (
    IPCSupervisor,
    IPCUnavailable,
)


def _wait_for_pid_gone(pid: int, *, timeout: float = 1.0, interval: float = 0.005) -> None:
    """Poll until SIGKILL'd ``pid`` is fully reaped (kernel released its socket)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(interval)


pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.integration,
    pytest.mark.real_ipc,
    pytest.mark.xdist_group("real_sidecar"),
]

_EXPECTED_CAPS = frozenset({"seal", "open", "attest"})


async def test_real_sidecar_handshake(subprocess_sidecar) -> None:
    """#14 Spawn the real sidecar; supervisor connects + completes HELLO.

    GREEN: IPCSupervisor connects over the tmp UDS, completes the HELLO
    handshake at protocol v=1, and surfaces ``backend_caps`` matching
    ``("seal", "open", "attest")``.
    """
    socket_path, _pid = subprocess_sidecar

    sup = IPCSupervisor(
        socket_path,
        protocol_version=1,
        expected_caps=_EXPECTED_CAPS,
    )
    try:
        await sup.connect()
        # Round-trip a real seal+open against the FernetBackend to prove
        # the handshake completed AND the connection is usable.
        async with sup.acquire() as client:
            ct = await client.seal(b"hello-world")
            pt = await client.open(ct)
        assert bytes(pt) == b"hello-world"
    finally:
        await sup.aclose()


async def test_real_sidecar_reconnect_after_sigkill(
    subprocess_sidecar,
    sidecar_socket_path: Path,
    fernet_shares: tuple[bytes, bytes],
    tmp_path: Path,
) -> None:
    """#15 SIGKILL the real sidecar mid-session; restart it; next call succeeds.

    GREEN: kill child by pid; relaunch a fresh sidecar on the same socket;
    issue a second IPC call and assert the supervisor transparently
    rebuilt the connection without falling back to in-process crypto.

    The supervisor's ``open()`` retries once on transport failure
    (``ipc_supervisor.py:505``). After SIGKILL the first attempt fails;
    the second attempt reconnects against the freshly-spawned sidecar.
    """
    socket_path, pid = subprocess_sidecar

    sup = IPCSupervisor(
        socket_path,
        protocol_version=1,
        expected_caps=_EXPECTED_CAPS,
    )
    try:
        await sup.connect()

        # First, seal+open a payload via the supervisor against the original
        # sidecar to prove the connection works. Capture a ciphertext we can
        # decrypt again later — Fernet shares are stable across the SIGKILL
        # since the replacement reads the same share files.
        async with sup.acquire() as client:
            ct = await client.seal(b"before-kill")
            pt_before = await client.open(ct)
        assert bytes(pt_before) == b"before-kill"

        # SIGKILL the original sidecar process. We can't reap (Popen handle
        # lives in the fixture); but the kernel tears down the listener
        # synchronously on SIGKILL so connect attempts will fail immediately.
        # Poll until the process is gone (kernel has released the bind),
        # then unlink the stale socket file so the replacement can claim it.
        os.kill(pid, signal.SIGKILL)
        _wait_for_pid_gone(pid)
        if socket_path.exists():
            try:
                socket_path.unlink()
            except OSError:
                pass

        # Spawn a replacement sidecar on the same socket path.
        share_a_path = tmp_path / "share_a_replacement.bin"
        share_b_path = tmp_path / "share_b_replacement.bin"
        share_a_path.write_bytes(fernet_shares[0])
        share_b_path.write_bytes(fernet_shares[1])
        env = {
            **os.environ,
            "WORTHLESS_SIDECAR_SOCKET": str(socket_path),
            "WORTHLESS_SIDECAR_SHARE_A": str(share_a_path),
            "WORTHLESS_SIDECAR_SHARE_B": str(share_b_path),
            "WORTHLESS_SIDECAR_ALLOWED_UID": str(os.getuid()),
            "WORTHLESS_LOG_LEVEL": "WARNING",
        }
        replacement = subprocess.Popen(  # noqa: S603 — args static, no shell
            [sys.executable, "-m", "worthless.sidecar"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            # Wait for the replacement to bind.
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if socket_path.exists():
                    break
                if replacement.poll() is not None:  # pragma: no cover
                    err = replacement.stderr.read().decode() if replacement.stderr else ""
                    pytest.fail(f"replacement sidecar exited rc={replacement.returncode}: {err}")
                time.sleep(0.05)
            else:  # pragma: no cover
                replacement.kill()
                pytest.fail(f"replacement sidecar did not bind {socket_path} within 5s")

            # Supervisor.open retries once on transport failure → reconnects.
            # Decrypt the ciphertext we sealed *before* the SIGKILL: the
            # replacement sidecar uses the same XOR shares so the same
            # Fernet key reconstructs and the original ct still opens.
            pt_after = await sup.open(ct, key_id="kid")
            assert bytes(pt_after) == b"before-kill", (
                "supervisor must reconnect transparently and decrypt against "
                "the freshly-spawned sidecar — no in-process crypto fallback"
            )
        finally:
            if replacement.poll() is None:
                try:
                    replacement.send_signal(signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                replacement.wait(timeout=2.0)
            except subprocess.TimeoutExpired:  # pragma: no cover
                replacement.kill()
    finally:
        await sup.aclose()


async def test_open_without_replacement_raises_unavailable(
    subprocess_sidecar,
) -> None:
    """SIGKILL the sidecar with no replacement → next ``open`` raises IPCUnavailable.

    Proves the no-fallback invariant from a real subprocess. The supervisor
    has no in-process crypto path; with the sidecar gone, ``open`` MUST
    surface :class:`IPCUnavailable` (the proxy maps it to HTTP 503).
    """
    socket_path, pid = subprocess_sidecar

    sup = IPCSupervisor(
        socket_path,
        protocol_version=1,
        expected_caps=_EXPECTED_CAPS,
    )
    try:
        await sup.connect()
        # Warm up: prove the connection works.
        async with sup.acquire() as client:
            ct = await client.seal(b"x")
        assert ct

        # Kill sidecar with no replacement. We can't reap (Popen handle lives
        # in the fixture); kernel tears down the listener on SIGKILL so the
        # next connect attempt fails synchronously.
        os.kill(pid, signal.SIGKILL)
        _wait_for_pid_gone(pid)
        if socket_path.exists():
            try:
                socket_path.unlink()
            except OSError:
                pass

        with pytest.raises(IPCUnavailable):
            await sup.open(ct, key_id="kid")
    finally:
        await sup.aclose()
