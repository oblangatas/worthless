"""End-to-end smoke test — proves the proxy boots and goes live.

Scope, honestly: this drives the lifecycle to a listening proxy and a 200
from ``/healthz``. It does NOT issue a proxied request, so it proves none of
the three product invariants (client-side split, gate-before-reconstruct,
server-side upstream call). ``/healthz`` also swallows its own DB error
(app.py:443-444), so a 200 is not a statement about storage health.

What it does prove is that lifespan completed: schema, migrations, decoy
preload, the sidecar IPC handshake, and the port bind. For proof that a real
request transits a real proxy, see
``tests/test_e2e.py::TestWrapProxiesRequest``.

Lifecycle: bootstrap home → lock a key → start proxy → /healthz → stop.

This test runs with a real (temp) home directory, real SQLite DB,
real Fernet encryption, and a real proxy process.  The only thing
mocked is the upstream LLM provider (we don't make real API calls).

Marked ``@pytest.mark.e2e`` so it can be selected or skipped in CI.
"""

from __future__ import annotations

import os
import signal
import time
from pathlib import Path

import httpx
import pytest

from worthless.cli.bootstrap import ensure_home
from worthless.cli.commands.lock import _lock_keys
from worthless.cli.commands.up import start_daemon
from worthless.cli.console import WorthlessConsole, set_console
from worthless.crypto.types import zero_buf
from worthless.cli.sidecar_lifecycle import (
    shutdown_sidecar,
    spawn_sidecar,
    split_to_tmpfs,
)
from worthless.cli.process import (
    build_proxy_env,
    check_pid,
    disable_core_dumps,
    pid_path,
    poll_health,
    read_pid,
)

from tests.helpers import fake_openai_key


def _spawn_sidecar_or_clean(shares):
    """``spawn_sidecar``, but never leave shards on disk if it raises.

    Ports the ``handle is None`` branch from ``up.py:540-556``. The two
    share files together ARE the Fernet key (sidecar/__main__.py:85-89),
    so a WRTLS-114 timeout must not strand them in pytest's basetemp,
    which CI can upload as an artifact. SR-02: zero both shards too.
    """
    try:
        return spawn_sidecar(shares.run_dir / "sidecar.sock", shares, allowed_uid=os.getuid())
    except BaseException:
        for path in (shares.share_a_path, shares.share_b_path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            shares.run_dir.rmdir()
        except OSError:
            pass
        zero_buf(shares.shard_a)
        zero_buf(shares.shard_b)
        raise


@pytest.mark.e2e
@pytest.mark.real_ipc
@pytest.mark.timeout(60)
class TestEndToEndSmoke:
    """Full lifecycle: bootstrap → lock → proxy → healthz → stop."""

    def test_lock_start_health_stop(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The product promise: lock a key, start the proxy, it's healthy.

        Steps:
        1. Bootstrap a fresh home in tmp_path
        2. Create .env with a fake OpenAI key
        3. Lock the key (split + store + rewrite .env with decoy)
        4. Start proxy daemon on a random-ish port
        5. Verify /healthz returns 200
        6. Stop the proxy
        7. Verify PID file cleaned up
        """
        # 1. Bootstrap
        home = ensure_home(tmp_path / ".worthless")
        set_console(WorthlessConsole(quiet=True, json_mode=False))

        # 2. Create .env
        env_path = tmp_path / ".env"
        original_key = fake_openai_key()
        env_path.write_text(f"OPENAI_API_KEY={original_key}\n")

        # 3. Lock — key gets split, .env rewritten with decoy
        # monkeypatch.chdir restores the cwd at teardown. A bare os.chdir
        # would leak into every later test in this xdist worker — harmless
        # while this test was skipped, not harmless now that it runs.
        monkeypatch.chdir(tmp_path)
        count = _lock_keys(env_path, home, quiet=True)
        assert count == 1, f"Expected 1 key locked, got {count}"

        # Verify .env was rewritten (original key no longer present)
        rewritten = env_path.read_text()
        assert original_key not in rewritten, "Original key should be replaced with decoy"
        assert "OPENAI_API_KEY=" in rewritten, "Var name should still be in .env"

        # 4. Start proxy daemon
        disable_core_dumps()
        proxy_env = build_proxy_env(home)

        # Mirror `worthless up` (up.py:504-519): the proxy cannot serve
        # /healthz without a sidecar to answer decrypt IPC — app.py:262-271
        # eager-connects the supervisor and fails loud with no fallback.
        # The wipe mirrors up.py's SR-02 step. ``home.fernet_key`` hands
        # back a fresh copy each call, so this clears our own temporary —
        # the cached original is covered separately by the weakref.finalize
        # at bootstrap.py:213.
        fernet_key = home.fernet_key
        try:
            shares = split_to_tmpfs(fernet_key, home.base_dir)
        finally:
            fernet_key[:] = bytearray(len(fernet_key))

        port = 18787  # high port to avoid conflicts
        pf = pid_path(home)
        log_file = home.base_dir / "proxy.log"

        # The helper cleans up shares if the spawn itself fails; the try
        # below covers a failure in start_daemon after the sidecar is up.
        handle = _spawn_sidecar_or_clean(shares)
        pid = None
        try:
            proxy_env["WORTHLESS_SIDECAR_SOCKET"] = str(handle.socket_path)
            pid = start_daemon(proxy_env, port, pf, log_file, WorthlessConsole(quiet=True))
            # 5. Verify /healthz
            healthy = poll_health(port, timeout=10.0)
            assert healthy, "Proxy should be healthy after start"

            # Double-check with a direct HTTP call
            resp = httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=5.0)
            assert resp.status_code == 200

            # Verify PID file exists and contains correct PID
            info = read_pid(pf)
            assert info is not None
            recorded_pid, recorded_port = info
            assert recorded_pid == pid
            assert recorded_port == port

        finally:
            # 6. Stop the proxy FIRST, then the sidecar it depends on —
            # same order as up.py's supervised shutdown.
            if pid is not None and check_pid(pid):
                os.kill(pid, signal.SIGTERM)
                # Wait for graceful shutdown
                for _ in range(20):
                    if not check_pid(pid):
                        break
                    time.sleep(0.25)
                else:
                    # Force kill if SIGTERM didn't work
                    os.kill(pid, signal.SIGKILL)

            shutdown_sidecar(handle)

            # 7. Clean up PID file
            pf.unlink(missing_ok=True)
            assert not pf.exists(), "PID file should be gone after cleanup"
