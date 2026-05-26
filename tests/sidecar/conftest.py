"""Shared sidecar test fixtures (subprocess env, share files).

Extracted from ``test_shutdown.py`` so other sidecar tests
(env-config, future health checks) can reuse the same setup
without duplication. Pytest autodiscovers every fixture in this
file for any test in ``tests/sidecar/``.

See ``engineering/ipc-contract.md`` for the env contract these fixtures wire up.
"""

from __future__ import annotations

import base64
import os
import secrets
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

# WOR-582: every test in tests/sidecar/ spawns a real sidecar subprocess.
# Running them under xdist -n auto causes nondeterministic worker crashes
# (same root cause as the readline/select fix in the test helpers).
# Marking the whole directory real_ipc routes all these tests to the serial
# CI pass (-n0 -m "real_ipc and not docker") instead of the parallel pass.
pytestmark = pytest.mark.real_ipc

# AF_UNIX sun_path is 104 bytes on macOS; pytest's tmp_path on macOS
# already eats ~90 bytes so we go straight to /tmp/w-* with mkdtemp.
_SUN_PATH_MAX = 104


def _write_shares(dir_: Path) -> tuple[Path, Path]:
    """Write two 44-byte XOR shares that reconstruct a valid Fernet key."""
    key = base64.urlsafe_b64encode(secrets.token_bytes(32))
    share_a = secrets.token_bytes(len(key))
    share_b = bytes(a ^ k for a, k in zip(share_a, key, strict=True))
    a_path = dir_ / "share_a"
    b_path = dir_ / "share_b"
    a_path.write_bytes(share_a)
    b_path.write_bytes(share_b)
    a_path.chmod(0o600)
    b_path.chmod(0o600)
    return a_path, b_path


@pytest.fixture
def sidecar_env() -> Iterator[tuple[Path, dict[str, str]]]:
    """Yield (socket_path, env) for spawning ``python -m worthless.sidecar``.

    Uses ``/tmp/w-*`` directly (not pytest's tmp_path) to stay inside the
    104-byte AF_UNIX ``sun_path`` limit on macOS, same rationale as
    ``tests/ipc/conftest.py::sidecar_socket_path``.
    """
    base = Path(tempfile.mkdtemp(prefix="w-", dir="/tmp"))
    sock = base / "s.sock"
    if len(str(sock)) >= _SUN_PATH_MAX:
        pytest.skip(f"tmp path too long for AF_UNIX: {sock}")
    a_path, b_path = _write_shares(base)
    env = {
        **os.environ,
        "WORTHLESS_SIDECAR_SOCKET": str(sock),
        "WORTHLESS_SIDECAR_SHARE_A": str(a_path),
        "WORTHLESS_SIDECAR_SHARE_B": str(b_path),
        "WORTHLESS_SIDECAR_ALLOWED_UID": str(os.getuid()),
    }
    try:
        yield sock, env
    finally:
        for p in (sock, a_path, b_path):
            try:
                p.unlink()
            except OSError:
                pass
        try:
            base.rmdir()
        except OSError:
            pass
