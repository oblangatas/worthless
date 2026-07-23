"""Red-team leakage tests for the sidecar's own logs (WOR-826).

The sidecar is the one process that reconstructs the Fernet key from raw share
bytes. These tests actively try to make it emit that material — driving its
error paths in a real subprocess and sweeping stdout+stderr — plus prove the
redaction filter and the redacting excepthook actually act in the running
process. Honest by design: T3 pins the shapes redaction does NOT cover.
"""

from __future__ import annotations

import logging
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from worthless.cli.log_redaction import RedactingFilter, _redact

from ._sentinels import (
    KEY_SENTINEL_B64,
    PROVIDER_TOKEN,
    SHARE_MARKER,
    grep_all,
    null_keyring_env,
)

pytestmark = pytest.mark.real_ipc

_RUN = "from worthless.sidecar.__main__ import _configure_logging"


def _spawn_sidecar(
    share_a: bytes, share_b: bytes, *, socket_occupied: bool = False
) -> subprocess.CompletedProcess[bytes]:
    """Spawn a real sidecar against the given share bytes; return the finished proc.

    Share/backend error paths return rc=1 before the socket binds. With
    ``socket_occupied=True`` a regular file sits at the socket path, so
    ``_check_socket_path_available`` refuses to bind (rc=2) — forcing an exit
    *after* the backend (and reconstructed key) exist. Either way the process
    exits promptly; no server lifecycle to manage.
    """
    base = Path(tempfile.mkdtemp(prefix="w-leak-", dir="/tmp"))
    a_path, b_path, sock = base / "share_a", base / "share_b", base / "s.sock"
    a_path.write_bytes(share_a)
    b_path.write_bytes(share_b)
    if socket_occupied:
        sock.write_text("not a socket")
    env = null_keyring_env(
        WORTHLESS_SIDECAR_SOCKET=str(sock),
        WORTHLESS_SIDECAR_SHARE_A=str(a_path),
        WORTHLESS_SIDECAR_SHARE_B=str(b_path),
        WORTHLESS_SIDECAR_ALLOWED_UID="1000",
    )
    try:
        return subprocess.run(
            [sys.executable, "-m", "worthless.sidecar"],
            env=env,
            capture_output=True,  # bytes, not text: the leak sweep must see raw bytes
            timeout=30,
        )
    finally:
        for p in (a_path, b_path, sock):
            p.unlink(missing_ok=True)
        base.rmdir()


# ---------------------------------------------------------------- T1: e2e sweep


def test_share_length_mismatch_path_leaks_nothing() -> None:
    """A length-mismatch error must report lengths only — never share bytes."""
    marker = SHARE_MARKER.encode()
    proc = _spawn_sidecar(marker + secrets.token_bytes(40), marker + secrets.token_bytes(8))
    assert proc.returncode == 1
    assert b"share load failed" in proc.stderr  # path was actually exercised
    assert not grep_all(SHARE_MARKER).leaked_in(proc.stdout, proc.stderr)


def test_invalid_fernet_key_path_leaks_nothing() -> None:
    """Equal-length shares that XOR to a bad key: no key/share bytes in output."""
    marker = SHARE_MARKER.encode()
    a = marker + secrets.token_bytes(40)
    b = marker + bytes(40)  # XOR leaves marker region intact, key is invalid b64 shape
    proc = _spawn_sidecar(a, b)
    assert proc.returncode == 1
    assert b"backend init failed" in proc.stderr
    # SHARE_MARKER is the real needle here: the derived key is a XOR b, never the
    # fixed KEY_SENTINEL_B64, so only the planted share marker can actually appear.
    assert not grep_all(SHARE_MARKER).leaked_in(proc.stdout, proc.stderr)


def test_successful_key_reconstruction_then_bind_failure_leaks_nothing() -> None:
    """Exercise the key-RESIDENT path: shares XOR to a valid Fernet key so the
    backend builds and the reconstructed key lives in memory, then a non-socket
    path forces a bind refusal. Assert the key never reaches stdout/stderr."""
    key = KEY_SENTINEL_B64.encode()  # 44-char urlsafe-b64 → a valid Fernet key
    a = secrets.token_bytes(len(key))
    b = bytes(x ^ y for x, y in zip(a, key, strict=True))
    proc = _spawn_sidecar(a, b, socket_occupied=True)
    assert proc.returncode == 2  # bind refused AFTER the backend was built
    assert b"not a socket" in proc.stderr  # the post-backend path was reached
    assert not grep_all(KEY_SENTINEL_B64).leaked_in(proc.stdout, proc.stderr)


# ------------------------------------------------ T2: redaction acts (real proc)


def test_sidecar_logger_redacts_provider_token_in_real_process() -> None:
    """A provider token logged as a str arg comes out [REDACTED] in the real process."""
    code = (
        f"{_RUN}; import logging; _configure_logging(logging.INFO); "
        f"logging.getLogger('worthless.sidecar').error('boom %s', {PROVIDER_TOKEN!r})"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env=null_keyring_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "[REDACTED]" in proc.stderr
    assert PROVIDER_TOKEN not in proc.stderr


def test_root_handler_carries_redacting_filter() -> None:
    """_configure_logging must attach the filter AFTER basicConfig creates the handler."""
    code = (
        f"{_RUN}; import logging; _configure_logging(logging.INFO); "
        "h = logging.getLogger().handlers[0]; "
        "print(any(type(f).__name__ == 'RedactingFilter' for f in h.filters))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env=null_keyring_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.stdout.strip() == "True", proc.stderr


# ------------------------------------------- T2b: excepthook redacts traceback


def test_uncaught_exception_traceback_is_redacted() -> None:
    """An uncaught exception whose message carries a token must not reach stderr raw."""
    code = (
        f"{_RUN}; import logging; _configure_logging(logging.INFO); "
        f"raise ValueError('leaked {PROVIDER_TOKEN}')"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env=null_keyring_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode != 0
    assert PROVIDER_TOKEN not in proc.stderr
    assert "[REDACTED]" in proc.stderr


# --------------------------------------------------- T3: honest blind-spot pin


def test_redaction_blindspot_is_documented() -> None:
    """Pin the TRUE boundary so no report claims raw-share/key coverage."""
    # Control: provider-shaped text IS redacted.
    assert _redact(f"token {PROVIDER_TOKEN}") == "token [REDACTED]"
    # A 44-char Fernet key (no provider prefix) is NOT matched.
    assert KEY_SENTINEL_B64 in _redact(f"key {KEY_SENTINEL_B64}")
    # An exception OBJECT passed as a %-arg is stringified AFTER the filter runs,
    # so a token inside it is NOT redacted — the exact reason T4 guards the sinks.
    rec = logging.LogRecord(
        "n", logging.ERROR, "p", 1, "boom %s", (ValueError(PROVIDER_TOKEN),), None
    )
    RedactingFilter().filter(rec)
    assert PROVIDER_TOKEN in rec.getMessage()
