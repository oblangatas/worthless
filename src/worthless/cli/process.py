"""Process lifecycle — pipe death detection, signal forwarding, PID files.

Shared infrastructure for ``wrap`` (ephemeral proxy + child) and ``up``
(standalone daemon) commands.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from worthless.cli.bootstrap import WorthlessHome
import os
import re
import signal
import subprocess  # nosec B404
import sys
import tempfile
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import httpx

from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.keystore import keyring_available
from worthless.cli.platform import IS_WINDOWS, check_pid_alive, popen_platform_kwargs

logger = logging.getLogger(__name__)

# Set by launchd/systemd units installed via ``worthless service install``.
_SERVICE_MANAGED_ENV = "WORTHLESS_SERVICE_MANAGED"

# Regex to capture the port from uvicorn's startup line
_UVICORN_PORT_RE = re.compile(r"Uvicorn running on http://[\d.]+:(\d+)")


def is_service_managed() -> bool:
    """True when ``worthless up`` is supervised by launchd or systemd."""
    return os.environ.get(_SERVICE_MANAGED_ENV, "").strip() == "1"


# ---------------------------------------------------------------------------
# Port resolution — canonical chain shared by ``lock``, ``up``, ``wrap``,
# and the default-command flow. One source of truth so all four commands
# write/bind/probe the same port for a given config.
# ---------------------------------------------------------------------------


def resolve_port(port_arg: int | None) -> int:
    """Resolve the proxy port from argument, env var, or default.

    Priority: explicit ``port_arg`` > ``WORTHLESS_PORT`` env > ``8787`` default.

    All consumers (``lock`` for the .env BASE_URL, ``up`` for the daemon
    bind, ``wrap`` for the ephemeral proxy bind) share this function so
    they agree on which port a child loading .env will reach.

    Raises:
        WorthlessError: when ``WORTHLESS_PORT`` is set to a non-integer
            value. Without this guard the underlying ``int()`` call would
            surface a raw ``ValueError`` traceback to every command —
            ``lock``, ``up``, ``wrap``, and the default flow. Caught
            here so the user sees a single-line CLI error.
    """
    if port_arg is not None:
        return port_arg
    env_port = os.environ.get("WORTHLESS_PORT")
    if env_port:
        try:
            return int(env_port)
        except ValueError as exc:
            raise WorthlessError(
                ErrorCode.BOOTSTRAP_FAILED,
                f"WORTHLESS_PORT must be an integer, got {env_port!r}. "
                f"Unset it (`unset WORTHLESS_PORT`) or set it to a port number.",
            ) from exc
    return 8787


def check_proxy_health(port: int) -> dict[str, object]:
    """Hit ``/healthz`` on *port* and return a status dict.

    Shared probe used by ``status`` (display health to the user),
    ``wrap`` (distinguish ``worthless up`` collision from a foreign
    process), the MCP server, and the default-command flow. Single
    canonical implementation so the heuristic doesn't drift across
    consumers.

    Returns: ``{"healthy": bool, "port": int, "mode": str | None,
    "requests_proxied": int}``. ``healthy=False`` covers connection
    refused, timeout, non-200, and non-JSON responses.
    """
    try:
        resp = httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=2.0)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "healthy": True,
                "port": port,
                "mode": data.get("mode", "up"),
                "requests_proxied": data.get("requests_proxied", 0),
            }
    except Exception:  # noqa: S110 — proxy may not be running; absence is the expected default state  # nosec B110
        pass

    return {"healthy": False, "port": port, "mode": None, "requests_proxied": 0}


# ---------------------------------------------------------------------------
# Core dump suppression
# ---------------------------------------------------------------------------


def build_proxy_env(home: WorthlessHome) -> dict[str, str]:
    """Build the environment dict for spawning a proxy process.

    When OS keyring is available, omits WORTHLESS_FERNET_KEY — the proxy
    reads from keyring directly via ``read_fernet_key()``.

    Forwards ``WORTHLESS_KEYRING_BACKEND`` so the proxy child inherits the
    parent's keyring opt-out choice. Without this, a production user who
    set ``WORTHLESS_KEYRING_BACKEND=null`` in their shell would get
    file-fallback in the CLI but the proxy child would still try the
    real OS keyring (defeating the override). Same forwarding handles
    the test-suite case (conftest sets the var; this propagates it).
    (WOR-463)
    """
    # Derive bind host without importing proxy.config (circular import risk).
    # Mirror logic from proxy/config.py _read_default_host so the env dict
    # is the single source of truth for the child process bind address.
    _host = os.environ.get("WORTHLESS_HOST", "").strip()
    if not _host:
        _mode = os.environ.get("WORTHLESS_DEPLOY_MODE", "loopback").strip().lower()
        _host = "0.0.0.0" if _mode in ("lan", "public") else "127.0.0.1"  # noqa: S104  # nosec B104
    env: dict[str, str] = {
        "WORTHLESS_DB_PATH": str(home.db_path),
        "WORTHLESS_HOME": str(home.base_dir),
        "WORTHLESS_HOST": _host,
    }
    if "WORTHLESS_KEYRING_BACKEND" in os.environ:
        env["WORTHLESS_KEYRING_BACKEND"] = os.environ["WORTHLESS_KEYRING_BACKEND"]
    if not keyring_available():
        env["WORTHLESS_FERNET_KEY"] = home.fernet_key.decode()
    return env


def disable_core_dumps() -> None:
    """Set RLIMIT_CORE to (0, 0) to prevent core dumps leaking key material.

    Silently ignored on platforms that don't support it (e.g. some CI runners).
    """
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError, AttributeError, ImportError):
        pass


# ---------------------------------------------------------------------------
# Liveness pipe — parent holds write_fd, proxy watches read_fd for EOF
# ---------------------------------------------------------------------------


def create_liveness_pipe() -> tuple[int, int]:
    """Create an OS pipe for death detection.

    Returns:
        (read_fd, write_fd).  Pass *read_fd* to the proxy via
        ``WORTHLESS_LIVENESS_FD``.  Keep *write_fd* open in the parent;
        closing it (or parent death) signals EOF to the proxy.
    """
    return os.pipe()


# ---------------------------------------------------------------------------
# Fernet key transport
# ---------------------------------------------------------------------------


@contextmanager
def fernet_transport(
    env: dict[str, str],
) -> Generator[tuple[str | None, int | None, list[int]], None, None]:
    """Context manager for Fernet key transport. Closes fds on failure.

    On Unix, creates a pipe fd for ``pass_fds``.
    On Windows, returns the key for later stdin delivery.

    Yields:
        (fernet_key, fernet_fd, extra_pass_fds).
    """
    # When keyring is available, the proxy reads the key directly — no pipe needed.
    if keyring_available():
        env.pop("WORTHLESS_FERNET_KEY", None)
        yield None, None, []
        return

    raw_key = env.pop("WORTHLESS_FERNET_KEY", None)
    fernet_fd: int | None = None
    fernet_fds: list[int] = []

    if raw_key and not IS_WINDOWS:
        r_fd, w_fd = os.pipe()
        key_bytes = raw_key.encode() if isinstance(raw_key, str) else raw_key
        written = os.write(w_fd, key_bytes)
        os.close(w_fd)
        if written != len(key_bytes):
            os.close(r_fd)
            raise OSError(f"Short write to Fernet pipe: {written}/{len(key_bytes)} bytes")
        fernet_fd = r_fd
        fernet_fds = [r_fd]

    fernet_key = raw_key if IS_WINDOWS else None
    try:
        yield fernet_key, fernet_fd, fernet_fds
    except BaseException:
        if fernet_fd is not None:
            os.close(fernet_fd)
        raise


def finalize_fernet_transport(
    proc: subprocess.Popen,
    fernet_key: str | None,
    fernet_fd: int | None,
) -> None:
    """Send Fernet key via stdin (Windows) and close parent fds."""
    if IS_WINDOWS and fernet_key and proc.stdin:
        key_bytes = fernet_key.encode() if isinstance(fernet_key, str) else fernet_key
        proc.stdin.write(key_bytes)
        proc.stdin.close()
    if fernet_fd is not None:
        os.close(fernet_fd)


def prepare_proxy_env(
    env: dict[str, str],
    fernet_fd: int | None,
    *,
    liveness_fd: int | None = None,
) -> dict[str, str]:
    """Build the full subprocess environment for a proxy process."""
    insecure = env.get("WORTHLESS_ALLOW_INSECURE", "true")
    full_env = {
        **os.environ,
        **env,
        "WORTHLESS_ALLOW_INSECURE": insecure,
    }
    # Always scrub WORTHLESS_FERNET_KEY from child env — the proxy
    # receives the key via fd (secure) or keyring, never via env.
    # Without this, os.environ bleed-through leaks the key in /proc.
    full_env.pop("WORTHLESS_FERNET_KEY", None)
    if fernet_fd is not None:
        full_env["WORTHLESS_FERNET_FD"] = str(fernet_fd)
    if liveness_fd is not None:
        full_env["WORTHLESS_LIVENESS_FD"] = str(liveness_fd)
    return full_env


def proxy_cmd(port: int, host: str = "127.0.0.1") -> list[str]:
    """Build the uvicorn command for the proxy.

    Args:
        port: Port for uvicorn to bind.
        host: Bind address.  Callers should derive this from
            ``build_proxy_env()["WORTHLESS_HOST"]`` so the env dict
            is the single source of truth for the bind address.
    """
    return [
        sys.executable,
        "-m",
        "uvicorn",
        "worthless.proxy.app:create_app",
        "--factory",
        "--host",
        host,
        "--port",
        str(port),
    ]


# ---------------------------------------------------------------------------
# Proxy spawning
# ---------------------------------------------------------------------------


def spawn_proxy(
    env: dict[str, str],
    port: int = 0,
    liveness_fd: int | None = None,
) -> tuple[subprocess.Popen, int]:
    """Start uvicorn with the proxy app.

    Args:
        env: Environment variables for the proxy (WORTHLESS_*).
        port: Port to bind.  ``0`` means OS-assigned random port.
        liveness_fd: If set, passed to the child and advertised via
            ``WORTHLESS_LIVENESS_FD``.

    Returns:
        (process, actual_port).
    """
    cmd = proxy_cmd(port, host=env.get("WORTHLESS_HOST", "127.0.0.1"))

    with fernet_transport(env) as (fernet_key, fernet_fd, fernet_fds):
        full_env = prepare_proxy_env(env, fernet_fd, liveness_fd=liveness_fd)

        pass_fds = [*fernet_fds]
        if liveness_fd is not None:
            pass_fds.append(liveness_fd)

        platform_kwargs = popen_platform_kwargs(detach=True, pass_fds=tuple(pass_fds))

        proc = subprocess.Popen(  # nosec B603
            cmd,
            env=full_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE if fernet_key else None,
            **platform_kwargs,
        )

        finalize_fernet_transport(proc, fernet_key, fernet_fd)

    if port == 0:
        # Parse actual port from uvicorn output
        actual_port = _parse_uvicorn_port(proc, timeout=15.0)
    else:
        actual_port = port

    return proc, actual_port


def _parse_uvicorn_port(proc: subprocess.Popen, timeout: float = 15.0) -> int:
    """Read uvicorn stdout until we find the port announcement."""
    assert proc.stdout is not None  # nosec B101

    # Read output in a thread so we can impose a deadline
    lines: list[str] = []

    def _reader():
        assert proc.stdout is not None  # nosec B101
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").strip()
            lines.append(line)
            m = _UVICORN_PORT_RE.search(line)
            if m:
                return

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    t.join(timeout=timeout)

    for line in lines:
        m = _UVICORN_PORT_RE.search(line)
        if m:
            return int(m.group(1))

    raise RuntimeError(
        f"Could not parse uvicorn port within {timeout}s. Output so far: {''.join(lines[:20])}"
    )


# ---------------------------------------------------------------------------
# Health polling
# ---------------------------------------------------------------------------

# Reject PIDs outside the valid range for any mainstream OS.
# Linux default pid_max is 4194304; macOS uses 99998. Shared by
# `poll_health_pid` (below) and `check_pid` (further down).
MAX_VALID_PID: int = 4_194_304


def _iter_healthz_responses(port: int, timeout: float) -> Generator[httpx.Response, None, None]:
    """Yield each 200 response from ``GET /healthz`` until *timeout*.

    Swallows connection/timeout/OS errors so callers see only successful
    responses. Private: call ``poll_health`` for liveness or
    ``poll_health_pid`` for authoritative PID resolution.
    """
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/healthz"
    with httpx.Client(timeout=2.0) as client:
        while time.monotonic() < deadline:
            try:
                resp = client.get(url)
                if resp.status_code == 200:
                    yield resp
            except (httpx.HTTPError, OSError):
                pass
            time.sleep(0.3)


def poll_health(port: int, timeout: float = 10.0) -> bool:
    """Return True if ``GET /healthz`` returns 200 within *timeout* seconds."""
    for _resp in _iter_healthz_responses(port, timeout):
        return True
    return False


def poll_health_pid(port: int, timeout: float = 10.0) -> int | None:
    """Poll ``GET /healthz`` and return the proxy's self-reported PID.

    The listening process exposes ``os.getpid()`` in the healthz payload. This
    is **not** an OS-level port→PID attribution (no ``lsof``/``ss``); callers
    must assume the payload is honest. That matches worthless's loopback
    same-UID threat model (worthless-wfz7).

    Returns the PID on success, ``None`` on timeout, non-200 response,
    malformed JSON, a payload missing the ``pid`` field, or a ``pid`` out
    of the valid range ``[2, MAX_VALID_PID]`` (in which case the caller
    is expected to fall back to its own best guess).
    """
    for resp in _iter_healthz_responses(port, timeout):
        try:
            payload = resp.json()
        except (ValueError, TypeError, httpx.HTTPError):
            return None
        if not isinstance(payload, dict):
            return None
        raw_pid = payload.get("pid")
        # bool subclasses int in Python — reject True/False.
        if isinstance(raw_pid, bool) or not isinstance(raw_pid, int):
            return None
        if raw_pid < 2 or raw_pid > MAX_VALID_PID:
            return None
        return raw_pid
    return None


# ---------------------------------------------------------------------------
# PID file management
# ---------------------------------------------------------------------------


def pid_path(home: WorthlessHome) -> Path:
    """Return the standard PID file path for a proxy daemon."""
    return home.base_dir / "proxy.pid"


def write_pid(pid_path: Path, pid: int, port: int) -> None:
    """Write PID file with ``pid\\nport`` format (0600 permissions).

    Writes atomically via a per-caller tmp file + ``os.replace`` — a
    racing ``read_pid`` can see the old content or the new, never a torn
    (truncated) state. The tmp name is unique per writer so two
    concurrent ``worthless up`` invocations can't clobber each other's
    in-flight tmp files and race the rename.
    """
    fd, tmp_name = tempfile.mkstemp(
        prefix=pid_path.name + ".",
        suffix=".tmp",
        dir=str(pid_path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        # mkstemp already creates at 0600 on POSIX; be explicit to guard
        # against umask / future cross-platform drift.
        tmp_path.chmod(0o600)
        os.write(fd, f"{pid}\n{port}\n".encode())
    except Exception:
        os.close(fd)
        tmp_path.unlink(missing_ok=True)
        raise
    else:
        os.close(fd)
    tmp_path.replace(pid_path)


def read_pid(pid_path: Path) -> tuple[int, int] | None:
    """Read PID file.  Returns ``(pid, port)`` or ``None`` if missing/corrupt."""
    try:
        text = pid_path.read_text().strip()
        parts = text.split("\n")
        if len(parts) < 2:
            return None
        return int(parts[0]), int(parts[1])
    except (FileNotFoundError, ValueError, IndexError, OSError):
        return None


def check_pid(pid: int) -> bool:
    """Return True if *pid* is alive. Cross-platform via ``psutil``.

    Rejects PIDs ≤ 1 or beyond the OS range to prevent signaling
    init, the caller's process group, or every user process.
    """
    if pid <= 1 or pid > MAX_VALID_PID:
        return False
    return check_pid_alive(pid)


def cleanup_stale_pid(pid_path: Path) -> bool:
    """Remove PID file if the recorded process is dead.

    Returns True if reclaimed (file removed or didn't exist),
    False if the process is still alive.
    """
    info = read_pid(pid_path)
    if info is None:
        # Missing or corrupt — treat as reclaimed
        try:
            pid_path.unlink(missing_ok=True)
        except OSError:
            pass
        return True

    pid, _port = info
    if check_pid(pid):
        return False  # Still alive

    pid_path.unlink(missing_ok=True)
    return True


# ---------------------------------------------------------------------------
# Signal forwarding
# ---------------------------------------------------------------------------


def forward_signals(
    proxy: subprocess.Popen,
    child: subprocess.Popen | None,
) -> None:
    """Register handlers that forward SIGINT/SIGTERM to *proxy* and *child*.

    Uses process group kill (``os.killpg``) on Unix, ``proc.terminate()``
    on Windows.  Only registers SIGINT on Windows (SIGTERM is not deliverable).
    """

    def _handler(signum: int, _frame: object) -> None:
        for proc in (child, proxy):
            if proc is not None and proc.poll() is None:
                try:
                    if IS_WINDOWS:
                        proc.terminate()
                    else:
                        os.killpg(os.getpgid(proc.pid), signum)
                except (ProcessLookupError, PermissionError, OSError):
                    pass

    signal.signal(signal.SIGINT, _handler)
    if not IS_WINDOWS:
        signal.signal(signal.SIGTERM, _handler)
