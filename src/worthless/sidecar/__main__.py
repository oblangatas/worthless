"""Env-configured sidecar entry point.

Launches the sidecar server from two XOR-share files and an allowlist,
then serves until ``SIGTERM``/``SIGINT``. Intended to be the container
entrypoint in ``docker/sidecar/Dockerfile`` (WOR-307 Day 3 prototype)
and usable directly from systemd / launchd in production.

Usage::

    python -m worthless.sidecar

Environment:

* ``WORTHLESS_SIDECAR_SOCKET``      Pathname AF_UNIX socket to bind.
* ``WORTHLESS_SIDECAR_SHARE_A``     Path to first XOR share file (raw bytes).
* ``WORTHLESS_SIDECAR_SHARE_B``     Path to second XOR share file (raw bytes).
* ``WORTHLESS_SIDECAR_ALLOWED_UID`` CSV of uids permitted to connect.
* ``WORTHLESS_SIDECAR_DRAIN_TIMEOUT`` (opt) Seconds to wait for in-flight
                                    handlers on shutdown; default ``5.0``.
* ``WORTHLESS_LOG_LEVEL`` (opt)     One of ``DEBUG|INFO|WARNING|ERROR|CRITICAL``
                                    (case-insensitive); default ``INFO``.
                                    Invalid value → rc=1.

Exit codes:

* ``0``  — graceful shutdown after signal
* ``1``  — config error (missing env, unreadable share, empty allowlist)
* ``2``  — bind failure

See ``engineering/ipc-contract.md`` for the wire contract this server honours.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import stat
import sys
from pathlib import Path

from worthless.cli.errors import WorthlessError

# Module-level import is load-bearing: tests patch
# ``_hardening.set_dumpable_zero``/``_hardening.check_yama_ptrace_scope``
# as module attributes to verify call order and refusal behaviour.
# Replacing this with ``from ._hardening import set_dumpable_zero, ...``
# silently breaks those tests (patches wouldn't apply to the local name).
from worthless.sidecar import _hardening
from worthless.sidecar.backends.fernet import FernetBackend
from worthless.sidecar.server import start_sidecar

_LOG = logging.getLogger("worthless.sidecar")

_REQUIRED_ENV = (
    "WORTHLESS_SIDECAR_SOCKET",
    "WORTHLESS_SIDECAR_SHARE_A",
    "WORTHLESS_SIDECAR_SHARE_B",
    "WORTHLESS_SIDECAR_ALLOWED_UID",
)

_PROBE_TIMEOUT_S = 1.0
_DEFAULT_DRAIN_TIMEOUT_S = 5.0

# Canonical stdlib level names. Aliases (``WARN``, ``FATAL``) are
# intentionally excluded — we don't want operator typos to silently
# resolve to a level whose name isn't in our docs. ``logging.getLevelName``
# would happily accept them otherwise. ``getLevelNamesMapping`` would
# be the cleaner check but it's 3.11+; we floor at 3.10.
_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


def _load_shares(a_path: Path, b_path: Path) -> tuple[bytes, bytes]:
    """Read two XOR shares from disk; the sidecar deliberately avoids any keyring fallback.

    See §11 of ``engineering/sidecar-topology.md`` for the no-keyring decision and
    why a keyring fallback would collapse the two-share split into one secret.
    """
    share_a = a_path.read_bytes()
    share_b = b_path.read_bytes()
    if len(share_a) != len(share_b):
        raise ValueError(f"share length mismatch: {len(share_a)} vs {len(share_b)}")
    return share_a, share_b


def _resolve_log_level(raw: str | None) -> int | None:
    """Map a ``WORTHLESS_LOG_LEVEL`` env value to a ``logging`` int.

    Returns the int level on success, ``None`` on a name we don't
    accept so the caller can ``return 1`` and emit a hint. ``None``
    or empty input defaults to ``INFO`` to keep the no-config happy
    path unchanged from pre-WOR-308 behavior.
    """
    if not raw:
        return logging.INFO
    name = raw.strip().upper()
    if name not in _VALID_LOG_LEVELS:
        return None
    level = logging.getLevelName(name)
    return level if isinstance(level, int) else None


async def _drain_server(
    server: asyncio.AbstractServer,
    stop: asyncio.Event,
    drain_timeout: float,
) -> None:
    """Shut the sidecar down with a bounded drain deadline.

    Blocks on ``stop``; then stops accepting new connections and waits up to
    ``drain_timeout`` seconds for in-flight handlers to finish. On deadline
    expiry, cancels the tracked handler tasks registered by
    ``start_sidecar`` on ``server._worthless_handler_tasks``.

    Pre-3.12 ``asyncio.Server.wait_closed`` returns as soon as the listener
    closes — it does **not** wait for connection tasks — so we drain the
    tracked-task set directly rather than leaning on ``wait_closed``.
    That also keeps behavior consistent on 3.12+, where ``wait_closed``
    *does* wait on connections.
    """
    await stop.wait()
    server.close()

    tasks: set[asyncio.Task[None]] = getattr(server, "_worthless_handler_tasks", set())
    if tasks:
        _, pending = await asyncio.wait(tasks, timeout=drain_timeout)
        if pending:
            _LOG.warning(
                "drain exceeded %.1fs — cancelling %d in-flight handler(s)",
                drain_timeout,
                len(pending),
            )
            for task in pending:
                task.cancel()
            still_pending: set[asyncio.Task[None]] = set()
            try:
                _, still_pending = await asyncio.wait(pending, timeout=1.0)
            except Exception as exc:  # noqa: BLE001 — shutdown must not raise
                _LOG.debug("post-cancel wait raised: %s", exc)
            if still_pending:
                _LOG.error("%d handler(s) ignored cancel; forcing close", len(still_pending))
                # abort_clients is 3.13+; on older Pythons we've done all we can.
                abort = getattr(server, "abort_clients", None)
                if callable(abort):
                    abort()

    try:
        await asyncio.wait_for(server.wait_closed(), timeout=1.0)
    except asyncio.TimeoutError:
        _LOG.debug("wait_closed timed out during final cleanup; continuing")


def _check_socket_path_available(path: Path) -> bool:
    """Probe ``path`` to decide whether we can safely bind there.

    Returns True in three cases: the path is missing, it's a stale socket
    inode (``connect`` → ``ECONNREFUSED``), or it's a socket inode whose
    peer has disappeared. The stale inode is unlinked before returning
    so the subsequent ``bind`` sees a clean path.

    Returns False when the path is occupied in a way we must not
    clobber — a live sidecar still accepting connections, or a
    non-socket file (which would indicate an operator config mistake;
    silently unlinking user data is worse than refusing to start).

    Rationale: ``asyncio.start_unix_server`` auto-unlinks *any* existing
    socket path before binding — including live ones — so two sidecars
    pointed at the same socket silently race for new connections. This
    probe closes that gap.
    """
    try:
        st = path.lstat()
    except FileNotFoundError:
        return True
    if not stat.S_ISSOCK(st.st_mode):
        _LOG.error("refusing to bind: %s exists and is not a socket", path)
        return False
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(_PROBE_TIMEOUT_S)
    try:
        probe.connect(str(path))
    except (ConnectionRefusedError, FileNotFoundError):
        # Stale inode — no one is accept()ing. Clear and proceed.
        path.unlink(missing_ok=True)
        return True
    except OSError as exc:
        _LOG.error("probe of existing socket %s failed: %s", path, exc)
        return False
    else:
        _LOG.error("sidecar already running on %s", path)
        return False
    finally:
        probe.close()


def _parse_allowlist(raw: str) -> tuple[int, ...]:
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if not parts:
        raise ValueError("allowlist is empty")
    return tuple(int(p) for p in parts)


async def _run() -> int:
    missing = [k for k in _REQUIRED_ENV if not os.environ.get(k)]
    if missing:
        _LOG.error("missing required env: %s", ", ".join(missing))
        return 1

    socket_path = Path(os.environ["WORTHLESS_SIDECAR_SOCKET"])
    share_a = Path(os.environ["WORTHLESS_SIDECAR_SHARE_A"])
    share_b = Path(os.environ["WORTHLESS_SIDECAR_SHARE_B"])
    try:
        allowed = _parse_allowlist(os.environ["WORTHLESS_SIDECAR_ALLOWED_UID"])
    except ValueError as exc:
        _LOG.error("bad WORTHLESS_SIDECAR_ALLOWED_UID: %s", exc)
        return 1

    # Parse drain_timeout BEFORE binding so a bad value fails fast without
    # the cost (and operator confusion) of a bind/unbind cycle.
    try:
        drain_timeout = float(
            os.environ.get("WORTHLESS_SIDECAR_DRAIN_TIMEOUT", str(_DEFAULT_DRAIN_TIMEOUT_S))
        )
    except ValueError as exc:
        _LOG.error("bad WORTHLESS_SIDECAR_DRAIN_TIMEOUT: %s", exc)
        return 1

    try:
        shares = _load_shares(share_a, share_b)
    except (OSError, ValueError) as exc:
        _LOG.error("share load failed: %s", exc)
        return 1

    try:
        backend = FernetBackend(shares=shares)
    except ValueError as exc:
        _LOG.error("backend init failed: %s", exc)
        return 1

    if not _check_socket_path_available(socket_path):
        return 2

    try:
        server = await start_sidecar(
            socket_path=socket_path,
            backend=backend,
            allowed_uids=allowed,
        )
    except OSError as exc:
        _LOG.error("bind failed on %s: %s", socket_path, exc)
        return 2

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _request_stop() -> None:
        _LOG.info("shutdown signal received; closing")
        stop.set()

    # add_signal_handler wires SIGTERM/SIGINT to the running loop safely;
    # signal.signal() would fight with asyncio's internal wakeup fd.
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _request_stop)

    _LOG.info(
        "sidecar ready on %s (allowed_uids=%s, backend_caps=%s, drain_timeout=%.1fs)",
        socket_path,
        list(allowed),
        ("seal", "open", "attest"),
        drain_timeout,
    )
    # Print a stable, machine-parseable ready line for supervisors.
    print(f"sidecar: ready socket={socket_path}", flush=True)

    try:
        await _drain_server(server, stop, drain_timeout=drain_timeout)
    except Exception as exc:  # noqa: BLE001 — best-effort drain
        _LOG.warning("drain raised during shutdown: %s", exc)
    _LOG.info("sidecar shut down cleanly")
    return 0


def main() -> int:
    raw_level = os.environ.get("WORTHLESS_LOG_LEVEL")
    level = _resolve_log_level(raw_level)
    if level is None:
        # basicConfig hasn't run yet — print to stderr directly so the
        # operator sees the error even with logging unconfigured.
        print(
            f"sidecar: bad WORTHLESS_LOG_LEVEL={raw_level!r}; "
            f"expected one of {sorted(_VALID_LOG_LEVELS)}",
            file=sys.stderr,
            flush=True,
        )
        return 1
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Hardening must run before share bytes enter the address space
    # (PR_SET_DUMPABLE=0 covers crashes mid-decrypt) and before the
    # IPC socket binds.
    #
    # assert_hardening_applied() validates AFTER the calls that the
    # kernel actually honored them — if an LSM/seccomp filter silently
    # no-op'd the prctl in the parent's preexec_fn, /proc/self/status
    # will report NoNewPrivs=0 or Dumpable=1 and we refuse to bind.
    # This is the post-spawn check security-engineer M2 required.
    #
    # YAMA gating (CodeRabbit fix): in Docker two-uid mode the kernel
    # uid wall (proxy_uid != crypto_uid) already blocks ptrace and
    # /proc/<pid>/mem regardless of YAMA scope. Refusing on
    # ptrace_scope=0 there would block legitimate startup on hosts
    # we can't tune (Render/Fly/managed Kubernetes). In bare-metal
    # same-uid mode, YAMA *is* the primary defense — refusal must
    # stay loud. We use the same env signal that gates priv-drop in
    # deploy/start.py: when WORTHLESS_DOCKER_PRIVDROP_REQUIRED=1 the
    # uid wall is in place and YAMA is defense-in-depth (warn-only);
    # otherwise YAMA refusal stays mandatory.
    try:
        _hardening.set_dumpable_zero()
        if os.environ.get("WORTHLESS_DOCKER_PRIVDROP_REQUIRED") == "1":
            try:
                _hardening.check_yama_ptrace_scope()
            except WorthlessError as exc:
                _LOG.warning(
                    "YAMA ptrace_scope is permissive but two-uid Docker "
                    "topology blocks cross-uid ptrace at the kernel; "
                    "treating as defense-in-depth: %s",
                    exc,
                )
        else:
            _hardening.check_yama_ptrace_scope()
        _hardening.assert_hardening_applied()
    except WorthlessError as exc:
        print(f"sidecar: {exc}", file=sys.stderr, flush=True)
        return 1
    return asyncio.run(_run())


if __name__ == "__main__":
    sys.exit(main())
