"""wrap command -- ephemeral proxy + child process lifecycle.

``worthless wrap python main.py`` starts a transparent proxy on the same
port ``worthless lock`` wrote into the user's ``.env`` (default 8787,
overridable via ``WORTHLESS_PORT``) and runs the child against it.

Wrap injects ``*_BASE_URL`` env vars into the child so it hits the local
proxy even without direnv or a pre-loaded ``.env``. Vars already present in
the parent environment (e.g. loaded by direnv) are left unchanged.  Its job
is process supervision: spawn proxy on lock's port, inject provider URLs,
spawn child, wait, clean up.

If lock's port is already serving (e.g. ``worthless up`` is running), wrap
fails fast with a clean error — the two commands are alternatives, not
combinable. Run one or the other.
"""

from __future__ import annotations

import logging
import os
import re
import socket
import subprocess  # nosec B404
import sys
import threading

import aiosqlite
import typer

from worthless._async import run_sync
from worthless.cli.bootstrap import WorthlessHome, get_home
from worthless.cli.errors import ErrorCode, WorthlessError, error_boundary, sanitize_exception
from worthless.cli.platform import fail_if_windows, popen_platform_kwargs
from worthless.cli.sentinel import is_partial, read_sentinel
from worthless.cli.process import (
    build_proxy_env,
    check_proxy_health,
    create_liveness_pipe,
    disable_core_dumps,
    forward_signals,
    poll_health,
    resolve_port,
    spawn_proxy,
)
from worthless.cli.sidecar_lifecycle import (
    SidecarHandle,
    shutdown_sidecar,
    spawn_sidecar,
    split_to_tmpfs,
)

logger = logging.getLogger(__name__)

# Provider → env var name for *_BASE_URL injection. ``wrap`` uses this to
# route the child through the local proxy without requiring direnv or a
# pre-loaded .env.  Unknown protocols fall back to
# ``{PROTO.upper().replace('-','_')}_BASE_URL`` (POSIX-safe).
_PROVIDER_URL_VAR: dict[str, str] = {
    "openai": "OPENAI_BASE_URL",
    "anthropic": "ANTHROPIC_BASE_URL",
    "openrouter": "OPENROUTER_BASE_URL",
}

# Allow-list for alias and protocol values used in URL path / env var
# construction. Stored values originate from the local worthless DB (no
# remote input), but a tampered DB could store arbitrary strings — validate
# before interpolating into the child environment.
_ALIAS_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_PROTO_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


def _port_in_use(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    """True if *port* on *host* currently accepts a TCP connection.

    Used to give a precise error message when ``spawn_proxy`` fails to
    bind. A best-effort probe; TOCTOU between this check and the actual
    bind is fine because we only use it for diagnostic messaging.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _diagnose_proxy_failure(port: int, exc: Exception) -> str:
    """Return a precise user-facing message when ``spawn_proxy`` fails.

    Three cases:
      1. Port serves a worthless proxy → ``up`` is already running, name it.
      2. Port serves something else → tell the user how to switch ports.
      3. Port is free → bubble up the original exception (some other bug).

    Uses :func:`worthless.cli.process.check_proxy_health` for the daemon
    probe — same canonical heuristic as ``status``, the MCP server, and
    the default-command flow, so wrap doesn't drift.
    """
    if not _port_in_use(port):
        return sanitize_exception(exc, generic="failed to start proxy")
    if check_proxy_health(port).get("healthy"):
        return (
            f"wrap couldn't bind port {port}: a worthless daemon is already "
            f"serving it (`worthless up` is running). Either run your command "
            f"directly (the daemon proxies it already), or stop the daemon "
            f"and re-run wrap."
        )
    return (
        f"wrap couldn't bind port {port}: another process holds it. "
        f"Stop that process, or set `WORTHLESS_PORT` to a free port "
        f"and re-run `worthless lock` so .env points at the same port."
    )


def _list_enrolled_aliases(home: WorthlessHome) -> list[tuple[str, str]]:
    """Return ``(alias, protocol)`` pairs. Empty when the DB is absent.

    Kept for the empty-DB guard in ``wrap`` (no enrolled keys → friendly
    error). The protocol field isn't used anymore but is preserved in the
    return shape so existing tests stay green.

    Uses a direct SQLite read — no Fernet key, no IPC socket required. This
    keeps the pre-flight enrollment check independent of sidecar readiness,
    which matters under WORTHLESS_FERNET_IPC_ONLY=1 where the sidecar has not
    yet started when this guard runs.
    """
    if not home.db_path.exists():
        return []

    async def _query() -> list[tuple[str, str]]:
        async with aiosqlite.connect(str(home.db_path)) as db:
            cursor = await db.execute(
                "SELECT s.key_alias, s.provider "
                "FROM shards s "
                "JOIN enrollments e ON s.key_alias = e.key_alias "
                "ORDER BY s.key_alias"
            )
            rows = await cursor.fetchall()
            return [(str(r[0]), str(r[1])) for r in rows if r[0] and r[1]]

    try:
        return run_sync(_query())
    except (OSError, aiosqlite.Error) as exc:
        logger.debug("alias list failed: %s", exc, exc_info=True)
        return []


def _run_child_and_wait(child: subprocess.Popen) -> int:
    """Wait for child to exit, return its exit code."""
    child.wait()
    return child.returncode


def _cleanup_proxy(
    proxy: subprocess.Popen,
    write_fd: int | None = None,
    timeout: float = 5.0,
) -> None:
    """Shut down the proxy process gracefully.

    1. Close write_fd (triggers EOF on liveness pipe -> proxy self-terminates)
    2. Terminate proxy
    3. Wait with timeout, SIGKILL if stuck
    """
    # Close liveness pipe write end
    if write_fd is not None:
        try:
            os.close(write_fd)
        except OSError:
            pass

    if proxy.poll() is not None:
        return  # Already dead

    try:
        proxy.terminate()
        proxy.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proxy.kill()
        proxy.wait(timeout=2)


def _cleanup_lifecycle(
    proxy: subprocess.Popen | None,
    write_fd: int | None,
    sidecar: SidecarHandle | None,
) -> None:
    """Tear down proxy and sidecar in the correct order.

    Proxy first so any in-flight upstream forwards complete; then sidecar.
    Mirrors ``_supervise_proxy_with_sidecar``'s shutdown ordering in
    ``up.py``. Each step is best-effort — a failure in one must not block
    the other.
    """
    if proxy is not None:
        try:
            _cleanup_proxy(proxy, write_fd)
        except Exception:  # noqa: S110 — best-effort cleanup; sidecar shutdown still required  # nosec B110
            pass
    elif write_fd is not None:
        try:
            os.close(write_fd)
        except OSError:
            pass
    if sidecar is not None:
        try:
            shutdown_sidecar(sidecar)
        except Exception:  # noqa: S110 — best-effort cleanup  # nosec B110
            pass


def _warn_if_sentinel_degraded(home: WorthlessHome) -> None:
    """WOR-658 Fix 8: if the last lock's bind-confirmation left a DEGRADED
    sentinel, warn the user before spawning the child. Cheap stderr write —
    no failure path; missing or unreadable sentinel is silent.
    """
    try:
        sentinel = read_sentinel(home.base_dir)
    except Exception:  # noqa: BLE001 — best-effort warn, never crash wrap
        return
    if not is_partial(sentinel):
        return
    sys.stderr.write(
        "[WARN] Last `worthless lock` left a DEGRADED sentinel — "
        "OpenClaw routing is not proven.\n"
        "       Run `worthless doctor` (or `worthless unlock` to roll back) "
        "before relying on this child.\n"
    )
    sys.stderr.flush()


def register_wrap_commands(app: typer.Typer) -> None:
    """Register the ``wrap`` command on the Typer app."""

    @app.command(
        context_settings={"allow_extra_args": True, "allow_interspersed_args": False},
    )
    @error_boundary
    def wrap(
        ctx: typer.Context,
        command: list[str] = typer.Argument(..., help="Command to run (e.g. python main.py)"),
    ) -> None:
        """Start ephemeral proxy, inject env vars, run COMMAND, clean up."""
        fail_if_windows()

        # Load home, verify keys enrolled
        home = get_home()
        aliases = _list_enrolled_aliases(home)
        if not aliases:
            raise WorthlessError(
                ErrorCode.KEY_NOT_FOUND,
                "No keys enrolled. Run 'worthless lock' first.",
            )

        # WOR-658 Fix 8: warn the user if the last lock's bind-confirmation
        # left a DEGRADED sentinel. wrap is the magic-moment command —
        # silently spawning a child whose proxy might not be in the path is
        # exactly the silent-bypass class WOR-658 was built to expose.
        _warn_if_sentinel_degraded(home)

        # Suppress core dumps
        disable_core_dumps()

        # The proxy refuses to start without an IPC peer, so the sidecar
        # must come up first. ``up.py`` uses the same ordering.
        sidecar: SidecarHandle | None = None
        try:
            shares = split_to_tmpfs(home.fernet_key, home.base_dir)
            socket_path = shares.run_dir / "sidecar.sock"
            sidecar = spawn_sidecar(socket_path, shares, allowed_uid=os.getuid())
        except WorthlessError:
            # Re-raise WorthlessError directly — don't overwrite
            # SIDECAR_NOT_READY or other structured error codes with a
            # generic PROXY_UNREACHABLE.
            _cleanup_lifecycle(proxy=None, write_fd=None, sidecar=sidecar)
            raise
        except Exception as exc:
            _cleanup_lifecycle(proxy=None, write_fd=None, sidecar=sidecar)
            raise WorthlessError(
                ErrorCode.PROXY_UNREACHABLE,
                sanitize_exception(exc, generic="failed to start sidecar"),
            ) from exc

        # Wrap pipe creation and env build so the sidecar is torn down if
        # either step raises (e.g. OS fd exhaustion or keyring error in
        # build_proxy_env).
        try:
            # Create liveness pipe
            read_fd, write_fd = create_liveness_pipe()

            # Build proxy environment with the sidecar socket path threaded in.
            proxy_env = build_proxy_env(home)
            proxy_env["WORTHLESS_SIDECAR_SOCKET"] = str(sidecar.socket_path)

            # In IPC-only mode the sidecar holds the Fernet key; the proxy
            # must NOT receive it in its environment. Defense in depth — the
            # canonical scrub lives in prepare_proxy_env, but scrubbing here
            # too keeps this call site self-evidently safe.
            proxy_env.pop("WORTHLESS_FERNET_KEY", None)
        except Exception:
            _cleanup_lifecycle(proxy=None, write_fd=None, sidecar=sidecar)
            raise

        # Spawn proxy on the same port `lock` wrote to .env so the child's
        # *_BASE_URL values resolve. (v0.3.4 fix: pre-fix this was port=0,
        # which gave the proxy a random port the child couldn't discover —
        # post-8rqs wrap stopped injecting BASE_URLs into child env, so the
        # child only sees .env, which holds lock's port.)
        target_port = resolve_port(None)

        # Pre-check the port BEFORE spawn_proxy. The realistic conflict
        # (e.g. ``worthless up`` already running on this port) is far
        # nastier than a clean failure: ``Popen(port=8787)`` returns
        # successfully because Popen doesn't wait on uvicorn's bind;
        # the new uvicorn child fails to bind in the background; then
        # ``poll_health(8787)`` polls the *foreign* daemon (which IS
        # healthy) and returns True. Wrap thinks ITS proxy is up, the
        # child runs against the foreign daemon, and the child never
        # learns it's piggybacking. No exception ever raises — neither
        # this function's exception path nor the ``poll_health``-timeout
        # fallback below — so this pre-check is the ONLY guard against
        # the silent-piggyback bug. Do not delete it on the assumption
        # the timeout fallback covers it (empirically: it never fires
        # in this case, because there's no timeout to fall back from).
        # TOCTOU between this check and spawn_proxy is sub-millisecond
        # in practice; the post-spawn ``poll_health``-timeout fallback
        # below catches the rare race where a daemon starts AFTER our
        # pre-check passed.
        if _port_in_use(target_port):
            os.close(read_fd)
            os.close(write_fd)
            _cleanup_lifecycle(proxy=None, write_fd=None, sidecar=sidecar)
            raise WorthlessError(
                ErrorCode.PROXY_UNREACHABLE,
                _diagnose_proxy_failure(
                    target_port,
                    OSError(f"port {target_port} already in use"),
                ),
            )

        try:
            proxy, port = spawn_proxy(
                env=proxy_env,
                port=target_port,
                liveness_fd=read_fd,
            )
        except Exception as exc:
            os.close(read_fd)
            _cleanup_lifecycle(proxy=None, write_fd=write_fd, sidecar=sidecar)
            raise WorthlessError(
                ErrorCode.PROXY_UNREACHABLE,
                _diagnose_proxy_failure(target_port, exc),
            ) from exc

        # Close read_fd in parent (proxy has it)
        os.close(read_fd)

        # Poll health. If we time out it usually means uvicorn child
        # failed to bind asynchronously (race that slipped past the
        # pre-check above) or a slower startup issue. Run the same
        # diagnostic so the user gets the actionable message instead of
        # a generic timeout.
        healthy = poll_health(port, timeout=15.0)
        if not healthy:
            _cleanup_lifecycle(proxy=proxy, write_fd=write_fd, sidecar=sidecar)
            raise WorthlessError(
                ErrorCode.PROXY_UNREACHABLE,
                _diagnose_proxy_failure(
                    target_port,
                    TimeoutError("proxy failed to become healthy within 15s"),
                ),
            )

        full_command = list(command) + ctx.args
        child_env = dict(os.environ)
        # Re-inject *_BASE_URL for each enrolled provider so wrap is
        # self-contained without requiring direnv or a pre-loaded .env.
        # Only sets vars absent from the parent env — direnv users keep
        # their value. Restores the _build_child_env contract deleted in
        # 4f496c9.
        for alias, protocol in aliases:
            if not _ALIAS_RE.match(alias):
                logger.warning("wrap: skipping alias %r — contains unsafe characters", alias)
                continue
            if not _PROTO_RE.match(protocol):
                logger.warning("wrap: skipping protocol %r — contains unsafe characters", protocol)
                continue
            var = _PROVIDER_URL_VAR.get(
                protocol,
                f"{protocol.upper().replace('-', '_')}_BASE_URL",
            )
            if var not in child_env:
                child_env[var] = f"http://127.0.0.1:{port}/{alias}/v1"

        # Spawn child
        try:
            child = subprocess.Popen(  # nosec B603
                full_command,
                env=child_env,
                **popen_platform_kwargs(detach=True),
            )
        except Exception as exc:
            _cleanup_lifecycle(proxy=proxy, write_fd=write_fd, sidecar=sidecar)
            raise WorthlessError(
                ErrorCode.WRAP_CHILD_FAILED,
                sanitize_exception(exc, generic="failed to start child process"),
            ) from exc

        # Register signal forwarding
        forward_signals(proxy=proxy, child=child)

        # Monitor proxy in background -- warn on crash but don't kill child
        def _watch_proxy():
            proxy.wait()
            if child.poll() is None:
                # Proxy died while child still running
                sys.stderr.write(
                    "worthless: warning: proxy crashed mid-session, "
                    "child continues without protection\n"
                )
                sys.stderr.flush()

        watcher = threading.Thread(target=_watch_proxy, daemon=True)
        watcher.start()

        # Wrap child wait + summary + cleanup in try/finally so
        # KeyboardInterrupt and unexpected exceptions still tear down proxy
        # and sidecar rather than leaving orphaned processes.
        try:
            # Wait for child
            exit_code = _run_child_and_wait(child)

            # Print post-run summary before cleanup. Uses the same canonical
            # health probe as ``_diagnose_proxy_failure`` above and ``status``.
            try:
                info = check_proxy_health(port)
                count = info.get("requests_proxied", 0)
                if count:
                    sys.stderr.write(f"worthless: proxied {count} requests\n")
                    sys.stderr.flush()
            except Exception:  # noqa: S110 — best-effort summary  # nosec B110
                pass
        finally:
            # Clean up proxy first, then sidecar (mirrors ``up.py`` ordering).
            _cleanup_lifecycle(proxy=proxy, write_fd=write_fd, sidecar=sidecar)

        raise typer.Exit(code=exit_code)
