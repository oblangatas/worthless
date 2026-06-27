"""Cross-platform abstractions for process management.

Centralises all ``sys.platform == "win32"`` checks so that command modules
only import helpers, never branch on platform themselves.

Uses ``psutil`` for reliable cross-platform process management.
"""

from __future__ import annotations

import os
import sys

import psutil

from worthless.cli.errors import ErrorCode, WorthlessError

IS_WINDOWS: bool = sys.platform == "win32"

# Single source of truth for the "Platforms" section of the README. Referenced
# from the native-Windows error message so a rename or repo move only needs a
# change in one place.
PLATFORMS_URL = "https://github.com/shacharm2/worthless#platforms"

# Windows creation flags (defined here to avoid conditional imports at use sites)
_DETACHED_PROCESS = 0x00000008
_CREATE_NO_WINDOW = 0x08000000
_CREATE_NEW_PROCESS_GROUP = 0x00000200

# Module-level warning state
_warned: bool = False


def popen_platform_kwargs(
    *,
    detach: bool = False,
    pass_fds: tuple[int, ...] = (),
) -> dict:
    """Return platform-appropriate kwargs for ``subprocess.Popen``.

    On Unix: ``start_new_session=True`` for detach, ``pass_fds`` forwarded.
    On Windows: ``creationflags`` for detach, ``pass_fds`` dropped (unsupported).
    """
    if IS_WINDOWS:
        if detach:
            return {"creationflags": _DETACHED_PROCESS | _CREATE_NO_WINDOW}
        return {"creationflags": _CREATE_NEW_PROCESS_GROUP}

    kwargs: dict = {}
    if detach:
        kwargs["start_new_session"] = True
    if pass_fds:
        kwargs["pass_fds"] = pass_fds
    return kwargs


def check_pid_alive(pid: int) -> bool:
    """Return True if *pid* is alive. Cross-platform via psutil."""
    return psutil.pid_exists(pid)


def read_process_env(pid: int) -> dict[str, str]:
    """Return the live environment dict of *pid*, or {} on any error."""
    try:
        return psutil.Process(pid).environ()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {}


def pid_in_tree(root_pid: int, candidate_pid: int) -> bool:
    """Return True if *candidate_pid* is *root_pid* or one of its descendants.

    Conservative on error: if *root_pid* is gone or we lack permission to
    inspect it, returns False so the caller falls back to *root_pid*. We
    never want a transient psutil failure to silently upgrade a foreign
    PID into our pidfile.

    Walks ``children(recursive=True)``; O(N) in descendant count. For the
    current single-process uvicorn launch this is O(1). If ``proxy_cmd``
    ever gains ``--workers`` or ``--reload``, consider walking upward via
    ``psutil.Process(candidate).parents()`` instead (usually 1-2 hops).
    """
    if candidate_pid == root_pid:
        return True
    try:
        descendants = psutil.Process(root_pid).children(recursive=True)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    return any(child.pid == candidate_pid for child in descendants)


def kill_tree(pid: int, *, force: bool = False) -> None:
    """Kill a process and all its descendants.

    Uses ``psutil`` for reliable cross-platform tree kill.
    With ``force=False`` (default), sends SIGTERM (graceful).
    With ``force=True``, sends SIGKILL (immediate).

    Raises ``PermissionError`` if access is denied on the parent process.
    """
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
    except psutil.NoSuchProcess:
        return  # Already dead
    except psutil.AccessDenied:
        raise PermissionError(f"access denied for PID {pid}") from None

    method = "kill" if force else "terminate"

    for child in children:
        try:
            getattr(child, method)()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    try:
        getattr(parent, method)()
    except psutil.NoSuchProcess:
        pass
    except psutil.AccessDenied:
        raise PermissionError(f"access denied for PID {pid}") from None


def warn_windows_once(*, quiet: bool = False) -> None:
    """Print a one-shot experimental warning on Windows.

    Used by commands that are allowed to run on Windows (currently only
    ``down``). Commands that rely on POSIX process semantics should call
    :func:`fail_if_windows` instead.

    The ``down`` exemption is narrow: a user who ran a pre-guard version
    of worthless on native Windows can have a stale pidfile in
    ``%USERPROFILE%\\.worthless\\`` that needs cleaning up. ``down`` is
    still useful there. A daemon started from WSL, on the other hand,
    lives in WSL's namespace and native ``down`` cannot touch it —
    that's out of scope by design.

    Suppressed by ``--quiet`` or ``WORTHLESS_WINDOWS_ACK=1``.
    """
    global _warned  # noqa: PLW0603
    if _warned or not IS_WINDOWS or quiet:
        return
    if os.environ.get("WORTHLESS_WINDOWS_ACK"):
        return
    _warned = True
    sys.stderr.write(
        "worthless: On Windows, key material may persist in memory "
        "after forced process termination.\n"
        "Set WORTHLESS_WINDOWS_ACK=1 to suppress this message.\n"
    )
    sys.stderr.flush()


def fail_if_windows() -> None:
    """Raise ``WorthlessError`` on native Windows.

    The proxy (``up``), ``wrap``, and default-command pipelines all rely
    on POSIX-specific primitives — ``setsid``, ``os.killpg``, fd
    inheritance for fernet-key transport, and signal-group shutdown.
    On native Windows they degrade in subtle and unsafe ways, so we
    refuse to start and point users at WSL or Docker.

    ``worthless down`` stays on :func:`warn_windows_once` so a Windows
    user who somehow already has a running daemon can still clean it
    up.
    """
    if not IS_WINDOWS:
        return
    raise WorthlessError(
        ErrorCode.PLATFORM_UNSUPPORTED,
        "Native Windows is not supported. Please use WSL or run via Docker.\n"
        f"See: {PLATFORMS_URL}\n"
        "(This check does not honor WORTHLESS_WINDOWS_ACK — that variable only "
        "silences the soft warning on 'worthless down'.)",
    )
