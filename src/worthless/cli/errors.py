"""Structured error codes (WRTLS-NNN) and exception type."""

from __future__ import annotations

import functools
import logging
import sys
import traceback
from enum import Enum, IntEnum

logger = logging.getLogger(__name__)


class ErrorCode(IntEnum):
    """Numeric codes for every anticipated CLI failure mode."""

    BOOTSTRAP_FAILED = 100
    ENV_NOT_FOUND = 101
    KEY_NOT_FOUND = 102
    SHARD_STORAGE_FAILED = 103
    PROXY_UNREACHABLE = 104
    LOCK_IN_PROGRESS = 105
    SCAN_ERROR = 106
    PORT_IN_USE = 107
    WRAP_CHILD_FAILED = 108
    PROXY_NOT_RUNNING = 109
    PLATFORM_UNSUPPORTED = 110
    UNSAFE_REWRITE_REFUSED = 111
    INVALID_INPUT = 112
    SIDECAR_CRASHED = 113
    SIDECAR_NOT_READY = 114
    DAEMON_NOT_SUPPORTED = 115
    YAMA_PTRACE_SCOPE_TOO_LOW = 116
    UNKNOWN = 199


class UnsafeReason(str, Enum):
    """Internal granular reason for ``UnsafeRewriteRefused``.

    Exposed on :attr:`UnsafeRewriteRefused.reason` and logged at DEBUG level.
    Never appears in the user-facing message.
    """

    PLATFORM = "platform"
    BASENAME = "basename"
    PATH_IDENTITY = "path_identity"
    SPECIAL_FILE = "special_file"
    SYMLINK = "symlink"
    CONTAINMENT = "containment"
    SIZE = "size"
    SNIFF = "sniff"
    DELTA = "delta"
    TOCTOU = "toctou"
    TMP_COLLISION = "tmp_collision"
    IO_ERROR = "io_error"
    LOCKED = "locked"
    VERIFY_FAILED = "verify_failed"
    FILESYSTEM = "filesystem"


_UNSAFE_REWRITE_PUBLIC_MESSAGE = "unsafe rewrite refused — your .env is unchanged"


_UNSAFE_REWRITE_HINTS: dict[UnsafeReason, str] = {
    UnsafeReason.FILESYSTEM: (
        "Your project's filesystem does not support atomic writes. "
        "Move the project to a journaled filesystem (on WSL, the Linux $HOME "
        "is recommended), or set WORTHLESS_FORCE_FS=1 to bypass at your own risk."
    ),
    UnsafeReason.LOCKED: (
        "Another worthless process is holding the lock. Wait for it to finish, then retry."
    ),
    UnsafeReason.PLATFORM: ("This platform is not supported for safe rewrites."),
    UnsafeReason.VERIFY_FAILED: (
        "Reconstruction verification failed — the derived key did not match. "
        "Retry; if the problem persists, run `worthless doctor`."
    ),
    UnsafeReason.SYMLINK: ("Target is a symlink. Replace it with a regular file and retry."),
    UnsafeReason.CONTAINMENT: (
        "Target is outside the repository. Run from the directory that owns the .env file."
    ),
    UnsafeReason.SPECIAL_FILE: (
        "Target is not a regular file. Replace it with a regular file and retry."
    ),
    UnsafeReason.BASENAME: ("Target basename is not allowed."),
    UnsafeReason.PATH_IDENTITY: ("Target path changed between resolution and open — retry."),
    UnsafeReason.SIZE: ("Target grew beyond the safe-rewrite size cap."),
    UnsafeReason.SNIFF: ("Target bytes look binary; safe rewrite is text-only."),
    UnsafeReason.DELTA: ("Rewrite delta is suspiciously large — refused as a safety measure."),
    UnsafeReason.TOCTOU: ("Target changed between baseline hash and rewrite — retry."),
    UnsafeReason.TMP_COLLISION: ("Could not allocate a unique temp-file name. Retry."),
    UnsafeReason.IO_ERROR: ("Disk I/O error during rewrite. Check disk health and retry."),
}


def unsafe_rewrite_hint(reason: UnsafeReason) -> str:
    """Return the user-facing one-line next-step hint for *reason*.

    Never leaks absolute paths, environment values, or the enum
    identifier. Always returns a string; falls back to a generic
    retry message for reasons without a bespoke hint.
    """
    return _UNSAFE_REWRITE_HINTS.get(
        reason, "Retry; if the problem persists, run `worthless doctor`."
    )


class WorthlessError(Exception):
    """CLI-layer exception carrying a structured error code."""

    def __init__(self, code: ErrorCode, message: str, *, exit_code: int = 1) -> None:
        self.code = code
        self.message = message
        self.exit_code = exit_code
        super().__init__(str(self))

    def __str__(self) -> str:  # noqa: D105
        return f"WRTLS-{self.code.value}: {self.message}"


class UnsafeRewriteRefused(WorthlessError):
    """Raised by ``safe_rewrite`` when any invariant refuses a rewrite.

    The public message is intentionally opaque. The granular cause is
    available via :attr:`reason` and is logged at DEBUG level. Neither
    absolute paths nor environment data ever appear in ``str(exc)``.
    """

    def __init__(self, reason: UnsafeReason) -> None:
        self.reason = reason
        super().__init__(
            ErrorCode.UNSAFE_REWRITE_REFUSED,
            _UNSAFE_REWRITE_PUBLIC_MESSAGE,
        )
        logger.debug("UnsafeRewriteRefused: reason=%s", reason.value)


def sanitize_exception(exc: Exception, *, generic: str = "an internal error occurred") -> str:
    """Return a user-safe single-line description for *exc*.

    Always returns the *generic* message to avoid leaking file paths, DB
    paths, stack traces, or library internals.  The original exception is
    logged at DEBUG level so operators can diagnose with ``--verbose`` or
    log-level configuration.
    """
    logger.debug("Sanitized exception: %r", exc)
    return generic


# ---------------------------------------------------------------------------
# Debug mode flag (toggled by --debug on the root CLI callback)
# ---------------------------------------------------------------------------

_debug: bool = False


def set_debug(enabled: bool) -> None:
    """Enable or disable debug mode (full tracebacks on error)."""
    global _debug  # noqa: PLW0603
    _debug = enabled


# ---------------------------------------------------------------------------
# @error_boundary — unified error handling for CLI commands
# ---------------------------------------------------------------------------


def error_boundary(fn=None, *, exit_code: int = 1):  # noqa: ANN001, ANN201
    """Decorator that catches exceptions and prints structured WRTLS errors.

    * ``WorthlessError`` → print code + message, exit with ``exc.exit_code``.
    * ``typer.Exit`` → re-raise as-is (already handled).
    * Any other ``Exception`` → wrap in WRTLS-199, exit with *exit_code*.
    * In ``--debug`` mode, full tracebacks are printed to stderr.

    Can be used bare (``@error_boundary``) or with an explicit fallback
    exit code (``@error_boundary(exit_code=2)``).
    """
    # Deferred: errors.py is imported before typer-based modules load.
    # TODO: break cycle by moving error_boundary to its own module.
    import typer

    def decorator(func):  # noqa: ANN001, ANN202
        @functools.wraps(func)
        def wrapper(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
            try:
                return func(*args, **kwargs)
            except typer.Exit:
                raise
            except WorthlessError as exc:
                if _debug:
                    traceback.print_exc(file=sys.stderr)
                else:
                    # Deferred: console imports errors, so we can't import at top.
                    from worthless.cli.console import get_console

                    console = get_console()
                    console.print_error(exc)
                    if isinstance(exc, UnsafeRewriteRefused):
                        console.print_hint(unsafe_rewrite_hint(exc.reason))
                raise typer.Exit(code=exc.exit_code) from exc
            except Exception as exc:
                if _debug:
                    traceback.print_exc(file=sys.stderr)
                else:
                    from worthless.cli.console import get_console

                    safe_msg = sanitize_exception(exc)
                    get_console().print_error(WorthlessError(ErrorCode.UNKNOWN, safe_msg))
                raise typer.Exit(code=exit_code) from exc

        return wrapper

    if fn is not None:
        # Bare @error_boundary usage
        return decorator(fn)
    # Parameterized @error_boundary(exit_code=2) usage
    return decorator
