"""Shared helpers for ``worthless service`` platform backends."""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.console import get_console
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.keystore import PLACEHOLDER_FERNET_KEY, sync_fernet_for_launchd
from worthless.cli.process import poll_health
from worthless.crypto.types import zero_buf
from worthless.storage.repository import ShardRepository


class ServiceState(str, Enum):
    NOT_INSTALLED = "not_installed"
    STOPPED = "stopped"
    RUNNING = "running"
    FAILED = "failed"


@dataclass(frozen=True)
class ServiceStatus:
    state: ServiceState
    unit_path: Path | None
    binary: str | None
    port: int
    healthy: bool
    detail: str = ""


def resolve_worthless_binary() -> Path:
    """Locate the ``worthless`` executable for unit/plist ``ExecStart``."""
    found = shutil.which("worthless")
    if found:
        return Path(found).resolve()
    fallback = Path.home() / ".local" / "bin" / "worthless"
    if fallback.is_file() and os.access(fallback, os.X_OK):
        return fallback.resolve()
    raise WorthlessError(
        ErrorCode.BOOTSTRAP_FAILED,
        "worthless binary not found on PATH. Install with `curl -sSL https://worthless.sh | sh`.",
    )


def atomic_write_text(path: Path, content: str, *, mode: int = 0o600) -> None:
    """Write *content* to *path* atomically at *mode*, refusing symlinks."""
    if path.is_symlink():
        raise WorthlessError(
            ErrorCode.UNSAFE_REWRITE_REFUSED,
            f"refusing to write through symlink: {path}",
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    if tmp.exists():
        tmp.unlink()
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.fchmod(fd, mode)
        data = content.encode("utf-8")
        os.write(fd, data)
    finally:
        os.close(fd)
    tmp.replace(path)
    path.chmod(mode)


def run_cmd(
    args: list[str],
    *,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a platform command; overridable in tests via patching."""
    return subprocess.run(  # nosec B603 — args constructed by trusted backends
        args,
        check=check,
        capture_output=capture,
        text=True,
    )


def _fernet_drift_check_result(home: WorthlessHome):
    from worthless.cli.commands.doctor.checks import fernet_drift
    from worthless.cli.commands.doctor.registry import CheckContext

    repo = ShardRepository(str(home.db_path), PLACEHOLDER_FERNET_KEY)
    ctx = CheckContext(home=home, repo=repo, fix=False, dry_run=False)
    return fernet_drift.run(ctx)


def _assert_no_fernet_drift_for_service_install(home: WorthlessHome) -> None:
    """W3-ADV-17: refuse install when keyring and file disagree (WOR-464)."""
    result = _fernet_drift_check_result(home)
    if result.get("status") == "error":
        raise WorthlessError(
            ErrorCode.KEY_NOT_FOUND,
            f"{result.get('summary', 'Fernet key drift detected')} "
            "Run `worthless doctor --explain fernet_drift` before "
            "`worthless service install`.",
        )


def preflight_service_install(home: WorthlessHome) -> None:
    """Refuse install when the proxy cannot start (no Fernet key)."""
    managed = current_platform_backend_name() in ("launchd", "systemd")
    if managed:
        _assert_no_fernet_drift_for_service_install(home)
    try:
        key = home.fernet_key
    except WorthlessError as exc:
        raise WorthlessError(
            ErrorCode.KEY_NOT_FOUND,
            "Cannot install service — the Fernet key is not available, so "
            "`worthless up` cannot start under launchd/systemd. "
            "Run `worthless doctor`. On macOS, ensure Keychain 'Always Allow' "
            "or use file-backed storage (WORTHLESS_FERNET_KEY_PATH).",
        ) from exc
    try:
        if managed:
            sync_fernet_for_launchd(home.base_dir, key=key)
    finally:
        zero_buf(key)


# worthless-rnl8: longer than the launchd cold start that produced the original
# false failure. Observed live on macOS with v0.3.11: the first spawn exited 1,
# launchd restarted it, and the proxy answered a few seconds after the old 15s
# deadline had already aborted the install. This is a ceiling on how long we
# WAIT, never a deadline the service must meet to be considered installed.
_HEALTH_WAIT_SECONDS = 45.0


def report_proxy_health(port: int, *, timeout: float = _HEALTH_WAIT_SECONDS) -> None:
    """Wait for ``/healthz``, and report honestly if it does not answer in time.

    This is deliberately NOT ``verify_*`` and deliberately does not raise.

    Every caller reaches this line only after the platform's own install/start
    calls have returned successfully — ``bootstrap`` + ``kickstart`` on launchd,
    ``enable`` + ``start`` on systemd. Arriving here is therefore proof that the
    unit is written and the service was started. The single open question is
    whether the proxy has finished coming up.

    Treating that open question as a failure is what worthless-rnl8 is: the user
    ran ``service install``, got ``WRTLS-104`` in red, and had a healthy
    service — install had simply stopped watching at 15s while launchd was
    restarting the process. A user who believes that error will uninstall
    something that works, or fall back to a foreground ``worthless up`` they
    have to babysit.

    So: say what was established, say what was not, and say how to settle it.
    """
    console = get_console()
    # The wait itself was invisible before — the operator read the silence as a
    # hang and interrupted it. Announce it before blocking.
    console.print_hint(f"Waiting up to {timeout:.0f}s for the proxy to answer on port {port}...")
    if poll_health(port, timeout=timeout):
        return
    console.print_warning(
        f"Service installed and started, but the proxy has not answered on port {port} yet. "
        "It may still be coming up — this is not an install error. "
        "Check with `worthless service status`, and `worthless service logs` if it stays down."
    )


def service_paths(home: WorthlessHome) -> tuple[Path, str]:
    """Return (log_path, worthless_home_str) for unit templates."""
    log_path = home.base_dir / "proxy.log"
    return log_path, str(home.base_dir)


_LAUNCHD_HOME_RE = re.compile(
    r"<key>WORTHLESS_HOME</key>\s*<string>([^<]+)</string>",
    re.DOTALL,
)
_SYSTEMD_HOME_RE = re.compile(r"Environment=WORTHLESS_HOME=([^\s\n]+)")


def _worthless_home_paths_in_unit(content: str) -> list[str]:
    """Extract ``WORTHLESS_HOME`` path(s) embedded in a launchd plist or systemd unit."""
    paths: list[str] = []
    launchd_match = _LAUNCHD_HOME_RE.search(content)
    if launchd_match:
        paths.append(launchd_match.group(1))
    systemd_match = _SYSTEMD_HOME_RE.search(content)
    if systemd_match:
        paths.append(systemd_match.group(1))
    return paths


def unit_file_matches_home(path: Path, home: WorthlessHome) -> bool:
    """Return True when *path* is a unit/plist for this ``WORTHLESS_HOME``.

    Install writes ``str(home.base_dir)`` (often unresolved, e.g. ``/tmp/...``).
    Match by realpath so symlink aliases like ``/tmp`` → ``/private/tmp`` still match.
    """
    if not path.is_file():
        return False
    try:
        expected = home.base_dir.resolve()
    except OSError:
        return False
    try:
        content = path.read_text()
    except OSError as exc:
        raise WorthlessError(
            ErrorCode.INVALID_INPUT,
            f"Cannot read service unit at {path}. Fix permissions or remove it manually.",
        ) from exc
    for raw in _worthless_home_paths_in_unit(content):
        try:
            if Path(raw).resolve() == expected:
                return True
        except OSError:
            continue
    return False


def refuse_foreign_unit(path: Path, home: WorthlessHome) -> None:
    """Refuse mutating a unit/plist that belongs to another ``WORTHLESS_HOME``."""
    if not path.is_file():
        return
    if unit_file_matches_home(path, home):
        return
    raise WorthlessError(
        ErrorCode.INVALID_INPUT,
        "An existing worthless service unit belongs to a different "
        "WORTHLESS_HOME. Remove or migrate it manually before continuing.",
    )


def current_platform_backend_name() -> str:
    if sys.platform == "darwin":
        return "launchd"
    if sys.platform.startswith("linux"):
        return "systemd"
    raise WorthlessError(
        ErrorCode.PLATFORM_UNSUPPORTED,
        "`worthless service` is supported on macOS and Linux only.",
    )
