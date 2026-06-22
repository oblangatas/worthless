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
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.process import poll_health
from worthless.crypto.types import zero_buf


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


def preflight_service_install(home: WorthlessHome) -> None:
    """Refuse install when the proxy cannot start (no Fernet key)."""
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
    zero_buf(key)


def verify_proxy_health(port: int, *, timeout: float = 15.0) -> None:
    if not poll_health(port, timeout=timeout):
        raise WorthlessError(
            ErrorCode.PROXY_UNREACHABLE,
            f"Service started but /healthz on port {port} did not respond within {timeout:.0f}s.",
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
    content = path.read_text()
    for raw in _worthless_home_paths_in_unit(content):
        try:
            if Path(raw).resolve() == expected:
                return True
        except OSError:
            continue
    return False


def current_platform_backend_name() -> str:
    if sys.platform == "darwin":
        return "launchd"
    if sys.platform.startswith("linux"):
        return "systemd"
    raise WorthlessError(
        ErrorCode.PLATFORM_UNSUPPORTED,
        "`worthless service` is supported on macOS and Linux only.",
    )
