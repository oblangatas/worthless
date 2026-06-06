"""Shared helpers for install.sh tests."""

from __future__ import annotations

import re
import stat
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO_ROOT / "install.sh"
INSTALL_FIXTURES = REPO_ROOT / "tests" / "install_fixtures"

EXIT_NETWORK = 10
EXIT_PLATFORM = 20
EXIT_PIPX_CONFLICT = 30
EXIT_INTERNAL = 40
EXIT_INTEGRITY = 50


def write_stub(bin_dir: Path, name: str, body: str) -> Path:
    """Write an executable POSIX sh stub at ``bin_dir/name``."""
    path = bin_dir / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


# Pinned uv version must match install.sh UV_VERSION. Kept in sync manually —
# a mismatch here breaks happy-path tests immediately, which is the signal.
_UV_VERSION = "0.11.7"


def read_install_pin() -> str:
    """Return the WORTHLESS_VERSION_PIN literal baked into install.sh."""
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(r'^WORTHLESS_VERSION_PIN="([^"]*)"', text, re.MULTILINE)
    assert match, 'install.sh must declare WORTHLESS_VERSION_PIN="..."'
    return match.group(1)


def install_sh_with_pin(dest_dir: Path, pin_value: str) -> Path:
    """Write a copy of install.sh into ``dest_dir`` with the baked pin replaced.

    Used to exercise the empty-pin fail-closed path (and any other pin value)
    without mutating the real install.sh on disk.
    """
    src = INSTALL_SH.read_text(encoding="utf-8")
    # Callable replacement: a string replacement would let a backslash in
    # pin_value act as a regex backreference (re.error or wrong output). A
    # lambda inserts pin_value literally.
    patched, n = re.subn(
        r'^WORTHLESS_VERSION_PIN="[^"]*"',
        lambda _m: f'WORTHLESS_VERSION_PIN="{pin_value}"',
        src,
        count=1,
        flags=re.MULTILINE,
    )
    assert n == 1, "expected exactly one WORTHLESS_VERSION_PIN line to patch"
    dest = dest_dir / "install.sh"
    dest.write_text(patched, encoding="utf-8")
    return dest


def write_happy_path_stubs(bin_dir: Path, *, with_worthless: bool = True) -> None:
    """Stub every binary install.sh invokes on the Darwin success path.

    This lets tests exercise the *final* messaging branches (on-your-PATH vs
    works-in-this-shell) without touching the network or really installing
    anything.

    ``with_worthless=False`` simulates the case where `uv tool install` ran
    but ~/.local/bin isn't on the test's synthetic PATH — we still hit the
    "not yet on your PATH" branch.
    """
    write_stub(bin_dir, "uname", "echo Darwin")
    write_stub(bin_dir, "sw_vers", 'echo "14.5"')
    write_stub(
        bin_dir,
        "uv",
        f"""printf 'uv %s\\n' "$*" >> "$HOME/uv-invocations.log"
case "$1" in
  --version) echo "uv {_UV_VERSION}" ;;
  tool) shift; case "$1" in
    install|upgrade) echo "ok" ;;
    list) ;;  # empty: no worthless line → fast-path miss → real install runs
    *) echo "uv tool: unhandled: $*" >&2; exit 1 ;;
  esac ;;
  run) echo "worthless 0.3.0" ;;
  *) echo "uv: unhandled: $*" >&2; exit 1 ;;
esac""",
    )
    if with_worthless:
        write_stub(bin_dir, "worthless", 'echo "worthless 0.3.0"')


def run_install(
    bin_dir: Path,
    env_extra: dict[str, str] | None = None,
    timeout: int = 15,
    install_sh: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run install.sh with ``bin_dir`` first on PATH; return CompletedProcess.

    Pass ``install_sh`` to run a patched copy (e.g. an emptied pin) instead of
    the canonical on-disk script.
    """
    script = install_sh if install_sh is not None else INSTALL_SH
    base_path = "/usr/bin:/bin:/usr/sbin:/sbin"
    env = {
        "PATH": f"{bin_dir}:{base_path}",
        "HOME": str(bin_dir.parent),
        "SHELL": "/bin/zsh",
        # WOR-463: prevent any subprocess `worthless` invocation from
        # writing fernet-key-* entries to the host's real keychain.
        # install.sh's smoke_test stubs `worthless` today, but this stays
        # defensive against future install.sh paths that exec the binary.
        "WORTHLESS_KEYRING_BACKEND": "null",
    }
    if env_extra:
        env.update(env_extra)
    return subprocess.run(  # noqa: S603
        ["sh", str(script)],  # noqa: S607
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


__all__ = [
    "EXIT_INTEGRITY",
    "EXIT_INTERNAL",
    "EXIT_NETWORK",
    "EXIT_PIPX_CONFLICT",
    "EXIT_PLATFORM",
    "INSTALL_FIXTURES",
    "INSTALL_SH",
    "REPO_ROOT",
    "install_sh_with_pin",
    "read_install_pin",
    "run_install",
    "write_happy_path_stubs",
    "write_stub",
]
