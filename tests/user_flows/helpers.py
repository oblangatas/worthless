"""Shared helpers for real CLI user-flow tests."""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path


def scrubbed_cli_env(home: Path, *, user_home: Path | None = None) -> dict[str, str | None]:
    """Return an env overlay that isolates user-flow CLI state.

    ``WORTHLESS_HOME`` isolates Worthless state. ``HOME``/``USERPROFILE``
    isolate host-level integrations such as OpenClaw detection, which probes
    ``~/.openclaw`` independently from ``WORTHLESS_HOME``.
    """
    resolved_user_home = user_home or home.parent / "user-home"
    resolved_user_home.mkdir(parents=True, exist_ok=True)
    return {
        "HOME": str(resolved_user_home),
        "USERPROFILE": str(resolved_user_home),
        "WORTHLESS_HOME": str(home),
        "WORTHLESS_DB_PATH": None,
        "WORTHLESS_FERNET_KEY": None,
        "WORTHLESS_FERNET_KEY_PATH": None,
        "WORTHLESS_FERNET_FD": None,
        "WORTHLESS_KEYRING_BACKEND": "null",
        "WORTHLESS_PORT": None,
        "OPENAI_API_KEY": None,
        "ANTHROPIC_API_KEY": None,
        "OPENAI_BASE_URL": None,
        "ANTHROPIC_BASE_URL": None,
        "PATH": os.environ.get("PATH"),
        "LANG": os.environ.get("LANG"),
        "LC_ALL": os.environ.get("LC_ALL"),
        "TERM": os.environ.get("TERM"),
    }


def free_port() -> int:
    """A loopback port nothing is listening on right now."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def worthless_bin() -> Path:
    """The console script under test.

    Defaults to the one beside the interpreter running the tests — the branch
    build. ``WORTHLESS_TEST_BIN`` aims this at a different binary, so CI can run
    the same test against an installed wheel: the artifact a user actually gets
    (worthless-d4h2). Without that, a packaging-only defect passes every test.
    """
    override = os.environ.get("WORTHLESS_TEST_BIN")
    return Path(override) if override else Path(sys.executable).parent / "worthless"
