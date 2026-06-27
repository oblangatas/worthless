"""Shared helpers for real CLI user-flow tests."""

from __future__ import annotations

import os
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
