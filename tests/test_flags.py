"""Unit tests for ipc_mode_active() (WOR-465 A4).

Four cases covering the full truth table of the predicate:

  (flag=on, platform=win32)       → False  — no Docker sidecar on Windows
  (flag=on, uid=0)                → False  — root reads fernet.key directly
  (flag=off)                      → False  — bare-metal path
  (flag=on, uid!=0, not win32)    → True   — proxy uid routes through IPC

The root-uid bypass (uid=0 → False) is a load-bearing security claim: it
covers entrypoint bootstrap and operator ``docker exec`` sessions that run
as root before the priv-drop dance. This case MUST stay tested so any
accidental removal of the guard is caught immediately.
"""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from worthless._flags import ipc_mode_active


class TestIpcModeActive:
    def test_returns_false_on_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Windows: always False — no Docker sidecar topology."""
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        with patch.object(sys, "platform", "win32"):
            assert ipc_mode_active() is False

    def test_returns_false_for_root_even_with_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """uid 0 bypasses IPC even when flag is set.

        Root reads fernet.key directly — covers entrypoint bootstrap and
        operator docker exec sessions before priv-drop. The bypass must
        be consistent across all three call sites (ensure_home, open_repo,
        doctor). Removing it here would let a root-exec'd CLI try IPC
        against a socket that may not yet exist.
        """
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        with patch("worthless._flags.os.geteuid", return_value=0):
            assert ipc_mode_active() is False

    def test_returns_false_when_flag_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Flag absent: bare-metal install — IPC mode is off."""
        monkeypatch.delenv("WORTHLESS_FERNET_IPC_ONLY", raising=False)
        assert ipc_mode_active() is False

    def test_returns_true_when_flag_on_nonroot_linux(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Flag on + non-root + Linux: proxy uid must route through sidecar IPC."""
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        with patch("worthless._flags.os.geteuid", return_value=1001):
            assert ipc_mode_active() is True
