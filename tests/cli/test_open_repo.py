"""Tests for open_repo() IPC routing guard (WOR-465 A4).

Pinned invariants:

  Flag ON + non-root  → IPCClient opened; home.fernet_key never accessed.
  Flag ON + uid 0     → root bypass; IPCClient not used; key read directly.
  Flag OFF            → legacy path; IPCClient not used; key read directly.
  IPC failure         → error propagates up; no silent fallback to key file.

The last invariant is the intentional asymmetry with ensure_home: ensure_home
tolerates a missing socket on first boot (sidecar not yet spawned). open_repo
does NOT — it is called after bootstrap completes, so a missing socket means
the sidecar crashed and the error must surface immediately.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from worthless.cli._repo_factory import open_repo
from worthless.cli.bootstrap import WorthlessHome


class TestOpenRepoIpcGuard:
    async def test_flag_on_nonroot_opens_ipc_client(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Flag ON + non-root: IPCClient is constructed; the direct-key path is skipped."""
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        monkeypatch.setenv("WORTHLESS_SIDECAR_SOCKET", str(tmp_path / "sidecar.sock"))
        home = WorthlessHome(base_dir=tmp_path)

        fake_client = MagicMock()
        fake_client.__aenter__ = AsyncMock(return_value=fake_client)
        fake_client.__aexit__ = AsyncMock(return_value=None)
        fake_repo = MagicMock()

        with (
            patch("worthless._flags.os.geteuid", return_value=1001),
            patch("worthless.cli._repo_factory.IPCClient", return_value=fake_client) as mock_ipc,
            patch("worthless.cli._repo_factory.ShardRepository", return_value=fake_repo),
        ):
            async with open_repo(home) as _repo:
                pass

        mock_ipc.assert_called_once()

    async def test_flag_on_root_bypasses_ipc(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Flag ON + uid 0: root bypass — IPCClient never instantiated."""
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        home = WorthlessHome(base_dir=tmp_path)
        home._seed_cached_fernet_key(b"\x00" * 32)
        fake_repo = MagicMock()

        with (
            patch("worthless._flags.os.geteuid", return_value=0),
            patch("worthless.cli._repo_factory.IPCClient") as mock_ipc,
            patch("worthless.cli._repo_factory.ShardRepository", return_value=fake_repo),
        ):
            async with open_repo(home) as _repo:
                pass

        mock_ipc.assert_not_called()

    async def test_flag_off_uses_key_not_ipc(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Flag OFF (bare metal): legacy path — IPCClient never instantiated."""
        monkeypatch.delenv("WORTHLESS_FERNET_IPC_ONLY", raising=False)
        home = WorthlessHome(base_dir=tmp_path)
        home._seed_cached_fernet_key(b"\x00" * 32)
        fake_repo = MagicMock()

        with (
            patch("worthless.cli._repo_factory.IPCClient") as mock_ipc,
            patch("worthless.cli._repo_factory.ShardRepository", return_value=fake_repo),
        ):
            async with open_repo(home) as _repo:
                pass

        mock_ipc.assert_not_called()

    async def test_ipc_failure_propagates_not_silently_swallowed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """IPC error must propagate up — must NOT fall back to home.fernet_key.

        If IPCClient.__aenter__ raises (sidecar down, socket removed), the
        exception must reach the caller. The code structure guarantees this
        (the non-IPC branch is unreachable once ipc_mode_active() is True),
        but this test pins the guarantee so a future refactor cannot silently
        introduce a try/except that swallows the failure and falls through to
        the direct-key path.
        """
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        monkeypatch.setenv("WORTHLESS_SIDECAR_SOCKET", str(tmp_path / "absent.sock"))
        home = WorthlessHome(base_dir=tmp_path)

        failing_client = MagicMock()
        failing_client.__aenter__ = AsyncMock(side_effect=OSError("connection refused"))
        failing_client.__aexit__ = AsyncMock(return_value=None)

        key_read: list[bool] = []

        def _trap_fernet_key(self: WorthlessHome) -> bytearray:
            key_read.append(True)
            return bytearray(32)

        with (
            patch("worthless._flags.os.geteuid", return_value=1001),
            patch("worthless.cli._repo_factory.IPCClient", return_value=failing_client),
            patch.object(WorthlessHome, "fernet_key", property(_trap_fernet_key)),
        ):
            with pytest.raises(OSError):
                async with open_repo(home) as _repo:
                    pass

        assert not key_read, (
            "fernet_key must never be accessed when IPC fails — "
            "open_repo must not fall back to the direct-key path"
        )
