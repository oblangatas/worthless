"""WOR-748: Fernet Keychain → file sync for service-managed startup.

Test surface (verification doc):
- W3-ADV-5  read order under SERVICE_MANAGED (test_keystore.py)
- W3-ADV-13 launchd file-only path after sync (this module + service install)
- W3-ADV-17 drift preflight before install (preflight + this module)
- W3-DIRTY-5 keyring canonical + wrong fernet.key (dirty_env)
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.keystore import read_fernet_key, sync_fernet_for_launchd
from worthless.crypto.types import zero_buf
from tests.fixtures.dirty_home import write_secure_fernet_key


def _canonical_key() -> bytes:
    return b"canonical-keyring-value-padded-to-44b!!"


def _stale_key() -> bytes:
    return b"stale-file-key-value-padded-to-44-bytes!!"


class TestSyncFernetForLaunchd:
    """Unit tests for sync_fernet_for_launchd (WOR-748 write path)."""

    def test_writes_keyring_canonical_to_file_with_0600(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_SERVICE_MANAGED", raising=False)
        canonical = _canonical_key()

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = canonical.decode()
            sync_fernet_for_launchd(tmp_path)

        fernet_path = tmp_path / "fernet.key"
        assert fernet_path.read_bytes().strip() == canonical
        assert stat.S_IMODE(fernet_path.stat().st_mode) == 0o600

    def test_overwrites_stale_file_with_keyring_canonical(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Interactive read uses keyring even when a stale fernet.key exists."""
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_SERVICE_MANAGED", raising=False)
        stale = _stale_key()
        canonical = _canonical_key()
        write_secure_fernet_key(tmp_path / "fernet.key", stale)

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = canonical.decode()
            sync_fernet_for_launchd(tmp_path)

        assert (tmp_path / "fernet.key").read_bytes().strip() == canonical

    def test_ignores_service_managed_for_read_order(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Sync must read keyring-first, not stale file under SERVICE_MANAGED."""
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.setenv("WORTHLESS_SERVICE_MANAGED", "1")
        stale = _stale_key()
        canonical = _canonical_key()
        write_secure_fernet_key(tmp_path / "fernet.key", stale)

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = canonical.decode()
            sync_fernet_for_launchd(tmp_path)

        assert (tmp_path / "fernet.key").read_bytes().strip() == canonical

    def test_supplied_key_skips_read_fernet_key(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """HF2: callers with a cached key must not re-read the keystore."""
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        canonical = _canonical_key()

        with patch("worthless.cli.keystore.read_fernet_key") as mock_read:
            sync_fernet_for_launchd(tmp_path, key=canonical)
            mock_read.assert_not_called()

        assert (tmp_path / "fernet.key").read_bytes().strip() == canonical

    def test_zeroes_key_buffer_after_write(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        canonical = _canonical_key()
        zeroed: list[bytearray] = []

        def _track_zero(buf: bytearray) -> None:
            zeroed.append(buf)
            zero_buf(buf)

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
            patch("worthless.cli.keystore.zero_buf", side_effect=_track_zero),
        ):
            mock_kr.get_password.return_value = canonical.decode()
            sync_fernet_for_launchd(tmp_path)

        assert zeroed, "sync must zero the key buffer (SR-02)"
        assert all(b == 0 for b in zeroed[0])

    def test_raises_when_no_key_anywhere(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        with (
            patch("worthless.cli.keystore.keyring_available", return_value=False),
            pytest.raises(WorthlessError) as exc_info,
        ):
            sync_fernet_for_launchd(tmp_path)
        assert exc_info.value.code == ErrorCode.KEY_NOT_FOUND


@pytest.mark.dirty_env
class TestW3Dirty5ManagedVsInteractive:
    """W3-DIRTY-5: keyring shard + wrong fernet.key — managed vs interactive split."""

    def test_after_sync_managed_read_uses_file_not_stale_keyring(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        canonical = _canonical_key()
        write_secure_fernet_key(tmp_path / "fernet.key", _stale_key())

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = canonical.decode()
            sync_fernet_for_launchd(tmp_path)

            monkeypatch.setenv("WORTHLESS_SERVICE_MANAGED", "1")
            mock_kr.get_password.return_value = "still-stale-in-keyring!!!"
            mock_kr.get_password.reset_mock()
            managed = read_fernet_key(tmp_path)

        try:
            assert managed == bytearray(canonical)
            mock_kr.get_password.assert_not_called()
        finally:
            zero_buf(managed)


class TestPreflightFernetSync:
    """W3-ADV-17 + install integration: preflight sync and drift gate."""

    def test_preflight_syncs_before_install_on_darwin(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from worthless.cli.commands.service._common import preflight_service_install

        base = tmp_path / ".worthless"
        base.mkdir()
        home = WorthlessHome(base_dir=base)
        monkeypatch.setattr(sys, "platform", "darwin")

        key_buf = bytearray(b"k" * 32)
        with (
            patch("worthless.cli.commands.service._common.sync_fernet_for_launchd") as mock_sync,
            patch(
                "worthless.cli.commands.service._common._assert_no_fernet_drift_for_service_install"
            ),
            patch.object(
                WorthlessHome,
                "fernet_key",
                property(lambda self: key_buf),
            ),
        ):
            preflight_service_install(home)
            mock_sync.assert_called_once_with(base, key=key_buf)

    def test_preflight_refuses_drift_before_sync(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from worthless.cli.commands.doctor.checks import fernet_drift
        from worthless.cli.commands.service._common import preflight_service_install

        base = tmp_path / ".worthless"
        base.mkdir()
        (base / ".bootstrapped").write_text("")
        write_secure_fernet_key(base / "fernet.key", _stale_key())
        home = WorthlessHome(base_dir=base)
        monkeypatch.setattr(sys, "platform", "darwin")

        with (
            patch("worthless.cli.commands.service._common.sync_fernet_for_launchd") as mock_sync,
            patch.object(fernet_drift, "keyring_available", return_value=True),
            patch("worthless.cli.commands.doctor.checks.fernet_drift._keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = _canonical_key().decode()
            with pytest.raises(WorthlessError) as exc_info:
                preflight_service_install(home)
            mock_sync.assert_not_called()

        assert exc_info.value.code == ErrorCode.KEY_NOT_FOUND
        assert "drift" in str(exc_info.value).lower()


class TestLockFernetSync:
    """Lock must sync fernet.key on Unix so a subsequent service install works."""

    def test_lock_success_calls_sync_on_darwin(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.delenv("WORTHLESS_FERNET_IPC_ONLY", raising=False)
        key_buf = bytearray(_canonical_key())
        with (
            patch("worthless.cli.commands.lock.sync_fernet_for_launchd") as mock_sync,
            patch("worthless.cli.commands.lock.zero_buf"),
            patch.object(
                WorthlessHome,
                "fernet_key",
                property(lambda self: bytearray(key_buf)),
            ),
        ):
            from worthless.cli.commands import lock as lock_mod

            lock_mod._sync_fernet_after_lock(WorthlessHome(base_dir=tmp_path))
            mock_sync.assert_called_once()
            assert mock_sync.call_args.args[0] == tmp_path
            assert bytes(mock_sync.call_args.kwargs["key"]) == _canonical_key()

    def test_lock_skips_sync_under_ipc_only(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        with patch("worthless.cli.commands.lock.sync_fernet_for_launchd") as mock_sync:
            from worthless.cli.commands import lock as lock_mod

            lock_mod._sync_fernet_after_lock(WorthlessHome(base_dir=tmp_path))
            mock_sync.assert_not_called()

    def test_lock_skips_sync_when_file_disagrees_with_canonical(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.delenv("WORTHLESS_FERNET_IPC_ONLY", raising=False)
        base = tmp_path / ".worthless"
        base.mkdir()
        write_secure_fernet_key(base / "fernet.key", _stale_key())
        key_buf = bytearray(_canonical_key())
        with (
            patch("worthless.cli.commands.lock.sync_fernet_for_launchd") as mock_sync,
            patch.object(
                WorthlessHome,
                "fernet_key",
                property(lambda self: bytearray(key_buf)),
            ),
        ):
            from worthless.cli.commands import lock as lock_mod

            lock_mod._sync_fernet_after_lock(WorthlessHome(base_dir=base))
            mock_sync.assert_not_called()


@pytest.mark.adversarial
class TestFernetSyncAdversarial:
    """WOR-748 adversarial guards (env poison, drift journey, idempotent sync)."""

    def test_adv_env_poison_does_not_win_when_key_supplied(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """ADV-ENV: shell env must not override canonical key passed by lock."""
        canonical = _canonical_key()
        poison = b"poison-env-key-value-padded-to-44-bytes!"
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", poison.decode())

        sync_fernet_for_launchd(tmp_path, key=canonical)

        assert (tmp_path / "fernet.key").read_bytes().strip() == canonical

    def test_adv_env_read_path_ignores_shell_env(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """ADV-ENV-READ: sync without key= must read keyring, not WORTHLESS_FERNET_KEY."""
        monkeypatch.delenv("WORTHLESS_SERVICE_MANAGED", raising=False)
        canonical = _canonical_key()
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "poison-env-key-value-padded-to-44-bytes!")

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = canonical.decode()
            sync_fernet_for_launchd(tmp_path)

        assert (tmp_path / "fernet.key").read_bytes().strip() == canonical

    def test_adv_drift_journey_lock_skips_install_refuses(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """ADV-DRIFT-JOURNEY: stale file + keyring A → lock skips sync → install blocked."""
        from worthless.cli.commands.doctor.checks import fernet_drift
        from worthless.cli.commands import lock as lock_mod
        from worthless.cli.commands.service._common import preflight_service_install

        base = tmp_path / ".worthless"
        base.mkdir()
        (base / ".bootstrapped").write_text("")
        canonical = _canonical_key()
        write_secure_fernet_key(base / "fernet.key", _stale_key())
        home = WorthlessHome(base_dir=base)
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.delenv("WORTHLESS_FERNET_IPC_ONLY", raising=False)
        key_buf = bytearray(canonical)

        with patch.object(
            WorthlessHome,
            "fernet_key",
            property(lambda self: bytearray(key_buf)),
        ):
            lock_mod._sync_fernet_after_lock(home)

        assert (base / "fernet.key").read_bytes().strip() == _stale_key()

        with (
            patch.object(fernet_drift, "keyring_available", return_value=True),
            patch("worthless.cli.commands.doctor.checks.fernet_drift._keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = canonical.decode()
            with pytest.raises(WorthlessError) as exc_info:
                preflight_service_install(home)

        assert exc_info.value.code == ErrorCode.KEY_NOT_FOUND
        assert "drift" in str(exc_info.value).lower()

    def test_adv_idempotent_sync_does_not_rewrite_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """ADV-IDEMPOTENT: matching file must not trigger _write_key_file."""
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        canonical = _canonical_key()
        write_secure_fernet_key(tmp_path / "fernet.key", canonical)
        before_mtime = (tmp_path / "fernet.key").stat().st_mtime

        with patch("worthless.cli.keystore._write_key_file") as mock_write:
            sync_fernet_for_launchd(tmp_path, key=canonical)
            mock_write.assert_not_called()

        assert (tmp_path / "fernet.key").stat().st_mtime == before_mtime


@pytest.mark.adversarial
class TestW3Adv14ManagedReadChain:
    """W3-ADV-14 partial: lock path → sync → preflight → managed read agrees."""

    def test_lock_sync_preflight_managed_read_chain(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from worthless.cli.commands import lock as lock_mod
        from worthless.cli.commands.service._common import preflight_service_install

        base = tmp_path / ".worthless"
        base.mkdir()
        (base / ".bootstrapped").write_text("")
        home = WorthlessHome(base_dir=base)
        canonical = _canonical_key()
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_FERNET_IPC_ONLY", raising=False)

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
            patch.object(
                WorthlessHome,
                "fernet_key",
                property(lambda self: bytearray(canonical)),
            ),
        ):
            mock_kr.get_password.return_value = canonical.decode()
            lock_mod._sync_fernet_after_lock(home)
            preflight_service_install(home)

            monkeypatch.setenv("WORTHLESS_SERVICE_MANAGED", "1")
            managed = read_fernet_key(base)

        try:
            assert (base / "fernet.key").read_bytes().strip() == canonical
            assert managed == bytearray(canonical)
        finally:
            zero_buf(managed)
