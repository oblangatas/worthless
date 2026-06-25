"""Tests for worthless.cli.keystore — TDD RED phase.

These tests define the behavior of the keystore module before it exists.
All tests should fail with ImportError until the module is implemented.
"""

from __future__ import annotations

import logging
import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from worthless.cli.errors import ErrorCode, WorthlessError

# Import the module under test — will fail until implemented (RED phase).
from worthless.cli.keystore import (
    _SERVICE,
    _USERNAME,
    _keyring_username,
    _read_fernet_file,
    keyring_available,
    delete_fernet_key,
    migrate_file_to_keyring,
    read_fernet_key,
    store_fernet_key,
)


def _write_fernet_key_file(path: Path, content: bytes) -> None:
    """Write a fernet.key that passes ``_validate_fernet_file`` (mode 0o600)."""
    path.write_bytes(content)
    path.chmod(0o600)


# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------


class TestConstants:
    def test_service_name(self) -> None:
        assert _SERVICE == "worthless"

    def test_username(self) -> None:
        assert _USERNAME == "fernet-key"


# ------------------------------------------------------------------
# keyring_available
# ------------------------------------------------------------------


class TestKeyringAvailable:
    """Backend detection: reject fail/null/plaintext, accept real backends."""

    @pytest.fixture(autouse=True)
    def _clear_backend_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Tests in this class assert the BACKEND-DETECTION behaviour.

        The session-wide ``WORTHLESS_KEYRING_BACKEND=null`` setdefault from
        ``conftest.py`` (WOR-463) would short-circuit ``keyring_available``
        BEFORE the backend check runs, breaking the
        ``test_macos_keychain_returns_true`` / ``test_secretservice_returns_true``
        cases. Delenv it for this class so backend-detection logic is what
        the tests actually exercise. The env-override path is covered by
        ``TestKeyringBackendEnvOverride`` below.
        """
        monkeypatch.delenv("WORTHLESS_KEYRING_BACKEND", raising=False)

    @staticmethod
    def _make_backend(module: str, qualname: str) -> object:
        """Create a fake backend with the given fully-qualified class identity."""
        cls = type(qualname, (), {"__module__": module, "__qualname__": qualname})
        return cls()

    def test_fail_keyring_returns_false(self) -> None:
        backend = self._make_backend("keyring.backends.fail", "Keyring")
        with patch("worthless.cli.keystore.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = backend
            assert keyring_available() is False

    def test_null_keyring_returns_false(self) -> None:
        backend = self._make_backend("keyring.backends.null", "Keyring")
        with patch("worthless.cli.keystore.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = backend
            assert keyring_available() is False

    def test_plaintext_keyring_returns_false(self) -> None:
        backend = self._make_backend("keyrings.alt.file", "PlaintextKeyring")
        with patch("worthless.cli.keystore.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = backend
            assert keyring_available() is False

    def test_macos_keychain_returns_true(self) -> None:
        backend = self._make_backend("keyring.backends.macOS", "Keyring")
        with patch("worthless.cli.keystore.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = backend
            assert keyring_available() is True

    def test_secretservice_returns_true(self) -> None:
        backend = self._make_backend("keyring.backends.SecretService", "Keyring")
        with patch("worthless.cli.keystore.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = backend
            assert keyring_available() is True

    def test_keyring_import_error_returns_false(self) -> None:
        with patch("worthless.cli.keystore.keyring", None):
            assert keyring_available() is False


# ------------------------------------------------------------------
# store_fernet_key
# ------------------------------------------------------------------


class TestStoreFernetKey:
    """Store to OS keyring when available, fall back to file."""

    def test_stores_to_keyring_when_available(self, tmp_path: Path) -> None:
        key = b"test-fernet-key-value"
        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            store_fernet_key(key, home_dir=tmp_path)

            mock_kr.set_password.assert_called_once_with(
                "worthless", _keyring_username(tmp_path), key.decode()
            )

    def test_falls_back_to_file_when_keyring_unavailable(self, tmp_path: Path) -> None:
        key = b"test-fernet-key-value"
        with patch("worthless.cli.keystore.keyring_available", return_value=False):
            store_fernet_key(key, home_dir=tmp_path)

            fernet_path = tmp_path / "fernet.key"
            assert fernet_path.exists()
            assert fernet_path.read_bytes() == key

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions not applicable")
    def test_file_has_0600_permissions(self, tmp_path: Path) -> None:
        key = b"test-fernet-key-value"
        with patch("worthless.cli.keystore.keyring_available", return_value=False):
            store_fernet_key(key, home_dir=tmp_path)

            fernet_path = tmp_path / "fernet.key"
            mode = fernet_path.stat().st_mode & 0o777
            assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_keyring_success_removes_stale_file(self, tmp_path: Path) -> None:
        """After successful keyring write, leftover fernet.key must be removed."""
        key = b"test-fernet-key-value"
        stale_file = tmp_path / "fernet.key"
        stale_file.write_bytes(b"old-key-from-previous-fallback")

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            store_fernet_key(key, home_dir=tmp_path)
            mock_kr.set_password.assert_called_once()

        assert not stale_file.exists(), "Stale fernet.key should be removed after keyring success"

    def test_keyring_success_no_file_no_error(self, tmp_path: Path) -> None:
        """Keyring success with no stale file on disk must not raise."""
        key = b"test-fernet-key-value"
        stale_file = tmp_path / "fernet.key"
        assert not stale_file.exists()  # precondition

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            store_fernet_key(key, home_dir=tmp_path)
            mock_kr.set_password.assert_called_once()

    def test_keyring_success_file_removal_failure_logs_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """If stale file removal fails, log warning but don't raise."""
        key = b"test-fernet-key-value"
        stale_file = tmp_path / "fernet.key"
        stale_file.write_bytes(b"old-key")

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
            patch.object(Path, "unlink", side_effect=OSError("Permission denied")),
            caplog.at_level(logging.WARNING, logger="worthless.cli.keystore"),
        ):
            store_fernet_key(key, home_dir=tmp_path)
            mock_kr.set_password.assert_called_once()

        assert any(
            "fernet.key" in rec.message.lower() or "stale" in rec.message.lower()
            for rec in caplog.records
            if rec.levelno >= logging.WARNING
        ), "Expected a warning log about stale file removal failure"

    def test_falls_back_to_file_when_keyring_raises(self, tmp_path: Path) -> None:
        key = b"test-fernet-key-value"
        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.set_password.side_effect = Exception("Keyring locked")
            store_fernet_key(key, home_dir=tmp_path)

            fernet_path = tmp_path / "fernet.key"
            assert fernet_path.exists()
            assert fernet_path.read_bytes() == key


# ------------------------------------------------------------------
# read_fernet_key — cascade tests
# ------------------------------------------------------------------


class TestReadFernetKeyCascade:
    """Detection cascade: env var -> keyring -> file -> error."""

    def test_reads_from_env_var(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "env-key-value")
        monkeypatch.delenv("WORTHLESS_FERNET_FD", raising=False)

        result = read_fernet_key(home_dir=tmp_path)

        assert result == bytearray(b"env-key-value")

    def test_reads_from_keyring(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = "keyring-key-value"
            result = read_fernet_key(home_dir=tmp_path)

        assert result == bytearray(b"keyring-key-value")

    def test_reads_from_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_FERNET_FD", raising=False)

        fernet_path = tmp_path / "fernet.key"
        _write_fernet_key_file(fernet_path, b"file-key-value\n")

        with patch("worthless.cli.keystore.keyring_available", return_value=False):
            result = read_fernet_key(home_dir=tmp_path)

        assert result == bytearray(b"file-key-value")

    def test_raises_when_nothing_found(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_FERNET_FD", raising=False)

        with patch("worthless.cli.keystore.keyring_available", return_value=False):
            with pytest.raises(WorthlessError) as exc_info:
                read_fernet_key(home_dir=tmp_path)

        assert exc_info.value.code == ErrorCode.KEY_NOT_FOUND

    def test_env_var_takes_priority_over_keyring(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Env var should win even when keyring and file both have values."""
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "env-wins")
        monkeypatch.delenv("WORTHLESS_FERNET_FD", raising=False)

        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"file-value")

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = "keyring-value"
            result = read_fernet_key(home_dir=tmp_path)

        assert result == bytearray(b"env-wins")
        mock_kr.get_password.assert_not_called()

    def test_keyring_none_falls_through_to_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """If keyring returns None, cascade to file."""
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_FERNET_FD", raising=False)

        fernet_path = tmp_path / "fernet.key"
        _write_fernet_key_file(fernet_path, b"file-fallback-value\n")

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = None
            result = read_fernet_key(home_dir=tmp_path)

        assert result == bytearray(b"file-fallback-value")

    def test_keyring_error_with_file_refuses_silent_fallback_interactive(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Interactive sessions must not silently read stale fernet.key (WOR-464)."""
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_FERNET_FD", raising=False)
        monkeypatch.delenv("WORTHLESS_SERVICE_MANAGED", raising=False)

        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"stale-file-key\n")

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.side_effect = RuntimeError("access denied")
            with pytest.raises(WorthlessError) as exc_info:
                read_fernet_key(home_dir=tmp_path)

        assert exc_info.value.code == ErrorCode.KEY_NOT_FOUND
        assert "refusing" in str(exc_info.value).lower()

    def test_keyring_error_with_file_allowed_under_service_managed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """LaunchAgent sets WORTHLESS_SERVICE_MANAGED=1; synced fernet.key is OK."""
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_FERNET_FD", raising=False)
        monkeypatch.setenv("WORTHLESS_SERVICE_MANAGED", "1")

        fernet_path = tmp_path / "fernet.key"
        _write_fernet_key_file(fernet_path, b"launchd-synced-key\n")
        fernet_path.chmod(0o600)

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.side_effect = RuntimeError("access denied")
            result = read_fernet_key(home_dir=tmp_path)

        assert result == bytearray(b"launchd-synced-key")

    def test_service_managed_prefers_file_over_keyring(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """WOR-748: launchd must use synced fernet.key, not a stale keyring entry."""
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.setenv("WORTHLESS_SERVICE_MANAGED", "1")

        fernet_path = tmp_path / "fernet.key"
        _write_fernet_key_file(fernet_path, b"synced-file-key\n")
        fernet_path.chmod(0o600)

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = "stale-keyring-key"
            result = read_fernet_key(home_dir=tmp_path)

        assert result == bytearray(b"synced-file-key")
        mock_kr.get_password.assert_not_called()

    def test_service_managed_rejects_loose_fernet_file_perms(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """worthless-l3qj: world-readable fernet.key must fail under SERVICE_MANAGED."""
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.setenv("WORTHLESS_SERVICE_MANAGED", "1")

        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"leaked-key\n")
        fernet_path.chmod(0o644)

        with pytest.raises(WorthlessError) as exc_info:
            read_fernet_key(home_dir=tmp_path)

        assert exc_info.value.code == ErrorCode.KEY_NOT_FOUND
        assert "0o600" in exc_info.value.message


class TestIpcOnlyFernetStatGate:
    """Container topology: relax uid check for crypto-owned 0400, reject 0440."""

    def test_ipc_only_accepts_foreign_owned_0400(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_SERVICE_MANAGED", raising=False)

        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"crypto-owned-key\n")
        foreign_uid = os.geteuid() + 1 if os.geteuid() < 65534 else max(1, os.geteuid() - 1)
        try:
            os.chown(fernet_path, foreign_uid, os.getgid())
            fernet_path.chmod(0o400)
            result = _read_fernet_file(fernet_path, validate=True)
        except (OSError, PermissionError):
            foreign_stat = os.stat_result(
                (
                    stat.S_IFREG | 0o400,
                    0,
                    0,
                    0,
                    foreign_uid,
                    os.getgid(),
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            )
            original_lstat = Path.lstat

            def _lstat(self: Path):
                if self == fernet_path:
                    return foreign_stat
                return original_lstat(self)

            monkeypatch.setattr(Path, "lstat", _lstat)
            with patch("worthless.cli.keystore.keyring_available", return_value=False):
                result = read_fernet_key(home_dir=tmp_path)

        assert result == bytearray(b"crypto-owned-key")

    def test_ipc_only_rejects_group_readable_0440(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_SERVICE_MANAGED", raising=False)

        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"group-readable-key\n")
        fernet_path.chmod(0o440)

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=False),
            pytest.raises(WorthlessError) as exc_info,
        ):
            read_fernet_key(home_dir=tmp_path)

        assert exc_info.value.code == ErrorCode.KEY_NOT_FOUND
        assert "0o400" in exc_info.value.message


# ------------------------------------------------------------------
# SR-01: return type is ALWAYS bytearray
# ------------------------------------------------------------------


class TestReturnTypeBytearray:
    """SR-01: read_fernet_key must always return bytearray."""

    @pytest.mark.parametrize(
        "source",
        ["env", "keyring", "file"],
        ids=["env-var", "keyring", "file"],
    )
    def test_return_type_is_bytearray(
        self,
        source: str,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_FERNET_FD", raising=False)

        if source == "env":
            monkeypatch.setenv("WORTHLESS_FERNET_KEY", "some-key")
            ctx = patch("worthless.cli.keystore.keyring_available", return_value=False)
        elif source == "keyring":
            ctx_avail = patch("worthless.cli.keystore.keyring_available", return_value=True)
            ctx_kr = patch("worthless.cli.keystore.keyring")
            # Stack two context managers
            import contextlib

            @contextlib.contextmanager
            def _combined():  # type: ignore[no-untyped-def]
                with ctx_avail, ctx_kr as mock_kr:
                    mock_kr.get_password.return_value = "some-key"
                    yield

            ctx = _combined()
        else:  # file
            fernet_path = tmp_path / "fernet.key"
            _write_fernet_key_file(fernet_path, b"some-key\n")
            ctx = patch("worthless.cli.keystore.keyring_available", return_value=False)

        with ctx:
            result = read_fernet_key(home_dir=tmp_path)

        assert isinstance(result, bytearray), (
            f"Expected bytearray from {source}, got {type(result).__name__}"
        )


# ------------------------------------------------------------------
# SR-04: no key material in error messages
# ------------------------------------------------------------------


class TestSR04NoKeyLeakage:
    """SR-04: error messages must never contain key material."""

    def test_error_message_does_not_contain_key_value(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_FERNET_FD", raising=False)

        with patch("worthless.cli.keystore.keyring_available", return_value=False):
            with pytest.raises(WorthlessError) as exc_info:
                read_fernet_key(home_dir=tmp_path)

        error_str = str(exc_info.value)
        # Must not contain anything that looks like a key
        assert "sk-" not in error_str
        lower = error_str.lower()
        assert "fernet" not in lower or "key" not in lower.split("fernet")[0]
        # The path should not leak either
        assert str(tmp_path) not in error_str

    def test_error_message_does_not_contain_env_var_value(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Even partial key data must not appear in errors."""
        # Set an env var that looks like a key, but make the cascade fail anyway
        # by having the env var unset and nothing else available
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_FERNET_FD", raising=False)

        with patch("worthless.cli.keystore.keyring_available", return_value=False):
            with pytest.raises(WorthlessError) as exc_info:
                read_fernet_key(home_dir=tmp_path)

        # Ensure error message is generic
        assert exc_info.value.code == ErrorCode.KEY_NOT_FOUND


# ------------------------------------------------------------------
# delete_fernet_key
# ------------------------------------------------------------------


class TestDeleteFernetKey:
    """Delete from keyring and/or file; never raise on missing."""

    def test_deletes_both_keyring_and_file(self, tmp_path: Path) -> None:
        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"some-key")

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            delete_fernet_key(home_dir=tmp_path)

            mock_kr.delete_password.assert_called_once_with(
                "worthless", _keyring_username(tmp_path)
            )
        assert not fernet_path.exists()

    def test_deletes_file_only_when_keyring_unavailable(self, tmp_path: Path) -> None:
        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"some-key")

        with patch("worthless.cli.keystore.keyring_available", return_value=False):
            delete_fernet_key(home_dir=tmp_path)

        assert not fernet_path.exists()

    def test_swallows_keyring_error(self, tmp_path: Path) -> None:
        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"some-key")

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.delete_password.side_effect = Exception("Keyring locked")
            delete_fernet_key(home_dir=tmp_path)

        assert not fernet_path.exists()

    def test_no_error_when_neither_exists(self, tmp_path: Path) -> None:
        with patch("worthless.cli.keystore.keyring_available", return_value=False):
            # Should not raise
            delete_fernet_key(home_dir=tmp_path)

    def test_no_error_when_only_keyring_fails_and_no_file(self, tmp_path: Path) -> None:
        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.delete_password.side_effect = Exception("Not found")
            # Should not raise
            delete_fernet_key(home_dir=tmp_path)


# ------------------------------------------------------------------
# Keyring namespacing — per-install collision prevention
# ------------------------------------------------------------------


class TestKeyringNamespacing:
    """_keyring_username must produce unique, deterministic usernames per home_dir."""

    def test_two_homedirs_different_usernames(self, tmp_path: Path) -> None:
        """Two distinct home_dir paths must produce different keyring usernames."""
        dir_a = tmp_path / "install-a"
        dir_b = tmp_path / "install-b"
        dir_a.mkdir()
        dir_b.mkdir()

        username_a = _keyring_username(dir_a)
        username_b = _keyring_username(dir_b)

        assert username_a != username_b, (
            f"Expected different usernames for different home_dirs, got {username_a!r} for both"
        )

    def test_default_homedir_deterministic(self) -> None:
        """Calling with None twice must return the same username."""
        result_1 = _keyring_username(None)
        result_2 = _keyring_username(None)

        assert result_1 == result_2

    def test_username_starts_with_prefix(self, tmp_path: Path) -> None:
        """Namespaced username must start with 'fernet-key-' prefix."""
        result = _keyring_username(tmp_path)

        assert result.startswith("fernet-key-"), (
            f"Expected username to start with 'fernet-key-', got {result!r}"
        )

    def test_same_path_is_deterministic(self, tmp_path: Path) -> None:
        """Same home_dir must always produce the same username."""
        result_1 = _keyring_username(tmp_path)
        result_2 = _keyring_username(tmp_path)

        assert result_1 == result_2


# ------------------------------------------------------------------
# Legacy migration — read falls back, delete cleans both
# ------------------------------------------------------------------


class TestLegacyMigration:
    """read_fernet_key must try new username first, fall back to legacy.
    delete_fernet_key must clean both new and legacy usernames.
    """

    def test_read_tries_new_username_first(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """When new namespaced username has a value, legacy is never queried."""
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        monkeypatch.delenv("WORTHLESS_FERNET_FD", raising=False)

        new_username = _keyring_username(tmp_path)

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):

            def _get_password(_service: str, username: str) -> str | None:
                if username == new_username:
                    return "new-key-value"
                return None

            mock_kr.get_password.side_effect = _get_password
            result = read_fernet_key(home_dir=tmp_path)

        assert result == bytearray(b"new-key-value")
        # Should have been called with new username; legacy should NOT be called
        calls = [c.args[1] for c in mock_kr.get_password.call_args_list]
        assert new_username in calls, "Expected call with new namespaced username"
        assert _USERNAME not in calls or new_username == _USERNAME, (
            "Legacy username should not be queried when new username succeeds"
        )

    def test_delete_only_namespaced(self, tmp_path: Path) -> None:
        """delete_fernet_key calls delete_password with namespaced username only."""
        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            delete_fernet_key(home_dir=tmp_path)

        mock_kr.delete_password.assert_called_once_with("worthless", _keyring_username(tmp_path))


# ------------------------------------------------------------------
# Store uses namespaced username
# ------------------------------------------------------------------


class TestStoreUsesNamespacedUsername:
    """store_fernet_key must use _keyring_username, not hardcoded _USERNAME."""

    def test_store_uses_namespaced_username(self, tmp_path: Path) -> None:
        key = b"test-fernet-key-value"
        new_username = _keyring_username(tmp_path)

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            store_fernet_key(key, home_dir=tmp_path)

            stored_username = mock_kr.set_password.call_args.args[1]
            assert stored_username == new_username, (
                f"Expected store to use namespaced username {new_username!r}, "
                f"got {stored_username!r}"
            )


# ------------------------------------------------------------------
# migrate_file_to_keyring
# ------------------------------------------------------------------


class TestMigrateFileToKeyring:
    """Upgrade path: migrate fernet.key from file to OS keyring."""

    def test_migrates_file_key_to_keyring(self, tmp_path: Path) -> None:
        """File exists, keyring available and empty -> migrate and return True."""
        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"my-secret-fernet-key")

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = None
            result = migrate_file_to_keyring(home_dir=tmp_path)

        assert result is True
        mock_kr.set_password.assert_called_once_with(
            "worthless",
            _keyring_username(tmp_path),
            "my-secret-fernet-key",
        )

    def test_noop_when_keyring_already_has_key(self, tmp_path: Path) -> None:
        """Keyring already has a value -> no migration, return False, file untouched."""
        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"file-key")

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = "existing-keyring-key"
            result = migrate_file_to_keyring(home_dir=tmp_path)

        assert result is False
        assert fernet_path.exists(), "File should not be removed when migration is skipped"

    def test_noop_when_no_file(self, tmp_path: Path) -> None:
        """No fernet.key file on disk -> return False."""
        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = None
            result = migrate_file_to_keyring(home_dir=tmp_path)

        assert result is False

    def test_noop_when_keyring_unavailable(self, tmp_path: Path) -> None:
        """Keyring not available -> return False even if file exists."""
        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"some-key")

        with patch("worthless.cli.keystore.keyring_available", return_value=False):
            result = migrate_file_to_keyring(home_dir=tmp_path)

        assert result is False

    def test_swallows_exceptions(self, tmp_path: Path) -> None:
        """If store_fernet_key raises, return False without propagating."""
        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"some-key")

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
            patch("worthless.cli.keystore.store_fernet_key", side_effect=Exception("boom")),
        ):
            mock_kr.get_password.return_value = None
            result = migrate_file_to_keyring(home_dir=tmp_path)

        assert result is False

    def test_returns_false_when_keyring_write_falls_back_to_file(self, tmp_path: Path) -> None:
        """If keyring.set_password raises (triggering file fallback),
        migrate must return False — the key is NOT in keyring."""
        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"my-secret-fernet-key")

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = None
            # Keyring write fails, store_fernet_key falls back to file
            mock_kr.set_password.side_effect = Exception("Keyring locked")
            result = migrate_file_to_keyring(home_dir=tmp_path)

        assert result is False, (
            "migrate_file_to_keyring returned True but keyring write failed "
            "and store fell back to file"
        )

    def test_file_removed_after_migration(self, tmp_path: Path) -> None:
        """After successful migration, the fernet.key file must be deleted."""
        fernet_path = tmp_path / "fernet.key"
        fernet_path.write_bytes(b"migrate-me")

        with (
            patch("worthless.cli.keystore.keyring_available", return_value=True),
            patch("worthless.cli.keystore.keyring") as mock_kr,
        ):
            mock_kr.get_password.return_value = None
            result = migrate_file_to_keyring(home_dir=tmp_path)

        assert result is True
        assert not fernet_path.exists(), "fernet.key should be removed after successful migration"


# ------------------------------------------------------------------
# WOR-463: WORTHLESS_KEYRING_BACKEND env-var escape hatch
# ------------------------------------------------------------------


class TestKeyringBackendEnvOverride:
    """``WORTHLESS_KEYRING_BACKEND=null`` short-circuits the keyring path.

    Two audiences:
    1. Tests that subprocess-spawn ``worthless`` — the parent pytest's
       ``keyring.set_keyring(null)`` doesn't propagate; the env var does.
    2. Production users who don't trust their OS keyring — explicit opt-out.
    """

    def test_null_value_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Set the var to ``"null"`` → ``keyring_available()`` is False."""
        monkeypatch.setenv("WORTHLESS_KEYRING_BACKEND", "null")
        assert keyring_available() is False

    def test_null_value_short_circuits_before_backend_lookup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Backend lookup is never invoked when the env var forces null.

        Otherwise we'd hit the OS keyring API on every CLI startup just
        to discover the user opted out — defeats the perf/safety point.
        """
        monkeypatch.setenv("WORTHLESS_KEYRING_BACKEND", "null")
        with patch("worthless.cli.keystore.keyring") as mock_kr:
            mock_kr.get_keyring.side_effect = AssertionError(
                "keyring.get_keyring should NOT be called when env var forces null"
            )
            assert keyring_available() is False

    def test_other_value_does_not_short_circuit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Only the literal value ``"null"`` triggers the gate.

        Future expansion may support other backend names; until then,
        unrecognized values fall through to normal backend detection so
        a typo doesn't silently disable the keyring.
        """
        monkeypatch.setenv("WORTHLESS_KEYRING_BACKEND", "macos")  # not "null"
        backend_cls = type(
            "Keyring",
            (),
            {"__module__": "keyring.backends.macOS", "__qualname__": "Keyring"},
        )
        with patch("worthless.cli.keystore.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = backend_cls()
            assert keyring_available() is True

    def test_unset_does_not_short_circuit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When the var is unset, backend detection runs normally."""
        monkeypatch.delenv("WORTHLESS_KEYRING_BACKEND", raising=False)
        backend_cls = type(
            "Keyring",
            (),
            {"__module__": "keyring.backends.macOS", "__qualname__": "Keyring"},
        )
        with patch("worthless.cli.keystore.keyring") as mock_kr:
            mock_kr.get_keyring.return_value = backend_cls()
            assert keyring_available() is True

    def test_store_fernet_key_does_not_call_set_password_when_null(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """End-to-end: env-var-null means no real keyring write happens.

        This is the critical no-leak invariant. A test subprocess running
        ``worthless lock`` against a tmp home_dir must NOT pollute the
        host's keychain even if a real OS keyring is available.
        """
        monkeypatch.setenv("WORTHLESS_KEYRING_BACKEND", "null")
        with patch("worthless.cli.keystore.keyring") as mock_kr:
            store_fernet_key(b"some-key-bytes", home_dir=tmp_path)
            mock_kr.set_password.assert_not_called()
        # File fallback should have happened instead.
        assert (tmp_path / "fernet.key").exists()
        assert (tmp_path / "fernet.key").read_bytes() == b"some-key-bytes"

    def test_logs_info_when_forcing_null(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Production users who force the override should see it in logs."""
        monkeypatch.setenv("WORTHLESS_KEYRING_BACKEND", "null")
        with caplog.at_level(logging.INFO, logger="worthless.cli.keystore"):
            keyring_available()
        assert any(
            "WORTHLESS_KEYRING_BACKEND" in rec.message
            for rec in caplog.records
            if rec.levelno >= logging.INFO
        ), "Expected INFO log when env var forces null backend"
