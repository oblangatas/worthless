"""WOR-456 supplemental tests — coverage for paths not exercised by the primary
test files added in this PR (test_doctor_icloud.py, test_keystore_macos.py).

Covers:
* WorthlessHome.recovery_dir property (bootstrap.py)
* keystore._is_macos_keyring() all branches (non-darwin, exception, backend check)
* keystore.store_fernet_key() WOR-456 dispatch to keystore_macos on darwin
* doctor._list_synced_keychain_entries() — exception swallowing, non-darwin no-op
* doctor._list_recovery_files() — no-dir, mixed extensions, sort order
* doctor._import_recovery_files() — empty list, None module, exception mid-import
* doctor._migrate_synced_keys() — empty list, None module, UserCancelled abort,
  partial success (first OK second non-fatal failure), multiple entries
* doctor._migrate_one() — value=None idempotent, existing recovery file (O_EXCL
  skip), KeychainNotFound on delete_synced, KeychainNotFound on delete_local
* doctor._print_synced_lines() — dry_run on/off
* doctor._doctor_confirm() — yes bypass, orphans-only prompt, synced-only prompt
  with multi-device warning, user decline
* doctor._doctor_apply() — migrated=0 warning path, orphans-only path
* doctor._doctor_run() integration — dry-run with findings, recovery-only output
* keystore_macos._raise_for_status() — each mapped status code (darwin-only)
* keystore_macos.KeychainError subclass repr scrubs value (darwin-only)

Cross-platform: most tests run on Linux CI by patching sys.platform or the
module-level ``_keystore_macos`` attribute directly.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands import doctor as doctor_module

runner = CliRunner(mix_stderr=False)

REQUIRES_DARWIN = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="Security.framework wrapper is darwin-only",
)


# ---------------------------------------------------------------------------
# Fixtures / shared helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_home(tmp_path: Path) -> WorthlessHome:
    """Bootstrapped tmp WorthlessHome (fresh DB + recovery dir setup ready)."""
    from worthless.cli.bootstrap import ensure_home

    return ensure_home(tmp_path / ".worthless")


def _stub_keystore_macos() -> MagicMock:
    """Minimal MagicMock for the keystore_macos public surface."""
    km = MagicMock()
    km.find_synced_entries.return_value = []
    km.read_password_any_scope.return_value = None
    km.read_password_local.return_value = None
    km.set_password_local.return_value = None
    km.delete_password_synced.return_value = None
    km.delete_password_local.return_value = None
    km.KeychainAuthDenied = type("KeychainAuthDenied", (Exception,), {})
    km.KeychainUserCancelled = type("KeychainUserCancelled", (Exception,), {})
    km.KeychainNotFound = type("KeychainNotFound", (Exception,), {})
    return km


def _async_returns(value):
    """Stub for an async function that returns ``value``."""

    async def _f(*_a, **_k):
        return value

    return _f


def _fake_orphan(i: int = 0):
    from worthless.storage.repository import EnrollmentRecord

    return EnrollmentRecord(
        key_alias=f"openai-fake-{i}",
        var_name=f"OPENAI_API_KEY_{i}",
        env_path=f"/tmp/.env-{i}",  # noqa: S108
        provider="openai",
        decoy_hash=None,
    )


# ===========================================================================
# Section 1: WorthlessHome.recovery_dir (bootstrap.py)
# ===========================================================================


class TestRecoveryDirProperty:
    """WorthlessHome.recovery_dir returns base_dir / 'recovery'."""

    def test_recovery_dir_returns_subdirectory(self, tmp_path: Path) -> None:
        """Property must return base_dir/recovery without creating it."""
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        expected = tmp_path / ".worthless" / "recovery"

        assert home.recovery_dir == expected

    def test_recovery_dir_not_created_by_property(self, tmp_path: Path) -> None:
        """Accessing the property must be side-effect-free — no directory creation."""
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        _ = home.recovery_dir

        assert not home.recovery_dir.exists(), (
            "recovery_dir property must not create the directory on access"
        )

    def test_recovery_dir_consistent_with_base_dir(self, tmp_path: Path) -> None:
        """Property is derived from base_dir; different base_dirs yield different paths."""
        home_a = WorthlessHome(base_dir=tmp_path / "a")
        home_b = WorthlessHome(base_dir=tmp_path / "b")

        assert home_a.recovery_dir != home_b.recovery_dir
        assert home_a.recovery_dir.parent == home_a.base_dir
        assert home_b.recovery_dir.parent == home_b.base_dir

    def test_recovery_dir_name_is_recovery(self, tmp_path: Path) -> None:
        """Directory name must be 'recovery' (not 'recover', 'recoveries', etc.)."""
        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        assert home.recovery_dir.name == "recovery"


# ===========================================================================
# Section 2: keystore._is_macos_keyring() all branches
# ===========================================================================


class TestIsMacosKeyring:
    """_is_macos_keyring() routing logic — cross-platform safe."""

    def test_returns_false_on_non_darwin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Always False when sys.platform != 'darwin'."""
        from worthless.cli import keystore as ks_mod

        monkeypatch.setattr(ks_mod.sys, "platform", "linux")
        monkeypatch.setattr(ks_mod, "keystore_macos", None)

        assert ks_mod._is_macos_keyring() is False

    def test_returns_false_when_keystore_macos_is_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Returns False when keystore_macos module is None (non-darwin import path)."""
        from worthless.cli import keystore as ks_mod

        monkeypatch.setattr(ks_mod.sys, "platform", "darwin")
        monkeypatch.setattr(ks_mod, "keystore_macos", None)

        assert ks_mod._is_macos_keyring() is False

    def test_returns_false_when_get_keyring_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns False (doesn't propagate) if keyring.get_keyring() raises."""
        import keyring as kr

        from worthless.cli import keystore as ks_mod

        def _raise():
            raise RuntimeError("keychain daemon unavailable")

        monkeypatch.setattr(ks_mod.sys, "platform", "darwin")
        monkeypatch.setattr(ks_mod, "keystore_macos", MagicMock())
        monkeypatch.setattr(kr, "get_keyring", _raise)

        assert ks_mod._is_macos_keyring() is False

    def test_returns_false_for_non_macos_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns False when the active backend module is NOT 'keyring.backends.macOS.*'."""
        import keyring as kr
        import keyring.backends.null as null_be

        from worthless.cli import keystore as ks_mod

        monkeypatch.setattr(ks_mod.sys, "platform", "darwin")
        monkeypatch.setattr(ks_mod, "keystore_macos", MagicMock())
        monkeypatch.setattr(kr, "get_keyring", lambda: null_be.Keyring())

        assert ks_mod._is_macos_keyring() is False

    def test_returns_true_for_macos_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns True when the active backend module starts with 'keyring.backends.macOS'."""
        import keyring as kr

        from worthless.cli import keystore as ks_mod

        # Fabricate a fake backend whose __module__ is the macOS backend.
        class _FakeMacOSBackend:
            pass

        _FakeMacOSBackend.__module__ = "keyring.backends.macOS"

        monkeypatch.setattr(ks_mod.sys, "platform", "darwin")
        monkeypatch.setattr(ks_mod, "keystore_macos", MagicMock())
        monkeypatch.setattr(kr, "get_keyring", lambda: _FakeMacOSBackend())

        assert ks_mod._is_macos_keyring() is True

    def test_returns_true_for_macos_backend_submodule(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """'keyring.backends.macOS.SomeSubmodule' also returns True (startswith)."""
        import keyring as kr

        from worthless.cli import keystore as ks_mod

        class _FakeMacOSSubBackend:
            pass

        _FakeMacOSSubBackend.__module__ = "keyring.backends.macOS.api"

        monkeypatch.setattr(ks_mod.sys, "platform", "darwin")
        monkeypatch.setattr(ks_mod, "keystore_macos", MagicMock())
        monkeypatch.setattr(kr, "get_keyring", lambda: _FakeMacOSSubBackend())

        assert ks_mod._is_macos_keyring() is True


# ===========================================================================
# Section 3: store_fernet_key() WOR-456 dispatch
# ===========================================================================


class TestStoreFernetKeyDispatch:
    """WOR-456 routing: when _is_macos_keyring() is True, keystore_macos.set_password_local
    is called instead of the upstream keyring.set_password."""

    def test_dispatches_to_keystore_macos_when_macos_keyring(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """On macOS with the native backend, writes go through keystore_macos
        to enforce kSecAttrSynchronizable=False (WOR-456 core contract)."""
        from worthless.cli import keystore as ks_mod

        km = _stub_keystore_macos()
        monkeypatch.setattr(ks_mod, "keystore_macos", km)
        monkeypatch.setattr(ks_mod, "_is_macos_keyring", lambda: True)
        # keyring_available() must also return True so the keyring branch executes.
        monkeypatch.setattr(ks_mod, "keyring_available", lambda: True)

        home_dir = tmp_path / ".worthless"
        home_dir.mkdir()
        test_key = b"A" * 44

        ks_mod.store_fernet_key(test_key, home_dir=home_dir)

        km.set_password_local.assert_called_once()
        call_args = km.set_password_local.call_args
        assert call_args.args[0] == "worthless"  # service
        assert call_args.args[2] == test_key.decode()  # password

    def test_uses_upstream_keyring_when_not_macos_keyring(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """When _is_macos_keyring() is False (Linux / null backend), the
        upstream keyring.set_password is used — keystore_macos is never touched."""
        from worthless.cli import keystore as ks_mod
        import keyring as kr

        km = _stub_keystore_macos()
        monkeypatch.setattr(ks_mod, "keystore_macos", km)
        monkeypatch.setattr(ks_mod, "_is_macos_keyring", lambda: False)
        monkeypatch.setattr(ks_mod, "keyring_available", lambda: True)

        set_password_calls: list = []
        monkeypatch.setattr(kr, "set_password", lambda *a, **kw: set_password_calls.append(a))

        home_dir = tmp_path / ".worthless"
        home_dir.mkdir()
        test_key = b"B" * 44

        ks_mod.store_fernet_key(test_key, home_dir=home_dir)

        assert len(set_password_calls) == 1, "upstream keyring.set_password must be called"
        km.set_password_local.assert_not_called()

    def test_falls_back_to_file_when_keyring_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """When keyring is unavailable, writes go to the file fallback
        regardless of the macOS dispatch."""
        from worthless.cli import keystore as ks_mod

        km = _stub_keystore_macos()
        monkeypatch.setattr(ks_mod, "keystore_macos", km)
        monkeypatch.setattr(ks_mod, "keyring_available", lambda: False)

        home_dir = tmp_path / ".worthless"
        home_dir.mkdir()
        test_key = b"C" * 44

        ks_mod.store_fernet_key(test_key, home_dir=home_dir)

        # keystore_macos was never called — file path was used.
        km.set_password_local.assert_not_called()
        fernet_file = home_dir / "fernet.key"
        assert fernet_file.exists(), "fernet.key file must be written when keyring unavailable"


# ===========================================================================
# Section 4: doctor._list_synced_keychain_entries()
# ===========================================================================


class TestListSyncedKeychainEntries:
    def test_returns_empty_when_keystore_macos_is_none(self) -> None:
        """Non-darwin: _keystore_macos is None → returns [] immediately."""
        with patch.object(doctor_module, "_keystore_macos", None):
            result = doctor_module._list_synced_keychain_entries()
        assert result == []

    def test_returns_empty_when_find_synced_entries_raises(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Exception from find_synced_entries is swallowed → returns []."""
        km = _stub_keystore_macos()
        km.find_synced_entries.side_effect = RuntimeError("keychain unavailable")

        with caplog.at_level(logging.DEBUG), patch.object(doctor_module, "_keystore_macos", km):
            result = doctor_module._list_synced_keychain_entries()

        assert result == []
        # Exception type (not value) must appear in debug log (SR-04).
        assert any("RuntimeError" in r.getMessage() for r in caplog.records), (
            "exception type must be logged at DEBUG level for supportability"
        )

    def test_returns_results_from_find_synced_entries(self) -> None:
        """On success, returns whatever find_synced_entries returns."""
        km = _stub_keystore_macos()
        km.find_synced_entries.return_value = ["fernet-key-abc", "fernet-key-def"]

        with patch.object(doctor_module, "_keystore_macos", km):
            result = doctor_module._list_synced_keychain_entries()

        assert result == ["fernet-key-abc", "fernet-key-def"]

    def test_passes_service_name_to_find_synced_entries(self) -> None:
        """Must call find_synced_entries with the '_SERVICE' constant."""
        from worthless.cli.keystore import _SERVICE

        km = _stub_keystore_macos()

        with patch.object(doctor_module, "_keystore_macos", km):
            doctor_module._list_synced_keychain_entries()

        km.find_synced_entries.assert_called_once_with(_SERVICE)


# ===========================================================================
# Section 5: doctor._list_recovery_files()
# ===========================================================================


class TestListRecoveryFiles:
    def test_returns_empty_when_recovery_dir_missing(self, fake_home: WorthlessHome) -> None:
        """No recovery_dir → empty list (directory absence is not an error)."""
        assert not fake_home.recovery_dir.exists()
        assert doctor_module._list_recovery_files(fake_home) == []

    def test_returns_empty_when_recovery_dir_empty(self, fake_home: WorthlessHome) -> None:
        """Empty recovery_dir → empty list."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        assert doctor_module._list_recovery_files(fake_home) == []

    def test_includes_only_recover_extension(self, fake_home: WorthlessHome) -> None:
        """Only files with .recover extension are returned; other files are ignored."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        (fake_home.recovery_dir / "fernet-key-abc.recover").write_bytes(b"v1")
        (fake_home.recovery_dir / "stale.txt").write_bytes(b"noise")
        (fake_home.recovery_dir / "fernet-key-def.recovery").write_bytes(b"v2")  # wrong ext

        result = doctor_module._list_recovery_files(fake_home)

        names = [f.name for f in result]
        assert names == ["fernet-key-abc.recover"], (
            f"Only .recover files should be included; got: {names}"
        )

    def test_returns_files_in_sorted_order(self, fake_home: WorthlessHome) -> None:
        """Results are sorted (alphabetically) for deterministic output."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        for name in ("c.recover", "a.recover", "b.recover"):
            (fake_home.recovery_dir / name).write_bytes(b"v")

        result = doctor_module._list_recovery_files(fake_home)
        names = [f.name for f in result]

        assert names == sorted(names), f"Results must be sorted; got: {names}"

    def test_returns_multiple_files(self, fake_home: WorthlessHome) -> None:
        """Multiple .recover files are all returned."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        for i in range(3):
            (fake_home.recovery_dir / f"key-{i}.recover").write_bytes(b"v")

        result = doctor_module._list_recovery_files(fake_home)
        assert len(result) == 3


# ===========================================================================
# Section 6: doctor._import_recovery_files() edge cases
# ===========================================================================


class TestImportRecoveryFiles:
    def test_returns_zero_on_empty_list(self) -> None:
        """Empty file list → 0 without touching keystore_macos."""
        assert doctor_module._import_recovery_files([]) == 0

    def test_returns_zero_when_keystore_macos_is_none(self, fake_home: WorthlessHome) -> None:
        """_keystore_macos=None → 0 (non-darwin path)."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        f = fake_home.recovery_dir / "key.recover"
        f.write_bytes(b"value")

        with patch.object(doctor_module, "_keystore_macos", None):
            result = doctor_module._import_recovery_files([f])

        assert result == 0

    def test_logs_warning_on_import_exception_and_continues(
        self,
        fake_home: WorthlessHome,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """An exception during one file's import is logged at WARNING and
        the loop continues to process remaining files."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        bad_file = fake_home.recovery_dir / "key-bad.recover"
        good_file = fake_home.recovery_dir / "key-good.recover"
        bad_file.write_bytes(b"bad-value")
        good_file.write_bytes(b"good-value")

        km = _stub_keystore_macos()
        call_count = [0]

        def side_effect(svc, acct):
            call_count[0] += 1
            if acct == "key-bad":
                raise RuntimeError("simulated keychain error")
            return None  # local password not found → import this one

        km.read_password_local.side_effect = side_effect

        with caplog.at_level(logging.WARNING), patch.object(doctor_module, "_keystore_macos", km):
            result = doctor_module._import_recovery_files([bad_file, good_file])

        # Exception type must be logged (SR-04 scrubbing).
        assert any("RuntimeError" in r.getMessage() for r in caplog.records)
        # Good file was still processed despite the earlier failure.
        assert result == 1

    def test_secret_value_not_in_warning_log(
        self,
        fake_home: WorthlessHome,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """SR-04: the recovery file content must never appear in warning logs."""
        secret = "SUPER-SECRET-FERNET-KEY-WOR456="  # noqa: S105
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        f = fake_home.recovery_dir / "key.recover"
        f.write_bytes(secret.encode("utf-8"))

        km = _stub_keystore_macos()
        km.read_password_local.side_effect = RuntimeError("boom")

        with caplog.at_level(logging.DEBUG), patch.object(doctor_module, "_keystore_macos", km):
            doctor_module._import_recovery_files([f])

        for record in caplog.records:
            assert secret not in record.getMessage(), (
                f"Secret leaked into log: {record.getMessage()}"
            )


# ===========================================================================
# Section 7: doctor._migrate_synced_keys() edge cases
# ===========================================================================


class TestMigrateSyncedKeysEdgeCases:
    def test_returns_zero_on_empty_list(self, fake_home: WorthlessHome) -> None:
        """Empty username list → 0 without creating recovery dir."""
        km = _stub_keystore_macos()
        with patch.object(doctor_module, "_keystore_macos", km):
            result = doctor_module._migrate_synced_keys([], fake_home)
        assert result == 0
        km.read_password_any_scope.assert_not_called()

    def test_returns_zero_when_keystore_macos_is_none(self, fake_home: WorthlessHome) -> None:
        """_keystore_macos=None → 0 immediately."""
        with patch.object(doctor_module, "_keystore_macos", None):
            result = doctor_module._migrate_synced_keys(["fernet-key-X"], fake_home)
        assert result == 0

    def test_aborts_on_user_cancelled(self, fake_home: WorthlessHome) -> None:
        """KeychainUserCancelled during the first entry aborts the run.
        Returns 0 (no successful migrations) and no state changes."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        km = _stub_keystore_macos()
        km.read_password_any_scope.side_effect = km.KeychainUserCancelled("cancelled")

        with patch.object(doctor_module, "_keystore_macos", km):
            result = doctor_module._migrate_synced_keys(["fernet-key-X", "fernet-key-Y"], fake_home)

        assert result == 0
        km.set_password_local.assert_not_called()
        km.delete_password_synced.assert_not_called()

    def test_partial_success_with_non_fatal_exception(self, fake_home: WorthlessHome) -> None:
        """A non-auth exception on entry N is logged and skipped; entries
        before N were already successfully counted."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        km = _stub_keystore_macos()
        # First entry succeeds; second raises a non-auth RuntimeError.
        km.read_password_local.return_value = "value-ok"
        call_count = [0]

        def read_any(svc, acct):
            call_count[0] += 1
            if call_count[0] == 1:
                return "value-ok"
            raise RuntimeError("unexpected keychain hiccup")

        km.read_password_any_scope.side_effect = read_any

        with patch.object(doctor_module, "_keystore_macos", km):
            result = doctor_module._migrate_synced_keys(
                ["fernet-key-first", "fernet-key-second"], fake_home
            )

        # First entry counted; second failed non-fatally.
        assert result == 1

    def test_multiple_entries_all_succeed(self, fake_home: WorthlessHome) -> None:
        """Happy path: all entries migrate → returns len(usernames)."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        km = _stub_keystore_macos()
        km.read_password_any_scope.return_value = "value"
        km.read_password_local.return_value = "value"

        with patch.object(doctor_module, "_keystore_macos", km):
            result = doctor_module._migrate_synced_keys(
                ["fernet-key-A", "fernet-key-B", "fernet-key-C"], fake_home
            )

        assert result == 3


# ===========================================================================
# Section 8: doctor._migrate_one() edge cases
# ===========================================================================


class TestMigrateOneEdgeCases:
    def test_no_op_when_value_is_none(self, fake_home: WorthlessHome) -> None:
        """If read_password_any_scope returns None (already migrated),
        no recovery file is created and no keychain mutations happen."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        km = _stub_keystore_macos()
        km.read_password_any_scope.return_value = None

        doctor_module._migrate_one("fernet-key-X", fake_home, km)

        km.set_password_local.assert_not_called()
        km.delete_password_synced.assert_not_called()
        assert not (fake_home.recovery_dir / "fernet-key-X.recover").exists()

    def test_skips_recovery_file_creation_if_already_exists(self, fake_home: WorthlessHome) -> None:
        """If the recovery file already exists (prior interrupted run),
        O_EXCL creation is skipped — the existing file is left intact."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        recovery = fake_home.recovery_dir / "fernet-key-X.recover"
        recovery.write_bytes(b"prior-run-value")

        km = _stub_keystore_macos()
        km.read_password_any_scope.return_value = "new-run-value"
        km.read_password_local.return_value = "new-run-value"

        doctor_module._migrate_one("fernet-key-X", fake_home, km)

        # File still contains the original prior-run value (not overwritten).
        assert recovery.read_bytes() == b"prior-run-value"

    def test_handles_keychain_not_found_on_delete_synced(self, fake_home: WorthlessHome) -> None:
        """KeychainNotFound on delete_password_synced is silently ignored
        (race condition: another doctor run already deleted it)."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        km = _stub_keystore_macos()
        km.read_password_any_scope.return_value = "value"
        km.read_password_local.return_value = "value"
        km.delete_password_synced.side_effect = km.KeychainNotFound("already gone")

        # Must not raise.
        doctor_module._migrate_one("fernet-key-X", fake_home, km)

        # Canonical write still happened.
        assert km.set_password_local.call_count >= 2  # staging + canonical

    def test_handles_keychain_not_found_on_delete_local_staging(
        self, fake_home: WorthlessHome
    ) -> None:
        """KeychainNotFound when deleting the staging slot is silently ignored."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        km = _stub_keystore_macos()
        km.read_password_any_scope.return_value = "value"
        km.read_password_local.return_value = "value"
        km.delete_password_local.side_effect = km.KeychainNotFound("staging already gone")

        # Must not raise.
        doctor_module._migrate_one("fernet-key-X", fake_home, km)

    def test_recovery_file_has_mode_0600(self, fake_home: WorthlessHome) -> None:
        """Recovery file must be created with mode 0o600 (owner read/write only)."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        km = _stub_keystore_macos()
        km.read_password_any_scope.return_value = "value"
        km.read_password_local.return_value = "value"

        doctor_module._migrate_one("fernet-key-X", fake_home, km)

        recovery = fake_home.recovery_dir / "fernet-key-X.recover"
        assert recovery.exists()
        mode_oct = oct(recovery.stat().st_mode)[-3:]
        assert mode_oct == "600", f"recovery file must be 0600, got {mode_oct}"

    def test_recovery_file_contains_utf8_encoded_value(self, fake_home: WorthlessHome) -> None:
        """Recovery file bytes must be the UTF-8 encoding of the keychain value."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        km = _stub_keystore_macos()
        secret_value = "fernet-key-WOR456-test-value="  # noqa: S105 — test fixture, not a real credential
        km.read_password_any_scope.return_value = secret_value
        km.read_password_local.return_value = secret_value

        doctor_module._migrate_one("fernet-key-X", fake_home, km)

        recovery = fake_home.recovery_dir / "fernet-key-X.recover"
        assert recovery.read_bytes() == secret_value.encode("utf-8")


# ===========================================================================
# Section 9: doctor._print_synced_lines()
# ===========================================================================


class TestPrintSyncedLines:
    def test_dry_run_appends_suffix(self, capsys) -> None:
        """In dry-run mode each line ends with ' (dry-run: no changes)'."""
        doctor_module._print_synced_lines(["fernet-key-abc", "fernet-key-def"], dry_run=True)
        captured = capsys.readouterr()
        assert "(dry-run: no changes)" in captured.out
        assert "fernet-key-abc" in captured.out
        assert "fernet-key-def" in captured.out

    def test_no_dry_run_no_suffix(self, capsys) -> None:
        """Without dry_run no suffix is appended."""
        doctor_module._print_synced_lines(["fernet-key-abc"], dry_run=False)
        captured = capsys.readouterr()
        assert "dry-run" not in captured.out
        assert "fernet-key-abc" in captured.out

    def test_empty_list_produces_no_output(self, capsys) -> None:
        """Empty list → no output lines."""
        doctor_module._print_synced_lines([], dry_run=False)
        assert capsys.readouterr().out == ""

    def test_each_entry_prefixed_with_bullet(self, capsys) -> None:
        """Each username line must be prefixed with '  • '."""
        doctor_module._print_synced_lines(["key-X"], dry_run=False)
        captured = capsys.readouterr()
        assert "  • key-X" in captured.out


# ===========================================================================
# Section 10: doctor._doctor_confirm()
# ===========================================================================


class TestDoctorConfirm:
    def _make_console(self) -> MagicMock:
        from worthless.cli.console import WorthlessConsole

        c = MagicMock(spec=WorthlessConsole)
        return c

    def test_yes_flag_returns_true_without_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """--yes bypasses the confirmation prompt entirely."""
        prompted: list = []
        monkeypatch.setattr("typer.confirm", lambda *a, **k: prompted.append(True) or True)
        console = self._make_console()

        result = doctor_module._doctor_confirm([], [], yes=True, console=console)

        assert result is True
        assert len(prompted) == 0, "typer.confirm must NOT be called when yes=True"

    def test_user_decline_returns_false_and_prints_cancelled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When user answers 'n', returns False and console.print_hint is called."""
        monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
        console = self._make_console()

        result = doctor_module._doctor_confirm([_fake_orphan()], [], yes=False, console=console)

        assert result is False
        console.print_hint.assert_called_once()
        hint_text = console.print_hint.call_args.args[0]
        assert "cancelled" in hint_text.lower(), (
            f"cancelled message must contain 'cancelled': {hint_text}"
        )

    def test_orphans_only_prompt_mentions_delete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Orphan-only prompt must mention 'delete' and the count."""
        prompts: list[str] = []
        monkeypatch.setattr(
            "typer.confirm",
            lambda prompt, **k: (prompts.append(prompt) or False),
        )
        console = self._make_console()

        doctor_module._doctor_confirm([_fake_orphan()], [], yes=False, console=console)

        assert prompts, "confirm must have been called"
        prompt = prompts[0]
        assert "delete" in prompt.lower(), f"prompt must mention 'delete': {prompt}"
        assert "1" in prompt, f"count must appear in prompt: {prompt}"

    def test_synced_only_prompt_contains_multi_device_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Synced-only prompt must embed the _MULTI_DEVICE_WARNING text verbatim."""
        prompts: list[str] = []
        monkeypatch.setattr(
            "typer.confirm",
            lambda prompt, **k: (prompts.append(prompt) or False),
        )
        console = self._make_console()

        doctor_module._doctor_confirm([], ["fernet-key-X"], yes=False, console=console)

        assert prompts, "confirm must have been called"
        # Check for key substrings from _MULTI_DEVICE_WARNING.
        for fragment in (
            "this-Mac-only",
            "recovery",
            "other Apple devices",
        ):
            assert fragment in prompts[0], (
                f"multi-device warning fragment '{fragment}' missing from prompt: {prompts[0]}"
            )

    def test_combined_prompt_mentions_both_orphan_and_migrate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Combined orphan + synced prompt must mention both actions."""
        prompts: list[str] = []
        monkeypatch.setattr(
            "typer.confirm",
            lambda prompt, **k: (prompts.append(prompt) or False),
        )
        console = self._make_console()

        doctor_module._doctor_confirm(
            [_fake_orphan(), _fake_orphan(1)],
            ["fernet-key-X"],
            yes=False,
            console=console,
        )

        prompt = prompts[0]
        assert "delete" in prompt.lower()
        assert "migrate" in prompt.lower()

    def test_user_accept_returns_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When user answers 'y', returns True."""
        monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
        console = self._make_console()

        result = doctor_module._doctor_confirm([_fake_orphan()], [], yes=False, console=console)
        assert result is True


# ===========================================================================
# Section 11: doctor._doctor_apply() edge cases
# ===========================================================================


class TestDoctorApply:
    def _make_console(self) -> MagicMock:
        from worthless.cli.console import WorthlessConsole

        return MagicMock(spec=WorthlessConsole)

    def test_no_migration_shows_warning(
        self,
        fake_home: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When _migrate_synced_keys returns 0 (auth denied), a warning is shown."""
        from worthless.storage.repository import ShardRepository

        monkeypatch.setattr(doctor_module, "_migrate_synced_keys", lambda *a, **k: 0)
        console = self._make_console()
        repo = ShardRepository(str(fake_home.db_path), fake_home.fernet_key)

        doctor_module._doctor_apply([], ["fernet-key-X"], repo, fake_home, console)

        console.print_warning.assert_called_once()
        warning_text = console.print_warning.call_args.args[0]
        assert "denied" in warning_text.lower() or "cancelled" in warning_text.lower(), (
            f"Warning must mention denial/cancellation: {warning_text}"
        )

    def test_successful_migration_shows_success_message(
        self,
        fake_home: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When _migrate_synced_keys returns > 0, a success message is shown."""
        from worthless.storage.repository import ShardRepository

        monkeypatch.setattr(doctor_module, "_migrate_synced_keys", lambda *a, **k: 2)
        console = self._make_console()
        repo = ShardRepository(str(fake_home.db_path), fake_home.fernet_key)

        doctor_module._doctor_apply([], ["fernet-key-X", "fernet-key-Y"], repo, fake_home, console)

        console.print_success.assert_called_once()
        success_text = console.print_success.call_args.args[0]
        assert "2" in success_text or "entries" in success_text or "ies" in success_text

    def test_plural_grammar_single_migration(
        self,
        fake_home: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Grammar: migrated=1 must use singular 'entry' not 'entries'."""
        from worthless.storage.repository import ShardRepository

        monkeypatch.setattr(doctor_module, "_migrate_synced_keys", lambda *a, **k: 1)
        console = self._make_console()
        repo = ShardRepository(str(fake_home.db_path), fake_home.fernet_key)

        doctor_module._doctor_apply([], ["fernet-key-X"], repo, fake_home, console)

        success_text = console.print_success.call_args.args[0]
        assert "entry" in success_text, f"Singular should use 'entry': {success_text}"
        assert "entries" not in success_text, f"Singular should NOT use 'entries': {success_text}"


# ===========================================================================
# Section 12: doctor._doctor_run() integration paths
# ===========================================================================


class TestDoctorRunIntegration:
    def test_dry_run_with_synced_finding_prints_planned_only(
        self,
        fake_home: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--fix --dry-run with synced entries: output mentions 'dry-run',
        no actual migration happens."""
        apply_called: list = []
        monkeypatch.setattr(
            doctor_module, "_list_synced_keychain_entries", lambda: ["fernet-key-X"]
        )
        monkeypatch.setattr(doctor_module, "_list_orphans", _async_returns([]))
        monkeypatch.setattr(doctor_module, "get_home", lambda: fake_home)
        monkeypatch.setattr(
            doctor_module,
            "_doctor_apply",
            lambda *a, **k: apply_called.append(True),
        )

        result = runner.invoke(app, ["doctor", "--fix", "--dry-run"])

        assert result.exit_code == 0, f"dry-run must exit 0: {result.output}"
        combined = result.output + (result.stderr or "")
        assert "dry-run" in combined.lower(), f"output must mention 'dry-run': {combined}"
        assert len(apply_called) == 0, "_doctor_apply must NOT be called in dry-run mode"

    def test_recovery_only_state_does_not_print_no_issues_found(
        self,
        fake_home: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When only recovery files were imported (no orphans, no synced),
        'No issues found.' must NOT appear — it was an active recovery action."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        (fake_home.recovery_dir / "key.recover").write_bytes(b"v")

        monkeypatch.setattr(doctor_module, "_list_synced_keychain_entries", lambda: [])
        monkeypatch.setattr(doctor_module, "_list_orphans", _async_returns([]))
        monkeypatch.setattr(doctor_module, "get_home", lambda: fake_home)
        # Simulate successful recovery import.
        monkeypatch.setattr(doctor_module, "_import_recovery_files", lambda _files: 1)

        result = runner.invoke(app, ["doctor"])

        combined = result.output + (result.stderr or "")
        assert "no issues found" not in combined.lower(), (
            f"Recovery-only state must not say 'no issues found': {combined}"
        )

    def test_recovery_import_prints_recovery_phrase(
        self,
        fake_home: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When recovery files are imported, output must include RECOVERY_IMPORT_PHRASE."""
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True)
        (fake_home.recovery_dir / "key.recover").write_bytes(b"v")

        monkeypatch.setattr(doctor_module, "_list_synced_keychain_entries", lambda: [])
        monkeypatch.setattr(doctor_module, "_list_orphans", _async_returns([]))
        monkeypatch.setattr(doctor_module, "get_home", lambda: fake_home)
        monkeypatch.setattr(doctor_module, "_import_recovery_files", lambda _files: 2)

        result = runner.invoke(app, ["doctor"])

        combined = result.output + (result.stderr or "")
        assert doctor_module.RECOVERY_IMPORT_PHRASE in combined, (
            f"Output must include RECOVERY_IMPORT_PHRASE "
            f"'{doctor_module.RECOVERY_IMPORT_PHRASE}': {combined}"
        )

    def test_clean_state_prints_no_issues_found(
        self,
        fake_home: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No recovery files, no orphans, no synced → 'No issues found.' exactly."""
        monkeypatch.setattr(doctor_module, "_list_synced_keychain_entries", lambda: [])
        monkeypatch.setattr(doctor_module, "_list_orphans", _async_returns([]))
        monkeypatch.setattr(doctor_module, "get_home", lambda: fake_home)

        result = runner.invoke(app, ["doctor"])

        combined = result.output + (result.stderr or "")
        assert "no issues found" in combined.lower(), (
            f"Clean state must report 'No issues found.': {combined}"
        )
        assert result.exit_code == 0

    def test_fix_yes_with_synced_entries_calls_apply(
        self,
        fake_home: WorthlessHome,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--fix --yes with synced entries calls _doctor_apply (confirm bypassed)."""
        apply_calls: list = []
        monkeypatch.setattr(
            doctor_module, "_list_synced_keychain_entries", lambda: ["fernet-key-X"]
        )
        monkeypatch.setattr(doctor_module, "_list_orphans", _async_returns([]))
        monkeypatch.setattr(doctor_module, "get_home", lambda: fake_home)
        monkeypatch.setattr(
            doctor_module,
            "_doctor_apply",
            lambda *a, **k: apply_calls.append(a),
        )

        result = runner.invoke(app, ["doctor", "--fix", "--yes"])

        assert result.exit_code == 0
        assert len(apply_calls) == 1, "_doctor_apply must be called with --fix --yes"


# ===========================================================================
# Section 13: keystore_macos._raise_for_status() error codes (darwin-only)
# ===========================================================================


@REQUIRES_DARWIN
class TestRaiseForStatus:
    """_raise_for_status maps OSStatus codes to named exception types."""

    def test_zero_does_not_raise(self) -> None:
        from worthless.cli import keystore_macos as km

        km._raise_for_status(0)  # must not raise

    def test_item_not_found_raises_keychain_not_found(self) -> None:
        from worthless.cli import keystore_macos as km

        with pytest.raises(km.KeychainNotFound):
            km._raise_for_status(km._ErrorCodes.item_not_found)

    def test_sec_auth_failed_raises_keychain_auth_denied(self) -> None:
        from worthless.cli import keystore_macos as km

        with pytest.raises(km.KeychainAuthDenied):
            km._raise_for_status(km._ErrorCodes.sec_auth_failed)

    def test_user_cancelled_raises_keychain_user_cancelled(self) -> None:
        from worthless.cli import keystore_macos as km

        # user_cancelled is an alias for keychain_denied (-128); the exception
        # class is KeychainUserCancelled.
        with pytest.raises(km.KeychainUserCancelled):
            km._raise_for_status(km._ErrorCodes.user_cancelled)

    def test_unknown_status_raises_base_keychain_error(self) -> None:
        from worthless.cli import keystore_macos as km

        with pytest.raises(km.KeychainError):
            km._raise_for_status(-99999)  # arbitrary unknown code

    def test_keychain_error_repr_does_not_include_password(self) -> None:
        """SR-04: KeychainError.__repr__ must never expose value bytes."""
        from worthless.cli import keystore_macos as km

        err = km.KeychainError(-25300, "test message with no secret")
        r = repr(err)
        assert "test message" not in r, "KeychainError.__repr__ must NOT include the msg string"
        assert "-25300" in r, "repr must include the status code"

    def test_keychain_not_found_is_subclass_of_keychain_error(self) -> None:
        from worthless.cli import keystore_macos as km

        assert issubclass(km.KeychainNotFound, km.KeychainError)

    def test_keychain_auth_denied_is_subclass_of_keychain_error(self) -> None:
        from worthless.cli import keystore_macos as km

        assert issubclass(km.KeychainAuthDenied, km.KeychainError)

    def test_keychain_user_cancelled_is_subclass_of_keychain_error(self) -> None:
        from worthless.cli import keystore_macos as km

        assert issubclass(km.KeychainUserCancelled, km.KeychainError)


# ===========================================================================
# Section 14: keystore_macos import guard (cross-platform)
# ===========================================================================


def test_keystore_macos_raises_import_error_on_non_darwin() -> None:
    """Importing keystore_macos on a non-darwin platform raises ImportError.

    This test is meaningfully executable only on non-darwin (Linux CI).
    On darwin it would succeed. The test guard inverts the normal darwin-only
    pattern: it ONLY runs on non-darwin where the guard fires.
    """
    if sys.platform == "darwin":
        pytest.skip("darwin can import keystore_macos — guard only fires on non-darwin")

    import importlib

    with pytest.raises(ImportError):
        importlib.import_module("worthless.cli.keystore_macos")


# ===========================================================================
# Section 15: Multi-device warning content validation
# ===========================================================================


def test_multi_device_warning_contains_required_substrings() -> None:
    """_MULTI_DEVICE_WARNING must contain the safety-critical substrings
    that are AND-bound by the consent prompt tests. This directly catches
    copy-paste drift where someone edits the constant but forgets to update
    the docstring."""
    warning = doctor_module._MULTI_DEVICE_WARNING

    required = [
        "this-Mac-only",
        "recovery",
        "other Apple devices",
        "other Macs",
    ]
    for fragment in required:
        assert fragment in warning, f"_MULTI_DEVICE_WARNING missing required fragment '{fragment}'"


# ===========================================================================
# Section 16: ICLOUD_LEAK_PHRASE / ICLOUD_FIX_PHRASE / RECOVERY_IMPORT_PHRASE
#             module-level constants
# ===========================================================================


def test_doctor_module_phrase_constants_are_non_empty() -> None:
    """All phrase constants must be non-empty strings — a blank constant
    silently passes every AND-bind check."""
    assert doctor_module.ICLOUD_LEAK_PHRASE
    assert doctor_module.ICLOUD_FIX_PHRASE
    assert doctor_module.RECOVERY_IMPORT_PHRASE

    assert isinstance(doctor_module.ICLOUD_LEAK_PHRASE, str)
    assert isinstance(doctor_module.ICLOUD_FIX_PHRASE, str)
    assert isinstance(doctor_module.RECOVERY_IMPORT_PHRASE, str)


def test_icloud_fix_phrase_names_the_command() -> None:
    """ICLOUD_FIX_PHRASE must contain 'doctor --fix' so the user always
    sees the recovery path in plain English."""
    assert "doctor --fix" in doctor_module.ICLOUD_FIX_PHRASE
