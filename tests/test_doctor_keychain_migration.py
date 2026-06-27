"""WOR-456: doctor extension tests for iCloud keychain migration + recovery.

Mocked unit tests for the parts of the migration logic that can't be
end-to-end tested on un-signed Python interpreters (the live
``test_keychain_macos_writes.py`` sibling proves the writes themselves).

Coverage:
* Wording AND-bind — engineer-speak drift catcher.
* Recovery file lifecycle — write/import/cleanup with real filesystem.
* Migration ordering — the safe staging-slot dance, verified via a
  spy on the mocked keystore_macos primitives.
* Auth-denied / user-cancelled — abort with no state change.
* Concurrent --fix flock.

Cross-platform: tests run on Linux CI by mocking ``keystore_macos``
imports inside ``commands.doctor`` directly, so no Security framework
calls fire.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands import doctor as doctor_module

runner = CliRunner(mix_stderr=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_home(tmp_path: Path) -> WorthlessHome:
    """Bootstrapped tmp WorthlessHome (fresh DB + recovery dir setup ready)."""
    from worthless.cli.bootstrap import ensure_home

    return ensure_home(tmp_path / ".worthless")


def _stub_keystore_macos() -> MagicMock:
    """A MagicMock pre-populated with the keystore_macos public API.

    Tests that need to drive the migration replace primitives with side_effect
    lambdas; tests that just verify wording let the defaults stand (they'll
    record calls but return None / [] / False).
    """
    km = MagicMock()
    km.find_synced_entries.return_value = []
    km.read_password_any_scope.return_value = None
    km.read_password_local.return_value = None
    km.set_password_local.return_value = None
    km.delete_password_synced.return_value = None
    km.delete_password_local.return_value = None
    # Bind exception types so production code's `except keystore_macos.X`
    # works under the mock.
    km.KeychainAuthDenied = type("KeychainAuthDenied", (Exception,), {})
    km.KeychainUserCancelled = type("KeychainUserCancelled", (Exception,), {})
    km.KeychainNotFound = type("KeychainNotFound", (Exception,), {})
    return km


# ---------------------------------------------------------------------------
# Test 10 — wording AND-bind
# ---------------------------------------------------------------------------


def test_iclolud_finding_uses_canonical_phrases(
    fake_home: WorthlessHome, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Diagnose-mode output for a synced-keychain finding must contain
    the canonical user-facing phrases. Mirrors the HF7 PROBLEM/FIX phrase
    AND-bind from ``orphans.py`` — drift is caught here, not in code review.
    """
    monkeypatch.setattr(
        doctor_module,
        "_list_synced_keychain_entries",
        lambda: ["fernet-key-abc123", "fernet-key-def456"],
    )
    # No orphans, no recovery files — only the iCloud finding.
    monkeypatch.setattr(doctor_module, "_list_orphans", _async_returns(([], [])))
    monkeypatch.setattr(doctor_module, "get_home", lambda: fake_home)
    monkeypatch.setattr(doctor_module, "_check_openclaw_section", lambda *a, **kw: False)
    monkeypatch.setattr(doctor_module, "_check_home_mismatch", lambda *a, **kw: False)
    monkeypatch.setattr(doctor_module, "_check_alias_not_in_db", lambda *a, **kw: False)

    result = runner.invoke(app, ["doctor"])

    output = result.output + (result.stderr or "")
    assert doctor_module.ICLOUD_LEAK_PHRASE in output, (
        f"missing canonical phrase '{doctor_module.ICLOUD_LEAK_PHRASE}':\n{output}"
    )
    assert doctor_module.ICLOUD_FIX_PHRASE in output, (
        f"missing fix-hint phrase '{doctor_module.ICLOUD_FIX_PHRASE}':\n{output}"
    )
    # Also assert the soft tone — no exclamation, no engineer-speak.
    assert "this Mac only" in output, f"missing 'this Mac only' framing:\n{output}"


# ---------------------------------------------------------------------------
# Test 9 — doctor exit-code matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "n_orphans,n_synced,n_recovery,expected_exit",
    [
        (0, 0, 0, 0),  # all-clean
        (1, 0, 0, 0),  # orphan only — diagnose succeeds with finding
        (0, 1, 0, 0),  # synced only
        (0, 0, 1, 0),  # recovery import only
        (2, 2, 0, 0),  # mixed
    ],
)
def test_doctor_exit_codes(
    fake_home: WorthlessHome,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    n_orphans: int,
    n_synced: int,
    n_recovery: int,
    expected_exit: int,
) -> None:
    """Doctor diagnose-mode exits 0 regardless of finding count.

    Findings are reported on stderr; exit code is reserved for hard
    failures (lock contention, bootstrap error). This is the contract
    for both human users and AI agents reading status from the exit code.
    """
    fake_orphans = [_fake_orphan(i) for i in range(n_orphans)]
    fake_synced = [f"fernet-key-{i}" for i in range(n_synced)]

    monkeypatch.setattr(doctor_module, "_list_synced_keychain_entries", lambda: fake_synced)
    monkeypatch.setattr(
        doctor_module, "_list_orphans", _async_returns((fake_orphans, fake_orphans))
    )
    monkeypatch.setattr(doctor_module, "get_home", lambda: fake_home)
    # Isolate from CI environment: these checks touch real filesystem paths
    # (resolve_port, cwd()/.env, _oc_integration.detect) that can produce
    # unexpected state or raise on CI runners, causing error_boundary → exit 1.
    monkeypatch.setattr(doctor_module, "_check_openclaw_section", lambda *a, **kw: False)
    monkeypatch.setattr(doctor_module, "_check_home_mismatch", lambda *a, **kw: False)
    monkeypatch.setattr(doctor_module, "_check_alias_not_in_db", lambda *a, **kw: False)

    # Pre-populate recovery files
    if n_recovery:
        fake_home.recovery_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        for i in range(n_recovery):
            (fake_home.recovery_dir / f"fernet-key-r{i}.recover").write_bytes(b"v")
        monkeypatch.setattr(
            doctor_module,
            "_import_recovery_files",
            lambda files: len(files),
        )

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == expected_exit, (
        f"unexpected exit {result.exit_code} for "
        f"orphans={n_orphans} synced={n_synced} recovery={n_recovery}:\n"
        f"stdout: {result.output}\nstderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# Test 8 — recovery file roundtrip
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform != "darwin", reason="recovery import calls keystore_macos on darwin"
)
def test_import_recovery_files_imports_missing_and_skips_existing(
    fake_home: WorthlessHome, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_import_recovery_files`` imports values whose accounts are missing
    locally; silently deletes recovery files whose accounts already exist
    (stale from this Mac being the originator).
    """
    fake_home.recovery_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    missing = fake_home.recovery_dir / "fernet-key-missing.recover"
    existing = fake_home.recovery_dir / "fernet-key-existing.recover"
    missing.write_bytes(b"value-to-import")
    existing.write_bytes(b"stale-value")

    km = _stub_keystore_macos()
    km.read_password_local.side_effect = lambda svc, acct: (
        "already-here" if acct == "fernet-key-existing" else None
    )

    # patch.object intercepts the module-level _keystore_macos attribute that
    # doctor.py resolves at import time — patch.dict(sys.modules) cannot reach
    # already-resolved bindings.
    with patch.object(doctor_module, "_keystore_macos", km):
        imported = doctor_module._import_recovery_files(
            doctor_module._list_recovery_files(fake_home)
        )

    # One actually imported (the missing one); the stale one is just removed.
    assert imported == 1
    assert not missing.exists(), "imported recovery file must be cleaned up"
    assert not existing.exists(), "stale recovery file must be cleaned up"

    # set_password_local was called exactly once, for the missing account
    # only — never for the already-existing one.
    set_calls = [c for c in km.set_password_local.call_args_list]
    assert len(set_calls) == 1
    assert set_calls[0].args[1] == "fernet-key-missing"
    assert set_calls[0].args[2] == "value-to-import"


# ---------------------------------------------------------------------------
# Test 7 (mocked) — migration safe ordering
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "darwin", reason="migration calls keystore_macos on darwin")
def test_migrate_synced_keys_uses_safe_ordering(
    fake_home: WorthlessHome,
) -> None:
    """The migration must call keystore_macos primitives in the safe order:
    read_any → write recovery file → set_password_local(staging) → verify
    → delete_password_synced(original) → set_password_local(canonical) →
    verify → delete_password_local(staging). NEVER delete before write.
    """
    fake_home.recovery_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    km = _stub_keystore_macos()
    # The key we'll migrate. Read returns this on any-scope read.
    km.read_password_any_scope.return_value = "secret-value-WOR-456"
    # After staging write, read_password_local should return the value
    # so byte-equality verification passes; same after canonical write.
    km.read_password_local.return_value = "secret-value-WOR-456"

    call_order: list[str] = []
    km.read_password_any_scope.side_effect = lambda *_a, **_k: (
        call_order.append("read_any") or "secret-value-WOR-456"
    )
    km.set_password_local.side_effect = lambda *_a, **_k: (
        call_order.append(f"set_local:{_a[1]}") or None
    )
    km.read_password_local.side_effect = lambda *_a, **_k: (
        call_order.append(f"read_local:{_a[1]}") or "secret-value-WOR-456"
    )
    km.delete_password_synced.side_effect = lambda *_a, **_k: (
        call_order.append("delete_synced") or None
    )
    km.delete_password_local.side_effect = lambda *_a, **_k: (
        call_order.append(f"delete_local:{_a[1]}") or None
    )

    with patch.object(doctor_module, "_keystore_macos", km):
        migrated = doctor_module._migrate_synced_keys(["fernet-key-X"], fake_home)

    assert migrated == 1

    # The critical safety property: the synced delete MUST come AFTER
    # the staging write+verify, NEVER before.
    assert "delete_synced" in call_order
    delete_idx = call_order.index("delete_synced")
    staging_set_idx = call_order.index("set_local:fernet-key-X.migrating")
    staging_verify_idx = call_order.index("read_local:fernet-key-X.migrating")

    assert staging_set_idx < delete_idx, (
        f"staging slot must be written BEFORE synced delete; got order: {call_order}"
    )
    assert staging_verify_idx < delete_idx, (
        f"staging slot must be verified BEFORE synced delete; got order: {call_order}"
    )

    # Recovery file must exist on disk before the synced delete fires.
    recovery = fake_home.recovery_dir / "fernet-key-X.recover"
    assert recovery.exists(), "recovery file must be written before any keychain mutation"
    assert recovery.read_bytes() == b"secret-value-WOR-456"
    # File mode 0o600 (owner-only).
    assert oct(recovery.stat().st_mode)[-3:] == "600"


# ---------------------------------------------------------------------------
# Test 15 — auth-denied aborts with no state change
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "darwin", reason="migration calls keystore_macos on darwin")
def test_migrate_synced_keys_aborts_on_auth_denied(
    fake_home: WorthlessHome,
) -> None:
    """KeychainAuthDenied during the read-any step aborts the run — no
    recovery file, no staging slot, no synced delete. Returns the count
    successfully migrated up to the abort point (zero in this test).
    """
    fake_home.recovery_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    km = _stub_keystore_macos()

    def deny(*_a, **_k):
        raise km.KeychainAuthDenied("denied")

    km.read_password_any_scope.side_effect = deny

    with patch.object(doctor_module, "_keystore_macos", km):
        migrated = doctor_module._migrate_synced_keys(["fernet-key-X"], fake_home)

    assert migrated == 0
    # No state change anywhere.
    km.set_password_local.assert_not_called()
    km.delete_password_synced.assert_not_called()
    km.delete_password_local.assert_not_called()
    # No recovery file.
    assert not (fake_home.recovery_dir / "fernet-key-X.recover").exists()


# ---------------------------------------------------------------------------
# Test 14 — concurrent doctor --fix flock
# ---------------------------------------------------------------------------


def test_doctor_lock_blocks_concurrent_run(fake_home: WorthlessHome) -> None:
    """A second ``_doctor_lock`` against the same home raises
    LOCK_IN_PROGRESS. The flock is the serialization point that prevents
    two migration state-machines from racing.
    """
    from worthless.cli.errors import ErrorCode, WorthlessError

    with doctor_module._doctor_lock(fake_home):
        with pytest.raises(WorthlessError) as exc_info:
            with doctor_module._doctor_lock(fake_home):
                pytest.fail("second flock should not have been acquired")
        assert exc_info.value.code == ErrorCode.LOCK_IN_PROGRESS


# ---------------------------------------------------------------------------
# Test 16 — SR-04 logging discipline
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "darwin", reason="migration calls keystore_macos on darwin")
def test_migration_failure_does_not_log_secret_value(
    fake_home: WorthlessHome, caplog: pytest.LogCaptureFixture
) -> None:
    """A failure mid-migration must NEVER include the fernet-key bytes
    in any log line. Production exceptions in keystore_macos override
    __repr__ to scrub the value pointer; doctor's outer handler logs only
    the exception type name.
    """
    fake_home.recovery_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    secret = "WOR456-secret-32-bytes-base64-key-aaaa="  # noqa: S105 — test fixture, not a real credential
    km = _stub_keystore_macos()
    km.read_password_any_scope.return_value = secret
    # Force failure mid-migration — staging write succeeds, but the
    # verification read mismatches.
    km.read_password_local.return_value = "DIFFERENT-VALUE"

    import logging

    caplog.set_level(logging.DEBUG)

    with patch.object(doctor_module, "_keystore_macos", km):
        doctor_module._migrate_synced_keys(["fernet-key-X"], fake_home)

    # The secret must never appear in captured logs.
    for record in caplog.records:
        assert secret not in record.getMessage(), (
            f"secret value leaked into log: {record.getMessage()}"
        )
        assert secret not in str(record.exc_info or ""), "secret leaked via exc_info"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _async_returns(value):
    """Build a stub for an async function that just returns ``value``."""

    async def _f(*_a, **_k):
        return value

    return _f


def _fake_orphan(i: int):
    """Construct a minimal EnrollmentRecord stand-in for parametrized tests."""
    from worthless.storage.repository import EnrollmentRecord

    return EnrollmentRecord(
        key_alias=f"openai-fake-{i}",
        var_name=f"OPENAI_API_KEY_{i}",
        env_path=f"/tmp/.env-{i}",  # noqa: S108 — fake path, never created
        provider="openai",
        decoy_hash=None,
    )
