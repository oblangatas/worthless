"""WOR-456: real-keychain tests proving Worthless writes are this-device-only.

Marker ``user_flow`` keeps these out of the default suite. macOS-only — the
``REQUIRES_DARWIN`` skip mirrors ``test_keychain_no_leak.py``.

Tests in this file:
* Test 3 — ``set_password_local`` writes a non-syncable entry.
* Test 5 — ``find_synced_entries`` filters correctly (synced subset only).
* Test 11 — ``store_fernet_key`` (production API) writes non-syncable on macOS.
* Test 12 — ``ensure_home`` first-run regen path inherits the fix.

Run: ``uv run pytest -m user_flow tests/user_flows/test_keychain_macos_writes.py -v``
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REQUIRES_DARWIN = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="Security.framework wrapper is darwin-only",
)


def _can_seed_synced_entries() -> bool:
    """Probe whether this Python process can add iCloud-syncable items.

    Unsigned binaries lack the ``keychain-access-groups`` entitlement
    needed by ``SecItemAdd`` with ``kSecAttrSynchronizable=True`` — calls
    fail with ``errSecMissingEntitlement (-34018)``. macOS's ``security``
    CLI hits the same wall.

    Tests that need pre-seeded synced state (migration / recovery /
    crash-safety) skip when this returns False. The non-synced write
    invariant — the actual production behavior change — is fully
    verifiable on unsigned binaries (tests 3, 11, 12).
    """
    if sys.platform != "darwin":
        return False
    from worthless.cli import keystore_macos as km

    try:
        query = km._build_dict(
            [
                (km.kSecClass, km.kSecClassGenericPassword),
                (km.kSecAttrService, "worthless-test-WOR-456-probe-entitlement"),
                (km.kSecAttrAccount, "probe"),
                (km.kSecValueData, b"v"),
                (km.kSecAttrSynchronizable, km.kCFBooleanTrue),
            ]
        )
        status = km.SecItemAdd(query, None)
        if status == 0:
            # Successfully seeded — clean up.
            km.delete_password_synced("worthless-test-WOR-456-probe-entitlement", "probe")
            return True
        return False
    except Exception:  # noqa: BLE001
        return False


REQUIRES_SYNC_ENTITLEMENT = pytest.mark.skipif(
    sys.platform != "darwin" or not _can_seed_synced_entries(),
    reason="Synced-entry seeding requires keychain-access-groups entitlement; "
    "skip on unsigned Python interpreters. Migration logic is covered by "
    "mocked unit tests in tests/test_doctor_keychain_migration.py.",
)


# ---------------------------------------------------------------------------
# Test 3 — non-sync write roundtrip
# ---------------------------------------------------------------------------


@pytest.mark.user_flow
@REQUIRES_DARWIN
def test_set_password_local_writes_non_synced_entry(unique_service: str) -> None:
    """Core invariant: writes via ``set_password_local`` are this-device-only.

    Default-scope read finds it; synced-scope scan does NOT.
    """
    from worthless.cli import keystore_macos

    keystore_macos.set_password_local(unique_service, "acct", "secret")

    # Default-scope read returns the value.
    assert keystore_macos.read_password_local(unique_service, "acct") == "secret"

    # Synced-scope scan does NOT include this account.
    assert "acct" not in keystore_macos.find_synced_entries(unique_service)
    assert keystore_macos.is_synced(unique_service, "acct") is False


# ---------------------------------------------------------------------------
# Test 5 — find_synced_entries filters correctly
# ---------------------------------------------------------------------------


@pytest.mark.user_flow
@REQUIRES_DARWIN
@REQUIRES_SYNC_ENTITLEMENT
def test_find_synced_entries_returns_only_synced(unique_service: str) -> None:
    """Pre-seed one synced + one non-synced entry under the same service.
    The scanner must return ONLY the synced account.
    """
    from worthless.cli import keystore_macos

    # Seed a synced entry directly via SecItemAdd with synchronizable=True.
    # Bypasses set_password_local intentionally to simulate pre-WOR-456
    # state on a real user's machine.
    _seed_synced_entry(unique_service, "synced-acct", "v1")

    # Seed a non-synced entry via the production path.
    keystore_macos.set_password_local(unique_service, "local-acct", "v2")

    synced = keystore_macos.find_synced_entries(unique_service)

    assert "synced-acct" in synced
    assert "local-acct" not in synced


def _seed_synced_entry(service: str, username: str, value: str) -> None:
    """Direct ctypes seed of a syncable entry — for migration-test setup.

    Mirrors the pre-WOR-456 leak path (``keyring`` library's omission of
    ``kSecAttrSynchronizable``) by explicitly setting it to True. This
    is the ONLY place in the test suite that creates synced entries; the
    rest of the suite cleans them up.
    """
    from worthless.cli import keystore_macos as km

    query = km._build_dict(
        [
            (km.kSecClass, km.kSecClassGenericPassword),
            (km.kSecAttrService, service),
            (km.kSecAttrAccount, username),
            (km.kSecValueData, value.encode("utf-8")),
            (km.kSecAttrSynchronizable, km.kCFBooleanTrue),
        ]
    )
    status = km.SecItemAdd(query, None)
    if status != 0:
        raise RuntimeError(f"_seed_synced_entry failed status={status}")


# ---------------------------------------------------------------------------
# Test 11 — store_fernet_key (production API) writes non-syncable
# ---------------------------------------------------------------------------


@pytest.mark.user_flow
@REQUIRES_DARWIN
def test_store_fernet_key_writes_non_synced_via_keystore_macos(
    unique_home_dir: Path,
) -> None:
    """End-to-end: the real production entry point writes a non-syncable entry.

    Pre-WOR-456 dispatch this would FAIL — ``store_fernet_key`` would route
    through the upstream ``keyring`` library and produce a syncable entry.
    """
    from worthless.cli import keystore_macos
    from worthless.cli.keystore import _keyring_username, store_fernet_key

    test_key = b"test-fernet-key-WOR-456-32bytes!"  # value doesn't matter
    store_fernet_key(test_key, home_dir=unique_home_dir)

    expected_acct = _keyring_username(unique_home_dir)

    # Local-scope read finds the value.
    assert keystore_macos.read_password_local("worthless", expected_acct) is not None

    # Synced-scope scan must NOT include this account.
    assert expected_acct not in keystore_macos.find_synced_entries("worthless"), (
        "store_fernet_key wrote a syncable entry — WOR-456 dispatch not wired"
    )


# ---------------------------------------------------------------------------
# Test 12 — ensure_home first-run regen inherits the fix
# ---------------------------------------------------------------------------


@pytest.mark.user_flow
@REQUIRES_DARWIN
def test_ensure_home_first_run_writes_non_synced(tmp_path: Path) -> None:
    """The bootstrap first-run path generates a fresh Fernet key and stores
    it via ``store_fernet_key``. WOR-456 fixes the dispatch inside
    ``store_fernet_key``, so bootstrap inherits the fix without touching
    ``bootstrap.py``.
    """
    from worthless.cli import keystore_macos
    from worthless.cli.bootstrap import ensure_home
    from worthless.cli.keystore import _keyring_username, delete_fernet_key

    home_dir = tmp_path / ".worthless-WOR-456-bootstrap"
    try:
        ensure_home(home_dir)
        expected_acct = _keyring_username(home_dir)

        assert expected_acct not in keystore_macos.find_synced_entries("worthless"), (
            "ensure_home first-run wrote a syncable entry"
        )
    finally:
        # Self-clean — ensure_home creates real keychain state.
        try:
            delete_fernet_key(home_dir=home_dir)
        except Exception:  # noqa: BLE001
            pass
