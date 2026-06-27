"""Shared fixtures for ``user_flow`` tests that touch the real macOS keychain.

WOR-456: tests under this directory hit the live system keychain. Two design
constraints:

1. **Never collide with the user's real ``worthless`` entries.** Tests
   generate UUID-suffixed service names (``worthless-test-WOR-456-<uuid>``).
   The user's production service is ``worthless`` — different prefix.
2. **Always clean up, even on SIGINT.** If a test crashes or the user hits
   ctrl-C mid-suite, the fixture's teardown OR the session-scoped
   finalizer purges every entry the suite created. Without this, failed
   runs would leave keychain residue forever.

Tests using ``unique_service`` go through ``keystore_macos`` directly with a
test-only service. Tests using ``unique_home_dir`` exercise the production
``store_fernet_key`` API which always uses ``service='worthless'`` — purge
goes through ``delete_fernet_key`` keyed off the per-home-dir derived
username instead of a service-prefix sweep.
"""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import pytest

# Module-level registry of (service, username) pairs to purge at session end.
# The session finalizer is belt-and-braces: per-test fixtures already purge
# on success and failure paths, but a SIGINT mid-test bypasses fixture
# teardown — the finalizer runs on the way out regardless.
_keychain_entries_to_purge: list[tuple[str, str]] = []


def _try_delete(service: str, account: str) -> None:
    """Best-effort delete of (service, account) in both default and synced scope.

    Swallows every error — this runs in teardown paths where raising would
    mask the real failure.
    """
    if sys.platform != "darwin":
        return
    try:
        from worthless.cli import keystore_macos
    except ImportError:
        return
    for deleter in (
        keystore_macos.delete_password_local,
        keystore_macos.delete_password_synced,
    ):
        try:
            deleter(service, account)
        except Exception:  # noqa: BLE001 - teardown must not raise
            pass


def _purge_service(service: str) -> None:
    """Delete every entry under ``service`` in either scope."""
    if sys.platform != "darwin":
        return
    try:
        from worthless.cli import keystore_macos
    except ImportError:
        return
    # Synced sweep
    try:
        for acct in keystore_macos.find_synced_entries(service):
            _try_delete(service, acct)
    except Exception:  # noqa: BLE001
        pass
    # Default-scope sweep (no list_local helper — best-effort by known
    # registered names only). The session finalizer covers any names this
    # function missed.
    for svc, acct in list(_keychain_entries_to_purge):
        if svc == service:
            _try_delete(svc, acct)


@pytest.fixture(autouse=True)
def _enable_real_keyring_for_user_flow_tests(request, monkeypatch):
    """Tests in this directory want the REAL keyring path, not file fallback.

    Session-wide ``tests/conftest.py`` neutralises keyring two ways
    (WOR-469): sets ``WORTHLESS_KEYRING_BACKEND=null`` via
    ``os.environ.setdefault`` so subprocess invocations gate at our
    custom check, AND calls ``keyring.set_keyring(null.Keyring())`` so
    in-process writes silently no-op. Both protect normal tests from
    polluting the host keychain. user_flow tests OPT OUT because they
    specifically verify the keychain integration.

    We restore the macOS keyring backend explicitly (the platform default
    when no override is active). Linux/Windows users running user_flow
    tests would need their platform's default backend; this fixture
    skips the restore on non-darwin since the only active user_flow
    keychain tests are darwin-only.
    """
    if not request.node.get_closest_marker("user_flow"):
        return

    monkeypatch.delenv("WORTHLESS_KEYRING_BACKEND", raising=False)

    if sys.platform == "darwin":
        import keyring
        import keyring.backends.macOS

        previous = keyring.get_keyring()
        keyring.set_keyring(keyring.backends.macOS.Keyring())
        # Restore the session's null backend after the test so other
        # (non-user_flow) tests in the same xdist worker stay isolated.
        monkeypatch.setattr(
            keyring,
            "set_keyring",
            keyring.set_keyring,  # no-op rebind so only our restore below runs
        )

        def _restore() -> None:
            keyring.set_keyring(previous)

        request.addfinalizer(_restore)


@pytest.fixture
def unique_service():
    """Per-test unique keychain service tag. Purges on teardown."""
    svc = f"worthless-test-WOR-456-{uuid4()}"
    yield svc
    _purge_service(svc)


@pytest.fixture
def unique_home_dir(tmp_path: Path) -> Path:
    """Per-test ``WORTHLESS_HOME`` so production code's ``_keyring_username``
    derivation yields a unique-per-test keychain account.

    Teardown purges via ``delete_fernet_key`` (production API), which knows
    how to key off the home dir. Defense-in-depth: also register the
    (service, account) tuple with the session finalizer so a crash mid-test
    still cleans up.
    """
    home = tmp_path / ".worthless-WOR-456"
    home.mkdir(mode=0o700)
    yield home
    # Production API — knows about both keyring lib path and our macOS path.
    try:
        from worthless.cli.keystore import _keyring_username, delete_fernet_key

        acct = _keyring_username(home)
        _keychain_entries_to_purge.append(("worthless", acct))
        delete_fernet_key(home_dir=home)
        # Also belt-and-braces: directly delete via keystore_macos in case
        # delete_fernet_key only goes through the upstream keyring library
        # on this code path.
        _try_delete("worthless", acct)
    except Exception:  # noqa: BLE001
        pass


def pytest_sessionfinish(session, exitstatus):
    """Final sweep — runs even on SIGINT or pytest crash.

    Per-test fixtures cover the happy path; this catches anything that
    leaked through (early termination before fixture teardown ran).
    """
    for svc, acct in _keychain_entries_to_purge:
        _try_delete(svc, acct)
