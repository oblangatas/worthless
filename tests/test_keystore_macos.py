"""Unit tests for ``worthless.cli.keystore_macos`` — Security framework wrapper.

Test design (per WOR-456 plan):

* Test 1 — symbol resolution. Catches a vendor-SDK rename before users hit it.
* Test 2 — query-shape introspection. Proves the SecItemAdd wire format
  carries ``kSecAttrSynchronizable=kCFBooleanFalse`` so written entries are
  this-device-only. Monkeypatches the SecItemAdd ctypes pointer so no real
  keychain mutation occurs.

Both REQUIRES_DARWIN: the CoreFoundation/Security symbols (``kSecAttrSynchronizable``,
``kCFBooleanFalse``) only resolve on macOS; on Linux/Windows the module
raises ImportError at load time per its platform guard. On non-darwin the
tests skip, which matches CI's expectation (Linux runners have no Security
framework).
"""

from __future__ import annotations

import sys

import pytest

REQUIRES_DARWIN = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="keystore_macos is a Security.framework wrapper; darwin-only",
)


# ---------------------------------------------------------------------------
# Test 1 — symbol resolution
# ---------------------------------------------------------------------------


@REQUIRES_DARWIN
def test_required_security_symbols_load() -> None:
    """All Security/CoreFoundation symbols our writes depend on must resolve.

    A vendor SDK rename (Apple deprecating ``kSecAttrSynchronizable``,
    say) would surface here as a clean ImportError on first import,
    instead of as a runtime AttributeError mid-``worthless lock``.
    """
    from worthless.cli import keystore_macos

    # Touching these attrs must not raise.
    assert keystore_macos.kSecAttrSynchronizable is not None
    assert keystore_macos.kSecAttrSynchronizableAny is not None
    assert keystore_macos.kCFBooleanFalse is not None
    assert keystore_macos.kCFBooleanTrue is not None

    # Pointer identity check — kCFBooleanFalse and kCFBooleanTrue are
    # distinct CoreFoundation singletons. If they collide, every write
    # would still be syncable. Catches a copy-paste of the in_dll name.
    assert keystore_macos.kCFBooleanFalse.value != keystore_macos.kCFBooleanTrue.value


# ---------------------------------------------------------------------------
# Test 2 — query-shape introspection
# ---------------------------------------------------------------------------


@REQUIRES_DARWIN
def test_set_password_local_query_carries_synchronizable_false(monkeypatch) -> None:
    """``set_password_local`` must pass ``kSecAttrSynchronizable=kCFBooleanFalse``
    in the query dict to ``SecItemAdd``.

    Strategy: replace the ``SecItemAdd`` ctypes function pointer with a
    capturing fake; call ``set_password_local``; then walk the captured
    CFDictionary via ``CFDictionaryGetValue`` and assert the
    synchronizable key maps to the false-singleton pointer.

    No real keychain mutation occurs — the fake SecItemAdd returns 0 (OK)
    without touching the database.

    Pre-WOR-456 this assertion would FAIL because the upstream ``keyring``
    library's query omits ``kSecAttrSynchronizable`` entirely, leaving
    items eligible for iCloud sync.
    """
    from worthless.cli import keystore_macos

    captured: dict[str, int] = {}

    def fake_sec_item_add(query_ptr, _result_ptr):
        # Look up kSecAttrSynchronizable in the captured dict via
        # CFDictionaryGetValue. The returned pointer should be the
        # kCFBooleanFalse singleton.
        sync_value = keystore_macos.CFDictionaryGetValue(
            query_ptr, keystore_macos.kSecAttrSynchronizable
        )
        captured["sync_value_ptr"] = sync_value if sync_value else 0
        return 0  # errSecSuccess

    # Patch the module-level SecItemAdd binding. Production code calls it
    # via the module attribute, so a setattr is enough.
    monkeypatch.setattr(keystore_macos, "SecItemAdd", fake_sec_item_add)

    keystore_macos.set_password_local("worthless-test-WOR-456-q", "acct", "secret")

    assert "sync_value_ptr" in captured, (
        "SecItemAdd was never called; set_password_local short-circuited"
    )
    # The captured pointer must equal kCFBooleanFalse — anything else
    # (NULL, kCFBooleanTrue, kSecAttrSynchronizableAny) means the wire
    # format would still allow sync.
    assert captured["sync_value_ptr"] == keystore_macos.kCFBooleanFalse.value, (
        "Query dict missing kSecAttrSynchronizable=kCFBooleanFalse — "
        "writes will sync to iCloud Keychain"
    )
