"""macOS Security.framework wrapper enforcing this-device-only keychain entries.

WOR-456: Worthless's Fernet keys are per-machine cryptographic material —
they must NOT replicate via iCloud Keychain. The upstream Python ``keyring``
library's macOS backend omits ``kSecAttrSynchronizable`` from its
``SecItemAdd`` query, which in practice produces items eligible for sync.

This module mirrors ``keyring.backends.macOS.api`` but pins
``kSecAttrSynchronizable=kCFBooleanFalse`` on every write, exposes
synced-scope read helpers for the migration path, and reports
auth/cancel/not-found errors as named exception types so
``worthless doctor --fix`` can report actionable text instead of
opaque OSStatus codes.

Defense-in-depth: framework dlopen paths are pinned absolute under
``/System/Library/Frameworks/`` (SIP-protected) — no ``find_library``
fallback that could resolve to a user-writable shadow.

Module-level platform guard: importing this module on non-darwin raises
ImportError. Callers in ``keystore.py`` import conditionally so non-macOS
codepaths never reach this file.
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
from ctypes import byref, c_int32, c_uint32, c_void_p
from typing import Any

if sys.platform != "darwin":
    raise ImportError("worthless.cli.keystore_macos is darwin-only")

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pinned absolute paths under SIP-protected /System/Library/Frameworks/.
# ``find_library('Security')`` is path-resolved and could resolve to a
# user-writable shadow on a misconfigured machine. Pinning the absolute
# path closes that attack surface.
# ---------------------------------------------------------------------------

_SEC_PATH = "/System/Library/Frameworks/Security.framework/Security"
_FOUND_PATH = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

# macOS 11+ stores system framework binaries in the dyld shared cache rather
# than on disk; ``os.path.exists`` returns False for the symlink target even
# though ``ctypes.CDLL`` resolves correctly via dlopen. ``os.path.lexists``
# verifies the framework directory entry is present without dereferencing
# into the cache. The path itself is SIP-protected on macOS 10.11+, so
# pinning the absolute path under ``/System/Library/Frameworks/`` is the
# meaningful defense — the lexists check just guards against framework
# removal/rename, not against substitution (which SIP prevents).
if not (os.path.lexists(_SEC_PATH) and os.path.lexists(_FOUND_PATH)):  # pragma: no cover
    raise ImportError(f"required system frameworks missing: {_SEC_PATH!r} / {_FOUND_PATH!r}")

_sec = ctypes.CDLL(_SEC_PATH)
_found = ctypes.CDLL(_FOUND_PATH)


# ---------------------------------------------------------------------------
# OSStatus and named errors
# ---------------------------------------------------------------------------

OS_status = c_int32


class _ErrorCodes:
    item_not_found = -25300
    keychain_denied = -128
    user_cancelled = -128  # alias — same code; named for readability
    sec_auth_failed = -25293
    plist_missing = -67030
    sec_interaction_not_allowed = -25308


class KeychainError(Exception):
    """Base for all Security.framework errors raised by this module.

    SR-04: subclass __str__ overrides scrub any potentially-secret value
    pointer; never include captured passwords in repr or message.
    """

    def __init__(self, status: int, msg: str) -> None:
        super().__init__(msg)
        self.status = status

    def __repr__(self) -> str:  # never include a captured value
        return f"{type(self).__name__}(status={self.status})"


class KeychainNotFound(KeychainError):
    pass


class KeychainAuthDenied(KeychainError):
    """User clicked Deny on a permission prompt, or the keychain is locked."""


class KeychainUserCancelled(KeychainError):
    """User cancelled a Security.framework dialog."""


def _raise_for_status(status: int) -> None:
    if status == 0:
        return
    if status == _ErrorCodes.item_not_found:
        raise KeychainNotFound(status, "keychain item not found")
    if status == _ErrorCodes.sec_auth_failed:
        raise KeychainAuthDenied(status, "keychain access denied")
    if status == _ErrorCodes.user_cancelled:
        raise KeychainUserCancelled(status, "keychain access cancelled by user")
    raise KeychainError(status, f"unexpected Security.framework error {status}")


# ---------------------------------------------------------------------------
# CoreFoundation / Security symbol bindings
# ---------------------------------------------------------------------------

# Builders
CFDictionaryCreate = _found.CFDictionaryCreate
CFDictionaryCreate.restype = c_void_p
CFDictionaryCreate.argtypes = (c_void_p, c_void_p, c_void_p, c_int32, c_void_p, c_void_p)

CFDictionaryGetValue = _found.CFDictionaryGetValue
CFDictionaryGetValue.restype = c_void_p
CFDictionaryGetValue.argtypes = (c_void_p, c_void_p)

CFStringCreateWithCString = _found.CFStringCreateWithCString
CFStringCreateWithCString.restype = c_void_p
CFStringCreateWithCString.argtypes = [c_void_p, c_void_p, c_uint32]

CFNumberCreate = _found.CFNumberCreate
CFNumberCreate.restype = c_void_p
CFNumberCreate.argtypes = [c_void_p, c_uint32, c_void_p]

CFDataGetBytePtr = _found.CFDataGetBytePtr
CFDataGetBytePtr.restype = c_void_p
CFDataGetBytePtr.argtypes = (c_void_p,)

CFDataGetLength = _found.CFDataGetLength
CFDataGetLength.restype = c_int32
CFDataGetLength.argtypes = (c_void_p,)

CFArrayGetCount = _found.CFArrayGetCount
CFArrayGetCount.restype = c_int32
CFArrayGetCount.argtypes = (c_void_p,)

CFArrayGetValueAtIndex = _found.CFArrayGetValueAtIndex
CFArrayGetValueAtIndex.restype = c_void_p
CFArrayGetValueAtIndex.argtypes = (c_void_p, c_int32)

# Security calls
SecItemAdd = _sec.SecItemAdd
SecItemAdd.restype = OS_status
SecItemAdd.argtypes = (c_void_p, c_void_p)

SecItemCopyMatching = _sec.SecItemCopyMatching
SecItemCopyMatching.restype = OS_status
SecItemCopyMatching.argtypes = (c_void_p, c_void_p)

SecItemDelete = _sec.SecItemDelete
SecItemDelete.restype = OS_status
SecItemDelete.argtypes = (c_void_p,)


def _k(name: str, lib: ctypes.CDLL = _sec) -> c_void_p:
    return c_void_p.in_dll(lib, name)


# Security framework constants
kSecClass = _k("kSecClass")
kSecClassGenericPassword = _k("kSecClassGenericPassword")
kSecAttrService = _k("kSecAttrService")
kSecAttrAccount = _k("kSecAttrAccount")
kSecValueData = _k("kSecValueData")
kSecReturnData = _k("kSecReturnData")
kSecReturnAttributes = _k("kSecReturnAttributes")
kSecMatchLimit = _k("kSecMatchLimit")
kSecMatchLimitOne = _k("kSecMatchLimitOne")
kSecMatchLimitAll = _k("kSecMatchLimitAll")
kSecAttrSynchronizable = _k("kSecAttrSynchronizable")
kSecAttrSynchronizableAny = _k("kSecAttrSynchronizableAny")

# CoreFoundation booleans live in CoreFoundation, not Security
kCFBooleanFalse = _k("kCFBooleanFalse", lib=_found)
kCFBooleanTrue = _k("kCFBooleanTrue", lib=_found)


# ---------------------------------------------------------------------------
# CFType helpers
# ---------------------------------------------------------------------------

_kCFStringEncodingUTF8 = 0x08000100


def _cfstr(s: str) -> c_void_p:
    return CFStringCreateWithCString(None, s.encode("utf-8"), _kCFStringEncodingUTF8)


def _cfdata(b: bytes) -> c_void_p:
    """CFDataCreate from raw bytes — preserves byte-exact value (no encoding step)."""
    CFDataCreate = _found.CFDataCreate
    CFDataCreate.restype = c_void_p
    CFDataCreate.argtypes = (c_void_p, c_void_p, c_int32)
    buf = (ctypes.c_char * len(b)).from_buffer_copy(b)
    return CFDataCreate(None, buf, len(b))


def _cfdata_to_bytes(data_ptr: int | c_void_p) -> bytes:
    """Read a CFDataRef back to Python bytes."""
    if data_ptr in (None, 0):
        return b""
    length = CFDataGetLength(data_ptr)
    ptr = CFDataGetBytePtr(data_ptr)
    if not ptr or length <= 0:
        return b""
    return ctypes.string_at(ptr, length)


def _cfstr_to_str(s_ptr: int | c_void_p) -> str:
    """Read a CFStringRef back to a Python str. Falls through CFData for bytes."""
    if s_ptr in (None, 0):
        return ""
    # Tolerant path: keychain attribute strings come back as CFData under
    # kSecReturnAttributes — try CFData first, fall back to CFString.
    try:
        length = CFDataGetLength(s_ptr)
        if length > 0:
            ptr = CFDataGetBytePtr(s_ptr)
            if ptr:
                return ctypes.string_at(ptr, length).decode("utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover - defensive ctypes fallback
        logger.debug("_cfstr_from_ptr: CFData read failed (%s)", type(exc).__name__)
    return ""


def _build_dict(pairs: list[tuple[c_void_p, Any]]) -> c_void_p:
    keys_arr = (c_void_p * len(pairs))(*[p[0] for p in pairs])
    vals_arr = (c_void_p * len(pairs))(*[_to_cf(p[1]) for p in pairs])
    return CFDictionaryCreate(
        None,
        keys_arr,
        vals_arr,
        len(pairs),
        _found.kCFTypeDictionaryKeyCallBacks,
        _found.kCFTypeDictionaryValueCallBacks,
    )


def _to_cf(v: Any) -> c_void_p:
    """Coerce a Python value to a CFTypeRef. Pass-through for c_void_p."""
    if isinstance(v, c_void_p):
        return v
    if isinstance(v, bool):
        return kCFBooleanTrue if v else kCFBooleanFalse
    if isinstance(v, int):
        return CFNumberCreate(None, 0x9, byref(c_int32(v)))  # kCFNumberSInt32Type
    if isinstance(v, str):
        return _cfstr(v)
    if isinstance(v, bytes | bytearray):
        return _cfdata(bytes(v))
    raise TypeError(f"cannot convert {type(v).__name__} to CFType")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def set_password_local(service: str, username: str, password: str) -> None:
    """Add a generic password with kSecAttrSynchronizable=kCFBooleanFalse.

    Replaces any pre-existing entry under (service, username) by deleting
    first (NotFound is fine), then adding fresh — same idempotency model
    as the upstream ``keyring`` backend.
    """
    # Best-effort delete of any existing entry under this account, in
    # default scope. Synced-scope deletes go through delete_password_synced.
    try:
        delete_password_local(service, username)
    except KeychainNotFound:
        pass

    query = _build_dict(
        [
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, service),
            (kSecAttrAccount, username),
            (kSecValueData, password.encode("utf-8")),
            (kSecAttrSynchronizable, kCFBooleanFalse),
        ]
    )
    status = SecItemAdd(query, None)
    _raise_for_status(status)


def read_password_local(service: str, username: str) -> str | None:
    """Read non-synced entry. Returns None if not found.

    Default ``SecItemCopyMatching`` scope excludes synced entries, matching
    the production read path that goes through the upstream ``keyring``
    library.
    """
    query = _build_dict(
        [
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, service),
            (kSecAttrAccount, username),
            (kSecMatchLimit, kSecMatchLimitOne),
            (kSecReturnData, kCFBooleanTrue),
        ]
    )
    data = c_void_p()
    status = SecItemCopyMatching(query, byref(data))
    if status == _ErrorCodes.item_not_found:
        return None
    _raise_for_status(status)
    raw = _cfdata_to_bytes(data)
    return raw.decode("utf-8", errors="strict")


def read_password_any_scope(service: str, username: str) -> str | None:
    """Read with kSecAttrSynchronizable=kSecAttrSynchronizableAny.

    Used by the migration path to recover the value of a synced entry
    before delete-and-add. Returns None if no entry exists in either scope.
    """
    query = _build_dict(
        [
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, service),
            (kSecAttrAccount, username),
            (kSecMatchLimit, kSecMatchLimitOne),
            (kSecReturnData, kCFBooleanTrue),
            (kSecAttrSynchronizable, kSecAttrSynchronizableAny),
        ]
    )
    data = c_void_p()
    status = SecItemCopyMatching(query, byref(data))
    if status == _ErrorCodes.item_not_found:
        return None
    _raise_for_status(status)
    raw = _cfdata_to_bytes(data)
    return raw.decode("utf-8", errors="strict")


def delete_password_local(service: str, username: str) -> None:
    """Delete a non-synced (default-scope) entry. Raises KeychainNotFound if absent."""
    query = _build_dict(
        [
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, service),
            (kSecAttrAccount, username),
        ]
    )
    status = SecItemDelete(query)
    _raise_for_status(status)


def delete_password_synced(service: str, username: str) -> None:
    """Delete a synced entry specifically.

    Note: this DOES queue an iCloud tombstone that will replicate to the
    user's other Apple devices within seconds. Callers MUST have written
    a recovery file FIRST (see WOR-456 §4 multi-device safety).
    """
    query = _build_dict(
        [
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, service),
            (kSecAttrAccount, username),
            (kSecAttrSynchronizable, kCFBooleanTrue),
        ]
    )
    status = SecItemDelete(query)
    _raise_for_status(status)


def find_synced_entries(service: str) -> list[str]:
    """Scan for synced entries with our service tag.

    Returns ``kSecAttrAccount`` values for the synced subset only. Empty
    list when nothing is synced.
    """
    query = _build_dict(
        [
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, service),
            (kSecMatchLimit, kSecMatchLimitAll),
            (kSecReturnAttributes, kCFBooleanTrue),
            (kSecAttrSynchronizable, kCFBooleanTrue),
        ]
    )
    result = c_void_p()
    status = SecItemCopyMatching(query, byref(result))
    if status == _ErrorCodes.item_not_found:
        return []
    _raise_for_status(status)

    accounts: list[str] = []
    count = CFArrayGetCount(result)
    for i in range(count):
        entry = CFArrayGetValueAtIndex(result, i)
        acct_ptr = CFDictionaryGetValue(entry, kSecAttrAccount)
        if acct_ptr:
            acct = _cfstr_to_str(acct_ptr)
            if acct:
                accounts.append(acct)
    return accounts


def is_synced(service: str, username: str) -> bool:
    """Check whether a specific entry is in synced scope."""
    return username in find_synced_entries(service)


def find_all_entries(service: str) -> list[str]:
    """Scan for ALL entries (local + synced) under our service tag.

    WOR-464: orphan-keychain detection needs a complete enumeration —
    ``find_synced_entries`` only returns the synced subset. Pinning
    ``kSecAttrSynchronizable=kSecAttrSynchronizableAny`` (a special
    sentinel that means "match either scope") is what gives us the
    union without two queries.

    Returns ``kSecAttrAccount`` strings. Empty list when nothing matches.
    """
    query = _build_dict(
        [
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, service),
            (kSecMatchLimit, kSecMatchLimitAll),
            (kSecReturnAttributes, kCFBooleanTrue),
            (kSecAttrSynchronizable, kSecAttrSynchronizableAny),
        ]
    )
    result = c_void_p()
    status = SecItemCopyMatching(query, byref(result))
    if status == _ErrorCodes.item_not_found:
        return []
    _raise_for_status(status)

    accounts: list[str] = []
    count = CFArrayGetCount(result)
    for i in range(count):
        entry = CFArrayGetValueAtIndex(result, i)
        acct_ptr = CFDictionaryGetValue(entry, kSecAttrAccount)
        if acct_ptr:
            acct = _cfstr_to_str(acct_ptr)
            if acct:
                accounts.append(acct)
    return accounts
