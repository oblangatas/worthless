"""Adversarial + property tests for the WOR-637 MAC subkey derivation.

The mac-oracle fix re-keys the sidecar ``mac`` verb (and the in-process
``_compute_decoy_hash`` path) with an HKDF-derived subkey instead of the raw
Fernet master key. These tests pin three things the happy-path tests cannot:

1. **Oracle closure (property-based).** For *arbitrary* attacker-chosen keys
   and values, the derived-key MAC is never equal to the master-key MAC. The
   single-input RED test in ``tests/ipc/test_mac_verb.py`` proves one case;
   Hypothesis proves it across the input space.
2. **Domain separation.** The MAC subkey and the ``attest`` subkey derived from
   the same Fernet key are distinct (different HKDF salt/info), so one verb's
   output can never be replayed as the other's.
3. **Known-answer vectors.** Hard-coded expected bytes lock the HKDF
   parameters (algorithm, salt, info, length) and the HMAC construction, so a
   future refactor that silently changes any of them fails loudly instead of
   invalidating every stored decoy hash.
"""

from __future__ import annotations

import base64
import hmac
from hashlib import sha256

from hypothesis import given
from hypothesis import strategies as st

from worthless.crypto.kdf import derive_mac_secret
from worthless.sidecar.backends.fernet import FernetBackend

# ---------------------------------------------------------------------------
# Known-answer vectors — pinned literals. Regenerating these means the
# derivation changed; that MUST be a deliberate, reviewed, migrated change.
# ---------------------------------------------------------------------------

_KAT_KEY_B64URL = b"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
_KAT_DERIVED_HEX = "d6ab265fde11a544fac1c8b36532d57c9690dd61b1f99b727eea26c9d83dffb8"
_KAT_VALUE = b"wor-637-known-answer"
_KAT_MAC_HEX = "9bb3323a3457a08bd7614c1feef77374eff2fb6b2664a744538eedba8ee8f144"


def _shares_for(fernet_key_44b: bytes) -> tuple[bytes, bytes]:
    share_a = b"\x5a" * len(fernet_key_44b)
    share_b = bytes(a ^ k for a, k in zip(share_a, fernet_key_44b, strict=True))
    return share_a, share_b


# ---------------------------------------------------------------------------
# Pure helper properties
# ---------------------------------------------------------------------------


def test_derive_mac_secret_is_32_bytes() -> None:
    secret = derive_mac_secret(_KAT_KEY_B64URL)
    assert isinstance(secret, bytes)
    assert len(secret) == 32


def test_derive_mac_secret_is_deterministic() -> None:
    assert derive_mac_secret(_KAT_KEY_B64URL) == derive_mac_secret(_KAT_KEY_B64URL)


def test_derive_mac_secret_is_not_the_input_key() -> None:
    """The derived subkey MUST differ from the master key it is derived from."""
    secret = derive_mac_secret(_KAT_KEY_B64URL)
    assert secret != _KAT_KEY_B64URL
    assert secret != _KAT_KEY_B64URL[:32]


def test_derive_mac_secret_bytearray_equals_bytes_and_leaves_input_intact() -> None:
    """A ``bytearray`` key MUST derive identically to the same ``bytes`` key.

    Pins the WOR-637 commit-2 SR-01 fix: the in-process caller
    (``ShardRepository._compute_decoy_hash``) passes its *zeroable*
    ``bytearray`` key buffer straight to ``derive_mac_secret`` rather than an
    un-zeroable ``bytes(...)`` copy. Without this test, a regression that did
    ``hkdf.derive(bytes(x))`` internally — re-introducing the un-zeroable copy
    — would pass every other test, since they all pass ``bytes``.

    Also asserts the input bytearray is left unmodified, so HKDF reading the
    buffer never consumes or mutates the caller's zeroable key.
    """
    key_bytes = bytes(_KAT_KEY_B64URL)
    key_bytearray = bytearray(_KAT_KEY_B64URL)
    snapshot = bytes(key_bytearray)  # copy of the original contents

    out_bytes = derive_mac_secret(key_bytes)
    out_bytearray = derive_mac_secret(key_bytearray)

    assert out_bytearray == out_bytes
    assert bytes(key_bytearray) == snapshot, (
        "derive_mac_secret must not mutate the caller's zeroable key buffer"
    )


# ---------------------------------------------------------------------------
# Known-answer vectors
# ---------------------------------------------------------------------------


def test_derive_mac_secret_known_answer() -> None:
    """Pin the exact derived bytes for a fixed key.

    Failure means the HKDF salt/info/length/algorithm changed. That silently
    rewrites every decoy hash, so it must be a deliberate, migrated change —
    never an accidental refactor.
    """
    assert derive_mac_secret(_KAT_KEY_B64URL).hex() == _KAT_DERIVED_HEX


def test_mac_known_answer_vector() -> None:
    """Pin the full ``mac`` output for a fixed (key, value).

    Locks the end-to-end construction: HKDF(derive_mac_secret) + HMAC-SHA256.
    """
    expected = hmac.new(derive_mac_secret(_KAT_KEY_B64URL), _KAT_VALUE, sha256).hexdigest()
    assert expected == _KAT_MAC_HEX


def test_mac_known_answer_is_not_master_key_mac() -> None:
    """The KAT output MUST differ from the master-key HMAC of the same value."""
    master = hmac.new(_KAT_KEY_B64URL, _KAT_VALUE, sha256).hexdigest()
    assert _KAT_MAC_HEX != master


# ---------------------------------------------------------------------------
# Domain separation: mac subkey vs attest subkey on a real backend
# ---------------------------------------------------------------------------


def test_mac_subkey_differs_from_attest_subkey() -> None:
    """A FernetBackend's MAC subkey and attest subkey MUST be distinct.

    Both are HKDF-derived from the same Fernet key but with different
    salt/info. If they ever collided, a ``mac`` tag could be replayed as an
    ``attest`` token (or vice versa) once a verifier exists.
    """
    backend = FernetBackend(shares=_shares_for(_KAT_KEY_B64URL))
    assert backend._mac_secret != backend._attest_secret
    # And neither equals the raw key.
    assert backend._mac_secret != _KAT_KEY_B64URL
    assert backend._attest_secret != _KAT_KEY_B64URL


# ---------------------------------------------------------------------------
# Oracle closure — property-based over arbitrary keys and values
# ---------------------------------------------------------------------------


@given(
    raw32=st.binary(min_size=32, max_size=32),
    value=st.binary(max_size=512),
)
def test_derived_mac_never_equals_master_key_mac(raw32: bytes, value: bytes) -> None:
    """For ANY key and ANY value, HMAC(derived, value) != HMAC(master, value).

    This is the oracle-closure invariant: the master key is never the effective
    MAC key, no matter what bytes an attacker chooses. Combined with the
    mac-verb test pinning ``backend.mac(value) == HMAC(derive_mac_secret(key),
    value)``, this proves ``backend.mac`` is never a master-key oracle.
    """
    fernet_key = base64.urlsafe_b64encode(raw32)  # valid 44-byte Fernet key
    derived_tag = hmac.new(derive_mac_secret(fernet_key), value, sha256).digest()
    master_tag = hmac.new(fernet_key, value, sha256).digest()
    assert derived_tag != master_tag


@given(raw32=st.binary(min_size=32, max_size=32))
def test_derived_subkey_never_equals_master_key(raw32: bytes) -> None:
    """For ANY Fernet key, the derived MAC subkey != the master key bytes."""
    fernet_key = base64.urlsafe_b64encode(raw32)
    subkey = derive_mac_secret(fernet_key)
    assert subkey != fernet_key
    # Compare against the equal-length raw 32-byte key material too: the
    # subkey is 32 bytes and fernet_key is 44, so the assertion above can
    # never fail on length alone. This one would catch a derivation that
    # merely returned the first 32 bytes of the key material.
    assert subkey != raw32
