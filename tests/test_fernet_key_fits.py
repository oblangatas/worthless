"""worthless-saaz: tell whether a Fernet key fits a token without decrypting it.

The boot check, ``lock`` and ``doctor`` ask "can this key open this shard?".
``Fernet.decrypt`` answers by producing the plaintext as immutable ``bytes``,
which can't be wiped (SR-01/SR-02). ``key_fits_token`` answers from the HMAC
alone. These tests pin it to the same answer ``Fernet.decrypt`` gives, so it
stays honest if ``cryptography`` changes the token format.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet, InvalidToken

from worthless.crypto.fernet_check import key_fits_token


def _decrypts(key: bytes, token: bytes) -> bool:
    try:
        Fernet(key).decrypt(token)
    except (InvalidToken, ValueError):
        return False
    return True


RIGHT = Fernet.generate_key()
WRONG = Fernet.generate_key()
TOKEN = Fernet(RIGHT).encrypt(b"shard-b-bytes")


def _tampered(token: bytes) -> bytes:
    raw = bytearray(token)
    raw[len(raw) // 2] ^= 0x01
    return bytes(raw)


@pytest.mark.parametrize(
    ("key", "token"),
    [
        (RIGHT, TOKEN),
        (WRONG, TOKEN),
        (RIGHT, _tampered(TOKEN)),
        (RIGHT, b"not-a-token"),
        (RIGHT, b""),
        (b"not-a-key", TOKEN),
    ],
    ids=["right-key", "wrong-key", "tampered", "garbage-token", "empty-token", "bad-key"],
)
def test_agrees_with_a_real_decrypt(key: bytes, token: bytes) -> None:
    assert key_fits_token(bytearray(key), token) is _decrypts(key, token)


def test_right_key_fits_and_wrong_key_does_not() -> None:
    """The two answers the callers act on, stated plainly."""
    assert key_fits_token(bytearray(RIGHT), TOKEN) is True
    assert key_fits_token(bytearray(WRONG), TOKEN) is False


def test_the_callers_key_is_left_intact() -> None:
    """The caller still needs its key afterwards (up.py hands it to the sidecar)."""
    key = bytearray(RIGHT)
    key_fits_token(key, TOKEN)
    assert bytes(key) == RIGHT
