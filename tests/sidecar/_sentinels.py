"""Planted-secret sentinels + output sweep for sidecar leak tests.

The sidecar handles two kinds of crown-jewel material: raw XOR *share* bytes
and the reconstructed base64 Fernet key. We plant recognizable markers of each
shape, drive the sidecar down its error paths, and sweep every captured output
channel (stdout AND stderr) for any trace of them.

A provider-shaped token (``PROVIDER_TOKEN``) is a *different* threat: the
``RedactingFilter`` is designed to catch that shape as text. The share/key
sentinels are the shapes the filter does NOT match — pinning the honest
boundary of what redaction can and can't do.
"""

from __future__ import annotations

import base64
import os

# A provider-prefixed token: the shape RedactingFilter/KEY_PATTERN DOES match.
# Synthetic leak sentinel, not a real credential.
PROVIDER_TOKEN = "sk-ant-api03-LEAKLEAK1234567890"  # noqa: S105

# A valid-shape Fernet key (44-char urlsafe b64, NO provider prefix): the shape
# the filter does NOT match. Used to pin the documented blind spot.
KEY_SENTINEL_B64 = base64.urlsafe_b64encode(b"K" * 32).decode()

# ASCII markers embedded in raw share bytes so a leaked share is greppable even
# after %r/%s/.hex() rendering.
SHARE_MARKER = "SHARESENTINEL"


def null_keyring_env(**overrides: str) -> dict[str, str]:
    """Base subprocess env: inherit, force the hermetic null keyring backend."""
    return {**os.environ, "WORTHLESS_KEYRING_BACKEND": "null", **overrides}


def grep_all(*needles: str) -> Grep:
    """Return a matcher that scans str/repr/hex forms of captured output."""
    return Grep(needles)


class Grep:
    def __init__(self, needles: tuple[str, ...]) -> None:
        self.needles = needles

    def leaked_in(self, *streams: str | bytes) -> list[str]:
        """Return the sentinels that appear in any stream (str, repr, or hex)."""
        hay = []
        for s in streams:
            if isinstance(s, bytes):
                hay.append(s.decode("latin-1", "replace"))
                hay.append(s.hex())
            else:
                hay.append(s)
        blob = "\n".join(hay)
        # Match a needle both as literal text and as its hex encoding — a
        # `.hex()` leak of share bytes renders the marker as e.g. 534841..., not
        # as the ASCII "SHARESENTINEL".
        return [n for n in self.needles if n in blob or bytes(n, "latin-1").hex() in blob]
