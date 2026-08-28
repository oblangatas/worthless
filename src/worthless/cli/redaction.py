"""Canonical secret-rendering helper for CLI output (SR-04 / WOR-655).

Before this module every subsystem rolled its own partial mask — the scan
preview emitted ``sk-a...wXyZ`` (a real prefix *and* a real suffix), which
is exactly the "a few real bytes is fine" habit SR-04 forbids. This is the
single place a secret-shaped string is turned into an output-safe token so
future emit sites import one helper instead of re-deriving a leaky mask.

The flat ``****`` (no prefix, no suffix, no length hint) is deliberate:
- a prefix ("sk-") narrows a brute-force search space;
- a suffix pins the exact key;
- a length hint leaks the provider/key family.

The existing layer-local tokens (``<redacted>`` for reprs, ``[REDACTED]``
for the log filter, the deep-redact sentinel *dict* for structured
rollback records) are intentionally left as-is — ``****`` is scoped to the
one render site (the scan preview) where a secret-shaped *string* reaches a
human/JSON channel, not a repo-wide token rename.
"""

from __future__ import annotations

import hashlib

_MASK = "****"


def mask_secret(value: str) -> str:  # noqa: ARG001 — value intentionally unused
    """Return a fixed, output-safe placeholder for a secret-shaped *value*.

    The input is intentionally ignored: no bytes of it — length, prefix, or
    suffix — survive into the return value.
    """
    return _MASK


def key_fingerprint(value: str) -> str:
    """Return a non-secret ``sha256(value)[:8]`` fingerprint of a key.

    Lets a human tell two masked keys apart (``scan --show-suffix``)
    without revealing any real byte of either. This is the same digest
    :func:`worthless.cli.commands.lock._make_alias` appends after the
    provider name; it lives here (not in ``lock``) because ``scan`` cannot
    import ``lock`` — ``lock`` imports ``scan`` — so a neutral home avoids
    the cycle. ``nosec``/``noqa``: non-cryptographic fingerprint, not a
    security primitive.
    """
    return hashlib.sha256(value.encode()).hexdigest()[:8]  # noqa: S324 # nosec B303
