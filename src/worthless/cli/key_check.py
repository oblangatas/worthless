"""Does the active Fernet key open the locked keys? (worthless-saaz)

One answer for ``up``, ``lock`` and ``doctor``. Checks each shard's HMAC
(:func:`key_fits_token`), so no plaintext is ever produced.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from worthless._flags import fernet_ipc_only_enabled
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.crypto.fernet_check import key_fits_token
from worthless.crypto.types import zero_buf
from worthless.storage.shard_reader import ShardReader

KEY_FIX = "Run `worthless doctor --explain fernet_drift` to find the right key."


async def aliases_key_cannot_open(db_path: Path, key: bytearray) -> tuple[int, list[str]]:
    """Return (enrolled alias count, enrolled aliases *key* can't open)."""
    reader = ShardReader(db_path)
    aliases = await reader.list_enrolled_aliases()
    dead = []
    for alias in aliases:
        enc = await reader.fetch_encrypted(alias)
        if enc is not None and not key_fits_token(key, enc.shard_b_enc):
            dead.append(alias)
    return len(aliases), dead


def refuse_a_key_that_opens_no_locked_key(home: WorthlessHome) -> None:
    """Stop ``lock``/``enroll`` sealing with a key that opens none of the existing keys.

    That is how a mixed database starts: the new key works, every older one
    is dead to the background service. Refusing picks no side (WOR-464).
    Skipped under IPC-only, where this process never holds the key.
    """
    if fernet_ipc_only_enabled() or not home.db_path.is_file():
        return
    key = home.fernet_key
    try:
        total, dead = asyncio.run(aliases_key_cannot_open(home.db_path, key))
    finally:
        zero_buf(key)
    if not total or len(dead) < total:
        return
    cause = (
        "WORTHLESS_FERNET_KEY is set in this shell to a different key — unset it. "
        if os.environ.get("WORTHLESS_FERNET_KEY")
        else ""
    )
    raise WorthlessError(
        ErrorCode.KEY_REFUSED,
        f"The key in use can't unlock any of your {total} locked key(s), so locking "
        f"more with it would leave them unreadable to each other. {cause}{KEY_FIX}",
    )
