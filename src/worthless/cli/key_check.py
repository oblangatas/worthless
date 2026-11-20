"""Does the active Fernet key open the locked keys? (worthless-saaz)

One answer for ``up``, ``lock`` and ``doctor``. Checks each shard's HMAC
(:func:`key_fits_token`), so no plaintext is ever produced.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from worthless._flags import fernet_ipc_only_enabled
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.crypto.fernet_check import key_fits_token
from worthless.crypto.types import zero_buf
from worthless.storage.shard_reader import ShardReader

logger = logging.getLogger(__name__)

KEY_FIX = "Run `worthless doctor --explain fernet_drift` to find the right key."


def _unopenable_path(home: WorthlessHome) -> Path:
    return home.base_dir / "run" / "unopenable-keys"


def record_unopenable(home: WorthlessHome, aliases: list[str]) -> None:
    """Leave the aliases the proxy's key can't open where ``status`` can read them.

    Names only, never key material (worthless-n2bj): ``status`` must not load the
    key itself (keychain prompts), and ``/healthz`` is unauthenticated. Rewritten
    on every proxy start; an empty list removes it. A disk error is logged, never
    raised: a hint for ``status`` must not stop the proxy starting.
    """
    path = _unopenable_path(home)
    try:
        if not aliases:
            path.unlink(missing_ok=True)
            return
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.unlink(missing_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(aliases)) + "\n")
        tmp.replace(path)
    except OSError as exc:
        logger.warning("Could not record the keys this key can't unlock at %s: %s", path, exc)


def read_unopenable(home: WorthlessHome) -> set[str]:
    """The aliases the last proxy start couldn't open (empty if none or unreadable)."""
    try:
        text = _unopenable_path(home).read_text(encoding="utf-8")
    except OSError:
        return set()
    return {line for line in text.splitlines() if line}


def enrolled_aliases(home: WorthlessHome) -> list[str]:
    """Every enrolled alias, without a key (for a key that couldn't even be read)."""
    if not home.db_path.is_file():
        return []
    return asyncio.run(ShardReader(home.db_path).list_enrolled_aliases())


def aliases_key_cannot_open(home: WorthlessHome, key: bytes | bytearray) -> tuple[int, list[str]]:
    """Return (enrolled alias count, enrolled aliases *key* can't open).

    ``(0, [])`` with no database, or under IPC-only: the sidecar owns the key
    there and this process must never check shards with one (WOR-465).
    """
    if fernet_ipc_only_enabled() or not home.db_path.is_file():
        return 0, []
    return asyncio.run(_aliases_key_cannot_open(home.db_path, key))


async def _aliases_key_cannot_open(db_path: Path, key: bytes | bytearray) -> tuple[int, list[str]]:
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
        return  # before home.fernet_key: never load the key just to skip
    key = home.fernet_key
    try:
        total, dead = aliases_key_cannot_open(home, key)
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
