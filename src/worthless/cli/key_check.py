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


_B64URL = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
MALFORMED_KEY = (
    "fernet.key isn't a valid key (44 characters of URL-safe base64) — it may be "
    f"corrupted. Restore it from a backup. {KEY_FIX}"
)


def key_is_well_formed(key: bytes | bytearray) -> bool:
    """A Fernet key's shape, checked in place (no copy of the key is made)."""
    return len(key) == 44 and key[43] == ord("=") and all(key[i] in _B64URL for i in range(43))


def unopenable_path(home: WorthlessHome) -> Path:
    return home.base_dir / "run" / "unopenable-keys"


def _key_file_refused_path(home: WorthlessHome) -> Path:
    return home.base_dir / "run" / "key-file-refused"


def _write_hint(path: Path, text: str | None) -> None:
    """Write (or with None, remove) a hint ``status`` reads. Never key material.

    ``status`` must not load the key itself (keychain prompts), and ``/healthz``
    is unauthenticated (worthless-n2bj). A disk error is logged, never raised:
    a hint for ``status`` must not stop the proxy starting.
    """
    try:
        if text is None:
            path.unlink(missing_ok=True)
            return
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.unlink(missing_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        tmp.replace(path)
    except OSError as exc:
        logger.warning("Could not write %s for `worthless status`: %s", path, exc)


def _read_hint(path: Path) -> str | None:
    """None when absent. Any other read error raises: status must say it couldn't tell."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def record_unopenable(home: WorthlessHome, aliases: list[str]) -> None:
    """The aliases the proxy's key can't open, by name; an empty list removes it."""
    _write_hint(unopenable_path(home), "\n".join(sorted(aliases)) + "\n" if aliases else None)


def read_unopenable(home: WorthlessHome) -> set[str]:
    """The aliases the last proxy start couldn't open. Raises OSError if unreadable."""
    return set((_read_hint(unopenable_path(home)) or "").split())


def record_key_file_refused(home: WorthlessHome, message: str | None) -> None:
    """Why the proxy refused to read ``fernet.key`` itself (symlink, mode, owner)."""
    _write_hint(_key_file_refused_path(home), message)


def read_key_file_refused(home: WorthlessHome) -> str | None:
    """The last proxy start's key-file refusal, if any. Raises OSError if unreadable."""
    text = _read_hint(_key_file_refused_path(home))
    return text.strip() if text else None


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
