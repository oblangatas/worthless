"""Fernet-free shard reader for the proxy (WOR-309 Phase 2).

The proxy gates BEFORE reconstruction. With WOR-309, Shard B decryption
is delegated to the sidecar over IPC, so the proxy only needs ciphertext
at rest. This reader exposes ``fetch_encrypted()`` ONLY — no Fernet, no
``cryptography`` import. The AST CI guard at
``tests/architecture/test_proxy_imports.py`` enforces that the proxy
package never re-acquires a path to ``worthless.crypto.splitter`` or
``cryptography.fernet``; this module exists so the proxy can satisfy
that constraint.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite

from worthless.storage.models import EncryptedShard


class ShardReader:
    """Read-only ciphertext-at-rest accessor — no key material.

    Constructed with ``db_path`` only; cannot decrypt anything. Suitable
    for proxy use where reconstruction is delegated to the sidecar.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)

    @asynccontextmanager
    async def _connect(self) -> AsyncIterator[aiosqlite.Connection]:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("PRAGMA foreign_keys = ON")
            yield db

    async def fetch_encrypted(self, alias: str) -> EncryptedShard | None:
        """Return ciphertext-at-rest for *alias*, or ``None``.

        Mirrors :meth:`worthless.storage.repository.ShardRepository.fetch_encrypted`
        without the encrypt path or Fernet dependency.
        """
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT shard_b_enc, commitment, nonce, provider, prefix, charset, base_url "
                "FROM shards WHERE key_alias = ?",
                (alias,),
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            return EncryptedShard(
                shard_b_enc=memoryview(
                    row["shard_b_enc"]
                ).tobytes(),  # nosemgrep: sr01-key-material-not-bytearray
                commitment=memoryview(
                    row["commitment"]
                ).tobytes(),  # nosemgrep: sr01-key-material-not-bytearray
                nonce=memoryview(
                    row["nonce"]
                ).tobytes(),  # nosemgrep: sr01-key-material-not-bytearray
                provider=row["provider"],
                prefix=row["prefix"],
                charset=row["charset"],
                base_url=row["base_url"],
            )
