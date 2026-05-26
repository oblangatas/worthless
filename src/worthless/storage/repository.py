"""Encrypted shard repository backed by SQLite (STOR-01, STOR-02)."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from enum import Enum
from typing import TYPE_CHECKING

import aiosqlite
from cryptography.fernet import Fernet, InvalidToken

from worthless.defaults import DEFAULT_SPEND_CAP_TOKENS
from worthless.storage.models import EncryptedShard, EnrollmentRecord, StoredShard
from worthless.storage.schema import init_db, migrate_db

if TYPE_CHECKING:
    from worthless.ipc.client import IPCClient


class _Sentinel(Enum):
    USE_DEFAULT = "USE_DEFAULT"


_USE_DEFAULT = _Sentinel.USE_DEFAULT


class ShardRepository:
    """Async repository that encrypts Shard B at rest with Fernet.

    Each public method opens its own ``aiosqlite`` connection (simple PoC
    approach -- connection pooling is not needed at this stage).

    Two construction modes (WOR-465 A3b 2/3):

    * **Legacy / bare-metal**: pass ``bytes`` or ``bytearray`` Fernet key.
      ``seal`` / ``open`` / decoy-HMAC happen in-process. ``close()``
      zeroes the key bytes.
    * **IPC-only** (proxy container with ``WORTHLESS_FERNET_IPC_ONLY=1``):
      pass an :class:`worthless.ipc.client.IPCClient`. All crypto
      round-trips to the sidecar — the repository instance NEVER holds
      key material. ``close()`` is a no-op (no bytes to zero).

    .. todo:: Use a persistent connection or pool before production (STOR-01).
    """

    def __init__(
        self,
        db_path: str,
        key_or_client: bytes | bytearray | IPCClient,
    ) -> None:
        self._db_path = db_path

        if isinstance(key_or_client, bytes | bytearray):
            # Legacy / bare-metal path — unchanged from pre-A3b.
            self._ipc: IPCClient | None = None
            self._fernet_key_bytes: bytearray | None = bytearray(
                key_or_client
            )  # SR-01: mutable for zeroing
            self._fernet: Fernet | None = Fernet(
                memoryview(self._fernet_key_bytes).tobytes()
            )  # Fernet requires immutable bytes; we zero _fernet_key_bytes on close()
            # Note: Fernet internally stores an immutable copy — unavoidable with
            # the cryptography library. We zero what we control on close().
        elif (
            hasattr(key_or_client, "seal")
            and hasattr(key_or_client, "open")
            and hasattr(key_or_client, "mac")
        ):
            # IPC-only path (WOR-465 A3b). Duck-typed on the three verbs
            # the repository needs so test doubles work without importing
            # the concrete IPCClient.
            self._ipc = key_or_client  # type: ignore[assignment]
            self._fernet_key_bytes = None
            self._fernet = None
        else:
            raise TypeError(
                "ShardRepository: second argument must be bytes / bytearray / "
                f"IPCClient, got {type(key_or_client).__name__}"
            )

    def _get_fernet(self) -> Fernet:
        """Return the Fernet instance, raising if closed or IPC-only."""
        if self._fernet is None:
            if self._ipc is not None:
                raise RuntimeError(
                    "ShardRepository is in IPC-only mode; use async seal/open via the sidecar"
                )
            raise RuntimeError("ShardRepository has been closed")
        return self._fernet

    async def _seal(self, plaintext: bytes) -> bytes:
        """Encrypt *plaintext* via Fernet (legacy) or the sidecar (IPC mode)."""
        if self._ipc is not None:
            return await self._ipc.seal(plaintext)
        return self._get_fernet().encrypt(plaintext)

    def close(self) -> None:
        """Zero key material and release the Fernet instance (SR-02).

        No-op in IPC-only mode: the repository never held key bytes, so
        there is nothing to zero. Idempotent in both modes.
        """
        if self._fernet_key_bytes is not None:
            for i in range(len(self._fernet_key_bytes)):
                self._fernet_key_bytes[i] = 0
        self._fernet = None
        self._ipc = None

    @asynccontextmanager
    async def _connect(self) -> AsyncIterator[aiosqlite.Connection]:
        """Open a connection with foreign keys enabled."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("PRAGMA foreign_keys = ON")
            yield db

    async def initialize(self) -> None:
        """Create tables if they don't exist, then run migrations."""
        await init_db(self._db_path)
        await migrate_db(self._db_path)

    async def _compute_decoy_hash(self, value: str) -> str:
        """Compute HMAC-SHA256 of *value* keyed with the Fernet key material.

        WOR-465 A3b 2/3: in IPC-only mode this round-trips through
        ``ipc.mac`` so the repository instance never holds the key.
        The sidecar returns 32 raw bytes; we hex-encode here so output
        bytes are byte-identical to the legacy ``hmac.new(...).hexdigest()``
        path — load-bearing for stored decoy_hash rows.
        """
        if self._ipc is not None:
            tag = await self._ipc.mac(value.encode())
            return tag.hex()
        if self._fernet is None or self._fernet_key_bytes is None:
            raise RuntimeError("ShardRepository has been closed")
        return hmac.new(self._fernet_key_bytes, value.encode(), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # Shard CRUD
    # ------------------------------------------------------------------

    async def store(
        self,
        alias: str,
        shard: StoredShard,
        prefix: str | None = None,
        charset: str | None = None,
        base_url: str | None = None,
    ) -> None:
        """Encrypt *shard.shard_b* with Fernet and INSERT into the shards table.

        Accepts bytearray or bytes for shard_b (converts to bytes for Fernet).
        Raises ``aiosqlite.IntegrityError`` if *alias* already exists.
        """
        shard_b_enc = await self._seal(memoryview(shard.shard_b).tobytes())
        async with self._connect() as db:
            await db.execute(
                "INSERT INTO shards "
                "(key_alias, shard_b_enc, commitment, nonce, provider, prefix, charset, base_url) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    alias,
                    shard_b_enc,
                    memoryview(shard.commitment).tobytes(),
                    memoryview(shard.nonce).tobytes(),
                    shard.provider,
                    prefix,
                    charset,
                    base_url,
                ),
            )
            await db.commit()

    async def fetch_encrypted(self, alias: str) -> EncryptedShard | None:
        """Return the raw encrypted shard without Fernet decryption, or *None*.

        This enables gate-before-decrypt: the rules engine can evaluate
        before any key material is decrypted (CRYP-05).
        """
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT shard_b_enc, commitment, nonce, provider, prefix, charset, base_url, "
                "shard_a_enc "
                "FROM shards WHERE key_alias = ?",
                (alias,),
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            raw_a = row["shard_a_enc"]
            return EncryptedShard(
                shard_b_enc=memoryview(  # nosemgrep: sr01-key-material-not-bytearray
                    row["shard_b_enc"]
                ).tobytes(),
                commitment=memoryview(  # nosemgrep: sr01-key-material-not-bytearray
                    row["commitment"]
                ).tobytes(),
                nonce=memoryview(  # nosemgrep: sr01-key-material-not-bytearray
                    row["nonce"]
                ).tobytes(),
                provider=row["provider"],
                prefix=row["prefix"],
                charset=row["charset"],
                base_url=row["base_url"],
                shard_a_enc=memoryview(  # nosemgrep: sr01-key-material-not-bytearray
                    raw_a
                ).tobytes()
                if raw_a is not None
                else None,
            )

    async def decrypt_shard(self, encrypted: EncryptedShard) -> StoredShard:
        """Decrypt an :class:`EncryptedShard` into a :class:`StoredShard`.

        Became async in WOR-465 A3b 2/3: in IPC-only mode the call
        round-trips through the sidecar's ``open`` verb. All byte
        fields are wrapped in ``bytearray`` per SR-01.  When
        ``encrypted.shard_a_enc`` is present (legacy 16x2 rows), shard-A
        is also decrypted and returned; target-state rows leave ``shard_a=None``.
        """
        shard_a: bytearray | None = None
        if self._ipc is not None:
            shard_b = await self._ipc.open(encrypted.shard_b_enc)
            if encrypted.shard_a_enc is not None:
                shard_a = bytearray(await self._ipc.open(encrypted.shard_a_enc))
        else:
            fernet = self._get_fernet()
            shard_b = fernet.decrypt(encrypted.shard_b_enc)
            if encrypted.shard_a_enc is not None:
                shard_a = bytearray(fernet.decrypt(encrypted.shard_a_enc))
        return StoredShard(
            shard_b=bytearray(shard_b),
            commitment=bytearray(encrypted.commitment),
            nonce=bytearray(encrypted.nonce),
            provider=encrypted.provider,
            shard_a=shard_a,
        )

    async def retrieve(self, alias: str) -> StoredShard | None:
        """Decrypt and return a :class:`StoredShard` or *None*.

        Backward-compatible convenience that calls fetch_encrypted + decrypt_shard.
        """
        encrypted = await self.fetch_encrypted(alias)
        if encrypted is None:
            return None
        return await self.decrypt_shard(encrypted)

    async def delete(self, alias: str) -> bool:
        """Delete the shard record for *alias*. Returns True if deleted."""
        async with self._connect() as db:
            cursor = await db.execute("DELETE FROM shards WHERE key_alias = ?", (alias,))
            await db.commit()
            return cursor.rowcount > 0

    async def list_keys(self) -> list[str]:
        """Return a list of all enrolled key aliases."""
        async with self._connect() as db:
            cursor = await db.execute("SELECT key_alias FROM shards")
            rows = await cursor.fetchall()
            return [r[0] for r in rows]

    async def list_aliases_with_routing(
        self,
    ) -> list[tuple[str, str, str | None, str]]:
        """Return ``(alias, var_name, base_url, protocol)`` for every enrollment.

        Joins ``shards`` × ``enrollments`` so callers (worthless wrap, status,
        etc.) get the full routing tuple in one query. Multiple enrollments
        per alias produce multiple rows. ``base_url`` is ``None`` for legacy
        rows enrolled before worthless-8rqs — the proxy refuses to use those
        and prompts for re-lock.
        """
        async with self._connect() as db:
            cursor = await db.execute(
                "SELECT s.key_alias, e.var_name, s.base_url, s.provider "
                "FROM shards s "
                "JOIN enrollments e ON s.key_alias = e.key_alias "
                "ORDER BY s.key_alias"
            )
            rows = await cursor.fetchall()
            return [(r[0], r[1], r[2], r[3]) for r in rows if r[0] and r[1] and r[3]]

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    async def set_metadata(self, key: str, value: str) -> None:
        """Upsert a metadata key/value pair."""
        async with self._connect() as db:
            await db.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                (key, value),
            )
            await db.commit()

    async def get_metadata(self, key: str) -> str | None:
        """Return the metadata value for *key*, or *None*."""
        async with self._connect() as db:
            cursor = await db.execute(
                "SELECT value FROM metadata WHERE key = ?",
                (key,),
            )
            row = await cursor.fetchone()
            return row[0] if row else None

    # ------------------------------------------------------------------
    # Stable proxy auth token (kept for backward compatibility — no longer used
    # by the proxy or lock. The proxy now validates shard-A from the Bearer
    # header directly via commitment check instead of a stable token.
    # ------------------------------------------------------------------

    _AUTH_TOKEN_META_KEY = "proxy_auth_token_enc"  # noqa: S105 — metadata key, not a credential

    async def set_proxy_auth_token(self, token: str) -> None:
        """Fernet-encrypt *token* and persist it in the metadata table.

        Kept for backward compatibility. The proxy no longer reads this value;
        use of this method is deprecated post-16x2-revert.

        WOR-465 A3b: in IPC-only mode the encrypt round-trips through the
        sidecar's ``seal`` verb so the proxy uid never touches Fernet bytes.
        """
        token_bytes = token.encode()
        if self._ipc is not None:
            token_enc = await self._ipc.seal(token_bytes)
        else:
            token_enc = self._get_fernet().encrypt(token_bytes)
        await self.set_metadata(self._AUTH_TOKEN_META_KEY, token_enc.decode())

    async def get_proxy_auth_token(self) -> str | None:
        """Return the decrypted proxy auth token string, or *None* if not set.

        Kept for backward compatibility. The proxy no longer reads this value
        post-16x2-revert. Returns *None* if the token was encrypted with a
        different (rotated) Fernet key.

        WOR-465 A3b: in IPC-only mode the decrypt round-trips through the
        sidecar's ``open`` verb. An InvalidToken from the sidecar surfaces as
        an IPC error path; we treat it the same as the legacy InvalidToken.
        """
        raw = await self.get_metadata(self._AUTH_TOKEN_META_KEY)
        if raw is None:
            return None
        try:
            if self._ipc is not None:
                return (await self._ipc.open(raw.encode())).decode()
            return self._get_fernet().decrypt(raw.encode()).decode()
        except InvalidToken:
            # Token was encrypted with a different (rotated) key — treat as absent.
            return None

    async def upsert_locked_shard(
        self,
        alias: str,
        shard: StoredShard,
        *,
        prefix: str,
        charset: str,
        base_url: str,
    ) -> None:
        """Upsert a shard row, storing only shard-B (NOT shard-A) encrypted.

        Uses ``ON CONFLICT DO UPDATE`` (not ``INSERT OR REPLACE``) so the row
        is patched in place.  INSERT OR REPLACE deletes then re-inserts, which
        fires the ``enrollments → shards ON DELETE CASCADE`` and wipes all
        enrollment records for the alias — breaking the two-env-same-key case.

        On-conflict update keeps commitment, nonce, and shard-B in sync on
        every lock/re-lock.  shard-A is never stored server-side — it lives
        only in the client's .env file (as the format-preserving split value).

        ``prefix``, ``charset``, and ``base_url`` are required routing metadata.
        Passing ``None`` is a hard error: a NULL value in any of these columns
        breaks the proxy's reconstruction path and causes every request to fail
        with "re-lock required".

        Post-16x2-revert: ``shard_a_enc`` is explicitly set to NULL on every
        upsert so old rows that previously stored it are cleared.

        WOR-465 A3b: in IPC-only mode the encrypt round-trips through the
        sidecar's ``seal`` verb so the proxy uid never touches Fernet key
        bytes. Same dispatch shape as :meth:`decrypt_shard`.
        """
        if prefix is None:
            raise ValueError(
                "prefix is required routing metadata for upsert_locked_shard — "
                "use an empty string '' for keys that have no format prefix."
            )
        if charset is None:
            raise ValueError("charset is required routing metadata for upsert_locked_shard.")
        if base_url is None:
            raise ValueError(
                "base_url is required routing metadata for upsert_locked_shard — "
                "the proxy uses it to forward requests to the correct upstream."
            )
        # WOR-465 A3b: in IPC-only mode the encrypt round-trips through the
        # sidecar's ``seal`` verb so the proxy uid never touches Fernet bytes.
        shard_b_bytes = memoryview(shard.shard_b).tobytes()
        if self._ipc is not None:
            shard_b_enc = await self._ipc.seal(shard_b_bytes)
        else:
            fernet = self._get_fernet()
            shard_b_enc = fernet.encrypt(shard_b_bytes)  # Fernet requires immutable bytes
        # shard_a parameter is intentionally NOT encrypted/stored — it stays
        # client-side only (in .env and openclaw.json).
        async with self._connect() as db:
            await db.execute(
                "INSERT INTO shards "
                "(key_alias, shard_b_enc, commitment, nonce, provider, prefix, charset, "
                " base_url, shard_a_enc) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL) "
                "ON CONFLICT(key_alias) DO UPDATE SET "
                "  shard_b_enc = excluded.shard_b_enc, "
                "  commitment  = excluded.commitment, "
                "  nonce       = excluded.nonce, "
                "  provider    = excluded.provider, "
                "  prefix      = excluded.prefix, "
                "  charset     = excluded.charset, "
                "  base_url    = excluded.base_url, "
                "  shard_a_enc = NULL",
                (
                    alias,
                    shard_b_enc,
                    memoryview(shard.commitment).tobytes(),
                    memoryview(shard.nonce).tobytes(),
                    shard.provider,
                    prefix,
                    charset,
                    base_url,
                ),
            )
            await db.commit()

    # ------------------------------------------------------------------
    # Enrollment CRUD
    # ------------------------------------------------------------------

    async def store_enrolled(
        self,
        alias: str,
        shard: StoredShard,
        *,
        var_name: str,
        env_path: str | None = None,
        spend_cap: int | None | _Sentinel = _USE_DEFAULT,
        token_budget_daily: int | None = None,
        prefix: str | None = None,
        charset: str | None = None,
        base_url: str | None = None,
    ) -> None:
        """Atomically store a shard, enrollment record, and enrollment config.

        If the shard already exists (same alias), only the enrollment row
        is inserted.  The enrollment_config row uses INSERT OR IGNORE so
        re-enrollment never overwrites a user-modified spend cap.

        *spend_cap* semantics:

        - omitted / ``_USE_DEFAULT`` -> ``DEFAULT_SPEND_CAP_TOKENS``
        - explicit ``None`` -> NULL (unlimited)
        - integer -> that value
        """
        # Resolve sentinel to the concrete default
        effective_cap: int | None
        if spend_cap is _USE_DEFAULT:
            effective_cap = DEFAULT_SPEND_CAP_TOKENS
        else:
            effective_cap = spend_cap  # type: ignore[assignment]  # int | None at this point

        shard_b_enc = await self._seal(memoryview(shard.shard_b).tobytes())
        async with self._connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            await db.execute(
                "INSERT OR IGNORE INTO shards "
                "(key_alias, shard_b_enc, commitment, nonce, provider, prefix, charset, base_url) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    alias,
                    shard_b_enc,
                    memoryview(shard.commitment).tobytes(),
                    memoryview(shard.nonce).tobytes(),
                    shard.provider,
                    prefix,
                    charset,
                    base_url,
                ),
            )
            await db.execute(
                "INSERT OR IGNORE INTO enrollments "
                "(key_alias, var_name, env_path) "
                "VALUES (?, ?, ?)",
                (alias, var_name, env_path),
            )
            await db.execute(
                "INSERT OR IGNORE INTO enrollment_config"
                " (key_alias, spend_cap, token_budget_daily)"
                " VALUES (?, ?, ?)",
                (alias, effective_cap, token_budget_daily),
            )
            await db.commit()

    async def add_enrollment(
        self, alias: str, *, var_name: str, env_path: str | None = None
    ) -> None:
        """Add an enrollment row without touching the shards table.

        Uses INSERT OR IGNORE so duplicate (alias, var_name, env_path) tuples
        are silently ignored.
        """
        async with self._connect() as db:
            await db.execute(
                "INSERT OR IGNORE INTO enrollments (key_alias, var_name, env_path) "
                "VALUES (?, ?, ?)",
                (alias, var_name, env_path),
            )
            await db.commit()

    async def get_enrollment(
        self, alias: str, env_path: str | None = None
    ) -> EnrollmentRecord | None:
        """Return the enrollment for *alias*.

        If *env_path* is given, filter by exact match. Otherwise return the
        first enrollment for the alias (useful when only one exists).
        """
        async with self._connect() as db:
            if env_path is None:
                cursor = await db.execute(
                    "SELECT key_alias, var_name, env_path, decoy_hash FROM enrollments "
                    "WHERE key_alias = ? LIMIT 1",
                    (alias,),
                )
            else:
                cursor = await db.execute(
                    "SELECT key_alias, var_name, env_path, decoy_hash FROM enrollments "
                    "WHERE key_alias = ? AND env_path = ?",
                    (alias, env_path),
                )
            row = await cursor.fetchone()
            if row is None:
                return None
            return EnrollmentRecord(
                key_alias=row[0],
                var_name=row[1],
                env_path=row[2],
                decoy_hash=row[3],
            )

    async def find_enrollment_by_location(
        self, var_name: str, env_path: str
    ) -> EnrollmentRecord | None:
        """Return the enrollment for *var_name* + *env_path*, or ``None``."""
        async with self._connect() as db:
            cursor = await db.execute(
                "SELECT key_alias, var_name, env_path, decoy_hash FROM enrollments "
                "WHERE var_name = ? AND env_path = ?",
                (var_name, env_path),
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            return EnrollmentRecord(
                key_alias=row[0],
                var_name=row[1],
                env_path=row[2],
                decoy_hash=row[3],
            )

    async def list_enrollments(
        self,
        alias: str | None = None,
    ) -> list[EnrollmentRecord]:
        """Return enrollment records, optionally filtered by *alias*.

        LEFT JOIN with ``shards`` denormalizes ``provider`` onto each
        record so callers don't have to look it up separately. Records
        whose alias has no matching shard row keep ``provider=None``.
        """
        async with self._connect() as db:
            if alias is not None:
                cursor = await db.execute(
                    "SELECT e.key_alias, e.var_name, e.env_path, e.decoy_hash, s.provider "
                    "FROM enrollments e LEFT JOIN shards s ON e.key_alias = s.key_alias "
                    "WHERE e.key_alias = ?",
                    (alias,),
                )
            else:
                cursor = await db.execute(
                    "SELECT e.key_alias, e.var_name, e.env_path, e.decoy_hash, s.provider "
                    "FROM enrollments e LEFT JOIN shards s ON e.key_alias = s.key_alias "
                    "ORDER BY e.key_alias"
                )
            rows = await cursor.fetchall()
            return [
                EnrollmentRecord(
                    key_alias=r[0],
                    var_name=r[1],
                    env_path=r[2],
                    decoy_hash=r[3],
                    provider=r[4],
                )
                for r in rows
            ]

    async def set_spend_cap(self, alias: str, spend_cap: int | None) -> bool:
        """Update ``enrollment_config.spend_cap`` for *alias*.

        Returns True if the row existed and was updated, False if the alias
        has no enrollment_config row (call :meth:`store_enrolled` first).

        *spend_cap* semantics:
        - integer → set to that value
        - ``None``  → unlimited (NULL in DB)
        """
        async with self._connect() as db:
            cursor = await db.execute(
                "UPDATE enrollment_config SET spend_cap = ? WHERE key_alias = ?",
                (spend_cap, alias),
            )
            await db.commit()
            return cursor.rowcount > 0

    async def delete_enrollment(self, alias: str, env_path: str | None) -> bool:
        """Delete a single enrollment row. Returns True if deleted."""
        async with self._connect() as db:
            if env_path is None:
                cursor = await db.execute(
                    "DELETE FROM enrollments WHERE key_alias = ? AND env_path IS NULL",
                    (alias,),
                )
            else:
                cursor = await db.execute(
                    "DELETE FROM enrollments WHERE key_alias = ? AND env_path = ?",
                    (alias, env_path),
                )
            await db.commit()
            return cursor.rowcount > 0

    async def delete_enrolled(self, alias: str) -> bool:
        """Delete the shard and all enrollments for *alias* (CASCADE).

        Returns True if deleted.
        """
        async with self._connect() as db:
            cursor = await db.execute("DELETE FROM shards WHERE key_alias = ?", (alias,))
            await db.commit()
            return cursor.rowcount > 0

    async def revoke_all(self, alias: str) -> bool:
        """Atomically delete all DB records for *alias* in one transaction.

        Deletes spend_log, enrollment_config, and shards (CASCADE to enrollments).
        Returns True if the shard existed.
        """
        async with aiosqlite.connect(self._db_path, isolation_level=None) as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await db.execute("BEGIN IMMEDIATE")
            await db.execute("DELETE FROM spend_log WHERE key_alias = ?", (alias,))
            await db.execute("DELETE FROM enrollment_config WHERE key_alias = ?", (alias,))
            cursor = await db.execute("DELETE FROM shards WHERE key_alias = ?", (alias,))
            await db.execute("COMMIT")
            return cursor.rowcount > 0

    async def count_aliases(self) -> int:
        """Return the number of distinct enrolled aliases remaining."""
        async with self._connect() as db:
            cursor = await db.execute("SELECT COUNT(DISTINCT key_alias) FROM shards")
            row = await cursor.fetchone()
            return row[0] if row else 0

    # ------------------------------------------------------------------
    # Decoy hash registry (WOR-31)
    # ------------------------------------------------------------------

    async def set_decoy_hash(self, alias: str, env_path: str | None, decoy_value: str) -> None:
        """Store the HMAC-SHA256 hash of *decoy_value* on the enrollment row."""
        h = await self._compute_decoy_hash(decoy_value)
        async with self._connect() as db:
            if env_path is None:
                await db.execute(
                    "UPDATE enrollments SET decoy_hash = ? "
                    "WHERE key_alias = ? AND env_path IS NULL",
                    (h, alias),
                )
            else:
                await db.execute(
                    "UPDATE enrollments SET decoy_hash = ? WHERE key_alias = ? AND env_path = ?",
                    (h, alias, env_path),
                )
            await db.commit()

    async def is_known_decoy(self, value: str) -> bool:
        """Return True if *value* matches any stored decoy hash."""
        h = await self._compute_decoy_hash(value)
        async with self._connect() as db:
            cursor = await db.execute(
                "SELECT 1 FROM enrollments WHERE decoy_hash = ? LIMIT 1",
                (h,),
            )
            return await cursor.fetchone() is not None

    async def all_decoy_hashes(self) -> set[str]:
        """Return the set of all non-NULL decoy_hash values (for batch checks)."""
        async with self._connect() as db:
            cursor = await db.execute(
                "SELECT decoy_hash FROM enrollments WHERE decoy_hash IS NOT NULL"
            )
            return {row[0] for row in await cursor.fetchall()}
