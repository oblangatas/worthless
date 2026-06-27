"""Minimal enrollment stub for seeding test keys.

This is NOT the full CLI enrollment command — it is a minimal function
used by integration tests and early development to enroll keys directly.
"""

from __future__ import annotations

from pathlib import Path

from worthless.crypto.splitter import split_key
from worthless.storage.repository import ShardRepository, StoredShard


async def enroll_stub(
    alias: str,
    api_key: str,
    provider: str,
    db_path: str,
    fernet_key: bytes,
    shard_a_dir: str | None = None,
) -> bytearray:
    """Enroll a key by splitting and storing shard_b.

    Returns shard_a bytes (caller is responsible for secure storage).

    Args:
        alias: Key alias (alphanumeric, dash, underscore).
        api_key: The raw API key string to split.
        provider: Provider name (e.g., "openai", "anthropic").
        db_path: Path to the SQLite database.
        fernet_key: Fernet encryption key for shard_b at rest.
        shard_a_dir: Optional directory to write shard_a file.

    Returns:
        The shard_a bytes.
    """
    sr = split_key(api_key.encode())

    shard = StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider=provider,
    )

    repo = ShardRepository(db_path, fernet_key)
    await repo.initialize()
    await repo.store(alias, shard)

    shard_a = bytearray(sr.shard_a)

    if shard_a_dir:
        Path(shard_a_dir).mkdir(parents=True, exist_ok=True)
        shard_a_path = Path(shard_a_dir) / alias
        shard_a_path.write_bytes(shard_a)

    return shard_a
