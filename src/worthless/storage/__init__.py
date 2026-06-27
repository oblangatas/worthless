"""Worthless encrypted shard storage.

This package's ``__init__`` is intentionally Fernet-free: the proxy
imports :class:`worthless.storage.shard_reader.ShardReader` and pays no
``cryptography`` cost (WOR-309). Callers needing the encrypt path import
:class:`worthless.storage.repository.ShardRepository` directly.
"""

from worthless.storage.models import EncryptedShard, EnrollmentRecord, StoredShard
from worthless.storage.schema import init_db
from worthless.storage.shard_reader import ShardReader

__all__ = [
    "EncryptedShard",
    "EnrollmentRecord",
    "ShardReader",
    "StoredShard",
    "init_db",
]
