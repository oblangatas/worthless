"""Storage models — pure dataclasses, no cryptography import.

Split out of ``repository.py`` (WOR-309 Phase 2) so the proxy can import
shard records without transitively pulling Fernet. The proxy now
delegates decryption to the sidecar over IPC; it only needs the
ciphertext-at-rest record.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import NamedTuple


class EncryptedShard(NamedTuple):
    """Raw encrypted shard record — no Fernet decryption applied."""

    shard_b_enc: bytes
    commitment: bytes
    nonce: bytes
    provider: str
    prefix: str | None = None
    charset: str | None = None
    # worthless-8rqs: per-enrollment upstream URL. None means the row was
    # created before 8rqs landed; Phase-6 readers refuse to use it and prompt
    # the user to re-lock.
    base_url: str | None = None
    # Nullable column kept in schema for backward compatibility with pre-revert rows.
    # Target state (post-16x2-revert): upsert_locked_shard does NOT write this field;
    # proxy reads shard-A from the Bearer header, not from the DB.
    shard_a_enc: bytes | None = None
    # WOR-651/F4 + G5-C: shape-only OpenClaw rollback record so unlock (F2)
    # can restore the original provider entry without ever storing the real
    # key. ``oc_original_api_key_json`` is the full key-redacted original
    # entry (including its baseUrl) — non-secret, MAC-bound via
    # ``oc_rollback_mac`` below. A prior ``oc_original_base_url`` field was
    # dropped in G5-C: it duplicated the URL already in the JSON and was
    # NOT MAC-bound (a DB-write attacker could flip it silently). Stage A
    # unlock parses the URL from the JSON record — the source of truth.
    oc_original_api_key_json: str | None = None
    # WOR-621 F2 G2: HMAC-SHA256 hex tag over oc_original_api_key_json,
    # keyed by the fernet-derived MAC subkey. Unlock recomputes + compares;
    # mismatch → fail-safe skip. NON-secret; legacy rows are None (no MAC) —
    # G2-aware unlock paths treat None as "legacy / no tamper-bind" and fall
    # back to the G1 fail-closed JSON parse for backward compatibility until
    # a re-lock attaches a tag.
    oc_rollback_mac: str | None = None

    def __repr__(self) -> str:
        return (
            f"EncryptedShard(shard_b_enc=<{len(self.shard_b_enc)} bytes>, "
            f"commitment=<{len(self.commitment)} bytes>, "
            f"nonce=<{len(self.nonce)} bytes>, provider={self.provider!r}, "
            f"prefix={self.prefix!r}, base_url={self.base_url!r}, "
            f"shard_a_enc={'<present>' if self.shard_a_enc else 'None'})"
        )


@dataclass(frozen=True)
class BaseUrlRestore:
    """The ``*_BASE_URL`` line lock wrote for one enrollment, and what it replaced (WOR-1013).

    ``var`` is None when lock wrote no line for the key (``--keys-only``, or a
    line another key in the ``.env`` routes). ``original`` is the value as
    written before lock, or None when the line did not exist and lock added it.
    ``unsaved`` marks a line that had a value lock would not save (WOR-1027,
    WOR-1035), so unlock can tell the user it is gone (WOR-1042). It is left
    out of the JSON when False, so records saved before it keep their meaning.
    """

    var: str | None
    original: str | None
    unsaved: bool = False

    def __post_init__(self) -> None:
        # Checked on write too: a record lock MACs but unlock can't parse would
        # read as tampered with.
        if self.var is None and (self.original is not None or self.unsaved):
            raise ValueError("base_url restore has a value but no line")
        if self.unsaved and self.original is not None:
            raise ValueError("base_url restore has a value it says lock didn't save")

    def to_json(self) -> str:
        fields: dict[str, str | bool | None] = {"var": self.var, "original": self.original}
        if self.unsaved:
            fields["unsaved"] = True
        return json.dumps(fields, sort_keys=True)

    @classmethod
    def from_json(cls, record_json: str) -> BaseUrlRestore:
        """Parse :meth:`to_json` output; ``ValueError`` on any other shape."""
        parsed = json.loads(record_json)
        if not isinstance(parsed, dict) or set(parsed) - {"unsaved"} != {"var", "original"}:
            raise ValueError("base_url restore record has the wrong keys")
        var, original = parsed["var"], parsed["original"]
        if not (var is None or isinstance(var, str)):
            raise ValueError("base_url restore var is not a string")
        if not (original is None or isinstance(original, str)):
            raise ValueError("base_url restore original is not a string")
        record = cls(var=var, original=original, unsaved=bool(parsed.get("unsaved")))
        if record.to_json() != record_json:
            # Lock writes one form; "unsaved": false or 1 is not it.
            raise ValueError("base_url restore record is not in the form lock writes")
        return record


@dataclass
class EnrollmentRecord:
    """A single enrollment binding a key alias to a var name and optional env path.

    ``provider`` is denormalized via JOIN with ``shards`` at load time so
    callers don't need a separate lookup or alias-prefix parsing. The
    canonical source remains ``shards.provider``; this is a read-side
    convenience.
    """

    key_alias: str
    var_name: str
    env_path: str | None = None
    decoy_hash: str | None = field(default=None, repr=False)
    provider: str | None = None
    # WOR-715/WOR-435: the .env's permission bits captured at lock time, so
    # uninstall can restore the original mode. None = "not captured (pre-715
    # install), leave the file mode as-is".
    original_mode: int | None = None
    # WOR-1013: BaseUrlRestore JSON and its MAC, written by lock. Read them
    # through ShardRepository.verified_base_url_restore, never directly. None =
    # enrolled before WOR-1013.
    base_url_restore_json: str | None = field(default=None, repr=False)
    base_url_restore_mac: str | None = field(default=None, repr=False)


@dataclass
class StoredShard:
    """Decrypted shard record with bytearray fields (SR-01 compliance)."""

    shard_b: bytearray
    commitment: bytearray
    nonce: bytearray
    provider: str
    # shard_a is populated only when shard_a_enc was present in the DB row
    # (legacy 16x2 rows). In the target state (post-revert), shard_a is always
    # None here because upsert_locked_shard no longer writes shard_a_enc.
    shard_a: bytearray | None = None

    def __repr__(self) -> str:
        return (
            f"StoredShard(shard_b=<{len(self.shard_b)} bytes>, "
            f"commitment=<{len(self.commitment)} bytes>, "
            f"nonce=<{len(self.nonce)} bytes>, provider={self.provider!r}, "
            f"shard_a={'<present>' if self.shard_a else 'None'})"
        )

    def zero(self) -> None:
        """Zero all cryptographic fields in place (SR-02)."""
        bufs = [self.shard_b, self.commitment, self.nonce]
        if self.shard_a is not None:
            bufs.append(self.shard_a)
        for buf in bufs:
            buf[:] = b"\x00" * len(buf)
