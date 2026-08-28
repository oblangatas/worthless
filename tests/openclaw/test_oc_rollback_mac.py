"""WOR-621 F2 G2 — DB MAC tamper-bind for the OC rollback record (decision 4).

RED-first. The threat: a DB-write attacker (no fernet key access) flips the
stored ``oc_original_api_key_json`` from a SecretRef to plaintext. On the
next ``unlock`` the legitimate fernet-keyed reconstruction kicks in and the
real key gets written into a slot the attacker can read — a privilege
escalation via unlock.

The defense: bind the record to a HMAC tag keyed by the fernet-derived MAC
subkey (reusing :meth:`ShardRepository._compute_decoy_hash` — no new
crypto). Lock stores the tag; unlock recomputes and constant-time-compares.
Mismatch ⇒ fail-safe skip (leave on proxy, never synthesize plaintext) —
the same contract G1 already enforces for parse/corrupt records.

Pinned contracts (RED):
1. Storage round-trips a new ``oc_rollback_mac`` column alongside
   ``oc_original_api_key_json``.
2. Integration parse refuses a record whose stored MAC does not match
   ``_compute_decoy_hash(oc_original_api_key_json)`` — even when the JSON
   itself parses cleanly.
3. A SecretRef → plaintext flip in the stored JSON is the canonical attack
   the bind detects.
"""

from __future__ import annotations


import aiosqlite
import pytest

from worthless.openclaw.integration import build_oc_rollback_entry_record
from worthless.storage.repository import ShardRepository

from tests.conftest import stored_shard_from_split


def _legit_record(orig_base_url: str, secret_ref: dict) -> str:
    return build_oc_rollback_entry_record(
        {"baseUrl": orig_base_url, "apiKey": {"$ref": secret_ref}}
    )


@pytest.mark.asyncio
async def test_oc_rollback_mac_round_trips_through_storage(
    repo: ShardRepository, sample_split_result
) -> None:
    """Storage layer must accept and return a non-empty MAC tag alongside
    the rollback record. Without this column the unlock-time tamper check
    has nothing to verify against.
    """
    shard = stored_shard_from_split(sample_split_result, provider="openai")
    record = _legit_record(
        "https://api.openai.com/v1",
        {"source": "env", "provider": "openai", "id": "OPENAI_API_KEY"},
    )
    mac_tag = await repo._compute_decoy_hash(record)
    assert isinstance(mac_tag, str) and mac_tag, "MAC tag must be a non-empty hex string"

    await repo.upsert_locked_shard(
        "oc-mac-roundtrip",
        shard,
        prefix="sk-",
        charset="abc",
        base_url="https://api.worthless.local/oc-mac-roundtrip/v1",
        oc_original_api_key_json=record,
        oc_rollback_mac=mac_tag,
    )
    enc = await repo.fetch_encrypted("oc-mac-roundtrip")
    assert enc is not None
    assert enc.oc_rollback_mac == mac_tag


@pytest.mark.asyncio
async def test_integration_refuses_record_with_mismatched_mac(
    repo: ShardRepository, sample_split_result, tmp_db_path: str
) -> None:
    """The integration-layer parse must refuse a rollback record whose stored
    MAC does not match a fresh recompute over the (current) JSON — even when
    the JSON itself is well-formed. This is the load-bearing tamper check.
    """
    from worthless.openclaw.integration import _parse_oc_rollback_entry_record

    legit_record = _legit_record(
        "https://api.openai.com/v1",
        {"source": "env", "provider": "openai", "id": "OPENAI_API_KEY"},
    )
    legit_mac = await repo._compute_decoy_hash(legit_record)

    # Attacker flips the stored JSON from SecretRef → plaintext, leaving the
    # original (now-stale) MAC tag in place. The JSON parses cleanly today
    # (G1 fail-closed parser accepts it), so only the MAC check catches it.
    tampered_record = build_oc_rollback_entry_record(
        {"baseUrl": "https://api.openai.com/v1", "apiKey": "sk-attacker-placeholder"}
    )
    assert tampered_record != legit_record, "test premise: tampered JSON differs"

    recomputed_for_tampered = await repo._compute_decoy_hash(tampered_record)
    with pytest.raises(ValueError, match="rollback.*mac|tampered|tag"):
        _parse_oc_rollback_entry_record(
            tampered_record,
            expected_mac=legit_mac,
            recomputed_mac=recomputed_for_tampered,
        )


@pytest.mark.asyncio
async def test_integration_accepts_record_with_matching_mac(
    repo: ShardRepository, sample_split_result
) -> None:
    """The legit happy path: a record whose stored MAC matches a recompute
    over its JSON is accepted by the parse and round-trips to the same shape
    the G1 parser produces.
    """
    from worthless.openclaw.integration import _parse_oc_rollback_entry_record

    record = _legit_record(
        "https://api.openai.com/v1",
        {"source": "env", "provider": "openai", "id": "OPENAI_API_KEY"},
    )
    mac_tag = await repo._compute_decoy_hash(record)
    entry = _parse_oc_rollback_entry_record(record, expected_mac=mac_tag, recomputed_mac=mac_tag)
    # build_oc_rollback_entry_record(apiKey={"$ref": <pointer>}) stores the
    # ENTIRE {"$ref": …} dict as the secretref `ref` pointer (verbatim) —
    # ensuring unlock can write it back verbatim and never re-interpret.
    assert entry["apiKey"] == {
        "kind": "secretref",
        "ref": {"$ref": {"source": "env", "provider": "openai", "id": "OPENAI_API_KEY"}},
    }


@pytest.mark.asyncio
async def test_db_attacker_secretref_to_plaintext_flip_detected_at_unlock(
    repo: ShardRepository, sample_split_result, tmp_db_path: str
) -> None:
    """End-to-end threat: a DB-write attacker (no fernet key) edits the
    stored ``oc_original_api_key_json`` to flip a SecretRef→plaintext. The
    legit MAC tag stored alongside it is now stale, so the next unlock-time
    check refuses the row and falls back to fail-safe (leave on proxy).

    This is the canonical decision-4 attack that motivated G2.
    """
    from worthless.openclaw.integration import _parse_oc_rollback_entry_record

    shard = stored_shard_from_split(sample_split_result, provider="openai")
    legit_record = _legit_record(
        "https://api.openai.com/v1",
        {"source": "env", "provider": "openai", "id": "OPENAI_API_KEY"},
    )
    legit_mac = await repo._compute_decoy_hash(legit_record)
    await repo.upsert_locked_shard(
        "oc-mac-flip",
        shard,
        prefix="sk-",
        charset="abc",
        base_url="https://api.worthless.local/oc-mac-flip/v1",
        oc_original_api_key_json=legit_record,
        oc_rollback_mac=legit_mac,
    )

    # Attacker edits the JSON directly in SQLite — kind: secretref → plaintext.
    tampered = build_oc_rollback_entry_record(
        {"baseUrl": "https://api.openai.com/v1", "apiKey": "sk-attacker-placeholder"}
    )
    async with aiosqlite.connect(tmp_db_path) as db:
        await db.execute(
            "UPDATE shards SET oc_original_api_key_json = ? WHERE key_alias = 'oc-mac-flip'",
            (tampered,),
        )
        await db.commit()

    # Unlock-side parse refuses the row: the stored MAC no longer matches
    # the (now-tampered) JSON. The legit fernet-keyed recompute is what
    # makes this detection load-bearing.
    enc = await repo.fetch_encrypted("oc-mac-flip")
    assert enc is not None
    assert enc.oc_original_api_key_json == tampered, "test premise: tamper landed"
    assert enc.oc_rollback_mac == legit_mac, "test premise: stale MAC kept"

    recomputed_for_row = await repo._compute_decoy_hash(enc.oc_original_api_key_json)
    with pytest.raises(ValueError):
        _parse_oc_rollback_entry_record(
            enc.oc_original_api_key_json,
            expected_mac=enc.oc_rollback_mac,
            recomputed_mac=recomputed_for_row,
        )

    # Belt-and-suspenders: the attacker's planted plaintext is what's *stored*
    # (we put it there), but our tamper check made unlock REFUSE the row above
    # — so the attacker's value can never be written back into openclaw.json.
    # The point of G2 is exactly that: tampered → fail-safe skip.
