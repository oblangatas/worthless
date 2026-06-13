"""WOR-621 F2 G5-B (Gap 2a) — deep-redact ``build_oc_rollback_entry_record``.

RED-first. The threat: today ``build_oc_rollback_entry_record`` is a
shallow-copy + top-level ``apiKey`` substitution. So a user with a custom
OpenClaw provider entry that carries credentials in a NON-canonical field
(e.g. ``headers.Authorization: "Bearer sk-..."`` for a self-hosted gateway
that wants a raw bearer header rather than the auto-injected ``apiKey``,
or any nested config field a user added) ships their real key verbatim
into ``oc_original_api_key_json`` AND has it written back into
``openclaw.json`` on restore. The G3+G4 panel (Jenny) flagged this as
Gap 2a: the docstring claims "key-redacted full entry record" but only
top-level ``apiKey`` is touched.

The defense: walk the captured entry recursively (dicts AND lists) and
replace any string that ``KEY_PATTERN`` flags as key-shaped with a
``{"kind": "redacted-deep"}`` sentinel. The user has to re-paste those
nested credentials on unlock — but they were never safe in the rollback
record anyway.

Pinned contracts (RED):

1. A key-shaped string at depth >=2 in the captured entry is replaced by
   the sentinel dict in the resulting JSON.
2. A key-shaped string inside a nested list is also replaced.
3. Multiple key-shaped strings in one entry are all replaced.
4. A plain non-key string (URL, description) is preserved verbatim.
5. The existing top-level ``apiKey`` redaction path is unchanged (a
   plaintext apiKey → ``{"kind":"plaintext"}``; a dict apiKey →
   ``{"kind":"secretref","ref":<verbatim ref>}``).
6. The redacted record round-trips: ``_parse_oc_rollback_entry_record``
   accepts it without raising.

The sentinel is intentionally a dict (not a string like ``"<REDACTED>"``)
to make the contract unambiguous on the restore side: an attempt to
write a dict where the user had a string is loud and self-documenting,
not silent partial leakage.
"""

from __future__ import annotations

import json

from worthless.openclaw.integration import (
    _parse_oc_rollback_entry_record,
    build_oc_rollback_entry_record,
)

DEEP_REDACT_SENTINEL = {"kind": "redacted-deep"}
# A high-entropy OpenAI-shaped key used to drive every test. KEY_PATTERN
# requires a known provider prefix + 10+ word/dash chars — this clears it.
_PLANTED_KEY = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-abcd"
_PLANTED_ANTHROPIC = "sk-ant-api03-PqRsTuVwXyZ0123456789AbCdEfGhIjKl-mnop"
_PLANTED_GOOGLE = "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7"


def test_nested_dict_key_shaped_string_is_redacted_to_sentinel() -> None:
    """A user-custom field holding a raw key (e.g. self-hosted gateway that
    wants Authorization in a header) must NOT survive into the rollback
    record. Today it does."""
    original = {
        "baseUrl": "https://gateway.example.com/v1",
        "apiKey": "REDACTED-AT-TOP-LEVEL",  # top-level path covered separately
        "headers": {"Authorization": f"Bearer {_PLANTED_KEY}"},
    }
    record_json = build_oc_rollback_entry_record(original)
    record = json.loads(record_json)

    auth = record["headers"]["Authorization"]
    assert auth == DEEP_REDACT_SENTINEL, (
        f"deep-nested key-shaped string survived into rollback record: "
        f"{auth!r}; expected {DEEP_REDACT_SENTINEL!r}"
    )
    # The planted key must be absent from the entire serialized JSON.
    assert _PLANTED_KEY not in record_json, "planted key bytes leaked into rollback record JSON"


def test_nested_list_key_shaped_string_is_redacted() -> None:
    """A key embedded in a list (e.g. a list-of-pairs config) must also be
    scrubbed — JSON allows arbitrary nesting through lists."""
    original = {
        "baseUrl": "https://gateway.example.com/v1",
        "apiKey": "anything",
        "extraHeaders": [
            ["Authorization", f"Bearer {_PLANTED_ANTHROPIC}"],
            ["X-Custom", "harmless-value"],
        ],
    }
    record_json = build_oc_rollback_entry_record(original)
    record = json.loads(record_json)

    auth_pair = record["extraHeaders"][0]
    assert auth_pair[1] == DEEP_REDACT_SENTINEL, (
        f"key-shaped string inside list survived: {auth_pair!r}"
    )
    # The second pair is harmless and must be preserved verbatim.
    assert record["extraHeaders"][1] == ["X-Custom", "harmless-value"]
    assert _PLANTED_ANTHROPIC not in record_json


def test_multiple_key_shaped_strings_all_redacted() -> None:
    """If a user packed multiple keys into one entry (e.g. fallback creds),
    EVERY one must be scrubbed — not just the first match."""
    original = {
        "baseUrl": "https://gateway.example.com/v1",
        "apiKey": "top",
        "fallback": {
            "primary": f"Bearer {_PLANTED_KEY}",
            "secondary": _PLANTED_ANTHROPIC,
            "tertiary": {"value": _PLANTED_GOOGLE},
        },
    }
    record_json = build_oc_rollback_entry_record(original)

    for planted in (_PLANTED_KEY, _PLANTED_ANTHROPIC, _PLANTED_GOOGLE):
        assert planted not in record_json, (
            f"planted key {planted[:12]}... leaked into rollback record JSON"
        )


def test_plain_non_key_strings_preserved_verbatim() -> None:
    """Deep-redact must not damage harmless data: URLs, descriptions,
    model names, etc. Only key-shaped strings get scrubbed."""
    original = {
        "baseUrl": "https://api.openai.com/v1",
        "apiKey": "anything",
        "description": "primary OpenAI provider for shacharm",
        "models": ["gpt-4o", "gpt-4o-mini"],
        "metadata": {"region": "us-east-1", "tier": "paid"},
    }
    record_json = build_oc_rollback_entry_record(original)
    record = json.loads(record_json)

    # Everything except apiKey (which the existing path replaces with a
    # shape dict) must round-trip verbatim.
    assert record["baseUrl"] == "https://api.openai.com/v1"
    assert record["description"] == "primary OpenAI provider for shacharm"
    assert record["models"] == ["gpt-4o", "gpt-4o-mini"]
    assert record["metadata"] == {"region": "us-east-1", "tier": "paid"}


def test_top_level_apikey_plaintext_path_unchanged() -> None:
    """G5-B is additive: the existing top-level apiKey contract (plaintext
    string → ``{"kind":"plaintext"}``) must still hold byte-for-byte."""
    original = {
        "baseUrl": "https://api.openai.com/v1",
        "apiKey": _PLANTED_KEY,  # plaintext inline key
    }
    record_json = build_oc_rollback_entry_record(original)
    record = json.loads(record_json)

    assert record["apiKey"] == {"kind": "plaintext"}
    assert _PLANTED_KEY not in record_json


def test_top_level_apikey_secretref_path_unchanged() -> None:
    """SecretRef path: dict apiKey → ``{"kind":"secretref","ref":<verbatim>}``."""
    ref = {"source": "env", "provider": "openai", "id": "OPENAI_API_KEY"}
    original = {
        "baseUrl": "https://api.openai.com/v1",
        "apiKey": {"$ref": ref},
    }
    record_json = build_oc_rollback_entry_record(original)
    record = json.loads(record_json)

    assert record["apiKey"] == {
        "kind": "secretref",
        "ref": {"$ref": ref},
    }


def test_redacted_record_round_trips_through_parser() -> None:
    """The parser is strict on the apiKey shape; deep-redact must not break
    that contract — sentinels at non-apiKey paths are invisible to the
    parser, so the record must still parse cleanly."""
    original = {
        "baseUrl": "https://gateway.example.com/v1",
        "apiKey": _PLANTED_KEY,
        "headers": {"Authorization": f"Bearer {_PLANTED_KEY}"},
    }
    record_json = build_oc_rollback_entry_record(original)

    # No MAC args → shape-only validation (G1 backward-compat path).
    parsed = _parse_oc_rollback_entry_record(record_json)
    assert parsed["apiKey"]["kind"] == "plaintext"
    # The deep-redacted nested sentinel survives parse intact.
    assert parsed["headers"]["Authorization"] == DEEP_REDACT_SENTINEL


def test_key_shaped_dict_key_is_replaced_with_string_placeholder() -> None:
    """Pathological case (extremely unlikely in OpenClaw's strict schema
    but cheap to close): a user puts a key-shaped string AS a dict KEY,
    not a value. JSON dict keys must remain hashable, so they become the
    literal string placeholder ``"<redacted-deep-key>"`` rather than the
    value-side dict sentinel.
    """
    original = {
        "baseUrl": "https://gateway.example.com/v1",
        "apiKey": "top",
        "tokens": {_PLANTED_KEY: "label-for-this-token"},
    }
    record_json = build_oc_rollback_entry_record(original)
    record = json.loads(record_json)

    assert _PLANTED_KEY not in record_json, (
        "key-shaped string used as a dict KEY survived into rollback record"
    )
    tokens = record["tokens"]
    assert "<redacted-deep-key>" in tokens
    assert tokens["<redacted-deep-key>"] == "label-for-this-token"


def test_key_inside_secretref_pointer_is_redacted_defense_in_depth() -> None:
    """A SecretRef ``ref`` is meant to be a NON-secret pointer (env var name,
    secret-manager id). If a user mistakenly puts the literal key value
    into ref (e.g. ``{"id": "sk-..."}``), defense-in-depth still scrubs it."""
    original = {
        "baseUrl": "https://api.openai.com/v1",
        "apiKey": {"$ref": {"source": "env", "id": _PLANTED_KEY}},
    }
    record_json = build_oc_rollback_entry_record(original)
    assert _PLANTED_KEY not in record_json, (
        "key bytes mistakenly placed inside a SecretRef pointer must still "
        "be scrubbed by the deep walk"
    )
