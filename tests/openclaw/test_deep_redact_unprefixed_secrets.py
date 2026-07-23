"""WOR-827 — deep-redact catches high-entropy secrets with NO known prefix.

The residual left by G5-B (bead ``worthless-3l5l``): ``_deep_redact_key_strings``
detected key material only via ``KEY_PATTERN``, a prefix allowlist (``sk-``,
``sk-ant-``, ``AIza``, ``xai-`` …). A self-hosted gateway / Azure / Enterprise
/ custom provider whose credential is a bare UUID, a raw JWT, or a long
hex/base64 admin token carries none of those prefixes — so it survived
verbatim into ``oc_original_api_key_json`` and back into ``openclaw.json`` on
restore. WOR-655's Proof of Function named this exact gap as out of scope.

RED-first. These pin the entropy/shape fallback:

REDACTED (secret-shaped, no prefix):
  1. bare UUID v4
  2. raw JWT (``eyJ…``)
  3. 64-char hex token
  4. long random base64-ish admin token

PRESERVED (not secrets):
  5. plain English prose, a provider URL, a short git-style hash

Every test drives the real public leak surface (``build_oc_rollback_entry_record``)
and asserts the planted secret is ABSENT from the serialized JSON — the same
altitude an attacker would read.
"""

from __future__ import annotations

import json

from worthless.openclaw.integration import build_oc_rollback_entry_record

DEEP_REDACT_SENTINEL = {"kind": "redacted-deep"}

# Unprefixed secrets — none match KEY_PATTERN.
_UUID = "550e8400-e29b-41d4-a716-446655440000"
_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
    ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)
_HEX64 = "a3f5c9d2e1b8074653f9a2b1c8d7e6f504132a3f5c9d2e1b8074653f9a2b1c8d7"
_B64_TOKEN = "aB3dE6fH9jK2mN5pQ8rS1tU4vW7xY0zC3eF6gH9iJ2kL5mN8"  # noqa: S105 — test fixture, not a real credential


def _record_for(nested_value: str) -> tuple[str, dict]:
    original = {
        "baseUrl": "https://gateway.internal.example.com/v1",
        "apiKey": "top-handled-separately",
        "headers": {"Authorization": f"Bearer {nested_value}"},
    }
    record_json = build_oc_rollback_entry_record(original)
    return record_json, json.loads(record_json)


def test_bare_uuid_is_redacted() -> None:
    record_json, record = _record_for(_UUID)
    assert record["headers"]["Authorization"] == DEEP_REDACT_SENTINEL
    assert _UUID not in record_json


def test_raw_jwt_is_redacted() -> None:
    record_json, record = _record_for(_JWT)
    assert record["headers"]["Authorization"] == DEEP_REDACT_SENTINEL
    assert _JWT not in record_json


def test_64_char_hex_token_is_redacted() -> None:
    record_json, record = _record_for(_HEX64)
    assert record["headers"]["Authorization"] == DEEP_REDACT_SENTINEL
    assert _HEX64 not in record_json


def test_long_base64_admin_token_is_redacted() -> None:
    record_json, record = _record_for(_B64_TOKEN)
    assert record["headers"]["Authorization"] == DEEP_REDACT_SENTINEL
    assert _B64_TOKEN not in record_json


def test_unprefixed_secret_as_bare_value_is_redacted() -> None:
    """Not wrapped in ``Bearer`` — the raw token standing alone must go too."""
    for secret in (_UUID, _JWT, _HEX64, _B64_TOKEN):
        original = {"baseUrl": "https://gw.example.com/v1", "apiKey": "x", "token": secret}
        record_json = build_oc_rollback_entry_record(original)
        assert secret not in record_json, f"{secret[:12]}… survived as a bare value"


def test_plain_text_urls_and_short_hashes_are_preserved() -> None:
    """The entropy/shape fallback must not damage harmless data."""
    original = {
        "baseUrl": "https://api.openai.com/v1/chat/completions",
        "apiKey": "x",
        "description": "primary gateway for the west coast team",
        "commit": "a1b2c3d",  # 7-char git short hash
        "region": "us-east-1",
        "models": ["gpt-4o", "gpt-4o-mini"],
    }
    record_json = build_oc_rollback_entry_record(original)
    record = json.loads(record_json)
    assert record["baseUrl"] == "https://api.openai.com/v1/chat/completions"
    assert record["description"] == "primary gateway for the west coast team"
    assert record["commit"] == "a1b2c3d"
    assert record["region"] == "us-east-1"
    assert record["models"] == ["gpt-4o", "gpt-4o-mini"]


def test_azure_baseurl_with_embedded_guid_survives_restore() -> None:
    """A provider baseUrl may embed an Azure subscription GUID. It is a URL,
    not a credential; restore writes it back verbatim, so whole-redacting it
    would corrupt the provider on unlock. The URL exemption must preserve it."""
    azure_url = (
        "https://myapim.azure-api.net/subscriptions/"
        "550e8400-e29b-41d4-a716-446655440000/providers/openai/v1"
    )
    original = {"baseUrl": azure_url, "apiKey": "x", "models": ["gpt-4o"]}
    record = json.loads(build_oc_rollback_entry_record(original))
    assert record["baseUrl"] == azure_url, "Azure baseUrl with a GUID was over-redacted"


def test_url_exemption_does_not_leak_a_prefixed_key_in_a_url() -> None:
    """The URL exemption must not open a hole: a known-prefix key embedded in a
    URL value is still caught by KEY_PATTERN (via _is_secret_shaped)."""
    planted = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    original = {
        "baseUrl": "https://api.openai.com/v1",
        "apiKey": "x",
        "callback": f"https://gw.example.com/v1?token={planted}",
    }
    record_json = build_oc_rollback_entry_record(original)
    assert planted not in record_json, "prefixed key inside a URL leaked past the exemption"
