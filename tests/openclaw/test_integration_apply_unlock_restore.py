"""WOR-621 F2 (WOR-649) — ``apply_unlock`` RESTORE contract (RED-first).

F1 made ``apply_lock`` rewrite the provider's ORIGINAL entry (``openai``)
to point at the Worthless proxy with shard-A in ``apiKey`` — it no longer
creates a separate ``worthless-<id>`` decoy. So the symmetric undo can no
longer be "remove the decoy"; it must **restore the original entry
verbatim** from a non-secret rollback record (DF-3), offline.

This file defines the NEW contract test-first. The new entry point is::

    apply_unlock(restores: list[OcRestore], *, remove_skill=True)

where each ``OcRestore`` carries everything needed to put the original
entry back WITHOUT the DB ever having held the real key:

    OcRestore(
        provider,                  # original provider id, e.g. "openai"
        alias,                     # globally-unique shard-row id
        oc_original_api_key_json,  # shape-only record carrying the URL +
                                   #   {"kind":"plaintext"} or {"kind":"secretref","ref":{...}}
                                   #   (G5-C: oc_original_base_url field was dropped;
                                   #   the URL is inside this MAC-bound JSON record.)
        plaintext_key,             # bytearray|None — reconstructed CLIENT-side
                                   #   (shard-A ⊕ shard-B), owned+zeroed by unlock;
                                   #   None for the secretref branch
    )

These tests fail RED today (``apply_unlock`` takes ``aliases=``; there is
no ``OcRestore``). They turn GREEN when F2 lands.

Spec: WOR-621 §F2 + the Pass-1/Pass-2 design on WOR-649.
"""

from __future__ import annotations

import json
from pathlib import Path

_REAL_KEY = "sk-proj-redteam0000000000000000000000000000000000000000"
_ORIG_BASE_URL = "https://api.openai.com/v1"


def _seed_provider(config_path: Path, name: str, base_url: str, api_key: str) -> None:
    data = json.loads(config_path.read_text(encoding="utf-8"))
    data.setdefault("models", {}).setdefault("providers", {})[name] = {
        "baseUrl": base_url,
        "apiKey": api_key,
    }
    config_path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _providers(config_path: Path) -> dict:
    return json.loads(config_path.read_text(encoding="utf-8"))["models"]["providers"]


def test_oc_restore_is_exported() -> None:
    """The new restore-record type must be importable from integration."""
    from worthless.openclaw import integration

    assert hasattr(integration, "OcRestore"), "OcRestore record type missing"


def test_lock_then_unlock_round_trip_byte_identical_plaintext(
    openclaw_present: dict[str, Path],
) -> None:
    """RT-01 (new contract): seed the ORIGINAL ``openai`` entry with a real
    inline key → ``apply_lock`` rewrites it to proxy + shard-A →
    ``apply_unlock`` with a plaintext rollback record + the reconstructed
    key restores the entry **byte-for-byte**. No ``worthless-openai`` decoy
    ever appears.
    """
    from worthless.openclaw import integration

    config_path = openclaw_present["config_path"]
    _seed_provider(config_path, "openai", _ORIG_BASE_URL, _REAL_KEY)
    pre_bytes = config_path.read_bytes()

    integration.apply_lock(planned_updates=[("openai", "openai-deadbeef", "shard-a-token")])

    mid = _providers(config_path)
    # F1 contract: the ORIGINAL entry is rewritten — no decoy.
    assert "worthless-openai" not in mid, mid
    assert "openai" in mid
    assert mid["openai"]["baseUrl"].endswith("/openai-deadbeef/v1")
    assert mid["openai"]["apiKey"] != _REAL_KEY, "real key must not survive lock"

    integration.apply_unlock(
        restores=[
            integration.OcRestore(
                provider="openai",
                alias="openai-deadbeef",
                oc_original_api_key_json=integration.build_oc_rollback_entry_record(
                    {"baseUrl": _ORIG_BASE_URL, "apiKey": _REAL_KEY}
                ),
                plaintext_key=bytearray(_REAL_KEY.encode("utf-8")),
            )
        ]
    )

    assert config_path.read_bytes() == pre_bytes, (
        "unlock must restore the original entry byte-for-byte"
    )


def test_unlock_restores_secretref_verbatim_never_plaintext(
    openclaw_present: dict[str, Path],
) -> None:
    """A provider whose original key was a SecretRef must be restored AS a
    SecretRef — unlock must NEVER downgrade it to a reconstructed plaintext
    key (DF-3 invariant).
    """
    from worthless.openclaw import integration

    config_path = openclaw_present["config_path"]
    secret_ref = {"source": "env", "provider": "openai", "id": "OPENAI_API_KEY"}
    # Original entry holds a SecretRef-shaped apiKey, not an inline key.
    data = json.loads(config_path.read_text(encoding="utf-8"))
    data.setdefault("models", {}).setdefault("providers", {})["openai"] = {
        "baseUrl": _ORIG_BASE_URL,
        "apiKey": {"$ref": secret_ref},
    }
    config_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    pre_bytes = config_path.read_bytes()

    integration.apply_lock(planned_updates=[("openai", "openai-deadbeef", "shard-a-token")])

    integration.apply_unlock(
        restores=[
            integration.OcRestore(
                provider="openai",
                alias="openai-deadbeef",
                oc_original_api_key_json=integration.build_oc_rollback_entry_record(
                    {"baseUrl": _ORIG_BASE_URL, "apiKey": {"$ref": secret_ref}}
                ),
                plaintext_key=None,
            )
        ]
    )

    restored = _providers(config_path)["openai"]
    assert restored["apiKey"] == {"$ref": secret_ref}, "SecretRef must be restored verbatim"
    raw = config_path.read_text(encoding="utf-8")
    assert _REAL_KEY not in raw, "no plaintext key may be written for a SecretRef original"
    assert config_path.read_bytes() == pre_bytes


def test_unlock_corrupt_rollback_record_fails_safe(
    openclaw_present: dict[str, Path],
) -> None:
    """Decision 3: a corrupt/unparsable rollback record at unlock → fail
    safe. Leave the entry on the proxy (never synthesize plaintext), and
    surface the failure as a skip, not a silent pass.
    """
    from worthless.openclaw import integration

    config_path = openclaw_present["config_path"]
    _seed_provider(config_path, "openai", _ORIG_BASE_URL, _REAL_KEY)

    integration.apply_lock(planned_updates=[("openai", "openai-deadbeef", "shard-a-token")])
    locked = _providers(config_path)
    locked_apikey = locked["openai"]["apiKey"]

    result = integration.apply_unlock(
        restores=[
            integration.OcRestore(
                provider="openai",
                alias="openai-deadbeef",
                oc_original_api_key_json="{not valid json",
                plaintext_key=bytearray(_REAL_KEY.encode("utf-8")),
            )
        ]
    )

    after = _providers(config_path)
    # Fail-safe: still on the proxy, shard-A intact — NOT the real key.
    assert after["openai"]["apiKey"] == locked_apikey
    assert _REAL_KEY not in config_path.read_text(encoding="utf-8")
    assert any("openai" in p for p, _reason in result.providers_skipped), result.providers_skipped
