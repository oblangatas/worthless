"""WOR-621 F2 G5-A (Gap 3a) — MAC verification lives in Stage A, not in the CLI.

# The gap (caught by Jenny in the G3+G4 rotation review)

G2 stored a fernet-keyed MAC on every rollback record. G4 added the MAC
verify, but in the WRONG LAYER: only the CLI's
:func:`worthless.cli.commands.unlock._build_oc_restores` (`unlock.py:393-421`)
checks it. The integration layer's :func:`_apply_unlock_stage_a` (the
function that actually writes the restored entry to `openclaw.json`)
re-parses the record WITHOUT MAC args at `integration.py:1315`.

Any future caller — a test harness, an MCP wrapper, a script — that
invokes ``integration.apply_unlock(restores=…)`` directly, bypassing
``_build_oc_restores``, **skips the MAC check entirely** and re-opens the
decision-4 secretref→plaintext downgrade attack that G2 was meant to close.

This is the textbook "wrong layer for a fail-closed invariant" smell.
Stage A is the lowest layer that touches the record; the MAC check MUST
live there.

# The fix this RED pins

Extend :class:`OcRestore` with two new fields:

* ``expected_mac: str | None`` — the MAC the DB returned with the row.
* ``recomputed_mac: str | None`` — the CLI's freshly-computed MAC over the
  ``oc_original_api_key_json`` (via ``ShardRepository._compute_decoy_hash``).
  The caller does the async compute; Stage A stays sync.

Stage A's parse call becomes
``_parse_oc_rollback_entry_record(record, expected_mac=…, recomputed_mac=…)``.
Mismatch → fail-safe skip with ``rollback_record_invalid`` event +
``plaintext_key`` zeroed. Legacy rows (both ``None``) fall back to
shape-only validation per G1.

# What this test pins

1. Stage A REFUSES a record whose stored MAC doesn't match the freshly
   computed MAC over the (presumably-tampered) JSON. Event emitted,
   provider skipped, NO ``replace_provider`` call, ``plaintext_key``
   zeroed.

2. Stage A ACCEPTS a record whose stored MAC matches the recompute.
   Happy path, ``replace_provider`` writes the original entry verbatim.

3. Stage A FALLS BACK to shape-only validation when both MAC fields are
   ``None`` (legacy pre-G2 row).

4. The reconstructed real key NEVER lands in ``openclaw.json`` on the
   mismatched-MAC branch — even if the CLI passed a live ``plaintext_key``
   bytearray (this is the canonical decision-4 attack).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from worthless.openclaw import config as _config_mod
from worthless.openclaw import integration as _oi


# ---------------------------------------------------------------------------
# Fixtures (lifted from sibling restore module)
# ---------------------------------------------------------------------------


@pytest.fixture
def seeded_openclaw(openclaw_present: dict[str, Path]) -> dict[str, Path]:
    """OpenClaw config with the openai provider pre-rewritten to the proxy
    (the post-lock state Stage A is meant to undo).
    """
    config_path = openclaw_present["config_path"]
    config_path.write_text(
        json.dumps(
            {
                "models": {
                    "providers": {
                        "openai": {
                            "baseUrl": "http://127.0.0.1:8787/openai-ab5091b7/v1",
                            "apiKey": "sk-proj-shardA-fake",
                            "api": "openai-completions",
                            "models": [],
                        }
                    }
                }
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return openclaw_present


def _legit_plaintext_record() -> str:
    """A canonical G1+G2-shaped plaintext rollback record."""
    return _oi.build_oc_rollback_entry_record(
        {
            "baseUrl": "https://api.openai.com/v1",
            "apiKey": "sk-proj-original-fake-key-not-stored",
        }
    )


# ---------------------------------------------------------------------------
# 1. Stage A refuses on MAC mismatch
# ---------------------------------------------------------------------------


def test_stage_a_refuses_when_expected_mac_disagrees_with_recomputed_mac(
    seeded_openclaw: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Decision-4 attack at the integration layer: a caller that bypasses
    ``_build_oc_restores`` and feeds ``apply_unlock`` a record whose stored
    MAC doesn't match a recompute over its bytes MUST be refused by Stage A.

    Without this, the MAC check only exists in the CLI helper and a
    misconfigured test harness / MCP wrapper / script could skip it,
    re-opening the secretref→plaintext downgrade attack G2 closed.
    """
    monkeypatch.chdir(seeded_openclaw["home"])
    record = _legit_plaintext_record()

    # Build an OcRestore carrying a CLI-detected MAC mismatch. The new
    # fields (expected_mac, recomputed_mac) are what G5-A introduces. The
    # plaintext_key is LIVE — a real bytearray of the reconstructed key —
    # so this test also pins that the attacker's planted bytes NEVER reach
    # openclaw.json even when a live key is available.
    plaintext_key = bytearray(b"sk-proj-original-fake-key-not-stored")
    restore = _oi.OcRestore(
        provider="openai",
        alias="openai-ab5091b7",
        oc_original_api_key_json=record,
        plaintext_key=plaintext_key,
        expected_mac="aa" * 32,  # what the DB returned
        recomputed_mac="bb" * 32,  # what the CLI computed → mismatch
    )

    # Spy on replace_provider so we can assert Stage A did NOT write
    # anything on the mismatch path.
    replace_spy = MagicMock(wraps=_config_mod.replace_provider)
    monkeypatch.setattr(_config_mod, "replace_provider", replace_spy)

    result = _oi.apply_unlock(restores=[restore])

    assert result.detected is True
    assert "openai" not in result.providers_set
    skipped_codes = {code for _, code in result.providers_skipped}
    assert "rollback_record_invalid" in skipped_codes, (
        f"Stage A must skip with rollback_record_invalid on MAC mismatch; "
        f"got skips: {result.providers_skipped}"
    )

    # Defence in depth: the MAC gate must fire BEFORE any write attempt.
    replace_spy.assert_not_called()

    # And the post-state confirms it on disk: openclaw.json still has the
    # PROXY entry; the plaintext key value did not slip in.
    data = json.loads(seeded_openclaw["config_path"].read_text(encoding="utf-8"))
    assert data["models"]["providers"]["openai"]["baseUrl"].startswith("http://127.0.0.1:"), (
        "Stage A must NOT have restored on MAC mismatch"
    )
    assert b"sk-proj-original-fake-key-not-stored" not in (
        seeded_openclaw["config_path"].read_bytes()
    ), "reconstructed real key bytes must NEVER reach openclaw.json on the mismatch path"

    # Plaintext key bytearray was zeroed by Stage A's finally (G4 MED-1
    # safety net).
    assert all(b == 0 for b in plaintext_key), (
        "Stage A must zero plaintext_key on every exit path, including refusal"
    )


# ---------------------------------------------------------------------------
# 2. Stage A accepts on MAC match
# ---------------------------------------------------------------------------


def test_stage_a_accepts_when_macs_match(
    seeded_openclaw: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: a record whose stored MAC matches a recompute passes
    Stage A's gate and the original entry is restored verbatim.
    """
    monkeypatch.chdir(seeded_openclaw["home"])
    record = _legit_plaintext_record()
    matching_mac = "deadbeef" * 8  # CLI computes & DB stores the same value

    plaintext_key = bytearray(b"sk-proj-original-fake-key-not-stored")
    restore = _oi.OcRestore(
        provider="openai",
        alias="openai-ab5091b7",
        oc_original_api_key_json=record,
        plaintext_key=plaintext_key,
        expected_mac=matching_mac,
        recomputed_mac=matching_mac,
    )

    result = _oi.apply_unlock(restores=[restore])

    assert "openai" in result.providers_set, (
        f"Stage A should have restored openai on MAC match; "
        f"skipped: {result.providers_skipped}, events: "
        f"{[(e.code, e.detail) for e in result.events]}"
    )
    data = json.loads(seeded_openclaw["config_path"].read_text(encoding="utf-8"))
    assert data["models"]["providers"]["openai"]["baseUrl"] == "https://api.openai.com/v1"
    assert data["models"]["providers"]["openai"]["apiKey"] == "sk-proj-original-fake-key-not-stored"


# ---------------------------------------------------------------------------
# 3. Legacy NULL-MAC row falls back to shape-only check (G1 behavior)
# ---------------------------------------------------------------------------


def test_stage_a_falls_back_to_shape_only_when_macs_are_none(
    seeded_openclaw: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pre-G2 row that never had a MAC stored (NULL ``oc_rollback_mac``)
    must still unlock cleanly via shape-only validation. The fallback is
    what G1's docstring blesses: ``expected_mac=None`` AND
    ``recomputed_mac=None`` → no constant-time compare → shape-only parse.

    Without this fallback, every legacy row breaks on first unlock after
    G5-A lands. That would be a real regression.
    """
    monkeypatch.chdir(seeded_openclaw["home"])
    record = _legit_plaintext_record()

    plaintext_key = bytearray(b"sk-proj-original-fake-key-not-stored")
    restore = _oi.OcRestore(
        provider="openai",
        alias="openai-ab5091b7",
        oc_original_api_key_json=record,
        plaintext_key=plaintext_key,
        expected_mac=None,  # legacy: no MAC stored
        recomputed_mac=None,  # caller correctly mirrors that with None
    )

    result = _oi.apply_unlock(restores=[restore])

    assert "openai" in result.providers_set, (
        f"legacy NULL-MAC rows must unlock via shape-only fallback; "
        f"skipped: {result.providers_skipped}"
    )


# ---------------------------------------------------------------------------
# 4. SecretRef branch — same MAC gate, no plaintext fallthrough
# ---------------------------------------------------------------------------


def test_stage_a_refuses_secretref_on_mac_mismatch(
    seeded_openclaw: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The canonical decision-4 attack flips secretref→plaintext. Even on
    the SecretRef branch (no ``plaintext_key`` ever passed in), Stage A
    MUST refuse the mismatched record. Otherwise the parsed entry would
    be written with whatever the tampered record specifies — defeating
    the whole gate.
    """
    monkeypatch.chdir(seeded_openclaw["home"])

    secretref_record = _oi.build_oc_rollback_entry_record(
        {
            "baseUrl": "https://api.openai.com/v1",
            "apiKey": {
                "$ref": {
                    "source": "env",
                    "provider": "openai",
                    "id": "OPENAI_API_KEY",
                }
            },
        }
    )
    restore = _oi.OcRestore(
        provider="openai",
        alias="openai-ab5091b7",
        oc_original_api_key_json=secretref_record,
        plaintext_key=None,  # secretref branch — no live key
        expected_mac="aa" * 32,
        recomputed_mac="bb" * 32,
    )

    result = _oi.apply_unlock(restores=[restore])

    assert "openai" not in result.providers_set
    data = json.loads(seeded_openclaw["config_path"].read_text(encoding="utf-8"))
    assert data["models"]["providers"]["openai"]["baseUrl"].startswith("http://127.0.0.1:"), (
        "Stage A must NOT have restored on MAC mismatch — even on the secretref branch"
    )
