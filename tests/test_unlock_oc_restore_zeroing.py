"""SR-02: ``_build_oc_restores`` must not leave reconstructed plaintext keys in
memory if it raises mid-build (worthless-1m8i).

``_apply_openclaw_unlock`` (the consumer) zeros every ``OcRestore.plaintext_key``
in its ``finally``. But if ``_build_oc_restores`` itself raises AFTER building some
restores, the caller never receives the list — so those partial keys would linger
in the heap until GC. This pins the producer-side zeroing on the failure path.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

import worthless.cli.commands.unlock as unlock_mod
from worthless.cli.commands.unlock import _build_oc_restores, _PlannedRestore


def _planned(alias: str) -> _PlannedRestore:
    # oc_original_api_key_json=None -> the record-None branch, which just
    # re-reads the plaintext key and appends. That path touches neither repo
    # nor console, so MagicMock stand-ins are never called.
    return _PlannedRestore(
        alias=alias,
        provider="openai",
        enrollment=None,
        var_name="OPENAI_API_KEY",
        env_path=None,
        key_buf=bytearray(),
        oc_original_api_key_json=None,
    )


def test_build_oc_restores_zeros_partial_keys_when_it_raises_mid_build(monkeypatch) -> None:
    handed_out: list[bytearray] = []

    def spy_reread(p: _PlannedRestore) -> bytearray:
        if not handed_out:
            key = bytearray(b"sk-real-plaintext-secret-key-abcdef")
            handed_out.append(key)
            return key  # 1st alias: hand out a real reconstructed key
        raise RuntimeError("boom mid-build")  # 2nd alias: blow up AFTER key 1 is built

    monkeypatch.setattr(unlock_mod, "_reread_plaintext_from_env", spy_reread)

    with pytest.raises(RuntimeError, match="boom mid-build"):
        asyncio.run(
            _build_oc_restores(
                [_planned("openai-a"), _planned("openai-b")], MagicMock(), MagicMock()
            )
        )

    assert handed_out, "spy never handed out a key — test wiring broke"
    assert handed_out[0] == bytearray(len(handed_out[0])), (
        "SR-02: the plaintext key reconstructed before the raise was NOT zeroed"
    )


def test_build_oc_restores_zeros_an_in_flight_key_if_the_append_raises(monkeypatch) -> None:
    """CodeRabbit edge: a key re-read but NOT yet appended to `restores` (e.g. the
    OcRestore construction raises, or a KeyboardInterrupt fires between the re-read
    and the append) must still be zeroed — the accumulated-list guard alone misses it.
    """
    handed_out: list[bytearray] = []

    def spy_reread(p: _PlannedRestore) -> bytearray:
        key = bytearray(b"sk-in-flight-not-yet-appended-key")
        handed_out.append(key)
        return key

    monkeypatch.setattr(unlock_mod, "_reread_plaintext_from_env", spy_reread)

    def boom_ocrestore(*a, **k):
        raise RuntimeError("append boom")  # blow up AFTER the key was re-read, before it lands

    monkeypatch.setattr(unlock_mod._openclaw_integration, "OcRestore", boom_ocrestore)

    with pytest.raises(RuntimeError, match="append boom"):
        asyncio.run(_build_oc_restores([_planned("openai-a")], MagicMock(), MagicMock()))

    assert handed_out, "spy never handed out a key — test wiring broke"
    assert handed_out[0] == bytearray(len(handed_out[0])), (
        "SR-02: the in-flight key (re-read but not yet appended) was NOT zeroed"
    )
