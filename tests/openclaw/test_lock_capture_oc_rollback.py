"""WOR-621 F2 G3 — CLI lock captures the original OpenClaw provider entry.

After G3, every ``worthless lock`` invocation against a host with OpenClaw
present writes the per-provider rollback record (full original entry, key
value redacted to its shape) PLUS a fernet-keyed MAC over that record
into the ``shards`` row, BEFORE openclaw.json is rewritten.

This is the missing half of F2 (unlock): G1 wired ``_apply_unlock_stage_a``
to read the stored record and put the original entry back verbatim; G2
bound the record with the storage MAC to detect a DB-write attacker
flipping ``secretref`` → ``plaintext`` between lock and unlock. G3 wires
the lock-time CAPTURE so those records actually populate.

Threat model (SM-2): the DB write MUST precede the openclaw.json mutation,
so a crash between ``_pass1_db_writes`` and ``_apply_openclaw`` still
leaves a row the user can roll back from. The rollback record therefore
rides into the DB on the existing ``upsert_locked_shard`` write, in the
same transaction as shard-B.

Re-lock semantics (Pass-1 decision 2 on WOR-649):

* Original entry is NOT proxy-shaped → capture as the genuine original.
* Original entry IS proxy-shaped AND a prior record exists in the DB
  → REUSE the prior record verbatim (re-lock is a no-op for the
  rollback row; shard-A is not "the original").
* Original entry IS proxy-shaped AND no prior record → skip + warn
  ``relock_no_prior`` (NEVER capture shard-A as the original; legacy
  rows from before G3 fall here and stay unmodified).

These four tests pin those contracts at the CLI surface so the wiring
through ``_pass1_db_writes`` cannot regress without breaking them.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.openclaw.integration import (
    _parse_oc_rollback_entry_record,
    build_oc_rollback_entry_record,
    classify_oc_entry_for_capture,
)
from worthless.storage.repository import ShardRepository

from tests.helpers import fake_openai_key

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fixed_key() -> str:
    """A high-entropy fake OpenAI key reused across .env and openclaw.json.

    Reusing one value keeps the alias deterministic between fixtures.
    """
    return fake_openai_key()


@pytest.fixture
def env_file(tmp_path: Path, fixed_key: str) -> Path:
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fixed_key}\n")
    return env


@pytest.fixture
def sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pin HOME so apply_lock's detect() probes the sandbox."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(home)
    return home


def _seed_openclaw(
    sandboxed_home: Path,
    openai_entry: dict,
) -> dict[str, Path]:
    """Pre-stage ~/.openclaw/ with a workspace + an ``openai`` provider entry."""
    openclaw_dir = sandboxed_home / ".openclaw"
    workspace = openclaw_dir / "workspace"
    workspace.mkdir(parents=True)
    config_path = openclaw_dir / "openclaw.json"
    config_path.write_text(
        json.dumps(
            {"models": {"providers": {"openai": openai_entry}}},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return {"home": sandboxed_home, "workspace": workspace, "config_path": config_path}


def _alias_for_key(provider: str, value: str) -> str:
    """Mirror lock._make_alias so tests can find the DB row without scraping CLI output."""
    digest = hashlib.sha256(bytearray(value.encode())).hexdigest()[:8]
    return f"{provider}-{digest}"


async def _fetch(home: WorthlessHome, alias: str):
    repo = ShardRepository(str(home.db_path), home.fernet_key)
    return await repo.fetch_encrypted(alias)


# ---------------------------------------------------------------------------
# Plaintext original
# ---------------------------------------------------------------------------


def test_g3_captures_plaintext_original_entry_with_mac(
    home_dir: WorthlessHome,
    env_file: Path,
    sandboxed_home: Path,
    fixed_key: str,
) -> None:
    """Fresh lock against a plaintext ``openai`` entry populates the
    rollback columns on the shards row + a MAC that matches a recompute.

    Lock has not yet touched openclaw.json at the moment ``_pass1_db_writes``
    runs (SM-2: DB → .env → openclaw.json). G3 reads openclaw.json BEFORE
    the DB write so the captured record reflects the pre-lock entry, and
    threads ``oc_original_api_key_json`` / ``oc_rollback_mac`` into
    ``upsert_locked_shard``. (G5-C: ``oc_original_base_url`` was dropped —
    the original URL lives inside the MAC-bound JSON record.) Without G3
    these columns are NULL and unlock has nothing to restore.
    """
    original_entry = {
        "baseUrl": "https://api.openai.com/v1",
        "apiKey": fixed_key,
    }
    seeded = _seed_openclaw(sandboxed_home, original_entry)

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert result.exit_code == 0, result.output

    # Sanity: openclaw.json IS now proxy-shaped (post-F1 rewrite). The DB
    # row is what carries the original forward.
    data = json.loads(seeded["config_path"].read_text(encoding="utf-8"))
    assert data["models"]["providers"]["openai"]["baseUrl"].startswith("http://127.0.0.1:")

    alias = _alias_for_key("openai", fixed_key)
    enc = asyncio.run(_fetch(home_dir, alias))
    assert enc is not None, f"shards row missing for {alias!r}"

    # G5-C: the original URL is inside the MAC-bound JSON record (NOT a
    # separate column). The stored record is the FULL entry with apiKey
    # redacted to its shape. An idiomatic recompute over the same original
    # entry should round-trip byte-identical (build_oc_rollback_entry_record
    # is sort_keys=True).
    expected_record = build_oc_rollback_entry_record(original_entry)
    assert enc.oc_original_api_key_json == expected_record

    # Shape-level sanity: parse OK, plaintext kind, URL still in the record.
    parsed = _parse_oc_rollback_entry_record(enc.oc_original_api_key_json)
    assert parsed["apiKey"] == {"kind": "plaintext"}
    assert parsed["baseUrl"] == "https://api.openai.com/v1"

    # MAC tag is non-empty and matches a fresh recompute over the stored JSON
    # (G2 contract: caller verifies via _compute_decoy_hash). A NULL/legacy
    # tag here means lock didn't compute one — the unlock-side tamper check
    # has nothing to verify against and silently downgrades to G1 behavior.
    repo = ShardRepository(str(home_dir.db_path), home_dir.fernet_key)
    recomputed = asyncio.run(repo._compute_decoy_hash(enc.oc_original_api_key_json))
    assert enc.oc_rollback_mac, "G3 must populate oc_rollback_mac (got empty/None)"
    assert enc.oc_rollback_mac == recomputed


# ---------------------------------------------------------------------------
# SecretRef original
# ---------------------------------------------------------------------------


def test_g3_captures_secretref_original_entry(
    home_dir: WorthlessHome,
    env_file: Path,
    sandboxed_home: Path,
    fixed_key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the original entry's ``apiKey`` is a SecretRef pointer (object,
    not a string), G3 must capture the pointer verbatim in the rollback
    record so unlock restores it as a SecretRef — never downgraded to a
    written-back plaintext key.

    This is the canonical AC7-half-2 invariant: the DB never holds the
    user's real credential at rest, even when the original entry was
    pointing OpenClaw at one via SecretRef.
    """
    # SecretRef points at the env var carrying the same key value so lock-core
    # still sees a real key to split (the SDK at runtime would resolve the ref).
    # We need OPENAI_API_KEY in the environment for the SecretRef pointer to
    # mean what it claims — but the .env path already carries the value;
    # exporting it via monkeypatch keeps the lock-core happy on hosts where
    # the test runner strips it.
    monkeypatch.setenv("OPENAI_API_KEY", fixed_key)

    secretref = {"$ref": {"source": "env", "provider": "openai", "id": "OPENAI_API_KEY"}}
    original_entry = {
        "baseUrl": "https://api.openai.com/v1",
        "apiKey": secretref,
    }
    seeded = _seed_openclaw(sandboxed_home, original_entry)

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert result.exit_code == 0, result.output
    assert seeded["config_path"].exists()  # config_path used; silence linters

    alias = _alias_for_key("openai", fixed_key)
    enc = asyncio.run(_fetch(home_dir, alias))
    assert enc is not None

    # G5-C: URL lives inside the MAC-bound JSON record.
    parsed = _parse_oc_rollback_entry_record(enc.oc_original_api_key_json)
    assert parsed["baseUrl"] == "https://api.openai.com/v1"
    assert parsed["apiKey"]["kind"] == "secretref"
    assert parsed["apiKey"]["ref"] == secretref, (
        "SecretRef pointer must round-trip verbatim — unlock will write it back as-is"
    )

    repo = ShardRepository(str(home_dir.db_path), home_dir.fernet_key)
    recomputed = asyncio.run(repo._compute_decoy_hash(enc.oc_original_api_key_json))
    assert enc.oc_rollback_mac == recomputed


# ---------------------------------------------------------------------------
# Re-lock idempotency: a proxy-shaped entry WITH a prior record reuses it
# ---------------------------------------------------------------------------


def test_g3_relock_reuses_prior_record_when_entry_is_proxy_shaped(
    home_dir: WorthlessHome,
    env_file: Path,
    sandboxed_home: Path,
    fixed_key: str,
) -> None:
    """Re-locking after a previous lock must NOT capture the post-F1
    proxy-shaped entry as if IT were the user's original. The first lock
    populated the rollback record; the second lock must reuse it verbatim.

    Without this, re-lock overwrites ``oc_original_api_key_json`` with a
    record describing the proxy entry (apiKey=shard-A) — and unlock would
    then "restore" the user to … the proxy, with shard-A as their key,
    plus mark it as the genuine baseline.
    """
    original_entry = {
        "baseUrl": "https://api.openai.com/v1",
        "apiKey": fixed_key,
    }
    _seed_openclaw(sandboxed_home, original_entry)

    # First lock: captures the genuine original.
    first = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert first.exit_code == 0, first.output

    alias = _alias_for_key("openai", fixed_key)
    enc1 = asyncio.run(_fetch(home_dir, alias))
    assert enc1 is not None
    record_before = enc1.oc_original_api_key_json
    mac_before = enc1.oc_rollback_mac
    assert record_before, "first lock must seed the rollback record (G3 happy path)"

    # Second lock against the now-proxy-shaped entry. The .env still holds
    # the same key value so the alias resolves to the same row.
    second = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert second.exit_code == 0, second.output

    enc2 = asyncio.run(_fetch(home_dir, alias))
    assert enc2 is not None
    # G5-C: URL is inside the JSON record — preserving the record verbatim
    # also preserves the URL. No separate base_url assertion needed.
    assert enc2.oc_original_api_key_json == record_before, (
        "re-lock must NOT overwrite the original entry record with the proxy-shaped one"
    )
    assert enc2.oc_rollback_mac == mac_before


# ---------------------------------------------------------------------------
# Re-lock against proxy-shaped entry with NO prior record → skip + warn
# ---------------------------------------------------------------------------


def test_g3_relock_proxy_shaped_without_prior_record_does_not_capture_shard_a(
    home_dir: WorthlessHome,
    env_file: Path,
    sandboxed_home: Path,
    fixed_key: str,
) -> None:
    """Legacy rows (pre-G3) and unsynchronised re-locks may see an entry
    that is already proxy-shaped while the DB carries no prior rollback
    record. G3 must NOT capture the proxy entry (apiKey=shard-A) as if
    it were the user's original — that would synthesise a fake "original"
    pointing back at the proxy, and unlock would happily write shard-A
    into ``apiKey`` declaring success.

    Correct behaviour: leave the rollback columns NULL, warn the operator
    (``relock_no_prior`` — surfaced in the CLI output so the user can
    decide whether to manually re-seed or run unlock first), and proceed
    with the rest of lock as normal (shard-B refresh still happens; only
    the rollback row stays unmodified).
    """
    # Pre-seed openclaw.json with a proxy-shaped entry (mimics the post-F1
    # state on a host whose DB row predates G3). apiKey holds something that
    # looks like a shard-A string; it must NOT end up in the rollback record.
    proxy_shaped_entry = {
        "baseUrl": "http://127.0.0.1:8787/openai-stale001/v1",
        "apiKey": "sk-shard-a-from-an-older-lock-must-not-be-captured",
    }
    seeded = _seed_openclaw(sandboxed_home, proxy_shaped_entry)

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    # Lock-core itself still succeeds — only the rollback capture is skipped.
    assert result.exit_code == 0, result.output

    alias = _alias_for_key("openai", fixed_key)
    enc = asyncio.run(_fetch(home_dir, alias))
    assert enc is not None

    # The rollback columns stay NULL — nothing safe to capture.
    # (G5-C: oc_original_base_url column is gone; the JSON record is the
    # only place a URL could be captured, and it must be None here.)
    assert enc.oc_original_api_key_json is None, (
        "must not capture proxy-shaped entry record as 'original' "
        f"(got {enc.oc_original_api_key_json!r})"
    )
    assert enc.oc_rollback_mac is None
    # The stale shard-A from the proxy-shaped entry must NEVER land in the
    # rollback JSON, even as a "shape". This catches a wiring bug where
    # G3 captures the entry as plaintext while ignoring its proxy shape.
    if enc.oc_original_api_key_json:
        assert "sk-shard-a-from-an-older-lock" not in enc.oc_original_api_key_json

    # Operator must be warned (so they know unlock won't restore this entry).
    assert "relock_no_prior" in result.output, (
        f"missing 'relock_no_prior' warning in CLI output:\n{result.output}"
    )

    # openclaw.json is still rewritten to the current alias (lock-core
    # proceeds; only the rollback capture is suppressed).
    data = json.loads(seeded["config_path"].read_text(encoding="utf-8"))
    new_url = data["models"]["providers"]["openai"]["baseUrl"]
    assert new_url.endswith(f"/{alias}/v1"), new_url


# ---------------------------------------------------------------------------
# Re-lock when the live entry is GONE but a prior rollback record exists
# (Cursor thermo-nuclear finding — re-lock data-loss bug)
#
# Tested at the CLASSIFIER altitude — the bug is in the pure-function
# decision (``current_entry=None`` propagating ``(None, None)`` into the
# upsert). The CLI surface has a re-lock preflight (ENV_ALREADY_LOCKED)
# that masks the user-visible path on a shard-A-bearing .env, but the
# classifier-level invariant ("a NULL live entry must never erase a prior
# DB record") protects every caller (CLI today, programmatic API tomorrow,
# the broad-except branch in _read_openclaw_providers_for_capture).
# ---------------------------------------------------------------------------


def test_classifier_no_entry_with_prior_record_reuses_prior() -> None:
    """Pure unit: ``current_entry=None`` + a non-None prior record → ``reuse_prior``.

    Mirrors the proxy-shaped reuse-prior branch. Without this rule the
    classifier returned ``("no_entry", None, None)`` and the caller nulled
    the DB column (see e2e test above).
    """
    prior = build_oc_rollback_entry_record(
        {"baseUrl": "https://api.openai.com/v1", "apiKey": fake_openai_key()}
    )

    kind, base_url_slot, record_slot = classify_oc_entry_for_capture(
        current_entry=None,
        prior_entry_record_json=prior,
        proxy_base_url="http://127.0.0.1:8787",
    )

    assert kind == "reuse_prior"
    assert base_url_slot is None
    assert record_slot == prior


def test_classifier_no_entry_without_prior_returns_no_entry() -> None:
    """Pure unit: ``current_entry=None`` + no prior → ``no_entry`` (unchanged).

    Pins the original behaviour for the fresh-install path so the reuse-prior
    fix doesn't accidentally flip new locks to a reuse semantics.
    """
    kind, base_url_slot, record_slot = classify_oc_entry_for_capture(
        current_entry=None,
        prior_entry_record_json=None,
        proxy_base_url="http://127.0.0.1:8787",
    )

    assert kind == "no_entry"
    assert base_url_slot is None
    assert record_slot is None
