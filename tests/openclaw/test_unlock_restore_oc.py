"""WOR-621 F2 G4 — CLI unlock builds real ``OcRestore`` records.

G1 wired the integration layer (``_apply_unlock_stage_a`` restores the
original entry verbatim from a parsed rollback record). G2 bound the
record with the fernet-keyed storage MAC so a DB-write attacker can't
flip ``secretref`` → ``plaintext``. G3 wired the lock-side capture so
the columns actually populate.

G4 closes the loop on the unlock side: the CLI must

1. Read the captured rollback record + MAC from the ``shards`` row
   BEFORE pass-3 cleanup deletes it.
2. Constant-time-verify the MAC via the same
   :meth:`ShardRepository._compute_decoy_hash` G2 uses; mismatch →
   fail-safe skip (leave the provider on the proxy, NEVER write back
   anything synthesised from a tampered record).
3. Build :class:`OcRestore` records carrying the captured base_url +
   record JSON, plus — for the plaintext branch — a freshly-read
   plaintext key (read back from the just-restored ``.env``, which
   pass-2 wrote moments earlier; the in-memory ``key_buf`` was zeroed
   by ``_unlock_batch``'s ``finally``).
4. Pass them to ``apply_unlock(restores=…)`` so Stage A writes each
   original entry back verbatim — SecretRef pointer as a pointer
   (NEVER downgraded to a written-back plaintext key), plaintext as
   the original UTF-8 string.
5. Surface a truthful success line — "restored" not "removed" — and
   the matching failure copy.

The four CLI-level tests below pin those contracts end-to-end at the
Typer surface. Together with the four G3 tests in
``test_lock_capture_oc_rollback.py`` they prove the lock→unlock round
trip is byte-identical on the OpenClaw config side.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import aiosqlite
import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

from tests.helpers import fake_openai_key

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures (shape borrowed from test_lock_capture_oc_rollback.py — the lock
# half of this round-trip pins the same OpenClaw layout)
# ---------------------------------------------------------------------------


@pytest.fixture
def fixed_key() -> str:
    return fake_openai_key()


@pytest.fixture
def env_file(tmp_path: Path, fixed_key: str) -> Path:
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fixed_key}\n")
    return env


@pytest.fixture
def sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(home)
    return home


def _seed_openclaw(sandboxed_home: Path, openai_entry: dict) -> dict[str, Path]:
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


def _lock(home_dir: WorthlessHome, env_file: Path):
    return runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )


def _unlock(home_dir: WorthlessHome, env_file: Path):
    return runner.invoke(
        app,
        ["unlock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )


# ---------------------------------------------------------------------------
# AC7 ROUND-TRIP — plaintext apiKey restored byte-identical
# ---------------------------------------------------------------------------


def test_g4_round_trip_restores_plaintext_apikey_byte_identical(
    home_dir: WorthlessHome,
    env_file: Path,
    sandboxed_home: Path,
    fixed_key: str,
) -> None:
    """A user with a plaintext ``apiKey`` runs ``lock`` then ``unlock``:
    the original ``openai`` entry's ``baseUrl`` AND ``apiKey`` end up
    byte-identical to the pre-lock state.

    AC7: unlock restores the original verbatim, offline. Without G4 the
    entry stays pointed at the proxy with shard-A in the key slot (Stage
    A fail-safe-skips on the missing reconstructed key).
    """
    original_entry = {
        "baseUrl": "https://api.openai.com/v1",
        "apiKey": fixed_key,
    }
    seeded = _seed_openclaw(sandboxed_home, original_entry)

    locked = _lock(home_dir, env_file)
    assert locked.exit_code == 0, locked.output

    # Sanity: lock did rewrite to the proxy.
    after_lock = json.loads(seeded["config_path"].read_text(encoding="utf-8"))
    assert after_lock["models"]["providers"]["openai"]["baseUrl"].startswith(
        "http://127.0.0.1:"
    )
    assert after_lock["models"]["providers"]["openai"]["apiKey"] != fixed_key

    unlocked = _unlock(home_dir, env_file)
    assert unlocked.exit_code == 0, unlocked.output

    after_unlock = json.loads(seeded["config_path"].read_text(encoding="utf-8"))
    restored = after_unlock["models"]["providers"]["openai"]
    assert restored["baseUrl"] == "https://api.openai.com/v1", (
        f"baseUrl not restored: {restored['baseUrl']!r}"
    )
    assert restored["apiKey"] == fixed_key, (
        "apiKey must round-trip byte-identical — got a different value "
        "(shard-A was written back? key reconstruction missed?)"
    )


# ---------------------------------------------------------------------------
# AC7 invariant 2 — SecretRef pointer restored verbatim, never downgraded
# ---------------------------------------------------------------------------


def test_g4_round_trip_restores_secretref_pointer_never_writes_plaintext(
    home_dir: WorthlessHome,
    env_file: Path,
    sandboxed_home: Path,
    fixed_key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A user with a SecretRef-based ``apiKey`` runs ``lock`` then
    ``unlock``: the original SecretRef pointer is restored verbatim.

    Critical invariant: a SecretRef original is NEVER downgraded to a
    written-back plaintext key. The reconstructed key never enters
    ``openclaw.json`` for a secretref restore, even though pass-1
    reconstructs it for the .env restore.
    """
    monkeypatch.setenv("OPENAI_API_KEY", fixed_key)

    secretref = {"$ref": {"source": "env", "provider": "openai", "id": "OPENAI_API_KEY"}}
    original_entry = {
        "baseUrl": "https://api.openai.com/v1",
        "apiKey": secretref,
    }
    seeded = _seed_openclaw(sandboxed_home, original_entry)

    locked = _lock(home_dir, env_file)
    assert locked.exit_code == 0, locked.output

    unlocked = _unlock(home_dir, env_file)
    assert unlocked.exit_code == 0, unlocked.output

    after_unlock = json.loads(seeded["config_path"].read_text(encoding="utf-8"))
    restored = after_unlock["models"]["providers"]["openai"]

    assert restored["baseUrl"] == "https://api.openai.com/v1"
    assert restored["apiKey"] == secretref, (
        f"SecretRef pointer must round-trip verbatim, got {restored['apiKey']!r}"
    )
    # Defence in depth: the restored apiKey must NOT contain the real key.
    rendered = json.dumps(restored["apiKey"], sort_keys=True)
    assert fixed_key not in rendered, (
        "real key bytes must NEVER appear in a SecretRef restore — that "
        "would mean the reconstructed plaintext leaked into the config"
    )


# ---------------------------------------------------------------------------
# G2 enforcement — DB tamper of the rollback record fails the MAC gate
# ---------------------------------------------------------------------------


def test_g4_db_tamper_of_rollback_record_fails_safe_at_unlock(
    home_dir: WorthlessHome,
    env_file: Path,
    sandboxed_home: Path,
    fixed_key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The canonical decision-4 attack at unlock: a DB-write attacker
    (no fernet key) flips ``oc_original_api_key_json`` from
    ``{"kind": "secretref", "ref": …}`` to ``{"kind": "plaintext"}``
    between lock and unlock. Stage A's plaintext branch would then
    write the reconstructed real key into a slot the attacker can
    read — a privilege escalation via unlock. G2 stored a MAC that
    binds ``kind``; G4 must constant-time-verify it against a fresh
    recompute and refuse the restore on mismatch.

    Fail-safe outcome: the provider stays on the proxy (its stage-A
    ``replace_provider`` is skipped) and the user is told why.
    Crucially the reconstructed real key NEVER lands in
    ``openclaw.json`` even though pass-1 reconstructs it.
    """
    monkeypatch.setenv("OPENAI_API_KEY", fixed_key)

    # Seed with a SecretRef original — the attack target. The user's
    # real key lives only in env, never in openclaw.json.
    secretref = {"$ref": {"source": "env", "provider": "openai", "id": "OPENAI_API_KEY"}}
    original_entry = {
        "baseUrl": "https://api.openai.com/v1",
        "apiKey": secretref,
    }
    seeded = _seed_openclaw(sandboxed_home, original_entry)

    locked = _lock(home_dir, env_file)
    assert locked.exit_code == 0, locked.output

    after_lock = json.loads(seeded["config_path"].read_text(encoding="utf-8"))
    proxy_url_after_lock = after_lock["models"]["providers"]["openai"]["baseUrl"]
    shard_a_after_lock = after_lock["models"]["providers"]["openai"]["apiKey"]
    assert proxy_url_after_lock.startswith("http://127.0.0.1:")

    # Decision-4 attack: flip secretref → plaintext. Stored MAC was
    # computed over the secretref-shaped record; the recompute over
    # this plaintext-shaped record will differ → G4 must reject.
    attacker_record = json.dumps(
        {
            "baseUrl": "https://api.openai.com/v1",
            "apiKey": {"kind": "plaintext"},
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    async def _tamper() -> None:
        async with aiosqlite.connect(str(home_dir.db_path)) as db:
            await db.execute(
                "UPDATE shards SET oc_original_api_key_json = ? "
                "WHERE oc_original_api_key_json IS NOT NULL",
                (attacker_record,),
            )
            await db.commit()
    asyncio.run(_tamper())

    unlocked = _unlock(home_dir, env_file)
    # Detected+failed → exit 73 (lock-core preserved per L1, OpenClaw failure
    # surfaced loudly). NB: even though unlock-core succeeds (.env restored),
    # the failed OpenClaw cleanup MUST be reflected in the exit code.
    assert unlocked.exit_code == 73, unlocked.output

    after_unlock = json.loads(seeded["config_path"].read_text(encoding="utf-8"))
    restored = after_unlock["models"]["providers"]["openai"]
    # Fail-safe: entry untouched, still on the proxy with shard-A.
    assert restored["baseUrl"] == proxy_url_after_lock, (
        "tampered MAC must abort the restore — baseUrl moved off the proxy"
    )
    assert restored["apiKey"] == shard_a_after_lock, (
        "tampered MAC must abort the restore — apiKey changed"
    )
    # Defence in depth: the reconstructed real key must NEVER land in
    # openclaw.json on the tampered branch (the whole point of the attack).
    rendered = json.dumps(restored, sort_keys=True)
    assert fixed_key not in rendered, (
        "tampered restore wrote the reconstructed real key into openclaw.json "
        "(decision-4 escalation — the MAC gate did not fire)"
    )
    # Operator told why.
    assert "rollback_mac_mismatch" in unlocked.output or "rollback mac" in unlocked.output, (
        f"missing tamper warning in unlock output:\n{unlocked.output}"
    )


# ---------------------------------------------------------------------------
# CLI copy fix — success line says "restored" + failure copy is accurate
# ---------------------------------------------------------------------------


def test_g4_cli_success_copy_says_restored_not_removed(
    home_dir: WorthlessHome,
    env_file: Path,
    sandboxed_home: Path,
    fixed_key: str,
) -> None:
    """On a successful round-trip the CLI must say ``restored`` for each
    provider — never ``removed``. The decoy-era wording (``removed N
    provider(s)`` and ``worthless-* entries may remain``) was deferred
    from G1's review because the right copy depends on whether stage-A
    actually restores anything; G4 ships the real restore so the copy
    goes with it.
    """
    original_entry = {
        "baseUrl": "https://api.openai.com/v1",
        "apiKey": fixed_key,
    }
    _seed_openclaw(sandboxed_home, original_entry)

    locked = _lock(home_dir, env_file)
    assert locked.exit_code == 0, locked.output

    unlocked = _unlock(home_dir, env_file)
    assert unlocked.exit_code == 0, unlocked.output

    # Truthful success: provider was RESTORED, not removed. We assert on
    # "restored" as the verb anywhere in the OpenClaw-success block;
    # exact prose can evolve, the contract is the verb.
    assert "restored" in unlocked.output.lower(), (
        f"expected 'restored' in CLI output, got:\n{unlocked.output}"
    )
    # The decoy-era line must be gone.
    assert "removed 1 provider" not in unlocked.output, (
        "stale decoy-era copy still present: 'removed N provider(s)'"
    )
    # The decoy-era failure copy must also not be emitted on success.
    assert "worthless-* entries" not in unlocked.output, (
        "stale 'worthless-* entries may remain' copy leaked into success path"
    )
