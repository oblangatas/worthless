"""WOR-753: every failing doctor check carries a fix, and --explain prints it."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import ensure_home
from worthless.cli.commands.doctor.checks._remediation import PLAYBOOKS
from worthless.cli.commands.doctor.registry import ensure_registered
from worthless.storage.repository import ShardRepository, StoredShard

runner = CliRunner(mix_stderr=False)


@pytest.fixture
def fake_home(tmp_path: Path):
    return ensure_home(tmp_path / ".worthless")


def test_every_check_has_a_playbook() -> None:
    """Coverage: each registered check_id maps to a non-empty playbook."""
    ids = {c.check_id for c in ensure_registered()}
    missing = ids - set(PLAYBOOKS)
    assert not missing, f"checks without a remediation playbook: {missing}"
    assert all(PLAYBOOKS[i].strip() for i in ids)


def test_failing_check_finding_carries_remediation(fake_home, monkeypatch) -> None:
    """A real failure shows up in --json with a non-empty remediation on every finding."""
    # Seed an enrollment whose shard_a file is missing -> broken_status fails.
    repo = ShardRepository(str(fake_home.db_path), bytes(fake_home.fernet_key))
    shard = StoredShard(
        shard_b=bytearray(b"\x00" * 32),
        commitment=bytearray(b"\x00" * 32),
        nonce=bytearray(b"\x00" * 12),
        provider="openai",
    )
    asyncio.run(repo.initialize())
    asyncio.run(
        repo.store_enrolled("my-key", shard, var_name="OPENAI_API_KEY", env_path="/fake/.env")
    )

    from worthless.cli.commands.doctor import runner as runner_module

    monkeypatch.setattr(runner_module, "get_home", lambda: fake_home)

    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)

    failing = [c for c in payload["checks"] if c["status"] in ("warn", "error")]
    assert failing, "expected at least one failing check from the seeded broken enrollment"
    for check in failing:
        for finding in check["findings"]:
            assert finding.get("remediation"), f"{check['check_id']} finding has no remediation"


def test_explain_prints_playbook() -> None:
    result = runner.invoke(app, ["doctor", "--explain", "fernet_drift"])
    assert result.exit_code == 0
    assert "will not auto-pick" in result.stdout


def test_explain_unknown_lists_known_ids() -> None:
    result = runner.invoke(app, ["doctor", "--explain", "nope"])
    assert result.exit_code != 0
    assert "fernet_drift" in (result.stdout + result.stderr)


def test_explain_list_shows_catalog() -> None:
    result = runner.invoke(app, ["doctor", "--explain", "list"])
    assert result.exit_code == 0
    # the catalog names every check, on stdout (not an error)
    assert "fernet_drift" in result.stdout
    assert "orphan_db" in result.stdout


def test_each_playbook_leads_with_its_correct_verdict() -> None:
    """WOR-778: the verdict must be RIGHT, not just present — a 'gone' check must
    never reassure with 'safe'. Catches a wrong verdict, not merely a missing one."""
    # check_id -> verdict keywords, at least one of which must appear in the lead.
    expected = {
        "orphan_db": ("gone",),
        "broken_status": ("gone",),
        "fernet_drift": ("at risk",),
        "openclaw": ("exposed",),
        "icloud_keychain": ("isn't lost",),
        "orphan_keychain": ("safe",),
        "recovery_import": ("no secret",),
        "stranded_shards": ("nothing at risk",),
        "bind_confirmation": ("locked",),
    }
    assert set(expected) == set(PLAYBOOKS), "verdict map and PLAYBOOKS drifted — add the new check"
    for cid, oks in expected.items():
        lead = PLAYBOOKS[cid].lower()[:60]
        assert any(o in lead for o in oks), f"{cid} lead missing {oks}: {PLAYBOOKS[cid][:60]!r}"
    # A check whose key is GONE must never lead with the word 'safe'.
    for cid in ("orphan_db", "broken_status"):
        assert "safe" not in PLAYBOOKS[cid].lower()[:40], f"{cid} wrongly reassures with 'safe'"
