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
