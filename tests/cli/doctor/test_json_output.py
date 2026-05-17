"""WOR-464: ``worthless doctor --json`` output contract.

Pin the JSON envelope shape so machine consumers can rely on it:

  {"schema_version": "1",
   "ok": <bool>,
   "checks": [<CheckResult>, ...],
   "summary": {"total": N, "warn": N, "error": N, "fixed": N}}

Also assert no stray prints leak into stdout — JSON consumers need a
single parseable document.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import ensure_home
from worthless.cli.commands import doctor as doctor_module


runner = CliRunner(mix_stderr=False)


@pytest.fixture
def fake_home(tmp_path: Path):
    return ensure_home(tmp_path / ".worthless")


def test_json_emits_single_parseable_document(fake_home, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stdout must be exactly one JSON document. No log lines, no banners."""

    async def _no_orphans(_repo):
        return []

    monkeypatch.setattr(doctor_module, "_list_orphans", _no_orphans)
    monkeypatch.setattr(doctor_module, "_list_synced_keychain_entries", lambda: [])
    monkeypatch.setattr(doctor_module, "get_home", lambda: fake_home)
    # Also intercept the runner's get_home (different module-level import).
    from worthless.cli.commands.doctor import runner as runner_module

    monkeypatch.setattr(runner_module, "get_home", lambda: fake_home)

    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0, f"non-zero exit: {result.output} stderr={result.stderr}"

    # stdout must parse as JSON in one shot.
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "1"
    assert isinstance(payload["ok"], bool)
    assert isinstance(payload["checks"], list)
    assert "summary" in payload
    summary = payload["summary"]
    assert {"total", "warn", "error", "fixed"} <= set(summary.keys())


def test_json_includes_all_check_ids(fake_home, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every registered check appears in the JSON output, even ``ok`` ones."""

    async def _no_orphans(_repo):
        return []

    monkeypatch.setattr(doctor_module, "_list_orphans", _no_orphans)
    monkeypatch.setattr(doctor_module, "_list_synced_keychain_entries", lambda: [])
    from worthless.cli.commands.doctor import runner as runner_module

    monkeypatch.setattr(runner_module, "get_home", lambda: fake_home)

    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0

    payload = json.loads(result.stdout)
    ids = {c["check_id"] for c in payload["checks"]}
    expected = {
        "recovery_import",
        "orphan_db",
        "openclaw",
        "icloud_keychain",
        "orphan_keychain",
        "stranded_shards",
        "fernet_drift",
        "broken_status",
    }
    assert expected <= ids


def test_json_ok_true_on_clean_install(fake_home, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fresh home with no orphans, no synced keys → top-level ``ok=true``."""

    async def _no_orphans(_repo):
        return []

    monkeypatch.setattr(doctor_module, "_list_orphans", _no_orphans)
    monkeypatch.setattr(doctor_module, "_list_synced_keychain_entries", lambda: [])
    from worthless.cli.commands.doctor import runner as runner_module

    monkeypatch.setattr(runner_module, "get_home", lambda: fake_home)

    result = runner.invoke(app, ["doctor", "--json"])
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["summary"]["warn"] == 0
    assert payload["summary"]["error"] == 0
