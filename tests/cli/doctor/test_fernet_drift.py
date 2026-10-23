"""WOR-464: Fernet key drift check.

CRITICAL guardrail: this check MUST NEVER auto-repair. ``fixable``
is hardcoded False — losing the canonical key would render existing
locked secrets unrecoverable.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from typer.testing import CliRunner

from worthless.cli import key_check
from worthless.cli.app import app
from worthless.cli.bootstrap import ensure_home
from worthless.cli.commands.doctor.checks import fernet_drift
from worthless.cli.commands.doctor.registry import CheckContext
from worthless.storage.repository import ShardRepository

from tests.helpers import seal_enrolled


@pytest.fixture
def fake_home(tmp_path: Path):
    return ensure_home(tmp_path / ".worthless")


@pytest.fixture
def ctx(fake_home):
    repo = ShardRepository(str(fake_home.db_path), bytes(fake_home.fernet_key))
    return CheckContext(home=fake_home, repo=repo, fix=False, dry_run=False)


def test_fixable_always_false(ctx) -> None:
    """fernet_drift.fixable is hardcoded False regardless of state."""
    result = fernet_drift.run(ctx)
    assert result["fixable"] is False


def test_fixable_false_even_with_fix_flag(ctx, fake_home) -> None:
    """Even when ``fix=True``, the check reports fixable=False and fixed=[]."""
    # Plant a divergent file vs keyring scenario.
    fake_home.fernet_key_path.write_bytes(b"FILE_VALUE_DIFFERS" + b"=" * 26)

    with (
        patch.object(fernet_drift, "keyring_available", return_value=True),
        patch("worthless.cli.commands.doctor.checks.fernet_drift._keyring") as kr,
    ):
        kr.get_password.return_value = "KEYRING_VALUE_DIFFERS" + "=" * 23
        ctx.fix = True
        result = fernet_drift.run(ctx)

    assert result["fixable"] is False
    assert result["fixed"] == []


def test_no_drift_when_only_keyring_present(ctx, fake_home) -> None:
    """Only keyring entry, no file: no drift, status ok."""
    # Fake home from ensure_home may have written a file; remove it.
    if fake_home.fernet_key_path.exists():
        fake_home.fernet_key_path.unlink()

    with (
        patch.object(fernet_drift, "keyring_available", return_value=True),
        patch("worthless.cli.commands.doctor.checks.fernet_drift._keyring") as kr,
    ):
        kr.get_password.return_value = "SOME_VALUE" + "=" * 33
        result = fernet_drift.run(ctx)

    assert result["status"] == "ok"
    assert result["findings"] == []


def test_drift_detected_when_values_differ(ctx, fake_home) -> None:
    """Both sources present with different bytes → status=error."""
    fake_home.fernet_key_path.write_bytes(b"AAA" + b"=" * 41)

    with (
        patch.object(fernet_drift, "keyring_available", return_value=True),
        patch("worthless.cli.commands.doctor.checks.fernet_drift._keyring") as kr,
    ):
        kr.get_password.return_value = "BBB" + "=" * 41
        result = fernet_drift.run(ctx)

    assert result["status"] == "error"
    assert len(result["findings"]) == 1
    assert "instructions" in result["findings"][0]


def test_no_drift_when_values_match(ctx, fake_home) -> None:
    """Both sources present with same bytes → status=ok."""
    same = b"SAME" + b"=" * 40
    fake_home.fernet_key_path.write_bytes(same)

    with (
        patch.object(fernet_drift, "keyring_available", return_value=True),
        patch("worthless.cli.commands.doctor.checks.fernet_drift._keyring") as kr,
    ):
        kr.get_password.return_value = same.decode("utf-8")
        result = fernet_drift.run(ctx)

    assert result["status"] == "ok"


# ---------------------------------------------------------------------------
# worthless-saaz: a key the background service can't use is drift too, even
# when only one key source exists. Real databases, sealed with real keys.
# ---------------------------------------------------------------------------

OTHER = Fernet.generate_key()


def _seal(home, key: bytes, *aliases: str) -> None:
    seal_enrolled(home.db_path, key, *aliases)


def _file_key(home) -> bytes:
    return home.fernet_key_path.read_bytes().strip()


def test_a_stale_only_key_is_an_error_not_ok(ctx, fake_home) -> None:
    """keyring-null / wiped keychain: the file is the only key and opens nothing."""
    _seal(fake_home, OTHER, "work", "side")
    result = fernet_drift.run(ctx)
    assert result["status"] == "error"
    assert result["fixable"] is False
    assert "2" in result["summary"]
    assert sorted(result["findings"][0]["cannot_unlock"]) == ["side", "work"]


def test_the_right_only_key_is_ok(ctx, fake_home) -> None:
    _seal(fake_home, _file_key(fake_home), "work")
    assert fernet_drift.run(ctx)["status"] == "ok"


def test_one_project_sealed_with_another_key_is_named(ctx, fake_home) -> None:
    """`lock` under WORTHLESS_FERNET_KEY=<other> — the case doctor called 'ok'."""
    _seal(fake_home, _file_key(fake_home), "work")
    _seal(fake_home, OTHER, "side")
    result = fernet_drift.run(ctx)
    assert result["status"] == "error"
    assert result["findings"][0]["cannot_unlock"] == ["side"]


def test_drift_says_which_source_opens_your_keys(ctx, fake_home) -> None:
    """Automates step 1 of the WOR-464 instructions without picking a side."""
    _seal(fake_home, _file_key(fake_home), "work")
    with (
        patch.object(fernet_drift, "keyring_available", return_value=True),
        patch("worthless.cli.commands.doctor.checks.fernet_drift._keyring") as kr,
    ):
        kr.get_password.return_value = OTHER.decode()
        result = fernet_drift.run(ctx)
    assert result["status"] == "error"
    assert result["findings"][0]["unlocks"] == {"file": "1 of 1", "keyring": "0 of 1"}


def test_docker_ipc_mode_never_checks(ctx, fake_home, monkeypatch) -> None:
    """WOR-465: the proxy uid owns no key there; don't read shards with one."""
    _seal(fake_home, OTHER, "work")
    monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
    with patch.object(key_check, "ShardReader", side_effect=AssertionError("read shards")):
        assert fernet_drift.run(ctx)["status"] == "ok"


def test_plain_doctor_names_what_the_service_key_cannot_unlock(fake_home) -> None:
    """Not just --json: plain `worthless doctor` used to say "No issues found."
    here (validator, PR #729)."""
    _seal(fake_home, _file_key(fake_home), "work")
    _seal(fake_home, OTHER, "side")
    result = CliRunner().invoke(app, ["doctor"], env={"WORTHLESS_HOME": str(fake_home.base_dir)})
    said = " ".join(result.output.split())
    assert "No issues found" not in said
    assert "side" in said and "can't unlock" in said


def test_plain_doctor_stays_quiet_when_the_key_fits(fake_home) -> None:
    _seal(fake_home, _file_key(fake_home), "work")
    result = CliRunner().invoke(app, ["doctor"], env={"WORTHLESS_HOME": str(fake_home.base_dir)})
    assert "can't unlock" not in result.output
