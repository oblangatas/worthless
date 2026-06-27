"""WOR-464: Fernet key drift check.

CRITICAL guardrail: this check MUST NEVER auto-repair. ``fixable``
is hardcoded False — losing the canonical key would render existing
locked secrets unrecoverable.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from worthless.cli.bootstrap import ensure_home
from worthless.cli.commands.doctor.checks import fernet_drift
from worthless.cli.commands.doctor.registry import CheckContext
from worthless.storage.repository import ShardRepository


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
