"""WOR-464: orphan-keychain check.

Critical guardrail tests:
  * Current install's active username is allowlisted — never marked orphan.
  * Non-darwin returns ``skipped_reason`` (no false-positive deletes).
  * ``--fix`` repairs orphans but skips allowlisted entries.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from worthless.cli.bootstrap import ensure_home
from worthless.cli.commands.doctor.checks import orphan_keychain
from worthless.cli.commands.doctor.registry import CheckContext
from worthless.cli.keystore import _keyring_username
from worthless.storage.repository import ShardRepository


@pytest.fixture
def fake_home(tmp_path: Path):
    return ensure_home(tmp_path / ".worthless")


@pytest.fixture
def ctx(fake_home):
    repo = ShardRepository(str(fake_home.db_path), bytes(fake_home.fernet_key))
    return CheckContext(home=fake_home, repo=repo, fix=False, dry_run=False)


@pytest.mark.skipif(sys.platform != "darwin", reason="orphan_keychain darwin-only repair")
def test_active_install_username_is_allowlisted(ctx, fake_home, monkeypatch) -> None:
    """Current install's active key MUST NOT appear in orphan findings."""
    monkeypatch.setattr(orphan_keychain, "keyring_available", lambda: True)
    active = _keyring_username(fake_home.base_dir)
    fake_keystore = MagicMock()
    fake_keystore.find_all_entries.return_value = [active]
    fake_keystore.KeychainNotFound = type("KeychainNotFound", (Exception,), {})

    with patch("worthless.cli.keystore_macos", fake_keystore):
        result = orphan_keychain.run(ctx)

    accounts = [f["keychain_account"] for f in result["findings"]]
    assert active not in accounts


def test_non_darwin_skipped_reason(ctx, monkeypatch) -> None:
    """Linux/Windows: check ``skipped_reason`` is set, no findings."""
    monkeypatch.setattr(orphan_keychain.sys, "platform", "linux")
    result = orphan_keychain.run(ctx)
    assert result["status"] == "ok"
    assert result["findings"] == []
    assert result["skipped_reason"] == "non-darwin platform"


@pytest.mark.skipif(sys.platform != "darwin", reason="orphan_keychain darwin-only repair")
def test_fix_deletes_only_non_allowlisted(ctx, fake_home, monkeypatch) -> None:
    """``fix=True`` deletes orphans but never the active username."""
    monkeypatch.setattr(orphan_keychain, "keyring_available", lambda: True)
    active = _keyring_username(fake_home.base_dir)
    orphan_a = "fernet-key-deadbeef0001"
    orphan_b = "fernet-key-deadbeef0002"

    fake_keystore = MagicMock()
    fake_keystore.find_all_entries.return_value = [active, orphan_a, orphan_b]
    fake_keystore.KeychainNotFound = type("KeychainNotFound", (Exception,), {})

    ctx.fix = True
    with patch("worthless.cli.keystore_macos", fake_keystore):
        result = orphan_keychain.run(ctx)

    # Active username never appears in delete call list.
    delete_calls = [c.args[1] for c in fake_keystore.delete_password_local.call_args_list]
    assert active not in delete_calls
    assert orphan_a in delete_calls
    assert orphan_b in delete_calls
    assert result["status"] == "ok"  # all orphans repaired


@pytest.mark.skipif(sys.platform != "darwin", reason="orphan_keychain darwin-only")
def test_findings_are_well_formed(ctx, monkeypatch) -> None:
    """Each finding dict contains the documented keychain_account key."""
    monkeypatch.setattr(orphan_keychain, "keyring_available", lambda: True)
    orphan = "fernet-key-deadbeef1234"
    fake_keystore = MagicMock()
    fake_keystore.find_all_entries.return_value = [orphan]
    fake_keystore.KeychainNotFound = type("KeychainNotFound", (Exception,), {})

    with patch("worthless.cli.keystore_macos", fake_keystore):
        result = orphan_keychain.run(ctx)

    assert result["findings"], "expected at least one finding"
    for f in result["findings"]:
        assert isinstance(f, dict)
        assert "keychain_account" in f
