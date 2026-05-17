"""WOR-464: registry contract tests.

Pin the public surface so future check additions don't silently break
JSON consumers:

  * SCHEMA_VERSION is a string.
  * ALL_CHECKS is ordered and contains every documented check_id.
  * Each registered check exposes ``check_id`` + ``run``.
  * Each ``run(ctx)`` returns the full CheckResult contract keys.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from worthless.cli.commands.doctor.registry import (
    CheckContext,
    ensure_registered,
)
from worthless.cli.commands.doctor.schema import SCHEMA_VERSION


EXPECTED_CHECK_IDS = {
    "recovery_import",
    "orphan_db",
    "openclaw",
    "icloud_keychain",
    "orphan_keychain",
    "stranded_shards",
    "fernet_drift",
    "broken_status",
}


def test_schema_version_is_string() -> None:
    assert isinstance(SCHEMA_VERSION, str)
    assert SCHEMA_VERSION  # non-empty


def test_all_checks_registered() -> None:
    checks = ensure_registered()
    ids = {c.check_id for c in checks}
    assert ids == EXPECTED_CHECK_IDS


def test_check_protocol_surface() -> None:
    for c in ensure_registered():
        assert hasattr(c, "check_id")
        assert callable(c.run)


def test_check_result_keys(tmp_path) -> None:
    """Every check must return the documented CheckResult keys."""
    from worthless.cli.bootstrap import ensure_home

    home = ensure_home(tmp_path / ".worthless")
    repo = MagicMock()
    repo.initialize = MagicMock(return_value=None)
    repo.list_enrollments = MagicMock(return_value=[])

    # Repo methods are async — use AsyncMock semantics via real ShardRepository
    from worthless.storage.repository import ShardRepository

    real_repo = ShardRepository(str(home.db_path), bytes(home.fernet_key))

    ctx = CheckContext(home=home, repo=real_repo, fix=False, dry_run=False)
    required_keys = {"check_id", "status", "findings", "summary", "fixable", "fixed"}

    for c in ensure_registered():
        result = c.run(ctx)
        missing = required_keys - set(result.keys())
        assert not missing, f"{c.check_id} missing keys: {missing}"
        assert result["status"] in {"ok", "warn", "error"}
        assert isinstance(result["findings"], list)
        assert isinstance(result["fixed"], list)
        assert isinstance(result["fixable"], bool)


def test_fernet_drift_is_never_fixable(tmp_path) -> None:
    """WOR-464 critical guardrail: fernet_drift.fixable MUST be False."""
    from worthless.cli.bootstrap import ensure_home
    from worthless.cli.commands.doctor.checks import fernet_drift
    from worthless.storage.repository import ShardRepository

    home = ensure_home(tmp_path / ".worthless")
    repo = ShardRepository(str(home.db_path), bytes(home.fernet_key))

    # Even with fix=True the check returns fixable=False.
    ctx = CheckContext(home=home, repo=repo, fix=True, dry_run=False)
    result = fernet_drift.run(ctx)
    assert result["fixable"] is False


@pytest.mark.parametrize("check_id", sorted(EXPECTED_CHECK_IDS))
def test_check_id_is_snake_case(check_id: str) -> None:
    """check_id is snake_case per the JSON schema convention."""
    assert check_id.islower()
    assert all(c.isalnum() or c == "_" for c in check_id)
