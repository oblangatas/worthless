"""Seed user-flow test: real keyring + real CLI = 1 ``keyring.get_password``
per ``worthless lock``.

THIS IS the test pattern for ``@pytest.mark.user_flow``. THIS IS NOT a
mocked unit test — it spies on the actual ``keyring`` module while a real
CLI invocation runs. The full user-flow suite (install / uninstall /
multi-platform Docker matrix) is tracked in Linear under ``WOR-439``.

Why this lives here, not in ``tests/test_bootstrap_keyring.py``:

* Unit tests mock ``read_fernet_key`` entirely — they only verify the
  cache mechanism. The HF2 PR #125 ``migrate_file_to_keyring`` bypass
  fired ``keyring.get_password`` directly, completely bypassing the
  property and its cache. All unit tests passed; the bug shipped to
  review and was caught only when a manual spy on a real CLI run on
  2026-05-03 showed 2 calls instead of 1.

* User-flow tests run the real CLI against a real keyring and spy at
  the boundary. They are slow (touch real backends), require platform-
  appropriate keyring infrastructure (skipped if absent), and may
  prompt the user on macOS without 'Always Allow' set up.

* Default pytest run excludes the ``user_flow`` marker. Opt-in:
  ``pytest -m user_flow``.
"""

from __future__ import annotations

from pathlib import Path

import keyring
import pytest
from typer.testing import CliRunner

from tests.helpers import fake_openai_key
from worthless.cli.app import app
from worthless.cli.keystore import delete_fernet_key, keyring_available


@pytest.mark.user_flow
def test_lock_calls_keyring_get_password_once_on_existing_key_path(tmp_path: Path) -> None:
    """One ``keyring.get_password`` per ``worthless lock`` on the existing-key
    path — the HF2 contract.

    Pattern:
      1. First ``lock`` provisions the keyring entry (first-ever-boot path,
         not what we're measuring).
      2. Second ``lock`` runs against the existing keyring entry. THIS is
         the path we spy on.
      3. Assert ``keyring.get_password`` was called exactly once during the
         second run.

    Without the HF2 fixes (cache + ``migrate_file_to_keyring`` reorder),
    the second run fires 2 calls: one from the property's probe and one
    from ``migrate_file_to_keyring`` checking "is the key already in
    keyring?". This test catches that regression without monkey-patching.
    """
    if not keyring_available():
        pytest.skip("no keyring backend (CI without secret-service, fresh dev machine)")

    home = tmp_path / ".worthless"
    env_file = tmp_path / ".env"
    cli_env = {"WORTHLESS_HOME": str(home)}
    runner = CliRunner()

    # Provision the keyring entry: first-ever-boot path.
    env_file.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    first = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
    assert first.exit_code == 0, first.output

    # Reset .env to a fresh raw key for the second run (the first run
    # replaced the original with a shard-A value).
    env_file.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")

    try:
        original_get_password = keyring.get_password
        recorded_calls: list[tuple] = []

        def _spy(*args: object, **kwargs: object) -> object:
            recorded_calls.append(args)
            return original_get_password(*args, **kwargs)

        keyring.get_password = _spy
        try:
            second = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
            assert second.exit_code == 0, second.output
        finally:
            keyring.get_password = original_get_password

        assert len(recorded_calls) == 1, (
            f"existing-key path: expected 1 keyring.get_password call, "
            f"got {len(recorded_calls)}.\n"
            f"calls: {recorded_calls}\n"
            f"This is the HF2 contract; a result > 1 means a code path "
            f"is bypassing the WorthlessHome.fernet_key cache and reading "
            f"keyring directly."
        )
    finally:
        # Clean up the keyring entry we created so the test is idempotent
        # across runs and doesn't pollute the developer's keyring.
        try:
            delete_fernet_key(home_dir=home)
        except Exception:  # noqa: BLE001 — cleanup best-effort
            pass


@pytest.mark.user_flow
def test_unlock_calls_keyring_get_password_once_on_existing_key_path(tmp_path: Path) -> None:
    """One ``keyring.get_password`` per ``worthless unlock`` on the existing-key
    path — extends the lock contract to the unlock flow.

    Pattern (mirrors the lock test):
      1. First ``lock`` provisions the keyring entry (we don't measure this).
      2. Second ``unlock`` runs against the existing keyring entry. THIS is
         the path we spy on.
      3. Assert ``keyring.get_password`` was called exactly once during unlock.

    Without HF2's cache, unlock would fire 3+ keyring reads
    (bootstrap probe + ShardRepository init + per-alias decryption setup).
    With HF2, the cache collapses them to 1 per CLI invocation.
    """
    if not keyring_available():
        pytest.skip("no keyring backend (CI without secret-service, fresh dev machine)")

    home = tmp_path / ".worthless"
    env_file = tmp_path / ".env"
    cli_env = {"WORTHLESS_HOME": str(home)}
    runner = CliRunner()

    # Provision: first lock creates the keyring entry + .env shard-A.
    env_file.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    first = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
    assert first.exit_code == 0, first.output

    # Now spy on the unlock CLI invocation.
    try:
        original_get_password = keyring.get_password
        recorded_calls: list[tuple] = []

        def _spy(*args: object, **kwargs: object) -> object:
            recorded_calls.append(args)
            return original_get_password(*args, **kwargs)

        keyring.get_password = _spy
        try:
            unlock = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
            assert unlock.exit_code == 0, unlock.output
        finally:
            keyring.get_password = original_get_password

        assert len(recorded_calls) == 1, (
            f"existing-key unlock: expected 1 keyring.get_password call, "
            f"got {len(recorded_calls)}.\n"
            f"calls: {recorded_calls}\n"
            f"A result > 1 means a code path bypasses the cache for unlock — "
            f"the same bug class HF2 fixed in the lock path."
        )
    finally:
        try:
            delete_fernet_key(home_dir=home)
        except Exception:  # noqa: BLE001 — cleanup best-effort
            pass
