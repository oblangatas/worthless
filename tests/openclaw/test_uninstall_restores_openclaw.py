"""`worthless uninstall` must RESTORE openclaw.json end-to-end (WOR-713 PR2).

RED-first. The gap this closes: today the only uninstall→OpenClaw coverage is
``test_uninstall_calls_openclaw_undo_with_restored_aliases`` in
``tests/test_uninstall.py`` — a SPY that asserts ``_apply_openclaw_unlock`` was
called. It never proves the on-disk ``openclaw.json`` is actually put back.

These tests drive the REAL CLI (``worthless lock`` then ``worthless uninstall``)
against a sandboxed ``~/.openclaw`` (the ``openclaw_present`` conftest fixture,
which pins ``HOME`` via ``monkeypatch.setenv``) and an INDEPENDENT
``~/.worthless`` (passed via ``WORTHLESS_HOME`` so it does not collide with the
sandboxed ``HOME``). Modelled on
``tests/openclaw/test_integration_apply_unlock_restore.py`` (which exercises the
``integration.apply_unlock`` layer directly) and the apply-lock CLI-less F1/F2
tests — but here the assertion is the on-disk file after the full uninstall.

Contract (WOR-621 F1/F2 + WOR-713):
  * ``lock`` rewrites the original ``openai`` entry to point at the Worthless
    proxy with shard-A in ``apiKey`` (no ``worthless-openai`` decoy).
  * ``uninstall`` restores that original entry BYTE-FOR-BYTE from the
    non-secret rollback record — the user's editor/agent sees their real
    provider config again, pointing back at the real provider with the real
    key.

Run:  WORTHLESS_KEYRING_BACKEND=null uv run pytest \
        tests/openclaw/test_uninstall_restores_openclaw.py -p no:benchmark -q
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import ensure_home

runner = CliRunner()

_ORIG_BASE_URL = "https://api.openai.com/v1"


def _seed_original_openai(config_path: Path, api_key: str) -> None:
    """Write the user's ORIGINAL ``openai`` provider entry into openclaw.json."""
    data = json.loads(config_path.read_text(encoding="utf-8"))
    data.setdefault("models", {}).setdefault("providers", {})["openai"] = {
        "baseUrl": _ORIG_BASE_URL,
        "apiKey": api_key,
    }
    config_path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _providers(config_path: Path) -> dict:
    return json.loads(config_path.read_text(encoding="utf-8"))["models"]["providers"]


def test_uninstall_restores_original_openclaw_entry_end_to_end(
    openclaw_present: dict[str, Path], tmp_path: Path
) -> None:
    """WOR-713: real ``lock`` then real ``uninstall`` restores the original
    ``openai`` openclaw.json entry — proven on disk, not via a spy.

    Steps:
      1. Seed the user's real ``openai`` entry (real key, real provider URL).
      2. ``worthless lock`` the ``.env`` → lock rewrites the entry to the proxy
         + shard-A (verified mid-flight: apiKey changed, baseUrl is the proxy).
      3. ``worthless uninstall --yes`` → the entry must be restored to the
         ORIGINAL provider URL with the ORIGINAL key, and no ``worthless-*``
         decoy may linger.
    """
    from tests.helpers import fake_key

    # ``~/.worthless`` lives OUTSIDE the sandboxed HOME so the two sandboxes
    # don't collide; ``openclaw_present`` already pins HOME to tmp_path/home.
    worthless_home = ensure_home(tmp_path / "worthless-home")
    config_path = openclaw_present["config_path"]

    real_key = fake_key("sk-")
    _seed_original_openai(config_path, real_key)

    env = openclaw_present["home"] / ".env"
    env.write_text(f"OPENAI_API_KEY={real_key}\n")

    locked = runner.invoke(
        app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(worthless_home.base_dir)}
    )
    assert locked.exit_code == 0, locked.output

    mid = _providers(config_path)
    assert "worthless-openai" not in mid, f"lock created a decoy entry: {mid}"
    assert mid["openai"]["apiKey"] != real_key, "lock left the real key in openclaw.json"
    assert "/v1" in mid["openai"]["baseUrl"]
    assert mid["openai"]["baseUrl"] != _ORIG_BASE_URL, "lock did not rewrite baseUrl to the proxy"

    uninst = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(worthless_home.base_dir)}
    )
    assert uninst.exit_code == 0, uninst.output

    restored = _providers(config_path)
    assert "worthless-openai" not in restored, f"uninstall left a decoy entry: {restored}"
    assert restored["openai"]["baseUrl"] == _ORIG_BASE_URL, (
        f"uninstall did not restore the original provider URL: {restored['openai']}"
    )
    assert restored["openai"]["apiKey"] == real_key, (
        "uninstall did not restore the original real key to openclaw.json"
    )


def test_uninstall_restores_openclaw_byte_for_byte(
    openclaw_present: dict[str, Path], tmp_path: Path
) -> None:
    """WOR-713 (sharper): the openclaw.json bytes after ``lock`` → ``uninstall``
    must equal the bytes BEFORE ``lock``.

    The integration layer already promises a byte-identical round trip
    (``test_lock_then_unlock_round_trip_byte_identical_plaintext``); this proves
    the full ``worthless uninstall`` command preserves it, so an OpenClaw-primary
    user is left with exactly the config they started with — not a re-serialised
    near-copy.
    """
    from tests.helpers import fake_key

    worthless_home = ensure_home(tmp_path / "worthless-home")
    config_path = openclaw_present["config_path"]

    real_key = fake_key("sk-")
    _seed_original_openai(config_path, real_key)
    pre_bytes = config_path.read_bytes()

    env = openclaw_present["home"] / ".env"
    env.write_text(f"OPENAI_API_KEY={real_key}\n")

    locked = runner.invoke(
        app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(worthless_home.base_dir)}
    )
    assert locked.exit_code == 0, locked.output
    assert config_path.read_bytes() != pre_bytes, "lock should have mutated openclaw.json"

    uninst = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(worthless_home.base_dir)}
    )
    assert uninst.exit_code == 0, uninst.output

    assert config_path.read_bytes() == pre_bytes, (
        "uninstall must restore openclaw.json byte-for-byte to its pre-lock state"
    )


def test_uninstall_leaves_unrelated_openclaw_provider_untouched(
    openclaw_present: dict[str, Path], tmp_path: Path
) -> None:
    """WOR-713 (isolation): a provider Worthless never locked (e.g. a
    user-managed ``mistral`` entry) must survive ``lock`` → ``uninstall``
    unchanged. Uninstall only ever touches what it locked.
    """
    from tests.helpers import fake_key

    worthless_home = ensure_home(tmp_path / "worthless-home")
    config_path = openclaw_present["config_path"]

    real_key = fake_key("sk-")
    _seed_original_openai(config_path, real_key)
    # A user-managed provider Worthless has no business touching.
    data = json.loads(config_path.read_text(encoding="utf-8"))
    data["models"]["providers"]["mistral"] = {
        "baseUrl": "https://api.mistral.ai/v1",
        "apiKey": "user-managed-mistral-key",
    }
    config_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    env = openclaw_present["home"] / ".env"
    env.write_text(f"OPENAI_API_KEY={real_key}\n")
    locked = runner.invoke(
        app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(worthless_home.base_dir)}
    )
    assert locked.exit_code == 0, locked.output

    uninst = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(worthless_home.base_dir)}
    )
    assert uninst.exit_code == 0, uninst.output

    after = _providers(config_path)
    assert after["mistral"] == {
        "baseUrl": "https://api.mistral.ai/v1",
        "apiKey": "user-managed-mistral-key",
    }, f"uninstall mutated an unrelated provider entry: {after.get('mistral')}"
