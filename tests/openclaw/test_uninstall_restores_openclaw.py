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

import errno
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


def _agent_models(openclaw_present: dict[str, Path]) -> Path:
    return openclaw_present["home"] / ".openclaw" / "agents" / "main" / "agent" / "models.json"


def _lock_restorable_and_unrestorable(openclaw_present: dict[str, Path], tmp_path: Path):  # noqa: ANN202
    """Lock an OpenClaw-backed OpenAI key and an Anthropic key in two projects,
    then put a live symlink in place of the Anthropic ``.env``: safe_rewrite
    refuses it, so uninstall can't put that key back (f2ge). The OpenAI key is
    also cached in an agent's ``models.json``, which lock scrubs (WOR-796).

    Returns ``(worthless_home, openai_key, anthropic_key, restorable, unrestorable)``.
    """
    from tests.helpers import fake_anthropic_key, fake_key

    worthless_home = ensure_home(tmp_path / "worthless-home")
    openai_key = fake_key("sk-")
    _seed_original_openai(openclaw_present["config_path"], openai_key)
    _agent_models(openclaw_present).parent.mkdir(parents=True)
    _agent_models(openclaw_present).write_text(
        json.dumps({"providers": {"openai": {"apiKey": openai_key, "baseUrl": _ORIG_BASE_URL}}}),
        encoding="utf-8",
    )
    anthropic_key = fake_anthropic_key()

    restorable = openclaw_present["home"] / "app" / ".env"
    unrestorable = openclaw_present["home"] / "other" / ".env"
    for env, line in (
        (restorable, f"OPENAI_API_KEY={openai_key}\n"),
        (unrestorable, f"ANTHROPIC_API_KEY={anthropic_key}\n"),
    ):
        env.parent.mkdir()
        env.write_text(line)
        locked = runner.invoke(
            app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(worthless_home.base_dir)}
        )
        assert locked.exit_code == 0, locked.output

    assert openai_key not in _agent_models(openclaw_present).read_text(encoding="utf-8"), (
        "lock should have scrubbed the agent's cached key"
    )

    target = unrestorable.with_name("elsewhere.env")
    target.write_text("ANTHROPIC_API_KEY=whatever\n")
    unrestorable.unlink()
    unrestorable.symlink_to(target)
    return worthless_home, openai_key, anthropic_key, restorable, unrestorable


def _keep_built_restores(monkeypatch) -> list:  # noqa: ANN001
    """Every ``OcRestore`` uninstall builds, so a test can check its key at the end."""
    import worthless.cli.commands.uninstall as uninstall_mod

    built: list = []
    real_build = uninstall_mod._build_oc_restores

    async def _keep(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        restores = await real_build(*args, **kwargs)
        built.extend(restores)
        return restores

    monkeypatch.setattr(uninstall_mod, "_build_oc_restores", _keep)
    return built


def _all_zeroed(restores: list) -> bool:
    """At least one reconstructed key was built, and every one is all zeros."""
    keys = [r.plaintext_key for r in restores if r.plaintext_key is not None]
    return bool(keys) and not any(any(key) for key in keys)


def test_force_past_an_unrestorable_env_still_restores_openclaw_with_the_real_key(
    openclaw_present: dict[str, Path], tmp_path: Path, monkeypatch
) -> None:
    """WOR-1051: ``--force`` past one ``.env`` it can't restore must still give
    OpenClaw the real key of a ``.env`` it did restore, never NUL bytes, and
    still zero every reconstructed key by the end (SR-02).
    """
    from tests.helpers import assert_not_shown

    config_path = openclaw_present["config_path"]
    worthless_home, openai_key, anthropic_key, restorable, unrestorable = (
        _lock_restorable_and_unrestorable(openclaw_present, tmp_path)
    )
    built = _keep_built_restores(monkeypatch)

    # A wide console keeps a long tmp path on one line.
    uninst = runner.invoke(
        app,
        ["uninstall", "--yes", "--force"],
        env={"WORTHLESS_HOME": str(worthless_home.base_dir), "COLUMNS": "1000"},
    )

    assert uninst.exit_code == 0, uninst.output
    assert f"could NOT restore {unrestorable}" in uninst.output
    assert restorable.read_text() == f"OPENAI_API_KEY={openai_key}\n"
    assert _providers(config_path)["openai"] == {
        "baseUrl": _ORIG_BASE_URL,
        "apiKey": openai_key,
    }, "openclaw.json must get back the key uninstall restored, not NUL bytes"
    cached = json.loads(_agent_models(openclaw_present).read_text(encoding="utf-8"))
    assert cached["providers"]["openai"]["apiKey"] == openai_key, (
        "the agent's cached key must come back too, not NUL bytes"
    )
    assert built, "the restored .env should have built an OpenClaw restore"
    assert _all_zeroed(built), "SR-02: every reconstructed key must be zeroed by the end"
    assert_not_shown(uninst.output, openai_key, anthropic_key)


def test_force_zeroes_restored_keys_when_a_note_about_a_lost_key_cant_be_written(
    openclaw_present: dict[str, Path], tmp_path: Path, monkeypatch
) -> None:
    """WOR-1051, SR-02: under ``--force`` the notes about a ``.env`` uninstall
    couldn't restore print before the OpenClaw undo that zeroes the restored
    keys. A stderr that refuses that write (EAGAIN on a non-blocking pipe) stops
    the command there, and the keys it already reconstructed must still be zeroed.
    """
    from worthless.cli.console import WorthlessConsole

    worthless_home, *_ = _lock_restorable_and_unrestorable(openclaw_present, tmp_path)
    built = _keep_built_restores(monkeypatch)

    def _refuse(console, message: str) -> None:  # noqa: ANN001
        raise BlockingIOError(errno.EAGAIN, "Resource temporarily unavailable")

    monkeypatch.setattr(WorthlessConsole, "print_key_note", _refuse)

    uninst = runner.invoke(
        app, ["uninstall", "--yes", "--force"], env={"WORTHLESS_HOME": str(worthless_home.base_dir)}
    )

    assert uninst.exit_code != 0, uninst.output
    assert worthless_home.base_dir.exists(), "stopped before the wipe"
    assert built, "the restored .env should have built an OpenClaw restore"
    assert _all_zeroed(built), "SR-02: a key reconstructed before the stop must be zeroed"
