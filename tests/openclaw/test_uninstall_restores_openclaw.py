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

import pytest
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


def _agent_dir(openclaw_present: dict[str, Path]) -> Path:
    return openclaw_present["home"] / ".openclaw" / "agents" / "main" / "agent"


def _cached_keys(agent_dir: Path) -> tuple[str, str]:
    """The OpenAI key in the agent's ``models.json`` and ``auth-profiles.json``."""
    models = json.loads((agent_dir / "models.json").read_text(encoding="utf-8"))
    profiles = json.loads((agent_dir / "auth-profiles.json").read_text(encoding="utf-8"))
    return models["providers"]["openai"]["apiKey"], profiles["profiles"]["main-openai"]["key"]


def _lock_openclaw_backed_key(
    openclaw_present: dict[str, Path], worthless_home
) -> tuple[str, Path]:  # noqa: ANN001
    """Lock an OpenAI key that openclaw.json and an agent's caches also hold: lock
    points openclaw.json at the proxy and scrubs the caches (WOR-796).

    Returns ``(key, env path)``.
    """
    from tests.helpers import fake_key

    key = fake_key("sk-")
    _seed_original_openai(openclaw_present["config_path"], key)
    agent_dir = _agent_dir(openclaw_present)
    agent_dir.mkdir(parents=True)
    (agent_dir / "models.json").write_text(
        json.dumps({"providers": {"openai": {"apiKey": key, "baseUrl": _ORIG_BASE_URL}}}),
        encoding="utf-8",
    )
    (agent_dir / "auth-profiles.json").write_text(
        json.dumps(
            {
                "version": 1,
                "profiles": {"main-openai": {"type": "api_key", "provider": "openai", "key": key}},
            }
        ),
        encoding="utf-8",
    )

    env = openclaw_present["home"] / "app" / ".env"
    env.parent.mkdir()
    env.write_text(f"OPENAI_API_KEY={key}\n")
    locked = runner.invoke(
        app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(worthless_home.base_dir)}
    )
    assert locked.exit_code == 0, locked.output
    assert key not in _cached_keys(agent_dir), "lock should have scrubbed the agent's caches"
    return key, env


def _lock_restorable_and_unrestorable(openclaw_present: dict[str, Path], tmp_path: Path):  # noqa: ANN202
    """An OpenClaw-backed OpenAI key (see above) and an Anthropic key in a second
    project whose ``.env`` uninstall then can't restore.

    Returns ``(worthless_home, openai_key, anthropic_key, restorable, unrestorable)``.
    """
    from tests.helpers import fake_anthropic_key, make_unrestorable

    worthless_home = ensure_home(tmp_path / "worthless-home")
    openai_key, restorable = _lock_openclaw_backed_key(openclaw_present, worthless_home)
    anthropic_key = fake_anthropic_key()
    unrestorable = openclaw_present["home"] / "other" / ".env"
    unrestorable.parent.mkdir()
    unrestorable.write_text(f"ANTHROPIC_API_KEY={anthropic_key}\n")
    locked = runner.invoke(
        app,
        ["lock", "--env", str(unrestorable)],
        env={"WORTHLESS_HOME": str(worthless_home.base_dir)},
    )
    assert locked.exit_code == 0, locked.output
    make_unrestorable(unrestorable)
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


def _assert_all_zeroed(restores: list) -> None:
    """SR-02: uninstall reconstructed at least one key, and every one is zeroed.
    Counts, never echoes, a key left in memory."""
    keys = [r.plaintext_key for r in restores if r.plaintext_key is not None]
    assert keys, "uninstall should have reconstructed a key for OpenClaw"
    left = sum(1 for key in keys if any(key))
    assert left == 0, f"SR-02: {left} reconstructed key(s) left in memory"


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
    assert _cached_keys(_agent_dir(openclaw_present)) == (openai_key, openai_key), (
        "the agent's caches must get the real key back too, not NUL bytes"
    )
    _assert_all_zeroed(built)
    assert_not_shown(uninst.output, openai_key, anthropic_key)


def test_force_zeroes_restored_keys_when_a_note_about_a_lost_key_cant_be_written(
    openclaw_present: dict[str, Path], tmp_path: Path, monkeypatch
) -> None:
    """WOR-1051, SR-02: under ``--force`` the notes about a ``.env`` uninstall
    couldn't restore print before the OpenClaw undo that zeroes the restored
    keys. A stderr that refuses that write (EAGAIN on a non-blocking pipe) stops
    the command there, and the keys it already reconstructed must still be zeroed.
    """
    from tests.helpers import assert_not_shown, refuse_console_writes

    worthless_home, openai_key, anthropic_key, *_ = _lock_restorable_and_unrestorable(
        openclaw_present, tmp_path
    )
    built = _keep_built_restores(monkeypatch)
    refuse_console_writes(monkeypatch, "print_key_note")

    uninst = runner.invoke(
        app, ["uninstall", "--yes", "--force"], env={"WORTHLESS_HOME": str(worthless_home.base_dir)}
    )

    assert uninst.exit_code != 0, uninst.output
    assert worthless_home.base_dir.exists(), "stopped before the wipe"
    _assert_all_zeroed(built)
    assert_not_shown(uninst.output, openai_key, anthropic_key)


@pytest.mark.parametrize("stop", ["restored line", "proxy warning"])
def test_uninstall_zeroes_a_restored_key_when_it_stops_before_the_openclaw_undo(
    openclaw_present: dict[str, Path], tmp_path: Path, monkeypatch, stop: str
) -> None:
    """SR-02 (WOR-1051): after it restores a key, uninstall can still stop before
    the OpenClaw undo that zeroes it, on a line it can't write (EAGAIN on a
    non-blocking pipe): the "restored" line, or the warning that it couldn't stop
    the proxy. The key it reconstructed must still be zeroed.
    """
    import worthless.cli.commands.uninstall as uninstall_mod
    from tests.helpers import assert_not_shown, refuse_console_writes

    worthless_home = ensure_home(tmp_path / "worthless-home")
    key, env = _lock_openclaw_backed_key(openclaw_present, worthless_home)
    built = _keep_built_restores(monkeypatch)
    if stop == "restored line":
        refuse_console_writes(monkeypatch, "print_success", containing=f"restored {env}")
    else:

        def _cant_stop(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
            raise OSError("simulated: proxy won't stop")

        monkeypatch.setattr(uninstall_mod, "_stop_daemon", _cant_stop)
        refuse_console_writes(
            monkeypatch, "print_warning", containing="could not stop the proxy daemon"
        )

    uninst = runner.invoke(
        app, ["uninstall", "--yes"], env={"WORTHLESS_HOME": str(worthless_home.base_dir)}
    )

    assert uninst.exit_code != 0, uninst.output
    assert worthless_home.base_dir.exists(), "stopped before the wipe"
    _assert_all_zeroed(built)
    assert_not_shown(uninst.output, key)
