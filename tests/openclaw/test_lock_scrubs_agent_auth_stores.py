"""WOR-796 — lock scrubs the real key cached in OpenClaw's OWN
auth-profiles.json / models.json, replacing it with an env SecretRef that
resolves to shard-A.

The bug: ``lock`` scrubs ``.env`` + ``openclaw.json`` but never the
per-agent ``auth-profiles.json`` / ``models.json``, where OpenClaw caches
the resolved real key independent of ``openclaw.json``. A literal real key
in either file short-circuits SecretRef resolution in real OpenClaw
(``getCustomProviderApiKey`` / ``resolveProfileSecretString``) and is sent
upstream directly — a stolen home dir yields the real key with zero shards
needed.

Scope honesty: this ships the on-disk scrub. Live re-routing through the
proxy is gated on WOR-756 (daemon reload) — until that lands, ``lock`` must
print a loud "restart OpenClaw to apply" message when it scrubs something.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.key_patterns import KEY_PATTERN

from tests.helpers import fake_openai_key

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pin HOME so apply_lock's detect() sees the sandbox, not the real
    developer ``~/.openclaw/``.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(home)
    return home


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


@pytest.fixture
def real_key() -> str:
    return fake_openai_key()


@pytest.fixture
def openclaw_with_agent_caches(sandboxed_home: Path, real_key: str) -> dict[str, Path]:
    """Pre-stage ``~/.openclaw/`` with a workspace, empty openclaw.json, and
    TWO agent dirs (main + worker) whose models.json/auth-profiles.json both
    cache the SAME real key literally — the WOR-796 leak surface.
    """
    openclaw_dir = sandboxed_home / ".openclaw"
    (openclaw_dir / "workspace").mkdir(parents=True)
    _write_json(openclaw_dir / "openclaw.json", {"models": {"providers": {}}})

    paths: dict[str, Path] = {"home": sandboxed_home, "openclaw_dir": openclaw_dir}
    for agent_id in ("main", "worker"):
        agent_dir = openclaw_dir / "agents" / agent_id / "agent"
        models_path = agent_dir / "models.json"
        auth_profiles_path = agent_dir / "auth-profiles.json"
        _write_json(
            models_path,
            {"providers": {"openai": {"apiKey": real_key, "baseUrl": "https://api.openai.com/v1"}}},
        )
        _write_json(
            auth_profiles_path,
            {
                "version": 1,
                "profiles": {
                    f"{agent_id}-openai": {
                        "type": "api_key",
                        "provider": "openai",
                        "key": real_key,
                    }
                },
            },
        )
        paths[f"{agent_id}_models"] = models_path
        paths[f"{agent_id}_auth_profiles"] = auth_profiles_path
    return paths


@pytest.fixture
def env_file(tmp_path: Path, real_key: str) -> Path:
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={real_key}\n")
    return env


def _lock(env_file: Path, home_dir: WorthlessHome):
    return runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )


def _unlock(env_file: Path, home_dir: WorthlessHome):
    return runner.invoke(
        app,
        ["unlock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )


# ---------------------------------------------------------------------------
# AC 1 — post-lock re-audit = 0 real-key findings, all agents, both files
# ---------------------------------------------------------------------------


def test_lock_scrubs_real_key_from_both_files_all_agents(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_with_agent_caches: dict[str, Path],
) -> None:
    """Locking the key must scrub the cached real key from EVERY agent dir's
    models.json AND auth-profiles.json — not just ``main`` — replacing it
    with ``${OPENAI_API_KEY}`` and leaving baseUrl untouched.
    """
    result = _lock(env_file, home_dir)
    assert result.exit_code == 0, result.output

    for agent_id in ("main", "worker"):
        models = json.loads(openclaw_with_agent_caches[f"{agent_id}_models"].read_text())
        entry = models["providers"]["openai"]
        assert entry["apiKey"] == "${OPENAI_API_KEY}", (
            f"{agent_id} models.json apiKey not scrubbed: {entry!r}"
        )
        assert entry["baseUrl"] == "https://api.openai.com/v1", (
            f"{agent_id} models.json baseUrl was touched: {entry!r}"
        )
        assert not KEY_PATTERN.search(json.dumps(models)), (
            f"{agent_id} models.json still has a real-key-shaped finding"
        )

        profiles = json.loads(openclaw_with_agent_caches[f"{agent_id}_auth_profiles"].read_text())
        cred = profiles["profiles"][f"{agent_id}-openai"]
        assert cred["key"] == "${OPENAI_API_KEY}", (
            f"{agent_id} auth-profiles.json key not scrubbed: {cred!r}"
        )
        assert not KEY_PATTERN.search(json.dumps(profiles)), (
            f"{agent_id} auth-profiles.json still has a real-key-shaped finding"
        )


# ---------------------------------------------------------------------------
# AC 2 — no trace anywhere under agents/**; shard-A reaches OpenClaw's OWN
# .env (the resolution prerequisite); loud restart notice (pairs with 756)
# ---------------------------------------------------------------------------


def test_lock_leaves_no_trace_under_agents_dir_and_seeds_state_dir_env(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_with_agent_caches: dict[str, Path],
    real_key: str,
) -> None:
    """Recursive sweep of every file under ``agents/`` must find zero copies
    of the real key. Shard-A must reach OpenClaw's OWN ``.env``
    (``$OPENCLAW_STATE_DIR/.env`` / ``~/.openclaw/.env``) — NOT the
    project ``.env`` — or the freshly-written ``${VAR}`` ref resolves empty
    once OpenClaw reloads (fails closed, but that's still a regression this
    ticket must avoid). Until WOR-756 lands, lock must say so loudly.
    """
    result = _lock(env_file, home_dir)
    assert result.exit_code == 0, result.output

    agents_root = openclaw_with_agent_caches["openclaw_dir"] / "agents"
    for path in agents_root.rglob("*.json"):
        assert real_key not in path.read_text(), f"real key still present in {path}"

    state_env = openclaw_with_agent_caches["openclaw_dir"] / ".env"
    assert state_env.is_file(), "OpenClaw's own .env was not seeded with shard-A"
    state_env_body = state_env.read_text()
    assert "OPENAI_API_KEY=" in state_env_body, (
        f"OPENAI_API_KEY missing from OpenClaw's own .env:\n{state_env_body}"
    )
    assert real_key not in state_env_body, "the REAL key leaked into OpenClaw's own .env"

    assert "restart" in result.output.lower() and "openclaw" in result.output.lower(), (
        f"lock scrubbed a real key but printed no restart-OpenClaw notice:\n{result.output}"
    )


# ---------------------------------------------------------------------------
# AC 3 — re-lock of an already-${VAR} file is a clean idempotent no-op
# ---------------------------------------------------------------------------


def test_relock_of_already_scrubbed_files_is_a_byte_identical_noop(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_with_agent_caches: dict[str, Path],
) -> None:
    first = _lock(env_file, home_dir)
    assert first.exit_code == 0, first.output

    cache_keys = [
        k for k in openclaw_with_agent_caches if k.endswith(("_models", "_auth_profiles"))
    ]
    before = {k: openclaw_with_agent_caches[k].read_bytes() for k in cache_keys}

    second = _lock(env_file, home_dir)
    assert second.exit_code == 0, second.output

    after = {k: openclaw_with_agent_caches[k].read_bytes() for k in cache_keys}
    assert before == after, "re-lock rewrote an already-scrubbed agent auth store"


# ---------------------------------------------------------------------------
# AC 4 — unlock restores the real key in both files; baseUrl untouched
# ---------------------------------------------------------------------------


def test_unlock_restores_real_key_in_both_files_baseurl_untouched(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_with_agent_caches: dict[str, Path],
    real_key: str,
) -> None:
    locked = _lock(env_file, home_dir)
    assert locked.exit_code == 0, locked.output

    unlocked = _unlock(env_file, home_dir)
    assert unlocked.exit_code == 0, unlocked.output

    for agent_id in ("main", "worker"):
        models = json.loads(openclaw_with_agent_caches[f"{agent_id}_models"].read_text())
        entry = models["providers"]["openai"]
        assert entry["apiKey"] == real_key, (
            f"{agent_id} models.json real key not restored: {entry!r}"
        )
        assert entry["baseUrl"] == "https://api.openai.com/v1"

        profiles = json.loads(openclaw_with_agent_caches[f"{agent_id}_auth_profiles"].read_text())
        cred = profiles["profiles"][f"{agent_id}-openai"]
        assert cred["key"] == real_key, (
            f"{agent_id} auth-profiles.json real key not restored: {cred!r}"
        )


# ---------------------------------------------------------------------------
# AC 5 — negative: never emit a non-uppercase ref; unrelated entries
# untouched (still "block" exactly as before — scope is precise)
# ---------------------------------------------------------------------------


def test_scrub_refuses_lowercase_var_name_and_ignores_unplanned_providers(
    openclaw_with_agent_caches: dict[str, Path],
    real_key: str,
) -> None:
    """A lowercase ``${var}`` is NOT a valid SecretRef in real OpenClaw (the
    env-ref regex is uppercase-only) — writing one would just swap a real
    key leak for a broken-but-still-not-a-ref literal string. The scrubber
    must refuse rather than emit it. A provider never passed in
    ``planned_updates`` (nothing was locked for it) must be left
    byte-for-byte untouched — it still "blocks" exactly as before, same as
    if WOR-796 didn't exist for that provider.
    """
    from worthless.openclaw import integration

    # Seed a second, unrelated provider this call will NOT plan to lock.
    models_path = openclaw_with_agent_caches["main_models"]
    models = json.loads(models_path.read_text())
    models["providers"]["anthropic"] = {
        "apiKey": "sk-ant-api03-unrelated-real-key-fixture",
        "baseUrl": "https://api.anthropic.com/v1",
    }
    _write_json(models_path, models)
    before_anthropic = models_path.read_bytes()

    integration.scrub_agent_auth_stores(
        openclaw_with_agent_caches["home"],
        [("openai", "openai-abc12345", "sk-shard-a-fake")],
        {"openai-abc12345": "openai_api_key"},  # lowercase — invalid, must be refused
    )

    after = json.loads(models_path.read_text())
    assert after["providers"]["openai"]["apiKey"] == real_key, (
        "scrub must refuse a lowercase var name, not emit a broken/leaky ref"
    )
    assert models_path.read_bytes() == before_anthropic, (
        "scrub touched an unrelated provider that was never in planned_updates"
    )


# ---------------------------------------------------------------------------
# Adversarial-review follow-ups: a custom ``agentDir`` override must still be
# scanned (silent-bypass gap), and a symlinked auth store file must be
# refused rather than followed (F-CFG-15, matches openclaw.json's own writer).
# ---------------------------------------------------------------------------


def test_lock_scrubs_agent_with_custom_agentdir_override(
    home_dir: WorthlessHome,
    env_file: Path,
    sandboxed_home: Path,
    real_key: str,
    tmp_path: Path,
) -> None:
    """Real OpenClaw resolves an agent's working directory from
    ``openclaw.json``'s ``agents.list[].agentDir`` when set — a completely
    different discovery path than listing ``<state_dir>/agents/``. Without
    reading that override, an agent configured with a custom directory is
    invisible to the scrub: its cached real key survives untouched while
    `lock` still reports success.
    """
    openclaw_dir = sandboxed_home / ".openclaw"
    (openclaw_dir / "workspace").mkdir(parents=True)

    custom_dir = tmp_path / "custom-agent-workdir"
    custom_dir.mkdir()
    _write_json(
        custom_dir / "models.json",
        {"providers": {"openai": {"apiKey": real_key, "baseUrl": "https://api.openai.com/v1"}}},
    )
    _write_json(
        openclaw_dir / "openclaw.json",
        {
            "models": {"providers": {}},
            "agents": {"list": [{"id": "custom", "agentDir": str(custom_dir)}]},
        },
    )

    result = _lock(env_file, home_dir)
    assert result.exit_code == 0, result.output

    custom_models = json.loads((custom_dir / "models.json").read_text())
    entry = custom_models["providers"]["openai"]
    assert entry["apiKey"] == "${OPENAI_API_KEY}", (
        f"custom agentDir's models.json was never scanned — real key survived: {entry!r}"
    )
    assert entry["baseUrl"] == "https://api.openai.com/v1"


def test_scrub_refuses_symlinked_auth_store_file(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_with_agent_caches: dict[str, Path],
    tmp_path: Path,
) -> None:
    """An attacker who can write under ``~/.openclaw/agents/`` must not be
    able to plant ``models.json`` as a symlink to an arbitrary file and have
    the scrub's ``os.replace`` clobber the link TARGET (F-CFG-15) — the
    exact protection ``openclaw.json``'s own writer already has via
    ``_refuse_if_symlink``.
    """
    decoy_target = tmp_path / "decoy.txt"
    decoy_target.write_text("not json, should never be touched\n", encoding="utf-8")

    main_models = openclaw_with_agent_caches["main_models"]
    main_models.unlink()
    main_models.symlink_to(decoy_target)

    result = _lock(env_file, home_dir)
    assert result.exit_code == 0, (
        f"a planted symlink must degrade to best-effort skip, not crash lock:\n{result.output}"
    )
    assert decoy_target.read_text() == "not json, should never be touched\n", (
        "scrub followed the symlink and clobbered a file outside the agent dir"
    )
    assert main_models.is_symlink(), "the symlink itself should be left alone, not replaced"


# ---------------------------------------------------------------------------
# Bugbot findings on the RESTORE side (PR #424 review): the agent-cache
# surface must restore correctly regardless of what openclaw.json's OWN
# entry looked like before lock, must still restore when Stage A never
# runs at all, and must never restore to plaintext before we're sure
# openclaw.json's own restore won't be rolled back.
# ---------------------------------------------------------------------------


def test_unlock_restores_agent_cache_even_when_original_entry_was_secretref(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_with_agent_caches: dict[str, Path],
    real_key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provider whose ORIGINAL openclaw.json entry was already a
    SecretRef (not a literal key) still had a literal real key cached in
    its agent auth stores — scrubbed by lock like any other provider.
    Bugbot catch: unlock only re-read the reconstructed key for
    ``kind == "plaintext"`` entries, silently leaving a secretref-kind
    provider's agent cache scrubbed forever even after a clean unlock.
    """
    monkeypatch.setenv("EXISTING_VAR", "sk-something-unrelated-1234567890")
    openclaw_dir = openclaw_with_agent_caches["openclaw_dir"]
    original_ref = {"$ref": {"source": "env", "provider": "openai", "id": "EXISTING_VAR"}}
    _write_json(
        openclaw_dir / "openclaw.json",
        {
            "models": {
                "providers": {
                    "openai": {"baseUrl": "https://api.openai.com/v1", "apiKey": original_ref}
                }
            }
        },
    )

    locked = _lock(env_file, home_dir)
    assert locked.exit_code == 0, locked.output

    unlocked = _unlock(env_file, home_dir)
    assert unlocked.exit_code == 0, unlocked.output

    # openclaw.json's own entry restored to the ORIGINAL secretref — never
    # downgraded to plaintext.
    after = json.loads((openclaw_dir / "openclaw.json").read_text())
    assert after["models"]["providers"]["openai"]["apiKey"] == original_ref

    # The agent cache — a fully separate surface — must ALSO be restored,
    # even though openclaw.json's own entry never needed the real key.
    models = json.loads(openclaw_with_agent_caches["main_models"].read_text())
    assert models["providers"]["openai"]["apiKey"] == real_key, (
        "agent cache was not restored for a provider whose original "
        "openclaw.json entry was a secretref"
    )


def test_unlock_restores_agent_cache_even_when_openclaw_json_is_missing(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_with_agent_caches: dict[str, Path],
    real_key: str,
) -> None:
    """WOR-621 RT-03: openclaw.json can be deleted between lock and unlock
    — Stage A is skipped entirely in that case (nothing there to restore).
    Bugbot catch: the agent cache is a fully separate surface Stage A
    never touches anyway, so it must still get restored even when Stage A
    itself never runs.
    """
    locked = _lock(env_file, home_dir)
    assert locked.exit_code == 0, locked.output

    (openclaw_with_agent_caches["openclaw_dir"] / "openclaw.json").unlink()

    unlocked = _unlock(env_file, home_dir)
    assert unlocked.exit_code == 0, unlocked.output

    models = json.loads(openclaw_with_agent_caches["main_models"].read_text())
    assert models["providers"]["openai"]["apiKey"] == real_key, (
        "agent cache was not restored when openclaw.json was missing at unlock time"
    )


def test_unlock_rollback_does_not_leave_agent_cache_exposed_in_plaintext(
    sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bugbot HIGH finding: the agent-cache restore used to run BEFORE
    openclaw.json's own per-provider restore succeeded. If a LATER
    provider's write then failed, ``rollback_config`` reverts openclaw.json
    for EVERY provider processed this stage — but an EARLIER provider's
    agent cache would already have been restored to plaintext, leaving a
    plaintext key in the agent cache next to a config entry that reverted
    back to its locked (proxy) shape.

    Exercises ``_apply_unlock_stage_a`` / ``_restore_agent_auth_stores_after_unlock``
    directly (not the full CLI) for precise control over which provider's
    write fails.
    """
    from worthless.openclaw import integration as oc_integration

    openclaw_dir = sandboxed_home / ".openclaw"
    (openclaw_dir / "workspace").mkdir(parents=True)
    original_openai_entry = {"baseUrl": "https://api.openai.com/v1", "apiKey": "sk-original-openai"}
    original_anthropic_entry = {
        "baseUrl": "https://api.anthropic.com/v1",
        "apiKey": "sk-ant-original",
    }
    config_path = openclaw_dir / "openclaw.json"
    _write_json(
        config_path,
        {
            "models": {
                "providers": {
                    "openai": original_openai_entry,
                    "anthropic": original_anthropic_entry,
                }
            }
        },
    )

    agent_dir = openclaw_dir / "agents" / "main" / "agent"
    _write_json(
        agent_dir / "models.json",
        {
            "providers": {
                "openai": {"apiKey": "${OPENAI_API_KEY}", "baseUrl": "https://api.openai.com/v1"}
            }
        },
    )
    _write_json(agent_dir / "auth-profiles.json", {"profiles": {}})

    restores = [
        oc_integration.OcRestore(
            provider="openai",
            alias="openai-alias",
            oc_original_api_key_json=oc_integration.build_oc_rollback_entry_record(
                original_openai_entry
            ),
            plaintext_key=bytearray(b"sk-original-openai"),
            var_name="OPENAI_API_KEY",
        ),
        oc_integration.OcRestore(
            provider="anthropic",
            alias="anthropic-alias",
            oc_original_api_key_json=oc_integration.build_oc_rollback_entry_record(
                original_anthropic_entry
            ),
            plaintext_key=bytearray(b"sk-ant-original"),
            var_name="ANTHROPIC_API_KEY",
        ),
    ]

    # Force the SECOND provider's openclaw.json write to fail.
    real_replace_provider = oc_integration._config_mod.replace_provider
    call_count = {"n": 0}

    def _flaky_replace_provider(path, provider, entry):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise OSError("simulated disk failure")
        return real_replace_provider(path, provider, entry)

    monkeypatch.setattr(oc_integration._config_mod, "replace_provider", _flaky_replace_provider)

    # Snapshot BEFORE Stage A runs — matches apply_unlock's own SM-2
    # symmetry (read the pre-unlock config before any per-provider write).
    original_snapshot = json.loads(config_path.read_text())

    events: list = []
    providers_restored: list[str] = []
    providers_skipped: list[tuple[str, str]] = []
    agent_cache_blocked: set[str] = set()
    rollback_needed = oc_integration._apply_unlock_stage_a(
        config_path, restores, events, providers_restored, providers_skipped, agent_cache_blocked
    )
    assert rollback_needed is True, "the second provider's OSError must trigger a rollback"

    oc_integration.rollback_config(config_path, original_snapshot)

    oc_integration._restore_agent_auth_stores_after_unlock(
        restores,
        sandboxed_home,
        None,
        eligible=set() if rollback_needed else set(providers_restored),
    )

    # THE ASSERTION: openai's agent cache must STILL be scrubbed (${VAR}),
    # NOT restored to plaintext, even though its own openclaw.json write
    # succeeded before anthropic's failed and triggered the rollback.
    models = json.loads((agent_dir / "models.json").read_text())
    assert models["providers"]["openai"]["apiKey"] == "${OPENAI_API_KEY}", (
        "agent cache was restored to plaintext even though the whole-stage "
        "rollback reverted openclaw.json back to its locked shape"
    )
