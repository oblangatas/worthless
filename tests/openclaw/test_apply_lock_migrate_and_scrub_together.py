"""Cross-feature guard: a SINGLE ``apply_lock`` both heals a legacy decoy
layout (WOR-656) AND scrubs the real key cached in OpenClaw's agent auth
stores (WOR-796), with neither stage clobbering the other.

The two features were built on separate branches and merged. Each has its own
suite (``test_integration_apply_lock_migrate_legacy`` /
``test_lock_scrubs_agent_auth_stores``), but nothing exercised them on ONE home
in ONE lock — exactly the interaction a bad merge (wiring only one stage, or
letting one stage's write undo the other) would silently break. This is that
guard.

Staging order under test:
  * openclaw.json is in the pre-F1 decoy layout (real ``openai`` still holding
    the real key beside our proxy-shaped ``worthless-openai`` decoy) → the
    Stage A-pre legacy-decoy migration must fire.
  * agents/main/agent/{models.json,auth-profiles.json} literally cache the same
    real key → the Stage A2 scrub must fire.
One ``apply_lock`` → both effects on disk, both events emitted.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from worthless.cli.key_patterns import KEY_PATTERN
from worthless.openclaw import config as _config
from worthless.openclaw import integration as _integration
from worthless.openclaw.errors import OpenclawErrorCode
from worthless.openclaw.integration import IntegrationState

from tests.helpers import fake_openai_key

PROXY_URL = "http://127.0.0.1:8787"


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _legacy_config_holding_real_key(real_key: str) -> dict:
    """openclaw.json in the pre-F1 decoy layout: real ``openai`` (real key) plus
    our proxy-shaped ``worthless-openai`` decoy, with the default model pointed
    at the decoy so the WOR-656 repoint path also runs.
    """
    return {
        "gateway": {"authToken": "oc-gw-SECRET-must-survive", "port": 18789},
        "agents": {"defaults": {"model": {"primary": "worthless-openai/gpt-4o"}}},
        "models": {
            "providers": {
                "openai": {
                    "api": "openai-completions",
                    "apiKey": real_key,
                    "baseUrl": "https://api.openai.com/v1",
                    "models": [{"id": "gpt-4o"}],
                },
                "worthless-openai": {
                    "api": "openai-completions",
                    "apiKey": "sk-DECOY-shard-a-value-should-be-deleted",
                    "baseUrl": "http://127.0.0.1:8787/openai-558dd0d8/v1",
                    "models": [],
                },
            },
        },
    }


def _seed(tmp_path: Path, real_key: str) -> tuple[Path, IntegrationState, Path, Path]:
    """Stage a home that needs BOTH heals: decoy-layout openclaw.json + an agent
    dir whose models.json/auth-profiles.json cache the real key literally.
    """
    oc = tmp_path / ".openclaw"
    oc.mkdir()
    cfg = oc / "openclaw.json"
    _config._atomic_write_json(cfg, _legacy_config_holding_real_key(real_key))

    agent_dir = oc / "agents" / "main" / "agent"
    models_path = agent_dir / "models.json"
    auth_path = agent_dir / "auth-profiles.json"
    _write_json(
        models_path,
        {"providers": {"openai": {"apiKey": real_key, "baseUrl": "https://api.openai.com/v1"}}},
    )
    _write_json(
        auth_path,
        {
            "version": 1,
            "profiles": {
                "main-openai": {"type": "api_key", "provider": "openai", "key": real_key},
            },
        },
    )
    state = IntegrationState(
        present=True,
        config_path=cfg,
        workspace_path=None,
        skill_path=None,
        home_dir=oc.parent,
        notes=(),
    )
    return cfg, state, models_path, auth_path


def test_single_lock_migrates_decoy_and_scrubs_agent_stores(tmp_path: Path) -> None:
    real_key = fake_openai_key()
    cfg, state, models_path, auth_path = _seed(tmp_path, real_key)

    with patch.object(_integration, "detect", return_value=state):
        result = _integration.apply_lock(
            [("openai", "openai-new99999", "sk-shard-a-new")],
            proxy_base_url=PROXY_URL,
            env_var_by_alias={"openai-new99999": "OPENAI_API_KEY"},
        )

    codes = [e.code for e in result.events]

    # --- WOR-656: legacy decoy healed in openclaw.json --------------------
    data = json.loads(cfg.read_text(encoding="utf-8"))
    providers = data["models"]["providers"]
    assert "worthless-openai" not in providers, "legacy decoy must be deleted"
    assert providers["openai"]["baseUrl"] == f"{PROXY_URL}/openai-new99999/v1"
    assert providers["openai"]["apiKey"] == "sk-shard-a-new"
    assert data["agents"]["defaults"]["model"]["primary"] == "openai/gpt-4o", (
        "default model must be repointed off the removed decoy"
    )
    assert data["gateway"]["authToken"] == "oc-gw-SECRET-must-survive", (
        "sibling daemon-owned keys must survive the migration"
    )
    assert OpenclawErrorCode.LEGACY_DECOY_MIGRATED in codes, codes

    # --- WOR-796: real key scrubbed from BOTH agent stores ----------------
    models = json.loads(models_path.read_text(encoding="utf-8"))
    profiles = json.loads(auth_path.read_text(encoding="utf-8"))
    assert models["providers"]["openai"]["apiKey"] == "${OPENAI_API_KEY}", models
    assert profiles["profiles"]["main-openai"]["key"] == "${OPENAI_API_KEY}", profiles
    assert real_key not in models_path.read_text(encoding="utf-8")
    assert real_key not in auth_path.read_text(encoding="utf-8")
    assert not KEY_PATTERN.search(json.dumps(models)), "models.json still has a key-shaped value"
    assert not KEY_PATTERN.search(json.dumps(profiles)), (
        "auth-profiles still has a key-shaped value"
    )
    assert OpenclawErrorCode.AGENT_AUTH_STORE_SCRUBBED in codes, codes

    # --- both stages ran in ONE lock; the scrub only touches cleanly-written
    #     providers, so openai must have survived Stage A -------------------
    assert "openai" in result.providers_set, result.providers_set
