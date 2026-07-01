"""WOR-777 Layer 2 — re-lock removes worthless's stale agent models.json entry.

OpenClaw runs from ``<.openclaw>/agents/*/agent/models.json``, a projection it
regenerates each turn by MERGING openclaw.json over the existing file — and the
merge PRESERVES the existing apiKey/baseUrl (models-config.merge.ts).  So after
a re-lock rotates openclaw.json, the runtime keeps the OLD shard-A until the
stale projection is gone (confirmed live 2026-06-24).  The fix deletes
worthless's own entry from each agent models.json on lock, so OpenClaw's next
regen takes the new value wholesale (no-existing -> new-wins, merge.ts:227).

RED until ``config.unset_models_json_provider`` and
``integration._apply_lock_neutralize_models_json`` (+ the two event codes) exist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from worthless.openclaw.config import OpenclawConfigError, unset_models_json_provider
from worthless.openclaw.errors import OpenclawErrorCode, OpenclawIntegrationEvent
from worthless.openclaw.integration import _apply_lock_neutralize_models_json

PROXY = "http://127.0.0.1:8787"


def _models_json(provider: str, alias: str, *, api_key: str = "sk-proj-AAAA") -> dict:
    return {
        "providers": {
            provider: {
                "api": "openai-completions",
                "apiKey": api_key,
                "baseUrl": f"{PROXY}/{alias}/v1",
                "models": [],
            }
        }
    }


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


# --------------------------------------------------------------------------- #
# config.unset_models_json_provider — bare ``providers.<X>`` (models.json shape)
# --------------------------------------------------------------------------- #


class TestUnsetModelsJsonProvider:
    def test_removes_provider_and_returns_entry(self, tmp_path: Path) -> None:
        mj = tmp_path / "models.json"
        data = _models_json("openai", "openai-a1")
        data["providers"]["anthropic"] = {"apiKey": "sk-ant-keep", "baseUrl": f"{PROXY}/anth-b2/v1"}
        _write(mj, data)

        removed = unset_models_json_provider(mj, "openai")

        assert removed.get("baseUrl") == f"{PROXY}/openai-a1/v1"
        after = json.loads(mj.read_text(encoding="utf-8"))
        assert "openai" not in after["providers"]
        assert "anthropic" in after["providers"]  # sibling untouched

    def test_absent_provider_returns_empty(self, tmp_path: Path) -> None:
        mj = tmp_path / "models.json"
        _write(mj, _models_json("openai", "openai-a1"))
        assert unset_models_json_provider(mj, "gemini") == {}

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert unset_models_json_provider(tmp_path / "nope.json", "openai") == {}

    def test_symlinked_file_is_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real_models.json"
        _write(real, _models_json("openai", "openai-a1"))
        link = tmp_path / "models.json"
        link.symlink_to(real)
        with pytest.raises(OpenclawConfigError):
            unset_models_json_provider(link, "openai")
        # the symlink target must be left intact (not clobbered)
        assert "openai" in json.loads(real.read_text(encoding="utf-8"))["providers"]


# --------------------------------------------------------------------------- #
# integration._apply_lock_neutralize_models_json — discovery + guarded removal
# --------------------------------------------------------------------------- #


def _openclaw_dir(tmp_path: Path) -> Path:
    d = tmp_path / ".openclaw"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _config_path(oc_dir: Path) -> Path:
    return oc_dir / "openclaw.json"


class TestNeutralizeModelsJson:
    def test_removes_stale_proxy_entry_from_every_agent(self, tmp_path: Path) -> None:
        oc = _openclaw_dir(tmp_path)
        for agent in ("main", "research"):
            _write(
                oc / "agents" / agent / "agent" / "models.json", _models_json("openai", "openai-a1")
            )

        events: list[OpenclawIntegrationEvent] = []
        _apply_lock_neutralize_models_json(_config_path(oc), PROXY, ["openai"], events)

        for agent in ("main", "research"):
            after = json.loads((oc / "agents" / agent / "agent" / "models.json").read_text())
            assert "openai" not in after["providers"]
        removed_events = [
            e for e in events if e.code == OpenclawErrorCode.MODELS_JSON_STALE_REMOVED
        ]
        assert len(removed_events) == 2
        assert all(e.level == "info" for e in removed_events)

    def test_absent_agents_dir_is_silent_noop(self, tmp_path: Path) -> None:
        oc = _openclaw_dir(tmp_path)  # no agents/ subtree at all
        events: list[OpenclawIntegrationEvent] = []
        _apply_lock_neutralize_models_json(_config_path(oc), PROXY, ["openai"], events)
        assert events == []

    def test_empty_providers_set_is_noop(self, tmp_path: Path) -> None:
        oc = _openclaw_dir(tmp_path)
        _write(
            oc / "agents" / "main" / "agent" / "models.json", _models_json("openai", "openai-a1")
        )
        events: list[OpenclawIntegrationEvent] = []
        _apply_lock_neutralize_models_json(_config_path(oc), PROXY, [], events)
        assert events == []
        # entry must still be present (nothing locked -> nothing neutralized)
        after = json.loads((oc / "agents" / "main" / "agent" / "models.json").read_text())
        assert "openai" in after["providers"]

    def test_foreign_non_proxy_entry_is_preserved(self, tmp_path: Path) -> None:
        """A real key under providers.openai with a non-proxy baseUrl is NOT ours —
        must be left intact (we only neutralize our own stale projection)."""
        oc = _openclaw_dir(tmp_path)
        mj = oc / "agents" / "main" / "agent" / "models.json"
        _write(
            mj,
            {
                "providers": {
                    "openai": {"apiKey": "sk-proj-REAL", "baseUrl": "https://api.openai.com/v1"}
                }
            },
        )
        events: list[OpenclawIntegrationEvent] = []
        _apply_lock_neutralize_models_json(_config_path(oc), PROXY, ["openai"], events)
        assert "openai" in json.loads(mj.read_text())["providers"]
        assert all(e.code != OpenclawErrorCode.MODELS_JSON_STALE_REMOVED for e in events)

    def test_env_override_agent_dir_honored(self, tmp_path: Path) -> None:
        oc = _openclaw_dir(tmp_path)
        custom = tmp_path / "custom_agent"
        _write(custom / "models.json", _models_json("openai", "openai-a1"))
        events: list[OpenclawIntegrationEvent] = []
        _apply_lock_neutralize_models_json(
            _config_path(oc), PROXY, ["openai"], events, env={"OPENCLAW_AGENT_DIR": str(custom)}
        )
        assert "openai" not in json.loads((custom / "models.json").read_text())["providers"]

    def test_uncleanable_symlinked_models_json_emits_error_event(self, tmp_path: Path) -> None:
        """An EXISTING but uncleanable models.json (symlink attack vector) is a
        false-secure state — must emit an error-level event (partial failure),
        never a silent pass."""
        oc = _openclaw_dir(tmp_path)
        real = tmp_path / "real_models.json"
        _write(real, _models_json("openai", "openai-a1"))
        link = oc / "agents" / "main" / "agent" / "models.json"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(real)
        events: list[OpenclawIntegrationEvent] = []
        _apply_lock_neutralize_models_json(_config_path(oc), PROXY, ["openai"], events)
        err = [e for e in events if e.code == OpenclawErrorCode.MODELS_JSON_STALE_NOT_REMOVED]
        assert len(err) == 1
        assert err[0].level == "error"
        # symlink target left intact
        assert "openai" in json.loads(real.read_text())["providers"]
