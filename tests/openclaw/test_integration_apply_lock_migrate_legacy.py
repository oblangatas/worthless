"""WOR-656 F6 — ``apply_lock`` auto-heals the legacy OpenClaw decoy layout.

The pre-F1 installer left a proxy-shaped ``worthless-<provider>`` decoy beside
an UNTOUCHED original ``<provider>`` still holding the real key (the WOR-514
bypass). On ``worthless lock`` we now migrate in place: delete the decoy, let
Stage A rewrite the original to proxy+shard-A, and repoint
``agents.defaults.model.primary`` ONLY when it pointed at the decoy. Any write
failure rolls the whole config back. One-way heal — no unlock reversal.

Confirmed decisions under test:
  1. Migrate ONLY providers in ``planned_updates`` (never orphan decoys).
  2. Repoint ``agents.defaults.model.primary`` only (not per-agent).
  3. A single ``LEGACY_DECOY_MIGRATED`` INFO event per migrated decoy.
  4. Full rollback + error event on ANY partial write failure.
  5. SR-04: the attacker-influenceable alias is sanitized+capped in events; the
     decoy apiKey (shard-A) is NEVER logged.

The decoy shape mirrors the committed real-incident fixture
``install_incident/fixtures/openclaw.after-scenario-a.json``.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest.mock import patch


from worthless.openclaw import config as _config
from worthless.openclaw import integration as _integration
from worthless.openclaw.errors import OpenclawErrorCode
from worthless.openclaw.integration import IntegrationState, _MAX_ALIAS_LOG_LEN

PROXY_URL = "http://127.0.0.1:8787"
FIXTURE = Path(__file__).parent / "install_incident" / "fixtures" / "openclaw.after-scenario-a.json"


def _legacy_config(*, primary: str = "openai/gpt-4o") -> dict:
    """A legacy decoy layout: real ``openai`` + proxy-shaped ``worthless-openai``.

    Sibling top-level keys (gateway/channels) mirror what the OpenClaw daemon
    owns and worthless must never touch.
    """
    return {
        "gateway": {"authToken": "oc-gw-SECRET-must-survive", "port": 18789},
        "channels": {
            "discord": {"botToken": "discord-bot-token-must-survive", "enabled": True},
        },
        "agents": {"defaults": {"model": {"primary": primary}}},
        "models": {
            "providers": {
                "openai": {
                    "api": "openai-completions",
                    "apiKey": "sk-REAL-original-key-still-unprotected",
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


def _seed_state(tmp_path: Path, config: dict) -> tuple[Path, IntegrationState]:
    """Write ``config`` to a sandboxed openclaw.json and return (path, state).

    Seeds via ``_atomic_write_json`` so on-disk bytes match what a rollback
    write would produce (sort_keys + indent) — required for byte-identical
    assertions. ``workspace_path=None`` keeps Stage B (skill install) out of
    the way so tests stay focused on config behaviour.
    """
    oc = tmp_path / ".openclaw"
    oc.mkdir()
    cfg = oc / "openclaw.json"
    _config._atomic_write_json(cfg, copy.deepcopy(config))
    state = IntegrationState(
        present=True,
        config_path=cfg,
        workspace_path=None,
        skill_path=None,
        home_dir=oc.parent,
        notes=(),
    )
    return cfg, state


def _providers(cfg: Path) -> dict:
    return json.loads(cfg.read_text(encoding="utf-8"))["models"]["providers"]


def _event_strings(events) -> list[str]:  # type: ignore[no-untyped-def]
    out: list[str] = []
    for e in events:
        out.append(e.detail)
        for v in (e.extra or {}).values():
            out.append(str(v))
    return out


# ---------------------------------------------------------------------------
# 1. Happy path — legacy decoy migrated on the real-incident fixture shape
# ---------------------------------------------------------------------------


def test_migrate_happy_path_deletes_decoy_and_rewrites_original(tmp_path: Path) -> None:
    """Legacy fixture → after apply_lock: ``worthless-openai`` gone, ``openai``
    rewritten to proxy+shard-A, sibling daemon keys untouched.
    """
    fixture_config = json.loads(FIXTURE.read_text(encoding="utf-8"))
    cfg, state = _seed_state(tmp_path, fixture_config)

    with patch.object(_integration, "detect", return_value=state):
        result = _integration.apply_lock(
            [("openai", "openai-new99999", "sk-shard-a-new")],
            proxy_base_url=PROXY_URL,
        )

    providers = _providers(cfg)
    assert "worthless-openai" not in providers, "legacy decoy must be deleted"
    assert providers["openai"]["baseUrl"] == f"{PROXY_URL}/openai-new99999/v1"
    assert providers["openai"]["apiKey"] == "sk-shard-a-new"

    # Sibling top-level keys the daemon owns must survive verbatim.
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["gateway"]["authToken"] == "oc-gw-SECRET-must-survive"
    assert data["channels"]["discord"]["botToken"] == "discord-bot-token-must-survive"

    assert any(e.code == OpenclawErrorCode.LEGACY_DECOY_MIGRATED for e in result.events), [
        e.code for e in result.events
    ]


# ---------------------------------------------------------------------------
# 2. Primary repoint — ONLY when the default model points at the decoy
# ---------------------------------------------------------------------------


def test_migrate_repoints_primary_off_decoy(tmp_path: Path) -> None:
    """primary ``worthless-openai/gpt-4o`` → ``openai/gpt-4o`` after migration."""
    cfg, state = _seed_state(tmp_path, _legacy_config(primary="worthless-openai/gpt-4o"))

    with patch.object(_integration, "detect", return_value=state):
        _integration.apply_lock(
            [("openai", "openai-new99999", "sk-shard-a-new")],
            proxy_base_url=PROXY_URL,
        )

    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["agents"]["defaults"]["model"]["primary"] == "openai/gpt-4o"
    assert "worthless-openai" not in data["models"]["providers"]


def test_migrate_leaves_non_decoy_primary_untouched(tmp_path: Path) -> None:
    """primary already ``openai/gpt-4o`` stays unchanged (decoy still deleted)."""
    cfg, state = _seed_state(tmp_path, _legacy_config(primary="openai/gpt-4o"))

    with patch.object(_integration, "detect", return_value=state):
        _integration.apply_lock(
            [("openai", "openai-new99999", "sk-shard-a-new")],
            proxy_base_url=PROXY_URL,
        )

    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["agents"]["defaults"]["model"]["primary"] == "openai/gpt-4o"
    assert "worthless-openai" not in data["models"]["providers"]


# ---------------------------------------------------------------------------
# 3. Siblings untouched — only providers in planned_updates are migrated
# ---------------------------------------------------------------------------


def test_migrate_leaves_unplanned_siblings_intact(tmp_path: Path) -> None:
    """An unrelated ``anthropic`` + ``worthless-anthropic`` pair must NOT be
    touched when only ``openai`` is in planned_updates.
    """
    config = _legacy_config(primary="openai/gpt-4o")
    config["models"]["providers"]["anthropic"] = {
        "api": "anthropic-messages",
        "apiKey": "sk-ant-REAL-original",
        "baseUrl": "https://api.anthropic.com/v1",
        "models": [{"id": "claude-3-5-sonnet"}],
    }
    config["models"]["providers"]["worthless-anthropic"] = {
        "api": "anthropic-messages",
        "apiKey": "sk-ant-DECOY-shard-a",
        "baseUrl": "http://127.0.0.1:8787/anthropic-bbbb2222/v1",
        "models": [],
    }
    cfg, state = _seed_state(tmp_path, config)
    anthropic_before = copy.deepcopy(config["models"]["providers"]["anthropic"])
    worthless_anthropic_before = copy.deepcopy(config["models"]["providers"]["worthless-anthropic"])

    with patch.object(_integration, "detect", return_value=state):
        _integration.apply_lock(
            [("openai", "openai-new99999", "sk-shard-a-new")],
            proxy_base_url=PROXY_URL,
        )

    providers = _providers(cfg)
    # openai's decoy is gone…
    assert "worthless-openai" not in providers
    # …but the anthropic pair (not in planned_updates) is byte-for-byte intact.
    assert providers["anthropic"] == anthropic_before
    assert providers["worthless-anthropic"] == worthless_anthropic_before


# ---------------------------------------------------------------------------
# 4. Fail-safe — any write failure rolls back to a byte-identical config
# ---------------------------------------------------------------------------


def test_migrate_write_failure_rolls_back_byte_identical(tmp_path: Path) -> None:
    """os.replace raises mid-migration → full rollback: config byte-identical to
    the original snapshot, decoy still present, an error event surfaced.
    """
    cfg, state = _seed_state(tmp_path, _legacy_config(primary="worthless-openai/gpt-4o"))
    original_bytes = cfg.read_bytes()

    with (
        patch.object(_integration, "detect", return_value=state),
        patch("os.replace", side_effect=OSError("simulated disk full mid-migration")),
    ):
        result = _integration.apply_lock(
            [("openai", "openai-new99999", "sk-shard-a-new")],
            proxy_base_url=PROXY_URL,
        )

    # No partial state: atomic writes never completed, rollback restored nothing new.
    assert cfg.read_bytes() == original_bytes
    assert "worthless-openai" in _providers(cfg), "decoy must not be half-deleted"
    assert result.has_failure
    assert any(e.level == "error" for e in result.events), [
        (e.code, e.level) for e in result.events
    ]


# ---------------------------------------------------------------------------
# 5. No-op — already new-design (no decoy) is idempotent
# ---------------------------------------------------------------------------


def test_migrate_noop_when_already_new_design(tmp_path: Path) -> None:
    """No ``worthless-*`` decoy → no migration event, config byte-identical."""
    new_design = {
        "gateway": {"authToken": "oc-gw-SECRET-must-survive", "port": 18789},
        "agents": {"defaults": {"model": {"primary": "openai/gpt-4o"}}},
        "models": {
            "providers": {
                "openai": {
                    "api": "openai-completions",
                    "apiKey": "sk-shard-existing",
                    "baseUrl": "http://127.0.0.1:8787/openai-existing1/v1",
                    "models": [],
                },
            },
        },
    }
    cfg, state = _seed_state(tmp_path, new_design)
    original_bytes = cfg.read_bytes()

    with patch.object(_integration, "detect", return_value=state):
        result = _integration.apply_lock(
            [("openai", "openai-existing1", "sk-shard-existing")],
            proxy_base_url=PROXY_URL,
        )

    assert not any(e.code == OpenclawErrorCode.LEGACY_DECOY_MIGRATED for e in result.events), (
        "must not emit a migration event when there is no decoy"
    )
    assert cfg.read_bytes() == original_bytes, "re-lock on new-design must be byte-identical"


# ---------------------------------------------------------------------------
# 6. SR-04 — decoy alias sanitized+capped; decoy apiKey never logged
# ---------------------------------------------------------------------------


def test_migrate_events_redact_alias_and_never_log_shard_a(tmp_path: Path) -> None:
    """A decoy carrying a long alias + a key-shaped/control-char apiKey → the
    migration events contain no control chars, never the shard-A value, and the
    alias is sanitized + length-capped.
    """
    long_alias = "openai-" + "A" * 80  # 87 chars → forces the _MAX_ALIAS_LOG_LEN cap
    config = _legacy_config(primary="openai/gpt-4o")
    decoy = config["models"]["providers"]["worthless-openai"]
    decoy["baseUrl"] = f"http://127.0.0.1:8787/{long_alias}/v1"
    # Control chars + a key-shaped secret that must never reach any event.
    decoy["apiKey"] = "sk-DECOY-\x1b[31mSECRET\x00-SHARD-A-VALUE"
    cfg, state = _seed_state(tmp_path, config)

    with patch.object(_integration, "detect", return_value=state):
        result = _integration.apply_lock(
            [("openai", "openai-new99999", "sk-shard-a-new")],
            proxy_base_url=PROXY_URL,
        )

    migrated = [e for e in result.events if e.code == OpenclawErrorCode.LEGACY_DECOY_MIGRATED]
    assert migrated, "expected a LEGACY_DECOY_MIGRATED event"

    all_text = "".join(_event_strings(result.events))
    # No terminal-injection bytes leaked from the attacker-controlled config.
    assert "\x1b" not in all_text and "\x00" not in all_text
    # The decoy apiKey (shard-A half) must never appear in any event (SR-04).
    assert "SHARD-A-VALUE" not in all_text
    # The alias is capped: the full 80-char run is not echoed verbatim.
    assert "A" * 80 not in all_text
    alias_val = (migrated[0].extra or {}).get("alias", "")
    assert alias_val.endswith("…"), f"alias not truncated: {alias_val!r}"
    assert len(alias_val) <= _MAX_ALIAS_LOG_LEN + 1
