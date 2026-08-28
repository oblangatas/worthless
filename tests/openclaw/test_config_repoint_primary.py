"""Unit tests for ``config.repoint_model_primary`` (WOR-656 F6).

The legacy-decoy heal moves OpenClaw's default model off a
``worthless-<provider>`` decoy and onto the original ``<provider>``. That
repoint is a surgical, exact-match swap of ``agents.defaults.model.primary``
under the SAME flock + symlink-refusal + atomic-write contract as
:func:`worthless.openclaw.config.unset_provider`.

RED-first: ``repoint_model_primary`` does not exist yet — these tests fail on
import/attribute until it lands.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from worthless.openclaw import config as _config
from worthless.openclaw.config import OpenclawConfigError, repoint_model_primary

OLD_REF = "worthless-openai/gpt-4o"
NEW_REF = "openai/gpt-4o"


def _write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _base_config(primary: str) -> dict:
    """A config with a default-model pointer + unrelated sibling keys."""
    return {
        "gateway": {"authToken": "oc-gw-SECRET-must-survive", "port": 18789},
        "agents": {"defaults": {"model": {"primary": primary}}},
        "models": {"providers": {"openai": {"baseUrl": "https://api.openai.com/v1"}}},
    }


def test_repoint_changes_primary_on_exact_match(tmp_path: Path) -> None:
    """Exact match → primary is rewritten, unrelated keys preserved, returns True."""
    cfg = tmp_path / "openclaw.json"
    _write(cfg, _base_config(OLD_REF))

    changed = repoint_model_primary(cfg, old_ref=OLD_REF, new_ref=NEW_REF)

    assert changed is True
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["agents"]["defaults"]["model"]["primary"] == NEW_REF
    # Surgical read-modify-write: sibling keys must survive untouched.
    assert data["gateway"]["authToken"] == "oc-gw-SECRET-must-survive"
    assert data["models"]["providers"]["openai"]["baseUrl"] == "https://api.openai.com/v1"


def test_repoint_noop_when_primary_differs(tmp_path: Path) -> None:
    """A primary that does NOT equal old_ref → no write, byte-identical, returns False."""
    cfg = tmp_path / "openclaw.json"
    _write(cfg, _base_config("openai/gpt-4o"))
    original_bytes = cfg.read_bytes()

    changed = repoint_model_primary(cfg, old_ref=OLD_REF, new_ref=NEW_REF)

    assert changed is False
    assert cfg.read_bytes() == original_bytes


def test_repoint_noop_when_primary_absent(tmp_path: Path) -> None:
    """No agents.defaults.model.primary at all → no crash, no write, returns False."""
    cfg = tmp_path / "openclaw.json"
    _write(cfg, {"models": {"providers": {}}})
    original_bytes = cfg.read_bytes()

    changed = repoint_model_primary(cfg, old_ref=OLD_REF, new_ref=NEW_REF)

    assert changed is False
    assert cfg.read_bytes() == original_bytes


def test_repoint_refuses_symlink(tmp_path: Path) -> None:
    """F-CFG-15: a symlinked config is refused (OpenclawConfigError), target untouched."""
    real = tmp_path / "real.json"
    _write(real, _base_config(OLD_REF))
    link = tmp_path / "openclaw.json"
    link.symlink_to(real)

    with pytest.raises(OpenclawConfigError):
        repoint_model_primary(link, old_ref=OLD_REF, new_ref=NEW_REF)

    # The link target must NOT be rewritten through the symlink.
    restored = json.loads(real.read_text(encoding="utf-8"))
    assert restored["agents"]["defaults"]["model"]["primary"] == OLD_REF


def test_repoint_uses_atomic_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The rewrite must go through os.replace (atomic) so a crash cannot tear the file."""
    cfg = tmp_path / "openclaw.json"
    _write(cfg, _base_config(OLD_REF))

    calls: list[tuple] = []
    real_replace = _config.os.replace

    def _tracking_replace(src, dst):  # type: ignore[no-untyped-def]
        calls.append((src, dst))
        return real_replace(src, dst)

    monkeypatch.setattr(_config.os, "replace", _tracking_replace)

    changed = repoint_model_primary(cfg, old_ref=OLD_REF, new_ref=NEW_REF)

    assert changed is True
    assert calls, "repoint_model_primary must use os.replace (atomic write)"
