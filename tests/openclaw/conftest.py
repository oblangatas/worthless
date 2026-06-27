"""Shared fixtures for ``tests/openclaw/`` integration tests.

Three fixtures lifted from `test_integration_apply_lock.py`,
`test_integration_apply_unlock.py`, and
`test_integration_idempotency.py` (byte-identical bodies before this
extraction). Tests that need a different fixture shape — e.g.
``test_integration_injection.py`` pre-seeds a sentinel entry for
byte-comparison; ``test_integration_concurrency.py`` skips ``monkeypatch``
because spawned children don't inherit it; ``test_trust_fix.py`` uses
``sandboxed_home`` and adds an ``env_file`` — define their own
overrides at the test-file level (pytest resolves the closest fixture).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pin HOME at a tmp_path-rooted dir so ``detect()`` probes the sandbox.

    ``apply_lock`` / ``apply_unlock`` call ``detect()`` which reads
    ``Path.home()``. Without this, the developer's real ``~/.openclaw/``
    leaks into tests on machines where OpenClaw is installed.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    # Defensive: ``locate_config_path()`` checks ``./openclaw.json`` BEFORE
    # ``~/.openclaw/openclaw.json``. Without chdir, a project-local
    # openclaw.json in pytest's cwd would shadow the sandboxed home.
    monkeypatch.chdir(home)
    return home


@pytest.fixture
def openclaw_present(fake_home: Path) -> dict[str, Path]:
    """Pre-stage ``~/.openclaw/`` with workspace and an empty openclaw.json.

    Returns ``{home, workspace, config_path}`` for tests that need to
    assert on the on-disk artifacts. Default config has empty
    ``providers`` — tests that need a sentinel pre-seed (e.g. injection
    tests doing byte-identical comparisons) override this fixture
    locally.
    """
    openclaw_dir = fake_home / ".openclaw"
    workspace = openclaw_dir / "workspace"
    workspace.mkdir(parents=True)
    config_path = openclaw_dir / "openclaw.json"
    config_path.write_text(
        json.dumps({"models": {"providers": {}}}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {"home": fake_home, "workspace": workspace, "config_path": config_path}
