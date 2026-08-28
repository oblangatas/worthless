"""Phase 2.e — failure-injection harness for atomic-write + skill-copy paths.

Spec: ``engineering/research/openclaw/WOR-431-phase-2-spec.md`` § "Phase
2.e" rows GAP-INJ20 / INJ21 / INJ33. Mock-patches ``os.replace`` /
``os.fsync`` / the skill-asset copy loop to drive ENOSPC / EACCES /
mid-copy failures and assert:

  - the pre-existing on-disk file (or skill folder) is byte-identical
    after the failure (atomic-write contract holds)
  - no orphan temp/staging artifacts remain
  - a structured WRITE_FAILED / SKILL_INSTALL_FAILED event surfaces

These tests do NOT cross process boundaries — they patch in-process
attributes on the module under test. Per F-XS-40/41 contract they
also assert ``apply_lock`` does NOT raise (lock-core success contract).
"""

from __future__ import annotations

import errno
import json
from pathlib import Path

import pytest


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture
def openclaw_present(fake_home: Path) -> dict[str, Path]:
    """Pre-seed openclaw.json with a sentinel entry to byte-compare against."""
    openclaw_dir = fake_home / ".openclaw"
    workspace = openclaw_dir / "workspace"
    workspace.mkdir(parents=True)
    config_path = openclaw_dir / "openclaw.json"
    config_path.write_text(
        json.dumps(
            {
                "models": {
                    "providers": {
                        "preexisting-canary": {
                            "baseUrl": "https://canary.example.com/v1",
                            "apiKey": "must-not-be-clobbered",
                            "api": "openai-completions",
                            "models": [],
                        }
                    }
                }
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return {"home": fake_home, "workspace": workspace, "config_path": config_path}


def _list_temp_artifacts(parent: Path, prefix: str) -> list[str]:
    """Names of any leftover ``<prefix>...`` ``.tmp`` artifacts in ``parent``.

    ``_atomic_write_json`` uses ``mkstemp(prefix=f".{path.name}.", suffix=".tmp")``
    so we filter on the ``.tmp`` suffix to exclude the always-present
    ``.openclaw.json.lock`` flock sentinel which shares the prefix.
    For skill staging, ``skill.install`` uses
    ``mkdtemp(prefix=f".worthless.tmp.{pid}.")`` which lands as a directory —
    callers pass the matching prefix.
    """
    if not parent.exists():
        return []
    return sorted(
        p.name
        for p in parent.iterdir()
        if p.name.startswith(prefix) and (p.name.endswith(".tmp") or ".tmp." in p.name)
    )


# ---------------------------------------------------------------------------
# INJ-20: EACCES on os.replace during atomic-write
# ---------------------------------------------------------------------------


def test_inj20_eacces_on_os_replace_preserves_file_and_emits_event(
    openclaw_present: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """INJ-20: ``os.replace`` raises EACCES → pre-existing openclaw.json
    untouched, no leftover ``.openclaw.json.<pid>.tmp``, structured
    WRITE_FAILED event surfaces.

    The atomic-write contract is: serialize to tempfile + fsync +
    replace. A failure at the replace step must leave the user's file
    intact (the whole reason we go through tempfile-replace dance).
    """
    from worthless.openclaw import config as config_mod
    from worthless.openclaw import integration
    from worthless.openclaw.errors import OpenclawErrorCode

    monkeypatch.chdir(openclaw_present["home"])
    config_path = openclaw_present["config_path"]

    before = config_path.read_bytes()

    def _eacces(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.EACCES, "simulated EACCES on replace")

    monkeypatch.setattr(config_mod.os, "replace", _eacces)

    result = integration.apply_lock(
        planned_updates=[("openai", "openai-aaaa1111", "sk-shard-fresh")],
    )

    # Contract: did NOT raise; reported the failure structurally.
    assert result.detected is True
    assert "worthless-openai" not in result.providers_set
    assert any(e.code == OpenclawErrorCode.WRITE_FAILED for e in result.events), [
        e.code for e in result.events
    ]

    # Pre-existing file is byte-identical.
    after = config_path.read_bytes()
    assert after == before, "atomic-write contract violated: file mutated despite replace failure"

    # No orphan temp file in the parent dir.
    leftovers = _list_temp_artifacts(config_path.parent, f".{config_path.name}.")
    assert leftovers == [], f"orphan temp file(s): {leftovers}"


# ---------------------------------------------------------------------------
# INJ-21: ENOSPC on os.fsync mid-write
# ---------------------------------------------------------------------------


def test_inj21_enospc_on_fsync_preserves_file_and_emits_event(
    openclaw_present: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """INJ-21: ``os.fsync`` raises ENOSPC → pre-existing openclaw.json
    untouched, no leftover tempfile, structured WRITE_FAILED event.

    fsync fails BEFORE replace runs, so the failure must propagate out
    of the with-block, the tempfile cleanup must fire, and replace must
    never have been called.
    """
    from worthless.openclaw import config as config_mod
    from worthless.openclaw import integration
    from worthless.openclaw.errors import OpenclawErrorCode

    monkeypatch.chdir(openclaw_present["home"])
    config_path = openclaw_present["config_path"]
    before = config_path.read_bytes()

    def _enospc(_fd: int) -> None:
        raise OSError(errno.ENOSPC, "simulated ENOSPC on fsync")

    monkeypatch.setattr(config_mod.os, "fsync", _enospc)

    result = integration.apply_lock(
        planned_updates=[("openai", "openai-aaaa1111", "sk-shard-fresh")],
    )

    assert result.detected is True
    assert "worthless-openai" not in result.providers_set
    assert any(e.code == OpenclawErrorCode.WRITE_FAILED for e in result.events), [
        e.code for e in result.events
    ]

    after = config_path.read_bytes()
    assert after == before, "fsync failure leaked partial bytes into config"

    leftovers = _list_temp_artifacts(config_path.parent, f".{config_path.name}.")
    assert leftovers == [], f"orphan temp file(s) after fsync failure: {leftovers}"


# ---------------------------------------------------------------------------
# INJ-33: disk-full mid-copy in skill install — staging cleanup + intact prior
# ---------------------------------------------------------------------------


def test_inj33_skill_copy_failure_cleans_staging_and_preserves_existing(
    openclaw_present: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """INJ-33: skill-asset copy raises mid-loop → staging dir cleaned,
    existing skill folder untouched, SKILL_INSTALL_FAILED event surfaces.

    Pre-stages an existing ``workspace/skills/worthless/`` with sentinel
    content, then runs apply_lock with the copy loop patched to raise on
    writes inside the staging dir. The existing folder must survive
    byte-identical because ``rmtree(final, ignore_errors=True)`` runs
    AFTER asset-copy in skill.install — a copy failure means we never
    reach the rmtree, so ``final`` is intact.
    """
    from worthless.openclaw import integration
    from worthless.openclaw.errors import OpenclawErrorCode

    monkeypatch.chdir(openclaw_present["home"])
    workspace = openclaw_present["workspace"]
    skills_dir = workspace / "skills"
    skills_dir.mkdir(parents=True, exist_ok=True)

    # Pre-stage existing skill folder with sentinel.
    existing = skills_dir / "worthless"
    existing.mkdir()
    sentinel = existing / "SKILL.md"
    sentinel.write_text("# pre-existing sentinel — must survive\n", encoding="utf-8")
    sentinel_bytes = sentinel.read_bytes()

    real_write_text = Path.write_text

    def _failing_write_text(self: Path, *args: object, **kwargs: object) -> int:
        # Only fail writes happening inside a .worthless.tmp staging dir
        # (i.e., the install path), not unrelated test infra writes.
        if ".worthless.tmp." in str(self):
            raise OSError(errno.ENOSPC, "simulated ENOSPC mid-copy")
        return real_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", _failing_write_text)

    result = integration.apply_lock(
        planned_updates=[("openai", "openai-aaaa1111", "sk-shard-a")],
    )

    # apply_lock contract: did not raise.
    assert result.detected is True
    assert result.skill_installed is False
    assert any(e.code == OpenclawErrorCode.SKILL_INSTALL_FAILED for e in result.events), [
        e.code for e in result.events
    ]

    # Existing skill folder untouched.
    assert existing.is_dir()
    assert sentinel.read_bytes() == sentinel_bytes, "existing skill folder was clobbered"

    # No orphan staging dirs.
    leftovers = _list_temp_artifacts(skills_dir, ".worthless.tmp.")
    assert leftovers == [], f"orphan staging dir(s): {leftovers}"


# ---------------------------------------------------------------------------
# WOR-507: proxy_base_url host validation
# ---------------------------------------------------------------------------


class TestProxyBaseUrlValidation:
    """apply_lock must reject non-localhost proxy_base_url values (WOR-507).

    An attacker who controls the MCP config can supply a remote URL as
    proxy_base_url, causing the CLI to point enrolled keys at an exfiltration
    endpoint. The fix: validate the hostname against an allowlist before any
    config I/O begins, raising ValueError immediately.

    Both tests are RED before the fix: apply_lock accepts any URL today.
    """

    def test_apply_lock_rejects_attacker_url(
        self, fake_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """apply_lock raises ValueError when proxy_base_url points to a remote host."""
        from worthless.openclaw import integration

        monkeypatch.chdir(fake_home)
        with pytest.raises(ValueError, match="proxy_base_url"):
            integration.apply_lock(
                planned_updates=[("openai", "openai-aaaa1111", "sk-shard-a")],
                proxy_base_url="http://attacker.com/steal",
            )

    def test_apply_lock_rejects_cloud_metadata_ssrf(
        self, fake_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """apply_lock raises ValueError for SSRF to cloud metadata (169.254.x.x)."""
        from worthless.openclaw import integration

        monkeypatch.chdir(fake_home)
        with pytest.raises(ValueError, match="proxy_base_url"):
            integration.apply_lock(
                planned_updates=[("openai", "openai-aaaa1111", "sk-shard-a")],
                proxy_base_url="http://169.254.169.254/latest/meta-data/",
            )
