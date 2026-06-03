"""Phase 2.e — idempotency harness covering re-runs and crash recovery.

Spec: ``engineering/research/openclaw/WOR-431-phase-2-spec.md`` § "Phase
2.e" rows IDEM-24 / IDEM-42.

IDEM-24 pins ``apply_lock`` to byte-level reproducibility — same input,
byte-identical openclaw.json. The existing
``test_apply_lock_is_idempotent`` only asserts on shape; this test
catches a regression where field-ordering or whitespace drifts between
calls (which would manifest as gratuitous git churn for users who track
their openclaw.json in dotfiles).

IDEM-42 simulates a SIGKILL between Stage A (config write) and Stage B
(skill install): the next run must reconcile — final state has the
config entry intact AND the skill folder installed, with no orphan
``.worthless.tmp.*`` dirs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# ``fake_home`` + ``openclaw_present`` come from ``tests/openclaw/conftest.py``.


# ---------------------------------------------------------------------------
# IDEM-24: byte-identical openclaw.json after two apply_lock calls
# ---------------------------------------------------------------------------


def test_idem24_apply_lock_twice_byte_identical(
    openclaw_present: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """IDEM-24: ``apply_lock`` twice with same input ⇒ byte-identical config.

    Stronger than ``test_apply_lock_is_idempotent`` (shape-only). This
    pins the on-disk JSON down to whitespace and key order so:

      - field-ordering drift surfaces as a test failure (not as silent
        git churn for users tracking dotfiles)
      - whitespace drift (trailing newline, indent shifts) is caught
      - any future "stamp last-mutated-at" timestamp into the entry
        instantly fails this test (forcing the dev to opt in)
    """
    from worthless.openclaw import integration

    monkeypatch.chdir(openclaw_present["home"])
    planned = [
        ("openai", "openai-aaaa1111", "sk-shard-a-openai"),
        ("anthropic", "anthropic-bbbb2222", "sk-shard-a-anthropic"),
    ]

    integration.apply_lock(planned_updates=planned)
    after_first = openclaw_present["config_path"].read_bytes()

    integration.apply_lock(planned_updates=planned)
    after_second = openclaw_present["config_path"].read_bytes()

    assert after_first == after_second, (
        f"apply_lock is not byte-idempotent: first={after_first!r}\nsecond={after_second!r}"
    )


# ---------------------------------------------------------------------------
# IDEM-42: simulated mid-stage crash, next run reconciles
# ---------------------------------------------------------------------------


def test_idem42_crash_between_stages_then_reconcile(
    openclaw_present: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """IDEM-42: SIGKILL between Stage A and Stage B → next ``apply_lock``
    reconciles to the fully-installed state.

    Simulates the kill by mocking ``_skill_mod.install`` to raise on the
    FIRST invocation only. After the first apply_lock returns:
      - Stage A succeeded: openclaw.json has the provider entry
      - Stage B failed: skill folder absent, SKILL_INSTALL_FAILED event
      - no orphan staging dirs in workspace/skills/

    Then the mock is removed and apply_lock is invoked again with the
    same input. Expected:
      - config entry still present (idempotent re-write, byte-identical
        to the post-first-run state)
      - skill folder NOW present
      - no orphan staging dirs
      - second run's events reflect a fresh CONFIG_UPDATED + a successful
        skill install (no leftover SKILL_INSTALL_FAILED from the first run)
    """
    from worthless.openclaw import integration, skill
    from worthless.openclaw.errors import (
        OpenclawErrorCode,
        OpenclawIntegrationError,
    )

    monkeypatch.chdir(openclaw_present["home"])
    workspace = openclaw_present["workspace"]
    skills_dir = workspace / "skills"

    real_install = skill.install
    call_count = {"n": 0}

    def _install_kill_first(target_dir: Path) -> Path:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise OpenclawIntegrationError(
                OpenclawErrorCode.SKILL_INSTALL_FAILED,
                "simulated SIGKILL mid-stage-B",
            )
        return real_install(target_dir)

    # Patch the symbol the integration module imported (``_skill_mod.install``).
    monkeypatch.setattr(integration._skill_mod, "install", _install_kill_first)

    planned = [("openai", "openai-aaaa1111", "sk-shard-a")]

    # First call: Stage A succeeds, Stage B fails.
    first = integration.apply_lock(planned_updates=planned)
    assert first.detected is True
    assert "worthless-openai" in first.providers_set, "Stage A did not commit"
    assert first.skill_installed is False
    assert any(e.code == OpenclawErrorCode.SKILL_INSTALL_FAILED for e in first.events), (
        "expected SKILL_INSTALL_FAILED from first call"
    )
    assert not (skills_dir / "worthless").exists(), "skill folder leaked despite Stage B failure"

    # No orphan staging tempdirs.
    if skills_dir.exists():
        leftovers = sorted(
            p.name for p in skills_dir.iterdir() if p.name.startswith(".worthless.tmp.")
        )
        assert leftovers == [], f"orphan staging dirs after Stage B failure: {leftovers}"

    config_after_first = openclaw_present["config_path"].read_bytes()

    # Second call: mock now lets through. Reconcile.
    second = integration.apply_lock(planned_updates=planned)
    assert second.detected is True
    assert "worthless-openai" in second.providers_set
    assert second.skill_installed is True
    assert (skills_dir / "worthless" / "SKILL.md").exists()
    assert any(e.code == OpenclawErrorCode.CONFIG_UPDATED for e in second.events), [
        e.code for e in second.events
    ]
    # Second-run events must NOT carry the failure from the first run.
    assert not any(e.code == OpenclawErrorCode.SKILL_INSTALL_FAILED for e in second.events), (
        "second-run events contaminated with first-run failure"
    )

    # Stage A re-write was byte-identical (idempotent re-run — IDEM-24 cross-check).
    config_after_second = openclaw_present["config_path"].read_bytes()
    assert config_after_first == config_after_second, (
        "Stage A re-write was not byte-idempotent across runs"
    )

    # Final cleanup: no orphan staging dirs after success either.
    leftovers = sorted(p.name for p in skills_dir.iterdir() if p.name.startswith(".worthless.tmp."))
    assert leftovers == [], f"orphan staging dirs after successful reconcile: {leftovers}"
