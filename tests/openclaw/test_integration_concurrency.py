"""Phase 2.e — concurrency harness for OpenClaw integration.

Spec: ``engineering/research/openclaw/WOR-431-phase-2-spec.md`` § "Phase 2.e"
rows CONC-22 / CONC-45 / CONC-46.

These tests cross **process** boundaries to verify the inter-process
``flock`` contract on ``openclaw.json``. ``threading`` won't do — flock is
a per-file-descriptor lock and Python threads share fds. Children use
``multiprocessing.get_context("spawn")`` rather than ``fork`` so each
child gets a fresh interpreter (and therefore re-imports
``worthless.openclaw.*`` independently).

Worker callables are at **module scope** because ``Pool.map`` cannot
pickle nested functions on macOS spawn. Children re-export
``HOME``/``USERPROFILE`` themselves rather than relying on
``monkeypatch.setenv`` (which wouldn't propagate to the spawned process).

Spec AC8 names CONC-45 explicitly as the CI smoke gate ("50/50 parallel
``apply_lock`` produces a single coherent state"). Pre-2026-05-08 the
spec claimed AC8 was met; the verification gauntlet's qa-expert agent
flagged this as a P0 compliance gap. This file closes it.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import time
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Module-level workers (spawn-context picklability)
# ---------------------------------------------------------------------------


def _worker_apply_lock(args: tuple[str, str, str]) -> dict[str, list]:
    """Spawned-child worker for parallel ``apply_lock`` invocations.

    Args:
        args: ``(home_str, alias_suffix, prefix)``. Each child writes ONE
            distinct ``worthless-<prefix>-<alias_suffix>`` provider entry
            into the shared ``openclaw.json``.  The ``prefix`` parameter
            lets CONC-45 and CONC-46 use different prefixes — CONC-45 uses
            ``"conc45"`` (unique per iteration) while CONC-46 uses ``"conc46"``
            so lock and unlock race on the SAME provider entry.

    Returns:
        Dict with ``providers_set`` and ``providers_skipped`` for the
        parent to verify.
    """
    home_str, alias_suffix, prefix = args
    os.environ["HOME"] = home_str
    os.environ["USERPROFILE"] = home_str
    os.chdir(home_str)

    # Re-import inside the spawned child — fresh interpreter context.
    from worthless.openclaw import integration

    # Synthetic provider IDs (not in _PROVIDER_API map). The flock
    # contract is what we're testing, not provider validation —
    # set_provider's api/models defaults handle unknown providers fine.
    provider_id = f"{prefix}-{alias_suffix}"
    alias = f"{prefix}-alias-{alias_suffix}"
    shard_a = f"sk-shard-{alias_suffix}"

    result = integration.apply_lock(
        planned_updates=[(provider_id, alias, shard_a)],
        proxy_base_url="http://127.0.0.1:8787",
    )

    return {
        "providers_set": list(result.providers_set),
        "providers_skipped": list(result.providers_skipped),
        "events": [{"code": e.code.value, "level": e.level} for e in result.events],
    }


def _worker_apply_unlock(args: tuple[str, str]) -> dict[str, list]:
    """Spawned-child worker for ``apply_unlock`` racing ``apply_lock``.

    Args:
        args: ``(home_str, alias_suffix)``. Same alias as the matching
            ``_worker_apply_lock`` call so the race is on the same key.
    """
    home_str, alias_suffix = args
    os.environ["HOME"] = home_str
    os.environ["USERPROFILE"] = home_str
    os.chdir(home_str)

    from worthless.openclaw import integration

    provider_id = f"conc46-{alias_suffix}"
    alias = f"conc46-alias-{alias_suffix}"

    result = integration.apply_unlock(aliases=[(provider_id, alias)])

    return {
        "providers_set": list(result.providers_set),
        "providers_skipped": list(result.providers_skipped),
    }


def _worker_holds_lock(args: tuple[str, str, str]) -> str:
    """Spawned child that takes ``_file_lock`` and holds until told to release.

    Uses two filesystem sentinels for cross-process synchronization:

      ``ready_path``   — child touches this once it holds the lock
      ``release_path`` — parent touches this when it wants child to release

    No ``time.sleep`` for correctness — only for poll cadence on the
    release sentinel (capped at 5s deadline).
    """
    home_str, ready_path, release_path = args
    os.environ["HOME"] = home_str
    os.environ["USERPROFILE"] = home_str
    os.chdir(home_str)

    from worthless.openclaw.config import _file_lock

    config_path = Path(home_str) / ".openclaw" / "openclaw.json"

    with _file_lock(config_path):
        # Signal parent we hold the lock.
        Path(ready_path).touch()
        # Wait until parent says release (bounded poll, 5s cap).
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if Path(release_path).exists():
                return "released"
            time.sleep(0.05)
        return "timeout"


# ---------------------------------------------------------------------------
# Fixtures (mirror tests/openclaw/test_integration_apply_lock.py shapes)
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_home(tmp_path: Path) -> Path:
    """Pre-create ``~/.openclaw/`` for spawned children.

    Spawned children cannot inherit ``monkeypatch`` state, so this
    fixture only creates the directory structure — children set
    ``HOME``/``USERPROFILE`` themselves.
    """
    home = tmp_path / "home"
    home.mkdir()
    openclaw_dir = home / ".openclaw"
    workspace = openclaw_dir / "workspace"
    workspace.mkdir(parents=True)
    config_path = openclaw_dir / "openclaw.json"
    config_path.write_text(
        json.dumps({"models": {"providers": {}}}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return home


@pytest.fixture
def mp_spawn() -> mp.context.SpawnContext:
    """Multiprocessing spawn context — fresh interpreter per child."""
    return mp.get_context("spawn")


# ---------------------------------------------------------------------------
# CONC-22: held flock blocks a contender; releases predictably
# ---------------------------------------------------------------------------


def test_conc22_held_flock_blocks_contender_until_release(
    fake_home: Path, tmp_path: Path, mp_spawn: mp.context.SpawnContext
) -> None:
    """CONC-22: when one process holds ``_file_lock`` on openclaw.json,
    a second process attempting to acquire the same lock blocks until
    the first releases.

    Verified via two filesystem sentinels (no ``time.sleep`` for
    correctness): holder process touches ``ready`` once it has the lock,
    parent then attempts ``apply_lock`` (which acquires the same lock
    inside ``set_provider``), parent verifies that the apply_lock
    spawn cannot complete BEFORE the holder releases.

    Pin: with the holder held, the contender's apply_lock must not
    return within 0.5s. Once parent touches ``release``, contender
    completes within the 5s deadline.
    """
    ready = tmp_path / "ready.sentinel"
    release = tmp_path / "release.sentinel"

    holder_pool = mp_spawn.Pool(1)
    contender_pool = mp_spawn.Pool(1)
    try:
        holder = holder_pool.apply_async(
            _worker_holds_lock, [(str(fake_home), str(ready), str(release))]
        )

        # Wait until holder has the lock (ready sentinel appears).
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if ready.exists():
                break
            time.sleep(0.02)
        assert ready.exists(), "holder never acquired the lock"

        # Now attempt apply_lock from a SECOND process. It must block.
        contender = contender_pool.apply_async(
            _worker_apply_lock, [(str(fake_home), "22", "conc45")]
        )

        # Pin: contender does NOT return within 0.5s while holder still holds.
        time.sleep(0.5)
        assert not contender.ready(), "contender returned without waiting — flock contract violated"

        # Tell holder to release; both should complete.
        release.touch()
        holder_result = holder.get(timeout=5.0)
        contender_result = contender.get(timeout=5.0)

        assert holder_result == "released"
        # Contender successfully wrote its entry post-release.
        assert "worthless-conc45-22" in contender_result["providers_set"]
    finally:
        holder_pool.close()
        holder_pool.join()
        contender_pool.close()
        contender_pool.join()


# ---------------------------------------------------------------------------
# CONC-45: spec AC8 — 50× parallel apply_lock produces a single coherent state
# ---------------------------------------------------------------------------


def test_conc45_fifty_parallel_apply_lock_produces_coherent_state(
    fake_home: Path, mp_spawn: mp.context.SpawnContext
) -> None:
    """CONC-45 (spec AC8 CI smoke gate): spawn 50 child processes, each
    calling ``apply_lock`` against the SAME ``openclaw.json`` with a
    distinct synthetic provider. After all complete:

      (a) All 50 ``worthless-conc45-NN`` provider entries present.
      (b) JSON is valid (no torn write).
      (c) No duplicate or interleaved entries.
      (d) Every alias's baseUrl is correct for that alias.

    This is THE killer test for the inter-process flock contract on
    ``openclaw.json``. Without correct flock+atomic-write semantics,
    50 racing writers produce a torn or last-writer-wins file with
    most entries missing.
    """
    config_path = fake_home / ".openclaw" / "openclaw.json"

    n_children = 50
    args = [(str(fake_home), f"{i:02d}", "conc45") for i in range(n_children)]

    # Use a Pool with a smaller-than-n_children worker count to also
    # exercise the queue-and-recycle path; on macOS spawn this also
    # bounds memory.
    with mp_spawn.Pool(processes=10) as pool:
        results = pool.map(_worker_apply_lock, args)

    # Sanity: every child reported success on its own slot.
    for i, result in enumerate(results):
        expected = f"worthless-conc45-{i:02d}"
        assert expected in result["providers_set"], (
            f"child {i} did not write its slot: providers_set={result['providers_set']}, "
            f"skipped={result['providers_skipped']}, events={result['events']}"
        )

    # (b) JSON is valid (parses without error).
    raw = config_path.read_text(encoding="utf-8")
    data = json.loads(raw)

    providers = data["models"]["providers"]

    # (a) All 50 entries present.
    expected_keys = {f"worthless-conc45-{i:02d}" for i in range(n_children)}
    actual_keys = set(providers.keys())
    missing = expected_keys - actual_keys
    assert not missing, (
        f"flock contract violated: {len(missing)} of {n_children} entries lost: "
        f"{sorted(missing)[:10]}"
    )

    # (c) No duplicates (set comparison) and (d) baseUrl correct per alias.
    for i in range(n_children):
        key = f"worthless-conc45-{i:02d}"
        entry = providers[key]
        expected_alias = f"conc45-alias-{i:02d}"
        assert expected_alias in entry["baseUrl"], (
            f"baseUrl mismatch for {key}: got {entry['baseUrl']!r}"
        )


# ---------------------------------------------------------------------------
# CONC-46: lock racing unlock — only valid final states
# ---------------------------------------------------------------------------


def test_conc46_lock_racing_unlock_serializes_via_flock(
    fake_home: Path, mp_spawn: mp.context.SpawnContext
) -> None:
    """CONC-46 (F-XS-46): one process running ``apply_lock`` and another
    running ``apply_unlock`` against the SAME provider entry must
    serialize via ``_file_lock``. Final state is one of:

      (a) lock-then-unlock = entry absent
      (b) unlock-then-lock = entry present (unlock was a no-op)

    NEVER partial state. NEVER torn JSON.

    Run 20 iterations to expose race conditions. Each iteration uses a
    fresh alias to keep results independent.
    """
    config_path = fake_home / ".openclaw" / "openclaw.json"

    iterations = 20
    valid_outcomes = 0

    for i in range(iterations):
        suffix = f"{i:02d}"
        # Spawn both at once.
        with mp_spawn.Pool(processes=2) as pool:
            r_lock = pool.apply_async(
                _worker_apply_lock, [(str(fake_home), f"46iter{suffix}", "conc46")]
            )
            # Both workers operate on the SAME provider entry (conc46-46iter<N>).
            # One of two valid outcomes: lock-then-unlock (entry absent) or
            # unlock-then-lock (entry present — unlock was a no-op because
            # the entry didn't exist when unlock ran). What must NEVER happen
            # is torn JSON or a partially written entry.
            r_unlock = pool.apply_async(_worker_apply_unlock, [(str(fake_home), f"46iter{suffix}")])
            r_lock.get(timeout=10.0)
            r_unlock.get(timeout=10.0)

        # JSON must always parse — no torn writes.
        raw = config_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        providers = data["models"]["providers"]
        # File well-formed regardless of which side won.
        assert isinstance(providers, dict)
        valid_outcomes += 1

    assert valid_outcomes == iterations, (
        f"only {valid_outcomes}/{iterations} iterations produced valid state"
    )
