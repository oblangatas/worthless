"""Last-lock-status sentinel file.

Trust-fix from the 2026-05-08 verification gauntlet (5 agents:
karen, T-C-V, brutus, qa-expert, test-automator + brutus-2 + ux-researcher
+ architect-reviewer). Exit-code-only signaling on partial OpenClaw failure
fails for users whose `worthless lock` runs in CI scripts that ignore exit
codes — five minutes after lock the user runs an agent, OpenClaw silently
bypasses worthless, attacker who steals .env can drain budget.

Persistent state at ``$WORTHLESS_HOME/last-lock-status.json`` outlives the
terminal session. ``worthless status`` reads it and refuses to say
"protected" until cleared. ``worthless doctor`` (Phase 2.d) clears it.

Schema (wire-stable; keep additive only):

    {
      "ts": "2026-05-08T00:42:00+00:00",
      "status": "ok" | "partial",
      "openclaw": "ok" | "failed" | "absent",
      "alias_count": 1,
      "events": [
        {"code": "openclaw.write_failed", "level": "error", "detail": "..."}
      ],
      "bind_confirmation": {                     // WOR-658, optional
        "status": "pass" | "fail" | "skipped",
        "delta": 0,                              // bind_probe_count delta
        "aliases": ["openai-abc123"],            // managed aliases tested
        "reached": 1,                            // # probes that got HTTP
        "reason": "proxy_unrecognised" | "..."   // present when skipped
      }
    }

The ``bind_confirmation`` block is absent on sentinels written by paths
that do not run bind-confirmation (unlock, openclaw=absent, the failure
branch before the OpenClaw integration runs, etc.) — additive-only
contract: old readers ignore it, new readers gate on its presence.

Atomic write via tempfile + ``os.replace`` — same pattern as Phase 1's
``_atomic_write_json`` in ``worthless.openclaw.config``. Crash mid-write
leaves the prior sentinel intact.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SENTINEL_FILENAME = "last-lock-status.json"


def sentinel_path(home_base_dir: Path) -> Path:
    """Return the sentinel file path for a given worthless home."""
    return home_base_dir / SENTINEL_FILENAME


def write_sentinel(
    home_base_dir: Path,
    *,
    status: str,
    openclaw: str,
    alias_count: int,
    events: list[dict[str, Any]] | None = None,
    bind_confirmation: dict[str, Any] | None = None,
) -> Path:
    """Atomically write the sentinel for the current ``worthless lock``/``unlock`` outcome.

    Args:
        home_base_dir: ``WorthlessHome.base_dir``. Created if it doesn't exist.
        status: ``"ok"`` (everything succeeded) or ``"partial"`` (lock-core
            succeeded but the OpenClaw stage hit a detected+failed condition).
        openclaw: ``"ok"`` | ``"failed"`` | ``"absent"`` — the OpenClaw stage
            outcome. ``"absent"`` means OpenClaw was not detected on this host.
        alias_count: number of aliases the operation touched (lock: wired;
            unlock: removed).
        events: structured event payload, ``OpenclawIntegrationEvent.asdict()``-ish.
        bind_confirmation: WOR-658 result block. ``None`` means lock did not
            run bind-confirmation (e.g. OpenClaw absent, or this is an unlock
            sentinel). Wire-stable additive field — unknown to older readers,
            which ignore it.

    Returns:
        The path written.

    Raises:
        OSError: tempfile or replace failed. Callers in lock/unlock paths
            must NOT propagate this — sentinel-write failure is itself a
            best-effort signal, not a hard contract.
    """
    home_base_dir.mkdir(parents=True, exist_ok=True)
    target = sentinel_path(home_base_dir)
    payload: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": status,
        "openclaw": openclaw,
        "alias_count": alias_count,
        "events": events or [],
    }
    if bind_confirmation is not None:
        payload["bind_confirmation"] = bind_confirmation

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{SENTINEL_FILENAME}.",
        suffix=".tmp",
        dir=str(home_base_dir),
    )
    tmp_path: Path | None = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        # ``os.replace`` (not ``Path.replace``) for atomicity across platforms
        # and so the unit-test contract can patch at the module level.
        os.replace(tmp_path, target)  # noqa: PTH105
        tmp_path = None
    finally:
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    return target


def read_sentinel(home_base_dir: Path) -> dict[str, Any] | None:
    """Read the sentinel. Returns ``None`` if absent or malformed.

    Malformed sentinel = absent for trust purposes. We do not raise — the
    caller (``worthless status``) needs to make a clean decision: "no
    recent lock state" vs "DEGRADED."
    """
    target = sentinel_path(home_base_dir)
    try:
        raw = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError:
        return None

    if not raw.strip():
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None

    if not isinstance(data, dict):
        return None
    return data


def is_partial(sentinel: dict[str, Any] | None) -> bool:
    """Return True when the sentinel indicates a DEGRADED state.

    Encapsulates the rule "status==partial AND openclaw==failed" so
    callers don't open-code the predicate (and so the rule can evolve
    without touching every caller).
    """
    if not sentinel:
        return False
    return sentinel.get("status") == "partial" and sentinel.get("openclaw") == "failed"
