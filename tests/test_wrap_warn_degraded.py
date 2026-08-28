"""WOR-658 Fix 8: wrap warns when the last lock left a DEGRADED sentinel.

wrap is the magic-moment command — silently spawning a child whose proxy
might not be in the path is exactly the silent-bypass class WOR-658 was
built to expose. This test pins the contract that wrap reads the sentinel
before spawning and surfaces a clear [WARN] when bind-confirmation failed.

We test the helper directly. The full wrap command is sub-process heavy
(spawns sidecar, proxy, child); a direct test of ``_warn_if_sentinel_degraded``
is sufficient to pin the read + format contract.
"""

from __future__ import annotations

import json

import pytest

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.wrap import _warn_if_sentinel_degraded
from worthless.cli.sentinel import sentinel_path


def _write_sentinel(home: WorthlessHome, payload: dict) -> None:
    sentinel_path(home.base_dir).write_text(json.dumps(payload, sort_keys=True))


def test_wrap_warns_on_bind_fail_sentinel(
    home_dir: WorthlessHome, capsys: pytest.CaptureFixture
) -> None:
    """status=partial + openclaw=failed (the bind-fail state lock writes) →
    [WARN] before wrap spawns the child."""
    _write_sentinel(
        home_dir,
        {
            "ts": "2026-06-15T00:00:00+00:00",
            "status": "partial",
            "openclaw": "failed",
            "alias_count": 1,
            "events": [],
            "bind_confirmation": {"status": "fail", "delta": 0, "reached": 1},
        },
    )

    _warn_if_sentinel_degraded(home_dir)
    captured = capsys.readouterr()
    assert "[WARN]" in captured.err
    assert "degraded" in captured.err.lower()
    assert "doctor" in captured.err.lower() or "unlock" in captured.err.lower()


def test_wrap_silent_when_sentinel_clean(
    home_dir: WorthlessHome, capsys: pytest.CaptureFixture
) -> None:
    """status=ok + openclaw=ok → no warning. wrap's hot path stays quiet."""
    _write_sentinel(
        home_dir,
        {
            "ts": "2026-06-15T00:00:00+00:00",
            "status": "ok",
            "openclaw": "ok",
            "alias_count": 1,
            "events": [],
            "bind_confirmation": {"status": "pass", "delta": 1, "reached": 1},
        },
    )

    _warn_if_sentinel_degraded(home_dir)
    captured = capsys.readouterr()
    assert captured.err == ""


def test_wrap_silent_when_no_sentinel(
    home_dir: WorthlessHome, capsys: pytest.CaptureFixture
) -> None:
    """Sentinel missing entirely (lock never ran on this host) → no
    warning. Best-effort, never crashes wrap."""
    _warn_if_sentinel_degraded(home_dir)
    captured = capsys.readouterr()
    assert captured.err == ""


def test_wrap_warn_helper_tolerates_unreadable_sentinel(
    home_dir: WorthlessHome, capsys: pytest.CaptureFixture
) -> None:
    """Malformed sentinel JSON → still silent. wrap's hot path must not
    crash because the sentinel got corrupted."""
    sentinel_path(home_dir.base_dir).write_text("{not json")

    _warn_if_sentinel_degraded(home_dir)
    captured = capsys.readouterr()
    assert captured.err == ""
