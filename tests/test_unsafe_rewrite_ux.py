"""Safe-abort UX tests for ``UnsafeRewriteRefused`` (WOR-276 v2).

Tests 5 and 10 from the v2 plan. When a rewrite is refused, the user
must see:

1. A reassurance that ``.env`` was not modified — so they know no
   half-locked state was left behind and they can safely retry.
2. An actionable, reason-specific hint that tells them WHAT to do
   next, without leaking absolute paths or internal state.

The granular ``UnsafeReason`` identifier is intentionally opaque in
the output (operators can still get it via ``--debug`` and the DEBUG
log line), so we assert it does NOT appear unless explicitly enabled.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from worthless.cli.errors import (
    ErrorCode,
    UnsafeReason,
    UnsafeRewriteRefused,
    error_boundary,
)


runner = CliRunner(mix_stderr=False)


def _app_raising(reason: UnsafeReason) -> typer.Typer:
    app = typer.Typer()

    @app.command()
    @error_boundary
    def boom() -> None:
        raise UnsafeRewriteRefused(reason)

    return app


# ---------------------------------------------------------------------------
# Test 5: .env-unchanged reassurance lands and the granular reason does not.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("reason", list(UnsafeReason))
def test_unsafe_rewrite_prints_unchanged_reassurance(reason: UnsafeReason) -> None:
    result = runner.invoke(_app_raising(reason), [])
    assert result.exit_code == 1
    assert "unchanged" in result.stderr.lower()
    assert f"WRTLS-{ErrorCode.UNSAFE_REWRITE_REFUSED.value}" in result.stderr


@pytest.mark.parametrize("reason", list(UnsafeReason))
def test_unsafe_rewrite_does_not_leak_reason_identifier(reason: UnsafeReason) -> None:
    """Snake_case enum values must not appear verbatim.

    Single-word reasons like ``symlink`` and ``platform`` are ordinary
    English and are allowed to appear in the hint text. The tell-tale
    leak is a value with ``_`` separators (e.g. ``verify_failed``,
    ``path_identity``, ``tmp_collision``) or the ``reason=`` repr
    prefix — those are clearly internal identifiers.
    """
    result = runner.invoke(_app_raising(reason), [])
    assert "reason=" not in result.stderr
    assert f"UnsafeReason.{reason.name}" not in result.stderr
    if "_" in reason.value:
        assert reason.value not in result.stderr


# ---------------------------------------------------------------------------
# Test 10: no absolute paths leak into the output. ``UnsafeRewriteRefused``
# never carries a path today, but the hint printer must stay that way.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("reason", list(UnsafeReason))
def test_unsafe_rewrite_output_contains_no_abs_paths(tmp_path: Path, reason: UnsafeReason) -> None:
    result = runner.invoke(_app_raising(reason), [])
    # Walk every absolute path segment the test harness knows about.
    for candidate in (str(tmp_path), str(Path.home()), "/Users/", "/home/", "/tmp/"):  # noqa: S108
        assert candidate not in result.stderr, f"absolute path leaked: {candidate!r}"


# ---------------------------------------------------------------------------
# Reason-specific hint is actionable. A few key reasons should point the
# user at a concrete next step. Others fall back to a generic retry hint.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reason", "needle"),
    [
        (UnsafeReason.FILESYSTEM, "WORTHLESS_FORCE_FS"),
        (UnsafeReason.LOCKED, "another"),
        (UnsafeReason.PLATFORM, "supported"),
    ],
)
def test_reason_specific_hint(reason: UnsafeReason, needle: str) -> None:
    result = runner.invoke(_app_raising(reason), [])
    assert needle.lower() in result.stderr.lower()
