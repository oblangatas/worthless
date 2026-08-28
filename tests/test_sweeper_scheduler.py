"""Tests for the sweeper background task wired into the proxy lifespan.

Covers _sweep_loop in isolation: periodic execution, clean cancellation,
and resilience to exceptions from ledger.sweep().
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from worthless.proxy.app import _sweep_loop


@pytest.mark.asyncio
async def test_sweep_loop_runs_periodically() -> None:
    """_sweep_loop calls ledger.sweep() at least once within the interval."""
    ledger = MagicMock()
    ledger.sweep = AsyncMock(return_value=0)

    # Use a very short interval so the test is fast.
    interval = 0.05
    max_age = 300.0

    task = asyncio.create_task(_sweep_loop(ledger, interval, max_age))
    # Wait long enough for at least two ticks.
    await asyncio.sleep(interval * 2.5)
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    assert ledger.sweep.call_count >= 1
    ledger.sweep.assert_called_with(max_age)


@pytest.mark.asyncio
async def test_sweep_loop_cancels_cleanly() -> None:
    """Cancelling _sweep_loop raises no unhandled exception and completes promptly."""
    ledger = MagicMock()
    ledger.sweep = AsyncMock(return_value=0)

    task = asyncio.create_task(_sweep_loop(ledger, interval=10.0, max_age=300.0))
    # Cancel before the first sleep expires.
    await asyncio.sleep(0)
    task.cancel()
    # Should complete without hanging or propagating anything other than
    # CancelledError (which we suppress here as expected behaviour).
    try:
        await asyncio.wait_for(task, timeout=1.0)
    except asyncio.CancelledError:
        pass

    assert task.done()


@pytest.mark.asyncio
async def test_sweep_loop_continues_after_exception() -> None:
    """An exception from ledger.sweep() does not kill the loop; the next tick runs."""
    ledger = MagicMock()
    call_count = 0

    async def _sweep_side_effect(max_age: float) -> int:  # noqa: ARG001
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("transient DB error")
        return 0

    ledger.sweep = _sweep_side_effect

    interval = 0.05
    task = asyncio.create_task(_sweep_loop(ledger, interval, max_age=300.0))
    # Wait for three ticks: first raises, second and third succeed.
    await asyncio.sleep(interval * 3.5)
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    # Loop must have survived the first exception and called sweep again.
    assert call_count >= 2
