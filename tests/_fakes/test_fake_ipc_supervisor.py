"""Surface-parity tests for :class:`FakeIPCSupervisor`.

The fake must be drop-in compatible with the real supervisor for the
Phase 5 injection seam (``app.state.ipc_supervisor``). These tests pin
the contract:

* method signatures match the real supervisor
* ``open()`` returns ``bytearray`` (SR-01) — never ``bytes``
* configurable failure modes raise the documented exception classes
* default plaintext is recognisable & non-empty (so leak detectors work)
"""

from __future__ import annotations

import inspect

import pytest

from tests._fakes.fake_ipc_supervisor import (
    DEFAULT_FAKE_PLAINTEXT,
    FakeIPCClient,
    FakeIPCSupervisor,
)
from worthless.proxy.ipc_supervisor import (
    IPCBackpressure,
    IPCCapsMismatch,
    IPCSupervisor,
    IPCUnavailable,
    IPCVersionMismatch,
)


# ------------------------------------------------------------------
# Contract: surface parity with the real IPCSupervisor
# ------------------------------------------------------------------


class TestSurfaceParity:
    """The fake must expose every name the proxy reads off the real one."""

    @pytest.mark.parametrize("method_name", ["connect", "aclose", "acquire", "open"])
    def test_method_present(self, method_name: str) -> None:
        assert hasattr(FakeIPCSupervisor, method_name), (
            f"FakeIPCSupervisor missing public method {method_name!r}"
        )
        assert hasattr(IPCSupervisor, method_name), (
            f"IPCSupervisor missing public method {method_name!r} (test stale)"
        )

    def test_open_signature_matches(self) -> None:
        """``open(ciphertext, *, key_id)`` keyword-only parity."""
        real_sig = inspect.signature(IPCSupervisor.open)
        fake_sig = inspect.signature(FakeIPCSupervisor.open)
        assert list(real_sig.parameters.keys()) == list(fake_sig.parameters.keys())
        # key_id must be keyword-only on both
        assert real_sig.parameters["key_id"].kind is inspect.Parameter.KEYWORD_ONLY
        assert fake_sig.parameters["key_id"].kind is inspect.Parameter.KEYWORD_ONLY

    def test_backend_caps_property(self) -> None:
        sup = FakeIPCSupervisor()
        # Property returns a frozenset on both implementations.
        assert isinstance(sup.backend_caps, frozenset)
        assert "open" in sup.backend_caps


# ------------------------------------------------------------------
# Contract: lifecycle
# ------------------------------------------------------------------


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_connect_marks_connected(self) -> None:
        sup = FakeIPCSupervisor()
        assert not sup.is_connected
        await sup.connect()
        assert sup.is_connected
        assert sup.connect_calls == 1

    @pytest.mark.asyncio
    async def test_aclose_marks_closed_and_disconnected(self) -> None:
        sup = FakeIPCSupervisor()
        await sup.connect()
        await sup.aclose()
        assert sup.is_closed
        assert not sup.is_connected

    @pytest.mark.asyncio
    async def test_open_after_close_raises_unavailable(self) -> None:
        sup = FakeIPCSupervisor()
        await sup.connect()
        await sup.aclose()
        with pytest.raises(IPCUnavailable):
            await sup.open(b"ct", key_id="alias-1")


# ------------------------------------------------------------------
# Contract: open() returns bytearray (SR-01)
# ------------------------------------------------------------------


class TestOpenReturnsBytearray:
    @pytest.mark.asyncio
    async def test_returns_bytearray_not_bytes(self) -> None:
        sup = FakeIPCSupervisor()
        await sup.connect()
        result = await sup.open(b"ct", key_id="alias-1")
        # Strict bytearray identity — the proxy code path zero-fills via
        # ``buf[:] = b"\x00" * len(buf)`` which is bytearray-only. ``bytes``
        # is NOT a subclass of ``bytearray`` (and vice-versa) in Py3, so
        # ``type(result) is bytearray`` is the correct strict-identity check.
        assert isinstance(result, bytearray)
        assert type(result) is bytearray

    @pytest.mark.asyncio
    async def test_default_plaintext_returned(self) -> None:
        sup = FakeIPCSupervisor()
        await sup.connect()
        result = await sup.open(b"any-ciphertext", key_id="alias-1")
        assert bytes(result) == DEFAULT_FAKE_PLAINTEXT

    @pytest.mark.asyncio
    async def test_per_key_plaintext_overrides_default(self) -> None:
        sup = FakeIPCSupervisor()
        sup.set_plaintext("alias-1", b"custom-plaintext-for-alias-1")
        await sup.connect()
        result = await sup.open(b"any-ciphertext", key_id="alias-1")
        assert bytes(result) == b"custom-plaintext-for-alias-1"

    @pytest.mark.asyncio
    async def test_unknown_key_falls_back_to_default(self) -> None:
        sup = FakeIPCSupervisor()
        sup.set_plaintext("alias-1", b"alias-1-pt")
        await sup.connect()
        result = await sup.open(b"ct", key_id="alias-other")
        assert bytes(result) == DEFAULT_FAKE_PLAINTEXT

    @pytest.mark.asyncio
    async def test_each_call_returns_fresh_buffer(self) -> None:
        """Caller may zero the returned bytearray — it must not alias state."""
        sup = FakeIPCSupervisor()
        await sup.connect()
        first = await sup.open(b"ct", key_id="a")
        first[:] = b"\x00" * len(first)
        second = await sup.open(b"ct", key_id="a")
        # Second call must return real plaintext, unaffected by zero-fill.
        assert bytes(second) == DEFAULT_FAKE_PLAINTEXT
        # And the buffers are distinct objects.
        assert first is not second


# ------------------------------------------------------------------
# Contract: configurable failure
# ------------------------------------------------------------------


class TestFailureModes:
    @pytest.mark.asyncio
    async def test_fail_open_with_unavailable(self) -> None:
        sup = FakeIPCSupervisor()
        await sup.connect()
        sup.fail_open_with(IPCUnavailable, "boom")
        with pytest.raises(IPCUnavailable, match="boom"):
            await sup.open(b"ct", key_id="alias-1")

    @pytest.mark.asyncio
    async def test_fail_open_with_caps_mismatch(self) -> None:
        sup = FakeIPCSupervisor()
        await sup.connect()
        sup.fail_open_with(IPCCapsMismatch, "caps shrank")
        with pytest.raises(IPCCapsMismatch, match="caps shrank"):
            await sup.open(b"ct", key_id="alias-1")

    @pytest.mark.asyncio
    async def test_fail_open_with_backpressure(self) -> None:
        sup = FakeIPCSupervisor()
        await sup.connect()
        sup.fail_open_with(IPCBackpressure, "saturated")
        with pytest.raises(IPCBackpressure, match="saturated"):
            await sup.open(b"ct", key_id="alias-1")

    @pytest.mark.asyncio
    async def test_fail_connect_propagates(self) -> None:
        sup = FakeIPCSupervisor()
        sup.fail_connect_with(IPCVersionMismatch, "v9 not supported")
        with pytest.raises(IPCVersionMismatch, match="v9 not supported"):
            await sup.connect()
        assert not sup.is_connected

    @pytest.mark.asyncio
    async def test_clear_failures_restores_happy_path(self) -> None:
        sup = FakeIPCSupervisor()
        await sup.connect()
        sup.fail_open_with(IPCUnavailable, "boom")
        with pytest.raises(IPCUnavailable):
            await sup.open(b"ct", key_id="a")
        sup.clear_failures()
        result = await sup.open(b"ct", key_id="a")
        assert bytes(result) == DEFAULT_FAKE_PLAINTEXT


# ------------------------------------------------------------------
# Contract: acquire() yields a usable client double
# ------------------------------------------------------------------


class TestAcquire:
    @pytest.mark.asyncio
    async def test_acquire_yields_fake_client(self) -> None:
        sup = FakeIPCSupervisor()
        await sup.connect()
        async with sup.acquire() as client:
            assert isinstance(client, FakeIPCClient)
            assert "open" in client.backend_caps

    @pytest.mark.asyncio
    async def test_acquire_auto_connects_if_needed(self) -> None:
        sup = FakeIPCSupervisor()
        # Note: do not call connect() first — acquire should connect lazily.
        async with sup.acquire() as client:
            result = await client.open(b"ct", key_id=b"alias-1")
            assert result == DEFAULT_FAKE_PLAINTEXT
        assert sup.is_connected

    @pytest.mark.asyncio
    async def test_acquire_after_close_raises(self) -> None:
        sup = FakeIPCSupervisor()
        await sup.connect()
        await sup.aclose()
        with pytest.raises(IPCUnavailable):
            async with sup.acquire():
                pass  # pragma: no cover — expected to never execute


# ------------------------------------------------------------------
# Contract: call counters (helpful for assertions in proxy tests)
# ------------------------------------------------------------------


class TestCallCounters:
    @pytest.mark.asyncio
    async def test_open_call_counter_advances(self) -> None:
        sup = FakeIPCSupervisor()
        await sup.connect()
        for i in range(3):
            await sup.open(b"ct", key_id=f"alias-{i}")
        assert sup.open_calls == 3

    @pytest.mark.asyncio
    async def test_open_counter_advances_even_on_failure(self) -> None:
        """Failure path still counts the attempt — useful for retry assertions.

        Counter increments at function entry, before the failure check, so a
        Mock that raises still bumps ``open_calls``. Lets retry-policy tests
        assert "we tried N times" without needing successful returns.
        """
        sup = FakeIPCSupervisor()
        await sup.connect()
        sup.fail_open_with(IPCUnavailable, "down")
        for _ in range(2):
            with pytest.raises(IPCUnavailable):
                await sup.open(b"ct", key_id="a")
        assert sup.open_calls == 2
