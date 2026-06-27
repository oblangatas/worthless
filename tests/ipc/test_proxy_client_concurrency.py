"""WOR-309 Phase 5 slice 5.6 — strict concurrency / no-crosstalk tests.

The pre-existing ``test_32_concurrent_requests_distinct_responses`` in
``test_proxy_client_unit.py`` proves the supervisor *completes* 32 calls
without protocol errors, but the fake sidecar there returns a canned
``FAKE-PT`` regardless of input. That demonstrates "no errors", not "no
crosstalk" — a swapped reply id would silently land on the wrong
coroutine and the canned body would mask it.

This module exercises a stricter contract: the fake echoes each
ciphertext back as the plaintext, and we assert every coroutine
receives the *exact* bytes it submitted. That is the real no-crosstalk
property the supervisor's outer Semaphore + IPCClient inner Lock claim
to provide.

Two tests:

* ``test_32_coroutines_payload_distinct`` — 32 concurrent ``open``
  calls with unique payloads; assert each coroutine receives its own
  payload back.
* ``test_no_protocol_framing_interleave`` — same shape, but with the
  fake configured to delay replies; if two responses ever interleaved
  on the wire we'd see truncated frames or id mismatches surface as
  ``IPCProtocolError``.

Both tests share the in-process ``fake_sidecar`` fixture and configure
``handle.echo_ciphertext = True`` (added in this slice) to opt in to
payload-echo behaviour.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from worthless.proxy.ipc_supervisor import IPCSupervisor

# WOR-582: fake_sidecar with delay-configured replies can hang under py3.13 xdist
# workers (same asyncio event-loop conflict as test_proxy_client_unit.py).
# Serial pass eliminates the race.
pytestmark = [pytest.mark.asyncio, pytest.mark.real_ipc]

_EXPECTED_CAPS = frozenset({"seal", "open", "attest"})


async def _supervisor(socket_path: Path, **kwargs: object) -> IPCSupervisor:
    sup = IPCSupervisor(
        socket_path,
        protocol_version=1,
        expected_caps=_EXPECTED_CAPS,
        **kwargs,  # type: ignore[arg-type]
    )
    await sup.connect()
    return sup


async def test_32_coroutines_payload_distinct(fake_sidecar) -> None:
    """32 distinct payloads round-trip with no crosstalk.

    The fake is asked to echo each ciphertext as the plaintext. Every
    coroutine sends a unique payload and asserts the reply matches its
    own payload — a dropped, swapped, or interleaved reply would land
    the wrong bytes on the wrong coroutine and fail the assertion.
    """
    socket_path, handle = fake_sidecar
    handle.echo_ciphertext = True
    sup = await _supervisor(socket_path, max_concurrency=32)
    try:

        async def _one(i: int) -> tuple[int, bytes]:
            payload = f"ct-{i:04d}".encode()
            buf = await sup.open(payload, key_id="kid")
            return i, bytes(buf)

        results = await asyncio.gather(*(_one(i) for i in range(32)))
        # Every coroutine got back exactly the bytes it sent.
        for i, reply in results:
            expected = f"ct-{i:04d}".encode()
            assert reply == expected, (
                f"coroutine {i}: expected {expected!r}, got {reply!r} -- "
                "reply landed on the wrong coroutine (crosstalk)"
            )
    finally:
        await sup.aclose()


async def test_no_protocol_framing_interleave(fake_sidecar) -> None:
    """Concurrent calls do not corrupt length-prefix framing.

    Under burst, the inner per-connection write lock must serialise
    frame writes so no two ``encode_frame`` outputs interleave on the
    wire. We force burst contention by submitting 16 calls in parallel
    and asserting all complete cleanly with their own payloads.
    A framing interleave would surface as ``IPCProtocolError`` or a
    decode mismatch on the supervisor side.
    """
    socket_path, handle = fake_sidecar
    handle.echo_ciphertext = True
    sup = await _supervisor(socket_path, max_concurrency=16)
    try:
        payloads = [f"frame-{i:03d}-{'x' * (i % 7)}".encode() for i in range(16)]

        async def _one(payload: bytes) -> bytes:
            buf = await sup.open(payload, key_id="kid")
            return bytes(buf)

        results = await asyncio.gather(*(_one(p) for p in payloads))
        assert results == payloads, "framing interleaved or replies misordered"
    finally:
        await sup.aclose()
