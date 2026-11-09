"""WOR-1078: the proxy only talks to a socket the real sidecar is serving.

The sidecar checks the proxy's uid before it reads a frame
(``require_peer_uid`` in ``sidecar/server.py``). These tests pin the reverse
direction: ``IPCClient`` reads the server's uid off the connected socket and
refuses, before it writes the hello frame, when that uid isn't the sidecar uid
the deployment expects. Without the check, anyone who can bind or swap the
socket path (a stale-socket race, a writable run dir) sees every plaintext the
proxy sends to ``seal`` and can feed it any frame it likes.

Every test runs on a real AF_UNIX socket. A test process can't serve a socket
as another uid without root, so "served by an unexpected uid" is forced from
the client side: the expected sidecar uid is set to one this process doesn't
run as, and the kernel reports the real one.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import os
import signal
import socket
from collections.abc import AsyncIterator
from pathlib import Path

import aiosqlite
import httpx
import pytest
import pytest_asyncio
import respx

from worthless._flags import WORTHLESS_SIDECAR_UID_ENV
from worthless.crypto.splitter import split_key_fp
from worthless.ipc import peercred
from worthless.ipc.client import IPCAuthError, IPCClient
from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings
from worthless.proxy.ipc_supervisor import IPCSupervisor, IPCUnavailable
from worthless.proxy.rules import RateLimitRule, RulesEngine, SpendCapRule
from worthless.storage.repository import ShardRepository, StoredShard

from tests.ipc.conftest import FakeSidecarHandle

# Real sockets and a real sidecar: the serial real_ipc lane, like the rest of
# tests/ipc (WOR-582).
pytestmark = pytest.mark.real_ipc

# Any uid this process isn't running as. The kernel will report os.getuid().
_OTHER_UID = os.getuid() + 1


@dataclasses.dataclass
class _Impostor:
    """What a fake server at the sidecar's path saw from the client."""

    socket_path: Path
    received: bytearray = dataclasses.field(default_factory=bytearray)
    connections: int = 0
    disconnected: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)


@contextlib.asynccontextmanager
async def _serving_impostor(socket_path: Path) -> AsyncIterator[_Impostor]:
    """A server bound at the sidecar path that records every byte and never replies.

    Stands in for whoever won the race for the socket path. Before WOR-1078
    the client wrote its hello frame here and waited for a reply.
    """
    seen = _Impostor(socket_path=socket_path)

    async def _on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen.connections += 1
        try:
            while chunk := await reader.read(65536):
                seen.received.extend(chunk)
        finally:
            writer.close()
            seen.disconnected.set()

    server = await asyncio.start_unix_server(_on_connect, path=str(socket_path))
    try:
        yield seen
    finally:
        server.close()
        await server.wait_closed()


@pytest_asyncio.fixture
async def impostor(sidecar_socket_path: Path) -> AsyncIterator[_Impostor]:
    async with _serving_impostor(sidecar_socket_path) as seen:
        yield seen


async def _connect(socket_path: Path) -> None:
    async with IPCClient(socket_path, timeout=0.5):
        pass


async def test_refuses_a_socket_served_by_another_uid_before_sending_a_byte(
    impostor: _Impostor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deployment says the sidecar runs as another uid; this socket's server doesn't.

    The client must refuse with an AUTH error and close the connection
    without writing anything, not even the hello frame.
    """
    monkeypatch.setenv(WORTHLESS_SIDECAR_UID_ENV, str(_OTHER_UID))

    with pytest.raises(IPCAuthError, match="not served by the sidecar uid"):
        await _connect(impostor.socket_path)

    await asyncio.wait_for(impostor.disconnected.wait(), timeout=2.0)
    assert impostor.connections == 1
    assert bytes(impostor.received) == b"", (
        f"client wrote {len(impostor.received)} bytes to a socket the sidecar isn't serving"
    )


async def test_an_impostor_that_answers_hello_never_sees_seal_plaintext(
    fake_sidecar: tuple[Path, FakeSidecarHandle], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The user-visible promise: a value the proxy seals never reaches an impostor.

    The impostor speaks the protocol, so before WOR-1078 the handshake
    completed and the seal request carrying the plaintext reached it.
    """
    socket_path, impostor = fake_sidecar
    monkeypatch.setenv(WORTHLESS_SIDECAR_UID_ENV, str(_OTHER_UID))

    with pytest.raises(IPCAuthError):
        async with IPCClient(socket_path, timeout=0.5) as client:
            await client.seal(b"sk-live-the-key-the-proxy-protects")

    assert impostor.requests_seen == 0


async def test_unreadable_peer_credentials_fail_closed(
    impostor: _Impostor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the kernel won't say who is serving the socket, don't trust it."""

    def _no_creds(_sock: object) -> peercred.PeerCredentials:
        raise peercred.PeerCredError("simulated getsockopt failure")

    monkeypatch.setattr(peercred, "get_peer_credentials", _no_creds)

    with pytest.raises(IPCAuthError, match="peer credentials"):
        await _connect(impostor.socket_path)

    await asyncio.wait_for(impostor.disconnected.wait(), timeout=2.0)
    assert bytes(impostor.received) == b""


async def test_the_kernels_answer_is_what_gets_compared(
    fake_sidecar: tuple[Path, FakeSidecarHandle], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Accept when the peer credentials name the expected uid, even if it isn't ours.

    The tests above can't tell "compares the kernel's uid" from "compares our
    own uid", since this process serves every socket here. Reporting a foreign
    uid at the peer-credential boundary can: only a client that compares what
    the kernel said lets this connection through.
    """

    def _served_by_other_uid(_sock: object) -> peercred.PeerCredentials:
        return peercred.PeerCredentials(uid=_OTHER_UID, gid=_OTHER_UID, pid=None)

    monkeypatch.setattr(peercred, "get_peer_credentials", _served_by_other_uid)
    monkeypatch.setenv(WORTHLESS_SIDECAR_UID_ENV, str(_OTHER_UID))
    socket_path, _ = fake_sidecar

    async with IPCClient(socket_path, timeout=0.5) as client:
        assert await client.seal(b"for the sidecar running as another uid") == b"FAKE-CT"


@pytest.mark.parametrize(
    "raw",
    [
        "worthless-crypto",
        "-1",
        "10002.0",
        "10002,10003",
        # The kernel reports these for peers it can't map (overflowuid) or that
        # have no credentials at all, so trusting them trusts strangers.
        "65534",
        "4294967295",
        # Past int()'s digit limit: must still be an AUTH refusal, not ValueError.
        "9" * 5000,
        # Set but empty, as compose's ${VAR} gives for an unset host variable.
        # Falling back to our own uid would trust whoever shares it: in Docker,
        # the proxy's user, which can replace the socket link.
        "",
        "  ",
    ],
    ids=lambda raw: repr(raw) if len(raw) < 20 else f"{len(raw)}-digits",
)
async def test_a_malformed_sidecar_uid_is_refused_before_connecting(
    impostor: _Impostor, monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    """A typo in the operator's setting must not fall back to trusting anyone."""
    monkeypatch.setenv(WORTHLESS_SIDECAR_UID_ENV, raw)

    with pytest.raises(IPCAuthError, match=WORTHLESS_SIDECAR_UID_ENV):
        await _connect(impostor.socket_path)

    assert impostor.connections == 0
    assert bytes(impostor.received) == b""


async def test_running_as_the_no_user_uid_is_refused_too(
    impostor: _Impostor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the setting unset, our own uid is the expectation, and 65534 is still a stranger.

    A peer the kernel can't map into our user namespace also reports as
    65534, so a client running as nobody would otherwise trust it.
    """
    monkeypatch.setattr(os, "getuid", lambda: 65534)

    with pytest.raises(IPCAuthError, match="no-user uid"):
        await _connect(impostor.socket_path)

    assert impostor.connections == 0


@pytest.mark.parametrize("env_value", [None, str(os.getuid())], ids=["unset", "own-uid"])
async def test_the_real_sidecar_is_trusted(
    running_sidecar: object,
    sidecar_socket_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    env_value: str | None,
) -> None:
    """Single-uid install: unset or own uid both mean "the sidecar runs as me"."""
    if env_value is not None:
        monkeypatch.setenv(WORTHLESS_SIDECAR_UID_ENV, env_value)

    async with IPCClient(sidecar_socket_path) as client:
        ciphertext = await client.seal(b"hello sidecar")
        assert await client.open(ciphertext) == b"hello sidecar"


async def test_the_proxy_turns_an_impostor_into_unavailable(
    impostor: _Impostor, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The proxy's supervisor maps the refusal onto its 503 path; no bytes leave.

    The 503 body says only "sidecar unavailable", so the refusal must reach the
    proxy log, or an operator can't tell an impostor from a crashed sidecar.
    """
    caplog.set_level(logging.WARNING, logger="worthless.proxy.ipc_supervisor")
    monkeypatch.setenv(WORTHLESS_SIDECAR_UID_ENV, str(_OTHER_UID))
    sup = IPCSupervisor(
        impostor.socket_path,
        protocol_version=1,
        expected_caps=frozenset({"seal", "open"}),
        request_timeout_s=0.5,
    )
    try:
        with pytest.raises(IPCUnavailable, match="not served by the sidecar uid"):
            await sup.connect()
    finally:
        await sup.aclose()

    refusals = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and "not served by the sidecar uid" in r.getMessage()
    ]
    assert refusals, "a refused sidecar socket left no warning in the proxy log"

    await asyncio.wait_for(impostor.disconnected.wait(), timeout=2.0)
    assert bytes(impostor.received) == b""


@pytest.mark.integration
@respx.mock
async def test_a_proxy_that_reconnects_to_an_impostor_answers_503_and_sends_it_nothing(
    subprocess_sidecar: tuple[Path, int],
    fernet_shares: tuple[bytes, bytes],
    tmp_db_path: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The sidecar dies mid-run and someone else binds its path: the reconnect is refused.

    The proxy serves one request through the real sidecar. The sidecar is then
    SIGKILLed, which leaves its socket file behind (the WOR-352 stale-socket
    race), and an impostor binds the same path. The next request's reconnect
    must check the new server's uid before writing, so the request gets the
    usual 503, the impostor gets nothing, and the proxy log names both uids.

    This process can't run the sidecar as another uid, so the peer-credential
    boundary stands in for a split-uid kernel: while the sidecar process is
    alive it reports that process's connections as ``_OTHER_UID``, and after it
    dies it passes on the kernel's own answer.
    """
    socket_path, sidecar_pid = subprocess_sidecar
    sidecar_alive = True
    kernel_answer = peercred.get_peer_credentials

    def _split_uid_kernel(sock: socket.socket) -> peercred.PeerCredentials:
        creds = kernel_answer(sock)
        return dataclasses.replace(creds, uid=_OTHER_UID) if sidecar_alive else creds

    monkeypatch.setattr(peercred, "get_peer_credentials", _split_uid_kernel)
    monkeypatch.setenv(WORTHLESS_SIDECAR_UID_ENV, str(_OTHER_UID))
    caplog.set_level(logging.WARNING, logger="worthless.proxy.ipc_supervisor")

    # Seal shard B under the key the sidecar was started with, so it can open it.
    fernet_key = bytes(a ^ b for a, b in zip(*fernet_shares, strict=True))
    repo = ShardRepository(tmp_db_path, fernet_key)
    await repo.initialize()
    api_key = "sk-test-key-1234567890abcdef"
    split = split_key_fp(api_key, prefix="sk-", provider="openai")
    await repo.store(
        "test-key",
        StoredShard(
            shard_b=bytearray(split.shard_b),
            commitment=bytearray(split.commitment),
            nonce=bytearray(split.nonce),
            provider="openai",
        ),
        prefix=split.prefix,
        charset=split.charset,
        base_url="https://api.openai.com/v1",
    )
    upstream = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [], "usage": {"total_tokens": 5}})
    )

    settings = ProxySettings(
        db_path=tmp_db_path,
        fernet_key=bytearray(fernet_key),
        default_rate_limit_rps=100.0,
        upstream_timeout=10.0,
        streaming_timeout=30.0,
        allow_insecure=True,
        sidecar_socket_path=str(socket_path),
    )
    sup = IPCSupervisor(
        socket_path,
        protocol_version=settings.sidecar_protocol_version,
        expected_caps=settings.sidecar_expected_caps,
        request_timeout_s=1.0,
    )
    await sup.connect()
    app = create_app(settings)
    db = await aiosqlite.connect(tmp_db_path)
    app.state.db = db
    app.state.repo = repo
    app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
    app.state.rules_engine = RulesEngine(
        rules=[SpendCapRule(db=db), RateLimitRule(default_rps=settings.default_rate_limit_rps)]
    )
    app.state.ipc_supervisor = sup
    app.state.ipc_supervisor_preconnected = True

    request = {
        "url": "/test-key/v1/chat/completions",
        "headers": {
            "authorization": f"Bearer {split.shard_a.decode('utf-8')}",
            "content-type": "application/json",
        },
        "content": b'{"model": "gpt-4", "messages": []}',
    }
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            first = await client.post(**request)
            assert first.status_code == 200, first.text
            # Only the real sidecar can open shard B, so this is the full key.
            assert upstream.calls.last.request.headers["authorization"] == f"Bearer {api_key}"

            os.kill(sidecar_pid, signal.SIGKILL)
            os.waitpid(sidecar_pid, 0)
            sidecar_alive = False
            socket_path.unlink()

            async with _serving_impostor(socket_path) as impostor:
                second = await client.post(**request)
                assert second.status_code == 503, second.text
                assert second.json()["error"]["message"] == "sidecar unavailable"
                await asyncio.wait_for(impostor.disconnected.wait(), timeout=2.0)
                assert impostor.connections >= 1, "the proxy never reconnected to the path"
                assert bytes(impostor.received) == b"", (
                    f"proxy wrote {len(impostor.received)} bytes to the impostor on reconnect"
                )
    finally:
        await sup.aclose()
        await app.state.httpx_client.aclose()
        await db.close()

    refusals = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "sidecar connection refused" in r.getMessage()
    ]
    assert refusals, "the refused reconnect left no warning in the proxy log"
    assert f"sidecar uid {_OTHER_UID}" in refusals[-1], refusals[-1]
    assert f"peer uid {os.getuid()}" in refusals[-1], refusals[-1]
