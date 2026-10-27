"""The real key goes where worthless was told, not where its environment says (WOR-1071).

The proxy's upstream client used httpx's default ``trust_env=True``. httpx then
routes through ``HTTP(S)_PROXY`` / ``ALL_PROXY`` (and the macOS / Windows system
proxy when those are unset) and trusts any CA named by ``SSL_CERT_FILE`` /
``SSL_CERT_DIR``. A TLS-inspecting corporate proxy whose CA is trusted that way
sees every reconstructed key in clear. CPython's ``ssl.create_default_context``
also honours ``SSLKEYLOGFILE``, which writes the secrets that decrypt a capture.

These tests drive a real request through the client the real lifespan builds (no
injected ``httpx_client``), against local sockets only:

* an "env proxy" sink named by the proxy variables,
* an upstream TLS server whose certificate only a test CA vouches for: the
  inspecting-proxy case, where that CA reaches the client via ``SSL_CERT_FILE``,
* a CONNECT tunnel standing in for an egress proxy the operator opted into.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import ipaddress
import json
import logging
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from worthless.crypto.splitter import split_key_fp
from worthless.proxy.app import create_app
from worthless.proxy.config import ConfigError, ProxySettings
from worthless.storage.repository import ShardRepository, StoredShard

from tests._fakes import pin_shard_b

_REAL_KEY = "sk-envtrust-real-key-0123456789abcdef"
_ALIAS = "envtrust"

_CHAT_REPLY = json.dumps(
    {
        "id": "chatcmpl-envtrust",
        "object": "chat.completion",
        "created": 0,
        "model": "gpt-4o",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "pong"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
).encode()

_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
_TRANSPORT_VARS = (
    *_PROXY_VARS,
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SSLKEYLOGFILE",
    "WORTHLESS_UPSTREAM_PROXY",
    "WORTHLESS_UPSTREAM_CA_BUNDLE",
)


@pytest.fixture(autouse=True)
def _clean_transport_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test with no proxy, CA or keylog settings from the host."""
    for name in _TRANSPORT_VARS:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)


def _set_env_proxy(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, url)
        monkeypatch.setenv(name.lower(), url)


# ---------------------------------------------------------------------------
# Local sockets
# ---------------------------------------------------------------------------


def _content_length(head: bytes) -> int:
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            return int(value.strip())
    return 0


class _Recorder:
    """Every byte a local server received, across all its connections."""

    def __init__(self) -> None:
        self.received = bytearray()
        self.connections = 0


Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter, _Recorder], Awaitable[None]]


@contextlib.asynccontextmanager
async def _serve(
    handler: Handler, *, tls: ssl.SSLContext | None = None
) -> AsyncIterator[tuple[int, _Recorder]]:
    recorder = _Recorder()

    async def _on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        recorder.connections += 1
        try:
            await handler(reader, writer, recorder)
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(_on_connect, "127.0.0.1", 0, ssl=tls)
    try:
        yield server.sockets[0].getsockname()[1], recorder
    finally:
        server.close()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(server.wait_closed(), 2)


async def _answer_chat(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, rec: _Recorder
) -> None:
    """A provider: record the request, reply with a chat completion."""
    head = await reader.readuntil(b"\r\n\r\n")
    rec.received += head + await reader.readexactly(_content_length(head))
    writer.write(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(_CHAT_REPLY) + _CHAT_REPLY
    )
    await writer.drain()


async def _refuse(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, rec: _Recorder
) -> None:
    """A proxy that records what it was sent (CONNECT or a plain request) and refuses it."""
    head = await reader.readuntil(b"\r\n\r\n")
    rec.received += head + await reader.readexactly(_content_length(head))
    writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    await writer.drain()


async def _tunnel(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, rec: _Recorder
) -> None:
    """A non-inspecting egress proxy: honour CONNECT and pipe bytes both ways."""
    head = await reader.readuntil(b"\r\n\r\n")
    rec.received += head
    host, _, port = head.split(b" ")[1].decode().rpartition(":")
    up_reader, up_writer = await asyncio.open_connection(host, int(port))
    writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await writer.drain()

    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while data := await src.read(65536):
                rec.received += data
                dst.write(data)
                await dst.drain()
        except ConnectionError:
            pass
        finally:
            dst.close()

    await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))


# ---------------------------------------------------------------------------
# A test CA and a server certificate for 127.0.0.1
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def test_pki(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, Path]:
    """Return ``(ca_pem, server_cert_pem, server_key_pem)``.

    The CA stands in for a corporate TLS-inspection CA. Python 3.13 verifies
    with ``VERIFY_X509_STRICT``, hence the key-identifier extensions.
    """
    out = tmp_path_factory.mktemp("pki")
    now = datetime.datetime.now(datetime.timezone.utc)
    valid = {
        "not_valid_before": now - datetime.timedelta(days=1),
        "not_valid_after": now + datetime.timedelta(days=1),
    }

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "worthless test inspection CA")])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid["not_valid_before"])
        .not_valid_after(valid["not_valid_after"])
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid["not_valid_before"])
        .not_valid_after(valid["not_valid_after"])
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_pem = out / "ca.pem"
    ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_pem = out / "server.pem"
    cert_pem.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_pem = out / "server.key"
    key_pem.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_pem, cert_pem, key_pem


def _server_tls(test_pki: tuple[Path, Path, Path]) -> ssl.SSLContext:
    _ca, cert, key = test_pki
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


# ---------------------------------------------------------------------------
# One request through the lifespan-built upstream client
# ---------------------------------------------------------------------------


async def _proxied_chat(
    tmp_db_path: str, fernet_key: bytes, repo: ShardRepository, base_url: str
) -> httpx.Response:
    """Lock ``_REAL_KEY`` to *base_url*, boot the proxy for real, send one chat request.

    Settings are built here, after the test has set its environment, so the
    proxy reads ``WORTHLESS_UPSTREAM_*`` the way it does in production.
    """
    sr = split_key_fp(_REAL_KEY, prefix="sk-", provider="openai")
    shard = StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider="openai",
    )
    await repo.store(_ALIAS, shard, prefix=sr.prefix, charset=sr.charset, base_url=base_url)

    settings = ProxySettings(
        db_path=tmp_db_path, fernet_key=bytearray(fernet_key), allow_insecure=True
    )
    app = create_app(settings)
    pin_shard_b(app, _ALIAS, sr.shard_b)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client:
            return await client.post(
                f"/{_ALIAS}/v1/chat/completions",
                headers={"Authorization": f"Bearer {sr.shard_a.decode()}"},
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "ping"}]},
            )


_KEY = _REAL_KEY.encode()


# ---------------------------------------------------------------------------
# Ambient settings are ignored
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_env_proxy_vars_never_receive_the_real_key(
    tmp_db_path: str, fernet_key: bytes, repo: ShardRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HTTP(S)_PROXY / ALL_PROXY don't reroute the upstream call.

    A plain-http upstream makes the leak literal: httpx sends an env proxy the
    whole request, ``Authorization: Bearer <real key>`` included.
    """
    async with (
        _serve(_refuse) as (env_proxy_port, env_proxy),
        _serve(_answer_chat) as (up_port, upstream),
    ):
        _set_env_proxy(monkeypatch, f"http://127.0.0.1:{env_proxy_port}")

        resp = await _proxied_chat(tmp_db_path, fernet_key, repo, f"http://127.0.0.1:{up_port}/v1")

    assert _KEY not in env_proxy.received, "the proxy named by HTTP_PROXY received the real key"
    assert env_proxy.connections == 0, "the upstream call went through the env proxy"
    assert resp.status_code == 200, resp.text
    assert b"Bearer " + _KEY in upstream.received


@pytest.mark.asyncio
async def test_ca_trusted_only_via_ssl_cert_file_cannot_vouch_for_the_upstream(
    tmp_db_path: str,
    fernet_key: bytes,
    repo: ShardRepository,
    monkeypatch: pytest.MonkeyPatch,
    test_pki: tuple[Path, Path, Path],
) -> None:
    """A server only ``SSL_CERT_FILE``'s CA vouches for never gets the key.

    That server is what a TLS-inspecting proxy looks like to the client: it
    terminates TLS with a certificate from the corporate CA. The control is
    ``test_ca_bundle_opt_in_is_trusted_for_the_upstream``: the same server answers
    200 once its CA is trusted explicitly.
    """
    ca_pem, _cert, _key = test_pki
    async with _serve(_answer_chat, tls=_server_tls(test_pki)) as (port, inspector):
        monkeypatch.setenv("SSL_CERT_FILE", str(ca_pem))

        resp = await _proxied_chat(tmp_db_path, fernet_key, repo, f"https://127.0.0.1:{port}/v1")

    assert _KEY not in inspector.received, (
        "a CA trusted only via SSL_CERT_FILE received the real key"
    )
    assert resp.status_code == 502


@pytest.mark.asyncio
async def test_sslkeylogfile_gets_no_upstream_tls_secrets(
    tmp_db_path: str,
    fernet_key: bytes,
    repo: ShardRepository,
    monkeypatch: pytest.MonkeyPatch,
    test_pki: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    """SSLKEYLOGFILE would let anyone holding a packet capture decrypt the key.

    CPython opens the file, writing only a ``#`` header, as soon as it builds an
    SSL context. What must never appear is a secret line.
    """
    ca_pem, _cert, _key = test_pki
    keylog = tmp_path / "tls-keys.log"
    async with _serve(_answer_chat, tls=_server_tls(test_pki)) as (port, upstream):
        monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
        monkeypatch.setenv("WORTHLESS_UPSTREAM_CA_BUNDLE", str(ca_pem))

        resp = await _proxied_chat(tmp_db_path, fernet_key, repo, f"https://127.0.0.1:{port}/v1")

    written = keylog.read_text() if keylog.exists() else ""
    secrets = [line for line in written.splitlines() if line and not line.startswith("#")]
    assert not secrets, "upstream TLS secrets went to SSLKEYLOGFILE"
    assert resp.status_code == 200, resp.text
    assert b"Bearer " + _KEY in upstream.received


# ---------------------------------------------------------------------------
# Explicit opt-ins
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ca_bundle_opt_in_is_trusted_for_the_upstream(
    tmp_db_path: str,
    fernet_key: bytes,
    repo: ShardRepository,
    monkeypatch: pytest.MonkeyPatch,
    test_pki: tuple[Path, Path, Path],
) -> None:
    """``WORTHLESS_UPSTREAM_CA_BUNDLE`` is the one way to trust another CA."""
    ca_pem, _cert, _key = test_pki
    async with _serve(_answer_chat, tls=_server_tls(test_pki)) as (port, upstream):
        monkeypatch.setenv("WORTHLESS_UPSTREAM_CA_BUNDLE", str(ca_pem))

        resp = await _proxied_chat(tmp_db_path, fernet_key, repo, f"https://127.0.0.1:{port}/v1")

    assert resp.status_code == 200, resp.text
    assert b"Bearer " + _KEY in upstream.received


@pytest.mark.asyncio
async def test_upstream_proxy_opt_in_tunnels_https_without_seeing_the_key(
    tmp_db_path: str,
    fernet_key: bytes,
    repo: ShardRepository,
    monkeypatch: pytest.MonkeyPatch,
    test_pki: tuple[Path, Path, Path],
) -> None:
    """``WORTHLESS_UPSTREAM_PROXY`` routes https upstreams through a CONNECT tunnel.

    A proxy that doesn't inspect TLS only relays ciphertext. Env proxy variables
    pointing elsewhere are still ignored.
    """
    ca_pem, _cert, _key = test_pki
    async with (
        _serve(_answer_chat, tls=_server_tls(test_pki)) as (up_port, upstream),
        _serve(_tunnel) as (tunnel_port, tunnel),
        _serve(_refuse) as (env_proxy_port, env_proxy),
    ):
        _set_env_proxy(monkeypatch, f"http://127.0.0.1:{env_proxy_port}")
        monkeypatch.setenv("WORTHLESS_UPSTREAM_PROXY", f"http://127.0.0.1:{tunnel_port}")
        monkeypatch.setenv("WORTHLESS_UPSTREAM_CA_BUNDLE", str(ca_pem))

        resp = await _proxied_chat(tmp_db_path, fernet_key, repo, f"https://127.0.0.1:{up_port}/v1")

    assert resp.status_code == 200, resp.text
    assert tunnel.received.startswith(b"CONNECT 127.0.0.1:%d " % up_port)
    assert _KEY not in tunnel.received, "the tunnel saw the key in clear"
    assert b"Bearer " + _KEY in upstream.received
    assert env_proxy.connections == 0


@pytest.mark.asyncio
async def test_https_upstream_proxy_is_verified_like_a_provider(
    tmp_db_path: str,
    fernet_key: bytes,
    repo: ShardRepository,
    monkeypatch: pytest.MonkeyPatch,
    test_pki: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    """An ``https://`` egress proxy is verified like a provider, never by the env's TLS settings.

    httpcore's default context for the hop to the proxy would trust only certifi
    (plus SSL_CERT_FILE) and write SSLKEYLOGFILE; this proxy's test CA is in the
    bundle only.
    """
    ca_pem, _cert, _key = test_pki
    keylog = tmp_path / "tls-keys.log"
    async with (
        _serve(_answer_chat, tls=_server_tls(test_pki)) as (up_port, upstream),
        _serve(_tunnel, tls=_server_tls(test_pki)) as (tunnel_port, tunnel),
    ):
        monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
        monkeypatch.setenv("WORTHLESS_UPSTREAM_PROXY", f"https://127.0.0.1:{tunnel_port}")
        monkeypatch.setenv("WORTHLESS_UPSTREAM_CA_BUNDLE", str(ca_pem))

        resp = await _proxied_chat(tmp_db_path, fernet_key, repo, f"https://127.0.0.1:{up_port}/v1")

    assert resp.status_code == 200, resp.text
    assert tunnel.received.startswith(b"CONNECT 127.0.0.1:%d " % up_port)
    assert b"Bearer " + _KEY in upstream.received
    written = keylog.read_text() if keylog.exists() else ""
    assert not [line for line in written.splitlines() if line and not line.startswith("#")]


@pytest.mark.asyncio
async def test_upstream_proxy_opt_in_never_carries_a_plain_http_upstream(
    tmp_db_path: str, fernet_key: bytes, repo: ShardRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any proxy could read a plain-http request, so one never goes through it."""
    async with _serve(_refuse) as (proxy_port, egress), _serve(_answer_chat) as (up_port, upstream):
        monkeypatch.setenv("WORTHLESS_UPSTREAM_PROXY", f"http://127.0.0.1:{proxy_port}")

        resp = await _proxied_chat(tmp_db_path, fernet_key, repo, f"http://127.0.0.1:{up_port}/v1")

    assert egress.connections == 0
    assert resp.status_code == 200, resp.text
    assert b"Bearer " + _KEY in upstream.received


# ---------------------------------------------------------------------------
# Startup warning and settings validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_startup_warns_that_ambient_proxy_and_ca_settings_are_ignored(
    tmp_db_path: str,
    fernet_key: bytes,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    test_pki: tuple[Path, Path, Path],
) -> None:
    """Someone whose calls now fail behind a proxy learns why, and what to set.

    The warning names variables, never values: a proxy URL can hold a password.
    """
    ca_pem, _cert, _key = test_pki
    monkeypatch.setenv("HTTPS_PROXY", "http://corp-user:hunter2@egress.corp.example:3128")
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_pem))
    settings = ProxySettings(
        db_path=tmp_db_path, fernet_key=bytearray(fernet_key), allow_insecure=True
    )
    app = create_app(settings)

    with caplog.at_level(logging.WARNING):
        async with app.router.lifespan_context(app):
            pass

    text = caplog.text
    assert "HTTPS_PROXY" in text and "SSL_CERT_FILE" in text
    assert "WORTHLESS_UPSTREAM_PROXY" in text and "WORTHLESS_UPSTREAM_CA_BUNDLE" in text
    assert "hunter2" not in text and "egress.corp.example" not in text
    assert str(ca_pem) not in text


@pytest.mark.asyncio
async def test_startup_warns_about_an_ignored_system_proxy(
    tmp_db_path: str,
    fernet_key: bytes,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """With no proxy variables, macOS / Windows hand httpx the system proxy instead."""
    monkeypatch.setattr(
        "urllib.request.getproxies", lambda: {"https": "http://egress.corp.example:3128"}
    )
    settings = ProxySettings(
        db_path=tmp_db_path, fernet_key=bytearray(fernet_key), allow_insecure=True
    )
    app = create_app(settings)

    with caplog.at_level(logging.WARNING):
        async with app.router.lifespan_context(app):
            pass

    assert "system proxy settings" in caplog.text and "WORTHLESS_UPSTREAM_PROXY" in caplog.text
    assert "egress.corp.example" not in caplog.text


@pytest.mark.asyncio
async def test_no_warning_without_ambient_settings(
    tmp_db_path: str,
    fernet_key: bytes,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr("urllib.request.getproxies", dict)
    settings = ProxySettings(
        db_path=tmp_db_path, fernet_key=bytearray(fernet_key), allow_insecure=True
    )
    app = create_app(settings)

    with caplog.at_level(logging.WARNING):
        async with app.router.lifespan_context(app):
            pass

    assert "WORTHLESS_UPSTREAM" not in caplog.text


@pytest.mark.asyncio
async def test_no_warning_when_only_no_proxy_is_set(
    tmp_db_path: str,
    fernet_key: bytes,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A lone NO_PROXY routes nothing, so there is nothing to warn about."""
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1")
    monkeypatch.setenv("no_proxy", "localhost,127.0.0.1")
    settings = ProxySettings(
        db_path=tmp_db_path, fernet_key=bytearray(fernet_key), allow_insecure=True
    )
    app = create_app(settings)

    with caplog.at_level(logging.WARNING):
        async with app.router.lifespan_context(app):
            pass

    assert "WORTHLESS_UPSTREAM" not in caplog.text


@pytest.mark.asyncio
async def test_no_warning_once_the_operator_opted_in(
    tmp_db_path: str,
    fernet_key: bytes,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    test_pki: tuple[Path, Path, Path],
) -> None:
    ca_pem, _cert, _key = test_pki
    _set_env_proxy(monkeypatch, "http://egress.corp.example:3128")
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_pem))
    monkeypatch.setenv("WORTHLESS_UPSTREAM_PROXY", "http://egress.corp.example:3128")
    monkeypatch.setenv("WORTHLESS_UPSTREAM_CA_BUNDLE", str(ca_pem))
    settings = ProxySettings(
        db_path=tmp_db_path, fernet_key=bytearray(fernet_key), allow_insecure=True
    )
    app = create_app(settings)

    with caplog.at_level(logging.WARNING):
        async with app.router.lifespan_context(app):
            pass

    assert "WORTHLESS_UPSTREAM" not in caplog.text


class TestUpstreamSettings:
    """``WORTHLESS_UPSTREAM_PROXY`` / ``WORTHLESS_UPSTREAM_CA_BUNDLE`` parsing."""

    def test_unset_means_no_proxy_and_no_extra_ca(self) -> None:
        s = ProxySettings()
        assert s.upstream_proxy is None
        assert s.upstream_ca_bundle is None

    def test_read_from_env(
        self, monkeypatch: pytest.MonkeyPatch, test_pki: tuple[Path, Path, Path]
    ) -> None:
        ca_pem, _cert, _key = test_pki
        monkeypatch.setenv("WORTHLESS_UPSTREAM_PROXY", " http://egress.example:3128 ")
        monkeypatch.setenv("WORTHLESS_UPSTREAM_CA_BUNDLE", str(ca_pem))
        s = ProxySettings()
        s.validate()
        assert s.upstream_proxy == "http://egress.example:3128"
        assert s.upstream_ca_bundle == str(ca_pem)

    @pytest.mark.parametrize(
        "value",
        [
            "socks5://u:hunter2@egress.example:1080",
            "http://u:hunter2[@egress.example:3128",
            "egress.example:3128",
            "http://u:hunter2@:3128",
            "ftp://u:hunter2@egress.example",
        ],
    )
    def test_proxy_must_be_an_http_url_with_a_host(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("WORTHLESS_UPSTREAM_PROXY", value)
        with pytest.raises(ConfigError, match="WORTHLESS_UPSTREAM_PROXY") as exc:
            ProxySettings().validate()
        assert "hunter2" not in str(exc.value)

    @pytest.mark.parametrize("problem", ["missing", "no certificate", "relative", "directory"])
    def test_ca_bundle_must_load_at_startup(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, problem: str
    ) -> None:
        """A bundle the client couldn't use fails in validate(), naming the variable."""
        paths = {
            "missing": tmp_path / "missing.pem",
            "no certificate": tmp_path / "empty.pem",
            "relative": Path("bundle.pem"),
            "directory": tmp_path,
        }
        (tmp_path / "empty.pem").write_text("not a certificate\n")
        monkeypatch.setenv("WORTHLESS_UPSTREAM_CA_BUNDLE", str(paths[problem]))
        with pytest.raises(ConfigError, match="WORTHLESS_UPSTREAM_CA_BUNDLE"):
            ProxySettings().validate()

    def test_proxy_password_not_in_repr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_UPSTREAM_PROXY", "http://u:hunter2@egress.example:3128")
        assert "hunter2" not in repr(ProxySettings())
