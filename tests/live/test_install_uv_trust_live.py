"""Live: the uv install.sh bootstraps refuses servers chained through the compromised eMudhra keys.

GHSA-hq85-5cpj-mr62 (WOR-1116). Two checks, each a `uv tool install` the way
install.sh runs it, against a server uv 0.11.7 (install.sh's old pin) accepted:

- eMudhra's public test site chains
  leaf -> EM EV TLS CA - G3A-1 -> emSign Root TLS CA - G3 -> emSign ECC Root CA - G3,
  the root above the compromised intermediate keys. uv 0.11.7 completed TLS
  with it and read its 404 as "not found in the package registry". The pinned
  uv must not trust that root (`UnknownIssuer`).
- A localhost server sends a leaf signed with one of the compromised keys
  (EM OV TLS CA - G3C), from CPython's own test data. The pinned uv must refuse
  the chain because of the key itself (`CertDistrusted`), with uv's built-in
  roots and also with emSign Root TLS CA - G3 given as a trust anchor, where
  the chain would otherwise be valid.

Installs the pinned uv the way install.sh does: Astral's installer from
ASTRAL_INSTALLER_URL, checked against ASTRAL_INSTALLER_SHA256. Needs network;
skips if the test site or CPython's test data can't be reached, or the test
site no longer chains to that root. CI sets WORTHLESS_UV_TRUST_REQUIRED=1, so
there a skip fails instead: a green job means the checks ran.

Run:
    uv run pytest tests/live/test_install_uv_trust_live.py -m live -v
"""

from __future__ import annotations

import hashlib
import http.server
import io
import os
import socket
import ssl
import subprocess  # noqa: S404
import sys
import threading
import zipfile
from pathlib import Path
from typing import NoReturn

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from tests._install_helpers import read_install_var

_TEST_HOST = "testevg3.emsign.com"
_AFFECTED_ROOT = "emSign ECC Root CA - G3"
_TLS_ROOT = "emSign Root TLS CA - G3"

# CPython's test chain for the compromised keys (Lib/test/certdata, v3.14.10):
# a localhost leaf and its private key, signed with the leaked EM OV TLS CA -
# G3C key; that intermediate; and emSign Root TLS CA - G3, self-signed. Fetched
# at the tag's commit and checked by SHA-256, not committed: it holds a private
# key. CPython encrypts the zip so scanners don't flag the PEMs; the password is
# fixed and public (DISTRUSTED_SPKI_CHOSEN_KNIGHT in its test_ssl.py).
_DISTRUSTED_ZIP_URL = (
    "https://raw.githubusercontent.com/python/cpython/"
    "b703b2c5e704341d61e367b9b940b77ed11dded0/Lib/test/certdata/distrusted.zip"
)
_DISTRUSTED_ZIP_SHA256 = "8a9874e20b8583e80e9d7d6c82ea566c22d50458a93bfef6400d70dde132a053"
_DISTRUSTED_ZIP_PASSWORD = b"Brave Sir Robin"


def _served_chain(host: str) -> list[x509.Certificate]:
    """The certificates the server sends, unverified."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, 443), timeout=10) as raw,
        ctx.wrap_socket(raw, server_hostname=host) as tls,
    ):
        chain = tls.get_unverified_chain()
    return [x509.load_der_x509_certificate(der) for der in chain]


def _common_name(name: x509.Name) -> str:
    return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def _skip_unless_required(reason: str) -> NoReturn:
    """Skip, unless CI requires the check (WORTHLESS_UV_TRUST_REQUIRED=1): then fail."""
    if os.environ.get("WORTHLESS_UV_TRUST_REQUIRED") == "1":
        pytest.fail(reason)
    pytest.skip(reason)


@pytest.fixture(scope="module")
def pinned_uv(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """install.sh's pinned uv, installed through its SHA-checked Astral installer."""
    tmp_path = tmp_path_factory.mktemp("uv")
    version = read_install_var("UV_VERSION")
    url = read_install_var("ASTRAL_INSTALLER_URL").replace("${UV_VERSION}", version)
    response = httpx.get(url, follow_redirects=True, timeout=60)
    response.raise_for_status()
    installer = response.content
    assert hashlib.sha256(installer).hexdigest() == read_install_var("ASTRAL_INSTALLER_SHA256")
    (tmp_path / "uv-installer.sh").write_bytes(installer)
    home, bin_dir = tmp_path / "home", tmp_path / "bin"
    home.mkdir()
    subprocess.run(  # noqa: S603
        ["/bin/sh", str(tmp_path / "uv-installer.sh")],
        env={
            "HOME": str(home),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "UV_INSTALL_VERSION": version,
            "UV_INSTALL_DIR": str(bin_dir),
        },
        check=True,
    )
    uv = bin_dir / "uv"
    reported = subprocess.run([str(uv), "--version"], capture_output=True, text=True, check=True)  # noqa: S603
    assert reported.stdout.split()[1] == version
    return uv


def _uv_tool_install(
    uv: Path, index_url: str, home: Path, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """install.sh's `uv tool install`, with `index_url` as the index, no cache
    and this interpreter (so no Python download)."""
    home.mkdir()
    return subprocess.run(  # noqa: S603
        [
            str(uv),
            "tool",
            "install",
            "--force",
            "--no-cache",
            "--python",
            sys.executable,
            "--index-url",
            index_url,
            "worthless",
        ],
        env={
            "HOME": str(home),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "UV_NO_CONFIG": "1",
            **(extra_env or {}),
        },
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.live
@pytest.mark.timeout(300)
def test_pinned_uv_refuses_a_server_chained_to_the_emsign_g3_root(
    pinned_uv: Path, tmp_path: Path
) -> None:
    """`uv tool install` with the pinned uv fails TLS against the test site."""
    if not hasattr(ssl.SSLSocket, "get_unverified_chain"):
        _skip_unless_required("reading the server's chain needs Python 3.13+")
    try:
        top_issuer = _common_name(_served_chain(_TEST_HOST)[-1].issuer)
    except OSError as exc:
        _skip_unless_required(f"{_TEST_HOST} unreachable: {exc}")
    if top_issuer != _AFFECTED_ROOT:
        _skip_unless_required(f"{_TEST_HOST} now chains to {top_issuer!r}, not {_AFFECTED_ROOT!r}")

    result = _uv_tool_install(pinned_uv, f"https://{_TEST_HOST}/simple/", tmp_path / "home")
    assert result.returncode != 0
    assert "invalid peer certificate: UnknownIssuer" in result.stderr, result.stderr


class _NotFound(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_error(404)

    def log_message(self, *args: object) -> None:
        pass


@pytest.mark.live
@pytest.mark.timeout(300)
@pytest.mark.parametrize("root_as_anchor", [False, True], ids=["built-in roots", "root as anchor"])
def test_pinned_uv_refuses_a_server_using_a_compromised_emsign_key(
    pinned_uv: Path, tmp_path: Path, root_as_anchor: bool
) -> None:
    """`uv tool install` with the pinned uv refuses a leaf signed with a leaked key.

    With uv's built-in roots, the server also sends the test site's
    cross-certificate from emSign Root TLS CA - G3 up to emSign ECC Root CA -
    G3: the chain someone holding the key could serve install.sh, which uv
    0.11.7 accepts. With emSign Root TLS CA - G3 given as a trust anchor
    (SSL_CERT_FILE), the chain is valid apart from the key, so only uv's block
    on the compromised keys (0.13.5 and later) can refuse it.
    """
    try:
        response = httpx.get(_DISTRUSTED_ZIP_URL, timeout=60)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        _skip_unless_required(f"CPython's distrusted.zip unreachable: {exc}")
    assert hashlib.sha256(response.content).hexdigest() == _DISTRUSTED_ZIP_SHA256
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        archive.setpassword(_DISTRUSTED_ZIP_PASSWORD)
        keycert = archive.read("distrusted/distrusted_keycert.pem")
        tls_root = archive.read("distrusted/distrusted_root.pem")

    served = keycert
    extra_env = {}
    if root_as_anchor:
        (tmp_path / "anchor.pem").write_bytes(tls_root)
        extra_env["SSL_CERT_FILE"] = str(tmp_path / "anchor.pem")
    else:
        if not hasattr(ssl.SSLSocket, "get_unverified_chain"):
            _skip_unless_required("reading the server's chain needs Python 3.13+")
        try:
            cross = _served_chain(_TEST_HOST)[-1]
        except OSError as exc:
            _skip_unless_required(f"{_TEST_HOST} unreachable: {exc}")
        names = (_common_name(cross.subject), _common_name(cross.issuer))
        if names != (_TLS_ROOT, _AFFECTED_ROOT):
            _skip_unless_required(f"{_TEST_HOST} no longer sends {_TLS_ROOT} under the G3 root")
        served += cross.public_bytes(Encoding.PEM)

    (tmp_path / "served.pem").write_bytes(served)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "served.pem")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _NotFound)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        index_url = f"https://localhost:{server.server_address[1]}/simple/"
        result = _uv_tool_install(pinned_uv, index_url, tmp_path / "home", extra_env)
    finally:
        server.shutdown()
        server.server_close()
    assert result.returncode != 0
    assert "CertDistrusted" in result.stderr, result.stderr
