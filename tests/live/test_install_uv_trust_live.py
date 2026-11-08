"""Live: the uv install.sh bootstraps refuses a server chained to emSign ECC Root CA - G3.

GHSA-6q48-6c7w-9gw2 (WOR-1116). eMudhra's public test site chains
leaf -> EM EV TLS CA - G3A-1 -> emSign Root TLS CA - G3 -> emSign ECC Root CA - G3,
the root above the compromised intermediate keys. uv 0.11.7, install.sh's old
pin, completed TLS with it and read its 404 as "not found in the package
registry". The pinned uv must refuse the connection, so a server holding a
certificate from those keys can't serve the install a package.

Installs the pinned uv the way install.sh does: Astral's installer from
ASTRAL_INSTALLER_URL, checked against ASTRAL_INSTALLER_SHA256. Needs network;
skips if the test site is gone or no longer chains to that root.

Run:
    uv run pytest tests/live/test_install_uv_trust_live.py -m live -v
"""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
import subprocess  # noqa: S404
import sys
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from tests._install_helpers import INSTALL_SH

_TEST_HOST = "testevg3.emsign.com"
_AFFECTED_ROOT = "emSign ECC Root CA - G3"


def _install_sh_value(name: str) -> str:
    match = re.search(rf'^{name}="([^"]+)"', INSTALL_SH.read_text(encoding="utf-8"), re.MULTILINE)
    assert match, f'install.sh must declare {name}="..."'
    return match.group(1)


def _chain_top_issuer(host: str) -> str:
    """CN of the issuer of the last certificate the server sends, unverified."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, 443), timeout=10) as raw,
        ctx.wrap_socket(raw, server_hostname=host) as tls,
    ):
        chain = tls.get_unverified_chain()
    top = x509.load_der_x509_certificate(chain[-1])
    return top.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


@pytest.mark.live
@pytest.mark.timeout(300)
def test_pinned_uv_refuses_a_server_chained_to_the_emsign_g3_root(tmp_path: Path) -> None:
    try:
        top_issuer = _chain_top_issuer(_TEST_HOST)
    except OSError as exc:
        pytest.skip(f"{_TEST_HOST} unreachable: {exc}")
    if top_issuer != _AFFECTED_ROOT:
        pytest.skip(f"{_TEST_HOST} now chains to {top_issuer!r}, not {_AFFECTED_ROOT!r}")

    version = _install_sh_value("UV_VERSION")
    url = _install_sh_value("ASTRAL_INSTALLER_URL").replace("${UV_VERSION}", version)
    installer = httpx.get(url, follow_redirects=True).content
    assert hashlib.sha256(installer).hexdigest() == _install_sh_value("ASTRAL_INSTALLER_SHA256")
    (tmp_path / "uv-installer.sh").write_bytes(installer)
    home, bin_dir = tmp_path / "home", tmp_path / "bin"
    home.mkdir()
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
    subprocess.run(  # noqa: S603
        ["/bin/sh", str(tmp_path / "uv-installer.sh")],
        env={**env, "UV_INSTALL_VERSION": version, "UV_INSTALL_DIR": str(bin_dir)},
        check=True,
        capture_output=True,
    )
    uv = bin_dir / "uv"
    reported = subprocess.run([str(uv), "--version"], capture_output=True, text=True, check=True)  # noqa: S603
    assert reported.stdout.split()[1] == version

    # install.sh's own call, with the test site as the index.
    result = subprocess.run(  # noqa: S603
        [
            str(uv),
            "tool",
            "install",
            "--force",
            "--no-cache",
            "--python",
            sys.executable,
            "--index-url",
            f"https://{_TEST_HOST}/simple/",
            "worthless",
        ],
        env={**env, "UV_NO_CONFIG": "1"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "invalid peer certificate: UnknownIssuer" in result.stderr, result.stderr
