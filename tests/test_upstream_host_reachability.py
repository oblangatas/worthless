"""Guard the reachability argument the CVE-2026-116566 suppression rests on.

WOR-1108. CPython before 3.16.0 lets ``socket.getaddrinfo()`` truncate a host
or port at a null byte, which can slip an attacker-chosen address past an
allowlist. No stable CPython has the fix, so ``.grype.yaml`` suppresses it on
one claim: the host and port the proxy resolves come only from the stored
``base_url`` (checked by lock's SSRF guard), never from the client's request.

Nothing stopped that claim from quietly becoming false: an adapter that built
its URL from a request header or the body would make the CVE reachable while
the suppression kept the scan green. This test is what catches it.

If you are here because this test failed: the fix is NOT to adjust the test.
Re-open ``.grype.yaml`` and decide whether CVE-2026-116566 is still safe to
suppress now that request input reaches the upstream address.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx
import pytest

from worthless.adapters.registry import _ADAPTERS
from worthless.cli.commands.lock import _validate_upstream_base_url
from worthless.cli.errors import WorthlessError

_BASE_URL = "https://api.example.com:8443/v1"

_HOSTILE_HEADERS = {
    "host": "evil.example\x00.api.example.com",
    "x-forwarded-host": "169.254.169.254",
    "x-forwarded-port": "80\x00",
    "content-type": "application/json",
}
_HOSTILE_BODY = (
    b'{"model": "m", "base_url": "http://169.254.169.254\\u0000/", '
    b'"url": "http://evil.example:80/", "messages": []}'
)


@pytest.mark.parametrize("path", sorted(_ADAPTERS))
def test_request_input_never_reaches_the_upstream_host_or_port(path: str) -> None:
    req = _ADAPTERS[path].prepare_request(
        body=_HOSTILE_BODY,
        headers=dict(_HOSTILE_HEADERS),
        api_key=bytearray(b"sk-test-not-a-real-key"),
        base_url=_BASE_URL,
    )
    upstream, stored = urlsplit(req.url), urlsplit(_BASE_URL)
    assert (upstream.hostname, upstream.port) == (stored.hostname, stored.port), req.url
    assert "\x00" not in req.url


@pytest.mark.parametrize(
    "url", ["https://evil.example\x00.api.openai.com/v1", "https://api.openai.com:443\x00/v1"]
)
def test_httpx_refuses_a_null_byte_before_any_lookup(url: str) -> None:
    """The actual defence: every upstream call goes through ``httpx.URL``, which
    refuses a NUL in the host or port, so the CVE's trigger never reaches
    ``getaddrinfo`` (httpx 0.28.1)."""
    with pytest.raises(httpx.InvalidURL):
        httpx.URL(url)


def test_lock_refuses_to_store_a_base_url_with_a_null_byte() -> None:
    with pytest.raises(WorthlessError):
        _validate_upstream_base_url("https://evil.example\x00.api.openai.com/v1")
