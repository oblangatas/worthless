"""The HTTP client that carries reconstructed keys to the provider (WOR-1071).

Built in one place so that nothing about where a real key goes, or which
certificates may vouch for the host that receives it, comes from the process
environment. httpx's default ``trust_env=True`` routes through ``HTTP(S)_PROXY``
/ ``ALL_PROXY`` (or the macOS / Windows system proxy when those are unset) and
trusts a CA named by ``SSL_CERT_FILE`` / ``SSL_CERT_DIR``: a TLS-inspecting
egress proxy whose CA is trusted that way reads every key in clear. CPython's
``ssl.create_default_context`` also honours ``SSLKEYLOGFILE``, which writes the
secrets that decrypt a packet capture.

The explicit replacements are ``WORTHLESS_UPSTREAM_PROXY`` and
``WORTHLESS_UPSTREAM_CA_BUNDLE``. ``tests/architecture/test_httpx_trust_env.py``
keeps any other httpx client out of the proxy package.
"""

from __future__ import annotations

import logging
import os
import ssl
import urllib.request

import httpx

from worthless.proxy.config import ProxySettings

logger = logging.getLogger(__name__)

_PROXY_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")
_CA_VARS = ("SSL_CERT_FILE", "SSL_CERT_DIR")


def upstream_ssl_context(ca_bundle: str | None) -> ssl.SSLContext:
    """Verify providers against certifi's CA list, or *ca_bundle* if the operator named one."""
    if ca_bundle is None:
        ctx = httpx.create_ssl_context(trust_env=False)
    else:
        ctx = ssl.create_default_context(cafile=ca_bundle)
    # create_default_context reads SSLKEYLOGFILE. None turns it off; typeshed says str.
    ctx.keylog_filename = None  # type: ignore[assignment]
    return ctx


def _ambient_proxy_sources() -> list[str]:
    named = [n for n in _PROXY_VARS if os.environ.get(n) or os.environ.get(n.lower())]
    if named:
        return named
    try:
        # Falls back to the macOS / Windows system settings when the env has no
        # proxy variable. Only the schemes httpx would have used count: a lone
        # NO_PROXY or FTP_PROXY routes nothing.
        found = urllib.request.getproxies()
    except Exception:  # noqa: BLE001 — a diagnostic must never stop the proxy starting
        return []
    return (
        ["the system proxy settings"] if any(found.get(k) for k in ("http", "https", "all")) else []
    )


def _warn_ignored_env(settings: ProxySettings) -> None:
    """Name the ambient proxy / CA settings the upstream call ignores, and the opt-in.

    Names only, never values: a proxy URL can carry a password.
    """
    if settings.upstream_proxy is None and (proxies := _ambient_proxy_sources()):
        logger.warning(
            "upstream calls ignore %s. If providers are reachable only through an "
            "egress proxy, set WORTHLESS_UPSTREAM_PROXY; whoever runs it can read "
            "your real keys if it inspects TLS.",
            ", ".join(proxies),
        )
    cas = [n for n in _CA_VARS if os.environ.get(n)]
    if settings.upstream_ca_bundle is None and cas:
        logger.warning(
            "upstream TLS ignores %s and verifies providers against the built-in CA "
            "list. To trust another CA, set WORTHLESS_UPSTREAM_CA_BUNDLE; anyone "
            "holding that CA's key can read your real keys.",
            ", ".join(cas),
        )


def build_upstream_client(settings: ProxySettings) -> httpx.AsyncClient:
    """Return the client the proxy forwards with.

    Its routing and TLS trust come from *settings* only. The environment is read
    just to warn about what is being ignored.
    """
    _warn_ignored_env(settings)
    ssl_ctx = upstream_ssl_context(settings.upstream_ca_bundle)
    limits = httpx.Limits(max_connections=100, max_keepalive_connections=20)
    mounts: dict[str, httpx.AsyncBaseTransport] = {}
    if settings.upstream_proxy is not None:
        # https:// only. Any proxy could read the key in a plain-http request, so
        # an http:// upstream (a local gateway) is always reached directly. An
        # https:// proxy is verified like a provider; httpcore's default context
        # for it would read SSL_CERT_FILE and SSLKEYLOGFILE.
        tls_to_proxy = settings.upstream_proxy.lower().startswith("https://")
        proxy = httpx.Proxy(settings.upstream_proxy, ssl_context=ssl_ctx if tls_to_proxy else None)
        mounts["https://"] = httpx.AsyncHTTPTransport(
            proxy=proxy, verify=ssl_ctx, trust_env=False, limits=limits
        )
    return httpx.AsyncClient(
        follow_redirects=False,
        trust_env=False,
        verify=ssl_ctx,
        mounts=mounts,
        timeout=httpx.Timeout(
            connect=10.0,
            read=settings.streaming_timeout,
            write=settings.upstream_timeout,
            pool=10.0,
        ),
        limits=limits,
    )
