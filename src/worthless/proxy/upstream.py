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


def _upstream_ssl_context(ca_bundle: str | None) -> ssl.SSLContext:
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
    routed = any(found.get(scheme) for scheme in ("http", "https", "all"))
    return ["the system proxy settings"] if routed else []


def ignored_env_notes(upstream_proxy: str | None, upstream_ca_bundle: str | None) -> list[str]:
    """Say which ambient proxy / CA settings upstream calls ignore, and the opt-in to set.

    Names only, never values: a proxy URL can carry a password. The proxy logs
    these at startup; ``worthless up`` / ``wrap`` print them too, because nothing
    shows the proxy's own output there (WOR-1074).
    """
    notes: list[str] = []
    if upstream_proxy is None and (proxies := _ambient_proxy_sources()):
        notes.append(
            f"Upstream calls ignore {', '.join(proxies)}. If providers are reachable only "
            "through an egress proxy, set WORTHLESS_UPSTREAM_PROXY. That proxy can read "
            "your real keys only if it inspects TLS and you trust its CA with "
            "WORTHLESS_UPSTREAM_CA_BUNDLE."
        )
    cas = [n for n in _CA_VARS if os.environ.get(n)]
    if upstream_ca_bundle is None and cas:
        notes.append(
            f"Upstream TLS ignores {', '.join(cas)} and verifies providers against the "
            "built-in CA list. To trust another CA, set WORTHLESS_UPSTREAM_CA_BUNDLE; "
            "anyone holding that CA's key can then read your real keys."
        )
    return notes


def warn_ignored_env(settings: ProxySettings) -> None:
    """Log :func:`ignored_env_notes` once at startup (``create_app``)."""
    for note in ignored_env_notes(settings.upstream_proxy, settings.upstream_ca_bundle):
        logger.warning("%s", note)


def build_upstream_client(settings: ProxySettings) -> httpx.AsyncClient:
    """Return the client the proxy forwards with. Routing and TLS trust come from *settings*."""
    ssl_ctx = _upstream_ssl_context(settings.upstream_ca_bundle)
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
