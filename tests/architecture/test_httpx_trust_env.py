"""Every httpx client worthless builds ignores the process environment (WOR-1071).

httpx defaults to ``trust_env=True``; why that hands real keys to a proxy is in
``worthless.proxy.upstream``. The behaviour is tested in
``tests/test_upstream_env_trust.py``; these guards stop a new client from
quietly bringing the default back.

1. Every httpx client, transport, SSL-context helper or module-level request
   helper (``httpx.get`` and friends build a client per call) under
   ``src/worthless`` passes ``trust_env=False`` as a literal keyword.
   ``**kwargs`` can't be checked, so it fails too, and so does a subclass of
   an httpx client.
2. Inside ``worthless.proxy`` only ``upstream.py`` builds an httpx client, so
   the key-carrying client has one source.
3. ``worthless.proxy`` imports no other HTTP client library or provider SDK.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import worthless

_SRC = Path(worthless.__file__).parent
_PROXY = _SRC / "proxy"
_FACTORY = _PROXY / "upstream.py"

_HTTPX_BUILDERS = frozenset(
    {
        "Client",
        "AsyncClient",
        "HTTPTransport",
        "AsyncHTTPTransport",
        "create_ssl_context",  # its default trust_env=True reads SSL_CERT_FILE
        "request",
        "stream",
        "get",
        "options",
        "head",
        "post",
        "put",
        "patch",
        "delete",
    }
)
# Provider SDKs build their own httpx client with the environment trusted.
_OTHER_HTTP_LIBS = frozenset(
    {
        "requests",
        "aiohttp",
        "urllib3",
        "httpx2",
        "httpcore",
        "websockets",
        "urllib.request",
        "http.client",
        "pycurl",
        "openai",
        "anthropic",
    }
)


def _httpx_calls(source: str) -> list[tuple[int, str, bool]]:
    """Return ``(line, name, passes trust_env=False)`` for each httpx builder call."""
    tree = ast.parse(source)
    modules: set[str] = set()
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(a.asname or a.name for a in node.names if a.name == "httpx")
        elif isinstance(node, ast.ImportFrom) and node.module == "httpx":
            names.update(
                {a.asname or a.name: a.name for a in node.names if a.name in _HTTPX_BUILDERS}
            )

    def builder(expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            if expr.value.id in modules and expr.attr in _HTTPX_BUILDERS:
                return expr.attr
        elif isinstance(expr, ast.Name):
            return names.get(expr.id)
        return None

    calls: list[tuple[int, str, bool]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (name := builder(node.func)):
            env_off = any(
                kw.arg == "trust_env"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is False
                for kw in node.keywords
            )
            calls.append((node.lineno, f"httpx.{name}", env_off))
        elif isinstance(node, ast.ClassDef):
            # A subclass can default trust_env however it likes; it can't be checked here.
            calls.extend(
                (node.lineno, f"subclass of httpx.{name}", False)
                for base in node.bases
                if (name := builder(base))
            )
    return calls


def _is_other_http_lib(module: str) -> bool:
    return module in _OTHER_HTTP_LIBS or module.split(".")[0] in _OTHER_HTTP_LIBS


def _imported_modules(source: str) -> set[str]:
    """Every module a file imports. ``from urllib import request`` counts as ``urllib.request``."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
            found.update(f"{node.module}.{a.name}" for a in node.names)
    return found


def _sources(root: Path) -> list[Path]:
    return sorted(root.rglob("*.py"))


def test_every_httpx_client_in_src_ignores_the_environment() -> None:
    offenders = [
        f"{path.relative_to(_SRC.parent)}:{line}: {name}(...) without trust_env=False"
        for path in _sources(_SRC)
        for line, name, env_off in _httpx_calls(path.read_text(encoding="utf-8"))
        if not env_off
    ]
    assert not offenders, "\n".join(offenders)


def test_only_the_upstream_factory_builds_a_client_inside_the_proxy() -> None:
    assert _FACTORY.is_file(), "the key-carrying client factory moved; update this guard"
    offenders = [
        f"{path.relative_to(_SRC.parent)}:{line}: {name}(...); use build_upstream_client()"
        for path in _sources(_PROXY)
        if path != _FACTORY
        for line, name, _env_off in _httpx_calls(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, "\n".join(offenders)


def test_proxy_imports_no_other_http_client_library() -> None:
    # The factory reads urllib.request.getproxies() to warn about a system proxy it ignores.
    allowed = {(_FACTORY, "urllib.request")}
    offenders = [
        f"{path.relative_to(_SRC.parent)}: imports {mod}"
        for path in _sources(_PROXY)
        for mod in sorted(_imported_modules(path.read_text(encoding="utf-8")))
        if _is_other_http_lib(mod) and (path, mod) not in allowed
    ]
    assert not offenders, "\n".join(offenders)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import httpx\nhttpx.AsyncClient()", [(2, "httpx.AsyncClient", False)]),
        ("import httpx\nhttpx.AsyncClient(trust_env=True)", [(2, "httpx.AsyncClient", False)]),
        ("import httpx\nhttpx.Client(**kw)", [(2, "httpx.Client", False)]),
        ("import httpx\nhttpx.post('u')", [(2, "httpx.post", False)]),
        ("import httpx as h\nh.AsyncHTTPTransport()", [(2, "httpx.AsyncHTTPTransport", False)]),
        ("from httpx import AsyncClient as C\nC()", [(2, "httpx.AsyncClient", False)]),
        ("def f():\n    import httpx\n    httpx.Client(timeout=1)", [(3, "httpx.Client", False)]),
        ("import httpx\nhttpx.AsyncClient(trust_env=False)", [(2, "httpx.AsyncClient", True)]),
        ("import httpx\nhttpx.Timeout(1.0)\nhttpx.URL('u')", []),
        (
            "import httpx\nhttpx.AsyncClient(trust_env=False, verify=httpx.create_ssl_context())",
            [(2, "httpx.AsyncClient", True), (2, "httpx.create_ssl_context", False)],
        ),
        (
            "import httpx\nclass C(httpx.AsyncClient): ...",
            [(2, "subclass of httpx.AsyncClient", False)],
        ),
    ],
)
def test_guard_sees_every_way_to_build_a_client(
    source: str, expected: list[tuple[int, str, bool]]
) -> None:
    assert _httpx_calls(source) == expected


@pytest.mark.parametrize(
    ("source", "banned"),
    [
        ("import requests", True),
        ("from urllib import request", True),
        ("from http import client", True),
        ("from openai import AsyncOpenAI", True),
        ("import httpcore._async", True),
        ("from urllib.parse import urlsplit", False),
        ("import httpx", False),
    ],
)
def test_guard_sees_every_way_to_import_another_http_library(source: str, banned: bool) -> None:
    found = _imported_modules(source)
    assert any(_is_other_http_lib(m) for m in found) is banned
