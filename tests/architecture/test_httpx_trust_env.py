"""Every httpx client worthless builds ignores the process environment (WOR-1071).

httpx defaults to ``trust_env=True``: it routes through ``HTTP(S)_PROXY`` /
``ALL_PROXY`` (or the macOS / Windows system proxy) and trusts a CA named by
``SSL_CERT_FILE`` / ``SSL_CERT_DIR``. On the client that carries reconstructed
keys, that hands every key to a TLS-inspecting proxy. The behaviour is tested in
``tests/test_upstream_env_trust.py``; these guards stop a new client from
quietly bringing the default back.

1. Every httpx client, transport or module-level request helper (``httpx.get``
   and friends build a client per call) under ``src/worthless`` passes
   ``trust_env=False`` as a literal keyword. ``**kwargs`` can't be checked, so
   it fails too.
2. Inside ``worthless.proxy`` only ``upstream.py`` builds an httpx client, so
   the key-carrying client has one source.
3. ``worthless.proxy`` imports no other HTTP client library.
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
_OTHER_HTTP_LIBS = frozenset(
    {"requests", "aiohttp", "urllib3", "httpx2", "urllib.request", "http.client", "pycurl"}
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

    calls: list[tuple[int, str, bool]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in modules
            and func.attr in _HTTPX_BUILDERS
        ):
            name = func.attr
        elif isinstance(func, ast.Name) and func.id in names:
            name = names[func.id]
        else:
            continue
        env_off = any(
            kw.arg == "trust_env" and isinstance(kw.value, ast.Constant) and kw.value.value is False
            for kw in node.keywords
        )
        calls.append((node.lineno, f"httpx.{name}", env_off))
    return calls


def _imported_modules(source: str) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
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
        if (mod in _OTHER_HTTP_LIBS or mod.split(".")[0] in _OTHER_HTTP_LIBS)
        and (path, mod) not in allowed
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
    ],
)
def test_guard_sees_every_way_to_build_a_client(
    source: str, expected: list[tuple[int, str, bool]]
) -> None:
    assert _httpx_calls(source) == expected
