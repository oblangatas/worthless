"""WOR-309 Phase 4 — CI guard banning crypto-fallback imports from proxy.

Per security signoff §C8 (``.research/10-security-signoff.md``): the
splitter is dead code in the proxy image post-WOR-309 and the architect's
"keep the symbol" call is defensible **iff** an AST CI guard makes
"future temptation" a CI failure rather than a code-review judgment call.

Three guards live in this file:

1. ``test_proxy_modules_do_not_import_crypto_splitter`` — walks every
   module under ``worthless.proxy.*`` and asserts none of them references
   ``worthless.crypto.splitter``, ``cryptography.fernet``, or
   ``from worthless import crypto`` (the bare package import). Both
   top-level and nested ``Import``/``ImportFrom`` nodes are checked.

2. ``test_lifespan_has_no_fallback_branch`` — source-level static
   assertion that the proxy lifespan has no ``except IPCUnavailable``
   anywhere in its body (the connect call MUST fail-loud).

The runtime-side guard lives at
``tests/ipc/test_no_inprocess_fallback.py``.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pkgutil
from pathlib import Path

import pytest

import worthless.proxy

# Banned dotted paths. Any Import / ImportFrom referencing these in any
# ``worthless.proxy.*`` module fails the guard.
_BANNED_MODULES: frozenset[str] = frozenset(
    {
        "worthless.crypto.splitter",
        "cryptography.fernet",
    }
)

# Banned package-level imports. ``from worthless import crypto`` would
# expose the entire crypto package (including splitter) via attribute
# lookup; bare ``worthless.crypto.reconstruction`` is allowed because it
# names a specific submodule that does not include the splitter.
_BANNED_FROM_IMPORTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("worthless", "crypto"),
    }
)


def _iter_proxy_module_files() -> list[tuple[str, Path]]:
    """Return ``[(module_name, file_path), ...]`` for every proxy module."""
    files: list[tuple[str, Path]] = []
    proxy_path = Path(worthless.proxy.__file__).parent
    for mod_info in pkgutil.walk_packages([str(proxy_path)], prefix="worthless.proxy."):
        module = importlib.import_module(mod_info.name)
        src = inspect.getsourcefile(module)
        if src is None:  # pragma: no cover — namespace pkgs / builtins
            continue
        files.append((mod_info.name, Path(src)))
    return files


def _scan_for_banned_imports(file_path: Path) -> list[str]:
    """Return a list of human-readable violations for ``file_path``."""
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _BANNED_MODULES:
                    violations.append(f"{file_path}:{node.lineno}: banned `import {alias.name}`")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            # Reject `from <banned> import …` directly.
            if module in _BANNED_MODULES:
                names = ", ".join(a.name for a in node.names)
                violations.append(
                    f"{file_path}:{node.lineno}: banned `from {module} import {names}`"
                )
                continue
            # Reject `from <pkg> import <subpkg>` for banned (pkg, sub) pairs.
            for alias in node.names:
                if (module, alias.name) in _BANNED_FROM_IMPORTS:
                    violations.append(
                        f"{file_path}:{node.lineno}: "
                        f"banned `from {module} import {alias.name}` (package import)"
                    )
                # Also reject `from worthless.crypto import splitter` style.
                full = f"{module}.{alias.name}" if module else alias.name
                if full in _BANNED_MODULES:
                    violations.append(
                        f"{file_path}:{node.lineno}: "
                        f"banned `from {module} import {alias.name}` (resolves to {full})"
                    )

    return violations


def test_proxy_modules_do_not_import_crypto_splitter() -> None:
    """AST CI guard: no ``worthless.proxy.*`` module imports crypto-fallback symbols.

    Walks every Python module under ``worthless.proxy``, parses each with
    :mod:`ast`, and inspects every ``Import`` / ``ImportFrom`` node (top
    level AND nested in functions/classes). Fails loudly with file + line
    + offending symbol so a CI failure is actionable.
    """
    modules = _iter_proxy_module_files()
    assert modules, "expected to discover at least one worthless.proxy.* module"

    all_violations: list[str] = []
    for _name, file_path in modules:
        all_violations.extend(_scan_for_banned_imports(file_path))

    assert not all_violations, (
        "WOR-309 fail-closed guard tripped — the proxy must NOT import any "
        "in-process key reconstruction primitive. Offending references:\n  "
        + "\n  ".join(all_violations)
    )


# ---------------------------------------------------------------------------
# Guard 3 — source-level static check on the proxy lifespan
# ---------------------------------------------------------------------------


def _lifespan_source() -> str:
    """Return the source text of the ``_lifespan`` async ctx-mgr in app.py."""
    import worthless.proxy.app as app_mod

    src = Path(app_mod.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src, filename=app_mod.__file__)
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_lifespan":
            return ast.get_source_segment(src, node) or ""
    pytest.fail("could not locate `_lifespan` in worthless.proxy.app")


def test_lifespan_has_no_fallback_branch() -> None:
    """Source-level guard: the lifespan startup MUST NOT swallow IPCUnavailable.

    Belt-and-suspenders on top of the runtime test in
    ``tests/ipc/test_no_inprocess_fallback.py``: parses the lifespan
    source and asserts (a) ``await ipc.connect()`` is present and
    (b) no ``except IPCUnavailable`` (or bare ``except:``) appears
    anywhere in the lifespan body.
    """
    body_src = _lifespan_source()
    assert "await ipc.connect()" in body_src, (
        "lifespan must call `await ipc.connect()` to fail-loud on sidecar absence"
    )

    tree = ast.parse(body_src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                pytest.fail("lifespan contains a bare `except:` — fail-closed guard tripped")
            handler_src = ast.unparse(node.type)
            if "IPCUnavailable" in handler_src:
                pytest.fail(
                    "lifespan contains `except IPCUnavailable` — fail-closed "
                    "guard tripped: the sidecar MUST be reachable at startup, "
                    "no fallback path is permitted"
                )
