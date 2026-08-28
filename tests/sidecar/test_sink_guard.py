"""Static guard: no sidecar log/print sink may interpolate secret material.

RedactingFilter cannot scrub raw share/key bytes (they aren't provider-shaped,
and exception-object %-args stringify after the filter runs). The real
invariant that keeps shares out of logs is that no sink *interpolates* them.
This AST guard enforces that invariant so a future f-string edit fails CI
instead of shipping a leak. It is a name-based heuristic: it catches a secret
name interpolated *directly* into a ``_LOG``/``print`` call; an aliased copy
(``s = shares; _LOG.info("%s", s)``) can evade it — a deliberate, documented limit.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import worthless.sidecar as _sc

pytestmark = pytest.mark.real_ipc  # dir-wide marker; this test itself is fast/static

_SIDECAR_DIR = Path(_sc.__file__).parent
# Names that hold raw key/share material anywhere under sidecar/.
_FORBIDDEN = {"share_a", "share_b", "shares", "key", "plaintext"}


def _is_log_call(func: ast.expr) -> bool:
    return (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id == "_LOG"
    )


def _is_print_call(func: ast.expr) -> bool:
    return isinstance(func, ast.Name) and func.id == "print"


def _bad_interpolations(path: Path, is_target) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text())
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and is_target(node.func):
            args = list(node.args) + [kw.value for kw in node.keywords]
            for arg in args:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Name) and sub.id in _FORBIDDEN:
                        hits.append((node.lineno, sub.id))
    return hits


@pytest.mark.parametrize("filename", ["__main__.py", "server.py", "backends/fernet.py"])
def test_no_log_sink_interpolates_secret_material(filename: str) -> None:
    hits = _bad_interpolations(_SIDECAR_DIR / filename, _is_log_call)
    assert not hits, f"{filename}: _LOG call interpolates secret name(s): {hits}"


def test_no_print_bypasses_with_secret_material() -> None:
    for py in _SIDECAR_DIR.rglob("*.py"):
        hits = _bad_interpolations(py, _is_print_call)
        assert not hits, f"{py.name}: print() interpolates secret name(s): {hits}"
