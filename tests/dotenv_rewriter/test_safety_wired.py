"""Gate-wiring tests: ``safe_rewrite`` is actually called by every entry point.

These tests use the ``safe_rewrite_spy`` fixture (from conftest) to
verify that each public rewriter function routes through the safety
gate exactly once per successful write, and zero times for no-ops.
A module-source assertion also guards against accidental re-introduction
of the unsafe ``python-dotenv`` ``set_key`` / ``unset_key`` calls.
"""

from __future__ import annotations

import inspect
from pathlib import Path


def test_add_calls_safe_rewrite_exactly_once(
    tmp_path: Path,
    make_env_file,
    safe_rewrite_spy,
) -> None:
    """``add_or_rewrite_env_key`` MUST call ``safe_rewrite`` exactly once."""
    from worthless.cli.dotenv_rewriter import add_or_rewrite_env_key

    env = make_env_file(tmp_path / ".env", content=b"EXISTING=keep\n")

    add_or_rewrite_env_key(env, "NEW_KEY", "new_value")

    assert safe_rewrite_spy.call_count == 1, (
        f"expected exactly 1 safe_rewrite call, got {safe_rewrite_spy.call_count}"
    )
    # The gate was invoked on our target path.
    assert safe_rewrite_spy.last.target == env


def test_rewrite_calls_safe_rewrite_exactly_once(
    tmp_path: Path,
    make_env_file,
    safe_rewrite_spy,
) -> None:
    """``rewrite_env_key`` MUST call ``safe_rewrite`` exactly once."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    env = make_env_file(tmp_path / ".env", content=b"EXISTING=old\n")

    rewrite_env_key(env, "EXISTING", "new_value")

    assert safe_rewrite_spy.call_count == 1, (
        f"expected exactly 1 safe_rewrite call, got {safe_rewrite_spy.call_count}"
    )
    assert safe_rewrite_spy.last.target == env


def test_remove_calls_safe_rewrite_exactly_once(
    tmp_path: Path,
    make_env_file,
    safe_rewrite_spy,
) -> None:
    """``remove_env_key`` on a present key MUST call ``safe_rewrite`` exactly once."""
    from worthless.cli.dotenv_rewriter import remove_env_key

    env = make_env_file(tmp_path / ".env", content=b"KEEP=yes\nDROP=me\n")

    remove_env_key(env, "DROP")

    assert safe_rewrite_spy.call_count == 1, (
        f"expected exactly 1 safe_rewrite call, got {safe_rewrite_spy.call_count}"
    )
    assert safe_rewrite_spy.last.target == env


def test_remove_noop_does_not_call_safe_rewrite(
    tmp_path: Path,
    make_env_file,
    safe_rewrite_spy,
) -> None:
    """``remove_env_key`` for an absent key MUST be a pure no-op (zero calls)."""
    from worthless.cli.dotenv_rewriter import remove_env_key

    env = make_env_file(tmp_path / ".env", content=b"KEEP=yes\n")

    remove_env_key(env, "NEVER_EXISTED")

    assert safe_rewrite_spy.call_count == 0, (
        f"expected zero safe_rewrite calls for no-op remove, got {safe_rewrite_spy.call_count}"
    )
    # File bytes are untouched.
    assert env.read_bytes() == b"KEEP=yes\n"


def test_python_dotenv_set_key_is_not_imported() -> None:
    """The unsafe ``set_key`` / ``unset_key`` symbols MUST NOT be imported or called.

    Module-source AST assertion: the implementation must route every
    destructive write through ``safe_rewrite`` rather than calling
    python-dotenv's ``set_key``/``unset_key`` (which bypass the gate).

    AST-based rather than substring-based so that a future maintainer
    writing a comment explaining *why* these symbols are forbidden
    (e.g. ``# we deliberately avoid python-dotenv's set_key``) does not
    trip the guard. We match only real import statements and call sites.
    """
    import ast

    from worthless.cli import dotenv_rewriter as rewriter_mod

    tree = ast.parse(inspect.getsource(rewriter_mod))
    banned = {"set_key", "unset_key"}
    for node in ast.walk(tree):
        # ``from dotenv import set_key`` / ``from dotenv.main import unset_key``
        if isinstance(node, ast.ImportFrom) and node.module in {"dotenv", "dotenv.main"}:
            imported = {alias.name for alias in node.names}
            leaked = imported & banned
            assert not leaked, f"banned dotenv imports: {sorted(leaked)}"
        # ``dotenv.set_key(...)`` attribute-access style — only flag when
        # the receiver is literally the ``dotenv`` module name, so that an
        # unrelated future helper exposing a ``.set_key(...)`` method does
        # not trip this guard with a misleading diagnostic.
        if (
            isinstance(node, ast.Attribute)
            and node.attr in banned
            and isinstance(node.value, ast.Name)
            and node.value.id == "dotenv"
        ):
            raise AssertionError(f"banned attribute access: dotenv.{node.attr}")
        # ``set_key(...)`` / ``unset_key(...)`` direct call after aliased import
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in banned
        ):
            raise AssertionError(f"banned direct call: {node.func.id}(...)")
