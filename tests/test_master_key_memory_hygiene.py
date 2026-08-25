"""SR-02: the master Fernet key must not outlive the code that read it.

Two leaks, same parent (worthless-1ige):

  * worthless-m7n0 — ``WorthlessHome._cached_fernet_key`` had no ``__del__``, no
    ``atexit`` hook and no explicit zero, so every CLI command handed the
    interpreter a bytearray of live master-key bytes to collect.
  * worthless-g648 — ``doctor`` zeroed its own buffer but never called
    ``repo.close()``, so ``ShardRepository._fernet_key_bytes`` (a second copy)
    survived the command.

Two things this module learned the hard way, both worth keeping in mind when
editing it:

1. **Assert on the BYTES.** A test that checks "close() was called" passes
   against an implementation that rebinds the reference and leaves the original
   allocation intact — which is the bug.
2. **Check the BINDING, not the file or the function.** Three versions of the
   sweep below shipped before it caught anything. v1 grepped one file. v2 asked
   whether the module contained any ``.close()``. v3 asked per-function -- and
   still passed, because ``doctor`` builds two repositories in one function, so
   closing the first vouched for the second. It is now AST-based and
   per-variable.
"""

from __future__ import annotations

import ast
import base64
import gc
from pathlib import Path

from worthless.cli.bootstrap import WorthlessHome
from worthless.storage.repository import ShardRepository

# A REAL Fernet key (32 url-safe base64 bytes) — ShardRepository builds a Fernet
# from it, so a malformed value fails in the constructor and never reaches the
# code under test. Deliberately non-zero: an all-zero key would make every
# "is it zeroed?" assertion below pass vacuously.
_KEY = base64.urlsafe_b64encode(bytes(range(1, 33)))
_ZEROS = b"\x00" * len(_KEY)


# --- worthless-m7n0: the cached key ---------------------------------------


def test_cached_key_is_zeroed_when_the_home_is_collected(tmp_path: Path) -> None:
    """The case an exit-only hook misses.

    ``ensure_home()`` builds a fresh WorthlessHome at each of its ~37 call
    sites, so a home dropped mid-command is collected long before interpreter
    shutdown. The first implementation of this fix used an atexit hook and a
    registry, and freed those buffers with the key still in them.
    """
    home = WorthlessHome(base_dir=tmp_path)
    home._seed_cached_fernet_key(_KEY)
    buf = home._cached_fernet_key
    assert buf is not None and bytes(buf) == _KEY

    del home
    gc.collect()

    assert bytes(buf) == _ZEROS, "the buffer must be zeroed when its home is collected"


def test_reseeding_zeroes_the_buffer_it_orphans(tmp_path: Path) -> None:
    """Four call sites can seed twice (e.g. an env read then a keyring read)."""
    home = WorthlessHome(base_dir=tmp_path)
    home._seed_cached_fernet_key(_KEY)
    first = home._cached_fernet_key
    assert first is not None and bytes(first) == _KEY

    home._seed_cached_fernet_key(_KEY)

    assert first is not home._cached_fernet_key, "a re-seed must allocate a new buffer"
    assert bytes(first) == _ZEROS, "the orphaned buffer must be zeroed, not just dropped"


def test_zeroing_happens_in_place_not_by_rebinding(tmp_path: Path) -> None:
    """Dropping the reference leaves the bytes readable in the freed allocation."""
    home = WorthlessHome(base_dir=tmp_path)
    home._seed_cached_fernet_key(_KEY)
    buf = home._cached_fernet_key
    assert buf is not None

    home._seed_cached_fernet_key(_KEY)  # triggers the zero-then-replace path

    assert len(buf) == len(_KEY), "must not truncate — the allocation is what matters"
    assert _KEY[:8] not in bytes(buf)


# --- worthless-g648: the repository's copy --------------------------------


def test_repository_close_zeroes_its_own_copy(tmp_path: Path) -> None:
    """The copy `doctor` was leaking: the repository's, not the caller's."""
    repo = ShardRepository(str(tmp_path / "w.db"), bytearray(_KEY))

    inner = repo._fernet_key_bytes
    assert inner is not None and bytes(inner) == _KEY, "repo holds its own copy"

    repo.close()

    assert bytes(inner) == _ZEROS, "close() must zero the repo's copy in place"
    assert repo._fernet is None, "the Fernet instance must be released"


def test_repository_close_is_idempotent(tmp_path: Path) -> None:
    repo = ShardRepository(str(tmp_path / "w.db"), bytearray(_KEY))
    repo.close()
    repo.close()  # must not raise


_PLACEHOLDER_HINTS = ("placeholder", "PLACEHOLDER")


def _closed_names(fn: ast.AST) -> set[str]:
    """Names on which ``<name>.close()`` is called anywhere in *fn*."""
    return {
        n.func.value.id
        for n in ast.walk(fn)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "close"
        and isinstance(n.func.value, ast.Name)
    }


def _real_key_repo_bindings(fn: ast.AST) -> list[tuple[str, int]]:
    """(variable, lineno) for each ShardRepository built from real key material.

    Placeholder keys are excluded by inspecting the ARGUMENT, not the source
    text: an earlier version skipped any line containing the word "placeholder",
    so a trailing comment could launder a genuine leak.
    """
    out: list[tuple[str, int]] = []
    for n in ast.walk(fn):
        if not isinstance(n, ast.Assign) or len(n.targets) != 1:
            continue
        target, call = n.targets[0], n.value
        if not isinstance(target, ast.Name):
            continue
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)):
            continue
        if call.func.id != "ShardRepository" or len(call.args) < 2:
            continue
        if any(h in ast.unparse(call.args[1]) for h in _PLACEHOLDER_HINTS):
            continue
        out.append((target.id, n.lineno))
    return out


def test_every_repository_built_from_a_real_key_is_closed_in_the_same_function() -> None:
    """Per-VARIABLE, via AST. Three weaker versions of this passed on real leaks.

    v1 grepped one file for ``repo.close()`` near the last ``finally:`` — it
    looked only at runner.py while three other sites leaked. v2 asked whether
    the MODULE contained any ``.close()`` — deleting a close() that the same PR
    had just added still passed. Both were static string matching pretending to
    be a guard.
    """
    cli = Path(__file__).resolve().parents[1] / "src/worthless/cli"
    offenders: list[str] = []
    checked = 0

    for path in sorted(cli.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            closed = _closed_names(node)
            for name, lineno in _real_key_repo_bindings(node):
                checked += 1
                if name not in closed:
                    offenders.append(
                        f"{path.relative_to(cli.parents[2])}:{lineno} in "
                        f"{node.name}(): '{name}' is built from real key material "
                        "and never closed — the repository's copy survives"
                    )

    assert checked >= 4, (
        f"only {checked} real-key ShardRepository sites found; the layout moved "
        "and this test no longer covers what it claims"
    )
    assert not offenders, "Un-closed ShardRepository (worthless-g648):\n" + "\n".join(offenders)


def test_the_sweep_can_actually_see_a_leak() -> None:
    """Guard the guard: the AST helpers must flag an unclosed real-key build.

    Both previous versions of the sweep passed against genuine leaks. This pins
    the detection itself against synthetic sources, so a future refactor of the
    helpers cannot quietly neuter them.
    """
    leaking = ast.parse(
        "def f(home):\n"
        "    repo = ShardRepository(str(home.db_path), home.fernet_key)\n"
        "    return repo\n"
    ).body[0]
    binds = _real_key_repo_bindings(leaking)
    assert binds and binds[0][0] == "repo", "must spot a real-key build and name it"
    assert "repo" not in _closed_names(leaking), "must spot the missing close()"

    # The hole that beat v3: one function building TWO repositories, where
    # closing the first satisfied a per-function check for the second.
    two = ast.parse(
        "def f(home):\n"
        "    a = ShardRepository(str(home.db_path), home.fernet_key)\n"
        "    b = ShardRepository(str(home.db_path), home.fernet_key)\n"
        "    a.close()\n"
    ).body[0]
    names = [n for n, _ in _real_key_repo_bindings(two)]
    assert names == ["a", "b"], "must see BOTH builds"
    assert _closed_names(two) == {"a"}, "closing 'a' must not vouch for 'b'"

    fixed = ast.parse(
        "def f(home):\n"
        "    repo = ShardRepository(str(home.db_path), home.fernet_key)\n"
        "    try:\n"
        "        return repo\n"
        "    finally:\n"
        "        repo.close()\n"
    ).body[0]
    assert "repo" in _closed_names(fixed), "must accept a closed build"

    placeholder = ast.parse(
        "def f(home):\n    repo = ShardRepository(str(home.db_path), PLACEHOLDER_FERNET_KEY)\n"
    ).body[0]
    assert not _real_key_repo_bindings(placeholder), (
        "a placeholder key holds no secret and must not be flagged"
    )

    # The hole in v2: a comment must not be able to launder a real-key build.
    disguised = ast.parse(
        "def f(home):\n"
        "    repo = ShardRepository(str(home.db_path), home.fernet_key)  # placeholder\n"
    ).body[0]
    assert _real_key_repo_bindings(disguised), (
        "a trailing 'placeholder' comment must NOT hide a real-key build — "
        "the exclusion reads the argument, not the source line"
    )
