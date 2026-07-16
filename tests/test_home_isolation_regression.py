"""Regression guard for worthless-q1k5 / worthless-xgjy / worthless-8vfc.

Tests that shell out to the real ``worthless`` binary — or drive it in-process
via Typer's ``CliRunner`` — must never leak the real machine's ``$HOME`` into
the process under test. ``_resolve_home()`` (``openclaw/integration.py``)
reads ``Path.home()``, not ``WORTHLESS_HOME``; on a machine with genuine
OpenClaw config already installed, a leaked ``$HOME`` makes ``detect()``
falsely report OpenClaw as present and trips the F7 proxy-health gate with a
``WRTLS-109`` failure unrelated to whatever the test actually checks.

worthless-xgjy centralized the fix into one autouse fixture
(``tests.conftest._isolate_process_home``) instead of 8 hand-copied env
dicts. worthless-8vfc is this file: nothing previously asserted the
isolation actually worked, and CI structurally can't catch a regression on
its own — CI runners never have real OpenClaw state to trip on, so a broken
fix and a working fix both look green there. These two tests make the
guarantee explicit and CI-checkable.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from tests import conftest
from tests.helpers import fake_openai_key
from tests.smoke.test_smoke_revoke import _run


def test_isolate_process_home_fixture_registered() -> None:
    """The suite-wide HOME/USERPROFILE sandbox must exist and be autouse.

    If this fails, every test that shells out to the real worthless binary
    with no local HOME override (the common case after worthless-xgjy) has
    lost its only protection against leaking the real machine's HOME.

    AST-based rather than introspecting pytest's fixture-marker internals —
    those aren't stable across pytest versions, and a source-level check is
    honestly a better fit for a "did this drift" regression guard anyway.
    """
    tree = ast.parse(inspect.getsource(conftest))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_isolate_process_home":
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and any(
                    kw.arg == "autouse"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                    for kw in decorator.keywords
                ):
                    return
            pytest.fail("_isolate_process_home exists but is not decorated autouse=True")
    pytest.fail(
        "tests.conftest._isolate_process_home is missing — the suite-wide "
        "HOME/USERPROFILE sandbox fixture (worthless-xgjy) was removed or renamed"
    )


@pytest.mark.e2e
@pytest.mark.real_ipc
def test_home_isolation_regresses_without_the_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live causality proof, against the real binary, both directions.

    Simulates the exact regression this ticket exists to catch — the
    autouse fixture's protection silently gone — by temporarily overriding
    HOME with a hostile value that looks like a real developer's machine,
    then shows the real, currently-shipped ``_run()`` helper in
    ``tests/smoke/test_smoke_revoke.py`` (which now has zero local HOME
    override; worthless-xgjy deleted it) fails with WRTLS-109. Then, back
    under this test's own genuine ``_isolate_process_home`` fixture, the
    identical call must pass.
    """
    hostile_home = tmp_path / "hostile-real-home"
    (hostile_home / ".openclaw").mkdir(parents=True)
    (hostile_home / ".openclaw" / "openclaw.json").write_text("{}")

    env_file = tmp_path / "proj" / ".env"
    env_file.parent.mkdir()
    env_file.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    smoke_home = tmp_path / ".worthless"

    # Simulate the regression: override the autouse fixture's HOME AND
    # USERPROFILE with a hostile value, as if the fixture were deleted or
    # broken. Both matter: native Windows Path.home() checks USERPROFILE
    # before HOME, so leaving USERPROFILE at the fixture's safe value would
    # let the subprocess resolve the safe path anyway on Windows CI runners,
    # silently defeating this simulation there. monkeypatch stacks LIFO, so
    # this wins over the autouse fixture for the duration of the `with`
    # block only.
    with monkeypatch.context() as m:
        m.setenv("HOME", str(hostile_home))
        m.setenv("USERPROFILE", str(hostile_home))
        broken = _run(["lock", "--env", str(env_file)], smoke_home)
        assert broken.returncode != 0, (
            "expected the simulated regression (hostile HOME) to fail, but "
            f"lock succeeded:\n{broken.stdout}\n{broken.stderr}"
        )
        assert "WRTLS-109" in broken.stdout + broken.stderr, (
            f"expected WRTLS-109 specifically:\n{broken.stdout}\n{broken.stderr}"
        )

    # Back outside the context: this test's own _isolate_process_home fixture
    # is genuinely active again. Same helper, same call, must now pass.
    fixed = _run(["lock", "--env", str(env_file)], smoke_home)
    assert fixed.returncode == 0, f"lock failed:\n{fixed.stdout}\n{fixed.stderr}"
