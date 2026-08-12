"""A timeout must KILL, not raise — assert the config that guarantees it.

pytest-timeout's default ``signal`` method raises ``Failed`` wherever the
process happens to be. Two measured consequences:

1. It can be swallowed. A timeout firing inside a test whose ``finally`` then
   blocks — ``Pool.join()`` on a child that will never be released — wedges the
   xdist worker FOREVER; no second alarm is armed. Measured at >150s still hung
   under a 3s timeout.
2. ``timeout_func_only`` defaults to False, so the timer is armed across the
   whole ``pytest_runtest_protocol`` — including xdist's report
   serialize-and-send, which sits OUTSIDE every ``CallInfo.from_call()`` catch.
   A ``Failed`` landing there means ``runtest_protocol_complete`` is never sent
   and the master trips ``assert not crashitem`` (xdist ``dsession.py:217``),
   aborting the WHOLE session and silently dropping every test that had not run
   yet — observed as 4004 expected vs 3992 reported, with no red anywhere.

``thread`` calls ``os._exit()``: uncatchable, and it routes to xdist's
``worker_errordown`` path, which reports a normal "worker 'gwN' crashed while
running <nodeid>" and keeps the session alive. Same wedge, 6s.

Nothing else fails if these settings are dropped — the suite goes green and the
crash simply comes back, at roughly one run in five. Hence this guard.
"""

from __future__ import annotations

import re
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

# ponytail: regex over the raw text, mirroring tests/test_mcp_dependency_cap.py —
# tomllib is 3.11+ and this repo still supports 3.10.
_TIMEOUT_METHOD = re.compile(r'^\s*timeout_method\s*=\s*"([^"]+)"', re.MULTILINE)
_ADDOPTS = re.compile(r'^\s*addopts\s*=\s*"([^"]*)"', re.MULTILINE)
_FUNC_ONLY = re.compile(r"^\s*timeout_func_only\s*=\s*(\w+)", re.MULTILINE)


def _pyproject_text() -> str:
    return PYPROJECT.read_text(encoding="utf-8")


def test_timeout_method_is_thread_not_signal() -> None:
    """``signal`` raises an exception; a blocking ``finally`` swallows it."""
    match = _TIMEOUT_METHOD.search(_pyproject_text())
    assert match is not None, (
        "timeout_method is unset, so pytest-timeout falls back to `signal`. "
        "A signal timeout raises an exception that test code can swallow, and a "
        "swallowed timeout hangs the xdist worker forever. Set "
        'timeout_method = "thread".'
    )
    assert match.group(1) == "thread", (
        f"timeout_method is {match.group(1)!r}, not 'thread'. Only the thread "
        "method (os._exit) is uncatchable, and only it routes to xdist's "
        "graceful worker_errordown path instead of the fatal workerfinished "
        "assert."
    )


def test_worker_restart_disabled() -> None:
    """Restarting a crashed worker re-runs the hanging test and recovers nothing.

    Measured: ``--max-worker-restart=0`` -> 6s and one honest failure;
    ``=3`` -> 40s and four failures, with the dropped scope-group sibling still
    unrecovered either way. Restarts are pure cost here.
    """
    match = _ADDOPTS.search(_pyproject_text())
    assert match is not None, "addopts missing from [tool.pytest.ini_options]"
    assert "--max-worker-restart=0" in match.group(1), (
        "addopts must pass --max-worker-restart=0; without it a hanging test is "
        "re-run once per restart, each attempt paying the full timeout."
    )


def test_func_only_not_enabled() -> None:
    """``timeout_func_only = true`` also closes the escape window — by giving up
    setup/teardown coverage entirely.

    Verified: with func_only enabled and a 5s timeout, a hanging fixture ran
    until killed by hand at 2m00s. The thread method closes the same window and
    keeps fixture coverage, so enabling func_only on top of it buys nothing and
    costs the hang protection.
    """
    match = _FUNC_ONLY.search(_pyproject_text())
    if match is None:
        return  # unset — correct, that is the default
    assert match.group(1).lower() not in {"true", "1"}, (
        "timeout_func_only is enabled: pytest-timeout will no longer bound "
        "hangs in fixtures/setup/teardown. A hanging fixture then runs forever. "
        "The thread method already closes the escape window without this cost."
    )
