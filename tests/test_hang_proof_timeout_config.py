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

import ast
import re
from pathlib import Path

import pytest

from tests.conftest import pytest_collection_modifyitems, pytest_configure

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"
# The whole .github tree, not just workflows/: composite actions under
# .github/actions/ can invoke pytest too, and an unguarded serial lane planted
# there was invisible to an earlier version of this file.
GITHUB = Path(__file__).resolve().parent.parent / ".github"

# A zero-worker (serial) pytest lane in ANY invocation form: `uv run pytest`,
# `python -m pytest`, `uv run --frozen pytest`, an env-var prefix, or flags
# folded across a line continuation. Matching the WORKER FLAG rather than the
# word `pytest` is what buys that — `-n0` / `--numprocesses=0` appears nowhere
# else in a workflow, whereas an earlier version of this file keyed on
# `^\s*(?:uv run )?pytest` and was blind to every form above.
_SERIAL_FLAG = re.compile(r"(?:-n\s*0(?!\d)|--numprocesses[= ]\s*0(?!\d))")
# Shell line continuations, so flags split across lines are seen as one command.
_CONTINUATION = re.compile(r"\\\n\s*")

# ponytail: regex over the raw text, mirroring tests/test_mcp_dependency_cap.py —
# tomllib is 3.11+ and this repo still supports 3.10.
_TIMEOUT_METHOD = re.compile(r'^\s*timeout_method\s*=\s*"([^"]+)"', re.MULTILINE)
_ADDOPTS = re.compile(r'^\s*addopts\s*=\s*"([^"]*)"', re.MULTILINE)
_FUNC_ONLY = re.compile(r"^\s*timeout_func_only\s*=\s*(\w+)", re.MULTILINE)


def _module_level_budgets(path: Path) -> list[int]:
    """Timeout budgets declared in a MODULE-LEVEL ``pytestmark``.

    Read via AST, not regex: a text search for ``pytest.mark.timeout(N)``
    anywhere in the file is satisfied by a single decorated test, which covers
    one test rather than the module. Only a module-level mark protects them all.
    Handles both shapes in use here — a bare ``pytestmark = pytest.mark.timeout(N)``
    and a list containing it alongside other marks.
    """
    budgets: list[int] = []
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets):
            continue
        for call in ast.walk(node.value):
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "timeout"
                and call.args
                and isinstance(call.args[0], ast.Constant)
                and isinstance(call.args[0].value, int)
            ):
                budgets.append(call.args[0].value)
    return budgets


# Modules whose real runtime under a loaded `-n auto` run approaches or exceeds
# the repo-global 30s budget, measured: the chaos suite runs 27-33s (it straddles
# the wall, which is what made this bug fire ~1 run in 5) and the openclaw
# concurrency suite launches ~90 child interpreters. Each must carry its own
# budget or it goes back to being cut at 30s.
_NEEDS_OWN_BUDGET = {
    "tests/chaos/test_lock_interrupt_chaos.py": 120,
    "tests/openclaw/test_integration_concurrency.py": 60,
}


def _pyproject_text() -> str:
    return PYPROJECT.read_text(encoding="utf-8")


class _MockItem:
    """Minimal stand-in for a collected item — the interface the hook uses."""

    def __init__(self, markers=()) -> None:
        self.nodeid = "tests/fake.py::test_fake"
        self.name = "test_fake"
        self.markers = list(markers)

    def add_marker(self, marker) -> None:
        self.markers.append(marker)

    def get_closest_marker(self, name):
        return next((m for m in self.markers if m.name == name), None)


class _MockConfig:
    def __init__(self, rootdir) -> None:
        self.rootdir = rootdir


class _ConfigureOption:
    def __init__(self, numprocesses) -> None:
        self.numprocesses = numprocesses
        self.timeout_method = "thread"


class _ConfigureConfig:
    """Stand-in for the config `pytest_configure` inspects."""

    def __init__(self, numprocesses=None, *, worker: bool = False) -> None:
        self.option = _ConfigureOption(numprocesses)
        self._env_timeout_method = "thread"
        if worker:
            self.workerinput = {}  # xdist sets this only inside a worker


@pytest.mark.parametrize("numprocesses", [None, 0])
def test_serial_runs_downgrade_to_signal(numprocesses) -> None:
    """No xdist worker means os._exit would kill pytest itself.

    `-o addopts=` wipes `-n auto` while leaving `timeout_method = "thread"` set,
    which is how several CI steps and scripts/hooks/live_e2e_gate.py end up
    serial-with-thread. Proven before this hook existed: exit 1, stack dump, no
    summary line, no test report at all.
    """
    config = _ConfigureConfig(numprocesses)
    pytest_configure(config)
    assert config._env_timeout_method == "signal", (
        "a serial run must fall back to `signal`; with `thread` a timeout "
        "os._exit()s pytest itself and the run reports nothing"
    )
    assert config.option.timeout_method == "signal"


@pytest.mark.parametrize(
    "config",
    [_ConfigureConfig(4), _ConfigureConfig(None, worker=True)],
    ids=["parallel-controller", "inside-xdist-worker"],
)
def test_parallel_runs_keep_thread(config) -> None:
    """The downgrade must NOT fire where the whole fix lives.

    Inside a worker the victim is expendable and xdist reports the kill as one
    honest failure — that is the entire point of the PR. `workerinput` is the
    only reliable "am I a worker" signal, since a worker inherits the parent's
    numprocesses.
    """
    pytest_configure(config)
    assert config._env_timeout_method == "thread", (
        "parallel runs must keep `thread`; downgrading here reintroduces the "
        "swallowed-timeout hang and the session-abort this PR fixes"
    )


def test_noconftest_lanes_pass_the_flag_explicitly() -> None:
    """`--noconftest` skips the auto-downgrade, so those lanes must be explicit."""
    offenders: list[str] = []
    for wf in sorted(p for pat in ("**/*.yml", "**/*.yaml") for p in GITHUB.glob(pat)):
        text = _CONTINUATION.sub(" ", wf.read_text(encoding="utf-8"))
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue  # a comment ABOUT the flag is not an invocation
            if "--noconftest" in line and "pytest" in line:
                if "--timeout-method=signal" not in line:
                    offenders.append(f"{wf.name}: {line.strip()[:110]}")

    assert not offenders, (
        "--noconftest skips tests/conftest.py, so the pytest_configure hook that "
        "downgrades thread->signal for serial runs never loads. These lanes must "
        "pass --timeout-method=signal themselves:\n  " + "\n  ".join(offenders)
    )


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


def test_worker_restart_disabled_only_on_the_lane_that_measured_it() -> None:
    """``--max-worker-restart=0`` belongs to the parallel suite lane, not addopts.

    For a worker killed by the ``thread`` timeout method, restarting only re-runs
    the hanging test and pays its budget again: measured 6s/1 failure at
    restart=0 versus 40s/4 at restart=3, with the dead worker's dropped
    scope-group sibling unrecovered either way.

    That reasoning is specific to TIMEOUT kills. A worker can also die for
    reasons a restart legitimately recovers — the user_flow lane drives live
    proxies and subprocesses. Putting the flag in global ``addopts`` applied a
    hang-tuned optimisation to lanes it was never measured against and turned a
    self-recovering crash into a red (CI run 31965508132). Hence: on the lane,
    never global.
    """
    match = _ADDOPTS.search(_pyproject_text())
    assert match is not None, "addopts missing from [tool.pytest.ini_options]"
    assert "--max-worker-restart" not in match.group(1), (
        "--max-worker-restart must NOT be in global addopts: it then applies to "
        "every lane, including user_flow, where a crashed worker recovers "
        "cleanly on restart and suppressing that turns a self-healing crash into "
        "a red. Put it on the parallel lane in .github/workflows/tests.yml."
    )

    text = _CONTINUATION.sub(" ", (GITHUB / "workflows" / "tests.yml").read_text(encoding="utf-8"))
    parallel_lanes = [ln for ln in text.splitlines() if "pytest" in ln and "-n auto" in ln]
    assert parallel_lanes, (
        "no `-n auto` pytest lane found in tests.yml — this guard lost sight of "
        "the lane it protects. Update it rather than leaving it green."
    )
    # At least one, not every one. tests.yml also runs a deliberately narrow
    # macOS subset lane that this flag was never measured against, and demanding
    # it there would repeat the over-application this test exists to prevent.
    assert any("--max-worker-restart=0" in ln for ln in parallel_lanes), (
        "no `-n auto` lane in tests.yml passes --max-worker-restart=0. It was "
        "moved out of global addopts on purpose, so if no lane carries it the "
        "setting is simply gone and a hanging test is re-run once per restart, "
        f"each attempt paying the full budget. Lanes: {parallel_lanes}"
    )


def test_serial_lanes_override_to_signal() -> None:
    """A ``-n0`` lane must NOT inherit ``thread``. There is no worker to kill.

    ``thread`` is right under ``-n auto``: the victim is an expendable xdist
    worker and the master reports it as one honest failure. With ``-n0`` the
    victim is pytest itself — ``os._exit()`` ends the run with exit 1 and NO
    test report, so one slow test becomes a blind red lane with nothing to read.
    That regression shipped once (CI run 31610847051, serial real_ipc pass) and
    this test exists so it cannot ship twice.
    """
    offenders: list[str] = []
    lanes_per_file: dict[str, int] = {}
    workflows = sorted(p for pat in ("**/*.yml", "**/*.yaml") for p in GITHUB.glob(pat))
    for workflow in workflows:
        text = _CONTINUATION.sub(" ", workflow.read_text(encoding="utf-8"))
        lanes = [line for line in text.splitlines() if _SERIAL_FLAG.search(line)]
        lanes_per_file[workflow.name] = len(lanes)
        for line in lanes:
            if "--timeout-method=signal" not in line:
                offenders.append(f"{workflow.name}: {line.strip()[:110]}")

    # Fail CLOSED, twice over. `assert not offenders` alone is vacuously true on
    # an empty scan, so a rename, a reflow, or a different invocation form would
    # leave this green while checking nothing — and the lane could quietly go
    # back to inheriting `thread`. Naming the file we KNOW holds a serial lane
    # makes that failure loud instead of silent: if the lane moves, this breaks
    # and someone has to look, which is the entire point.
    assert lanes_per_file.get("tests.yml"), (
        "no serial (zero-worker) pytest lane found in .github/workflows/tests.yml, "
        "where the real_ipc lane lives. Either it was genuinely removed (delete "
        "this test) or its form changed (update _SERIAL_FLAG). Do not leave this "
        f"guard silently passing. Lanes seen per file: {lanes_per_file}"
    )

    assert not offenders, (
        "serial (zero-worker) pytest invocations must pass --timeout-method=signal, "
        "because the repo default `thread` calls os._exit() and with no xdist "
        "worker that kills the run itself — exit 1, no report. Offenders:\n  "
        + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("family", ["real_ipc", "user_flow"])
def test_real_process_families_get_timeout_headroom(tmp_path, family: str) -> None:
    """The collection hook must actually attach the budget it promises.

    Both families drive real processes, so startup dominates their runtime and
    the 30s global is the wrong size. real_ipc waits on an AF_UNIX socket (CI
    allows 20s for that alone, leaving 10s for the body); user_flow drives a
    live proxy — the slowest measured 15.2s locally and ~32s on a macOS runner,
    straight through the wall, and failed there on CI run 31639231328.

    Without this test, deleting the injection loop leaves the whole suite green:
    the behaviour it adds is otherwise unobserved.
    """
    slow = _MockItem([getattr(pytest.mark, family)])
    plain = _MockItem()

    pytest_collection_modifyitems(_MockConfig(tmp_path), [slow, plain])

    injected = slow.get_closest_marker("timeout")
    assert injected is not None, (
        f"{family} items must get a timeout marker injected at collection; "
        "without it they inherit the 30s global and get cut mid-process-startup"
    )
    assert injected.args[0] >= 60, (
        f"injected budget {injected.args[0]}s is too tight — CI alone allows 20s "
        "for sidecar readiness, and the slowest user flow needs ~32s there"
    )
    assert plain.get_closest_marker("timeout") is None, (
        "only real-process families should get headroom; blanket injection would "
        "hide genuinely slow tests everywhere else"
    )


def test_real_ipc_injection_respects_an_explicit_marker(tmp_path) -> None:
    """An explicit per-test budget must win over the injected default."""
    explicit = _MockItem([pytest.mark.real_ipc, pytest.mark.timeout(999)])

    pytest_collection_modifyitems(_MockConfig(tmp_path), [explicit])

    budgets = [m.args[0] for m in explicit.markers if m.name == "timeout"]
    assert budgets == [999], f"explicit marker was clobbered or duplicated: {budgets}"


def test_slow_modules_carry_their_own_budget() -> None:
    """Modules that legitimately run near the 30s wall must not inherit it."""
    missing: list[str] = []
    for rel, minimum in _NEEDS_OWN_BUDGET.items():
        path = PYPROJECT.parent / rel
        if not path.exists():
            missing.append(f"{rel}: file not found (moved? update _NEEDS_OWN_BUDGET)")
            continue
        found = _module_level_budgets(path)
        if not any(n >= minimum for n in found):
            missing.append(
                f"{rel}: needs a MODULE-LEVEL pytestmark timeout(>={minimum}); "
                f"module-level budgets found: {found or 'none'}"
            )

    assert not missing, (
        "these modules run at or past the global 30s budget under load and must "
        "carry their own, or they get cut at the wall again:\n  " + "\n  ".join(missing)
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
