"""CLI core-dump protection — PR_SET_DUMPABLE=0, not just RLIMIT_CORE (dupf.10).

Why this file exists
--------------------
``disable_core_dumps()`` used to set only ``RLIMIT_CORE=(0, 0)``. On Linux the
kernel treats a **piped** ``core_pattern`` (systemd-coredump / apport — the
default on most Docker hosts, and not namespaced) as *unlimited size*: the
``RLIMIT_CORE == 0`` early-abort governs only the core *file* path. So a
key-holding CLI process could still have its full crash image piped to host
storage with the reconstructed Fernet key in it.

``PR_SET_DUMPABLE=0`` is evaluated *before* ``core_pattern`` is consulted, so
it aborts the dump before the pipe helper is ever spawned. That is the control
that actually closes the path; the rlimit is belt-and-suspenders for the file
case (and the only lever on macOS).

Per-process, verified empirically
---------------------------------
The dumpable bit lives on the ``mm``, so ``execve`` resets it to 1 — a parent
cannot harden a child this way. Measured in a Linux container:

    fork   -> dumpable inherited (0)
    execve -> dumpable RESET to 1     (RLIMIT_CORE is inherited across both)

Two consequences encoded by these tests:

1. Every key-holding process must call this itself. The sidecar's own startup
   call is what protects the sidecar; the CLI needs its own.
2. ``worthless wrap -- <user cmd>`` does **not** leak dumpable=0 into the
   user's program, so there is no debugger/core-dump regression for wrapped
   apps and no ``preexec_fn`` restore is needed.
"""

from __future__ import annotations

import ast
import logging
import sys
from pathlib import Path

import pytest

from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.process import disable_core_dumps

try:
    import resource
except ImportError:  # native Windows has no rlimit at all
    resource = None  # type: ignore[assignment]

LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="PR_SET_DUMPABLE is Linux-only")
# Guards only the rlimit-specific tests. Deliberately NOT a module-level skip:
# that would also skip test_windows_no_lever_does_not_abort_the_command, which is
# the one test that most needs to run on Windows.
NEEDS_RLIMIT = pytest.mark.skipif(resource is None, reason="no resource module (Windows)")


class TestRlimitStillApplied:
    """The pre-existing RLIMIT_CORE behavior must not regress."""

    @NEEDS_RLIMIT
    def test_sets_rlimit_core_to_zero(self) -> None:
        disable_core_dumps()
        assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)

    def test_idempotent(self) -> None:
        disable_core_dumps()
        disable_core_dumps()


class TestDumpableApplied:
    """The new control: the kernel must actually report dumpable == 0."""

    @LINUX_ONLY
    def test_kernel_reports_dumpable_zero(self) -> None:
        from worthless.sidecar._hardening import get_dumpable

        disable_core_dumps()
        assert get_dumpable() == 0

    def test_non_linux_none_is_a_silent_no_op(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Off-Linux there is no dumpable bit — None is genuinely indeterminate."""
        from worthless.cli import process as proc_mod

        monkeypatch.setattr(proc_mod.sys, "platform", "darwin")
        monkeypatch.setattr(proc_mod._hardening, "get_dumpable", lambda: None)
        disable_core_dumps()  # must not raise

    def test_non_linux_fails_closed_when_rlimit_did_not_apply(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Off-Linux the rlimit is the ONLY lever, so a failed setrlimit must not
        be reported as success — that would leave the caller believing it is
        protected when nothing was applied at all."""
        from worthless.cli import process as proc_mod

        monkeypatch.setattr(proc_mod.sys, "platform", "darwin")
        monkeypatch.setattr(proc_mod, "_set_rlimit_core_zero", lambda: False)
        monkeypatch.setattr(proc_mod._hardening, "set_dumpable_zero_or_log", lambda: None)
        monkeypatch.setattr(proc_mod._hardening, "get_dumpable", lambda: None)

        with pytest.raises(WorthlessError) as exc:
            disable_core_dumps(strict=True)
        assert exc.value.code is ErrorCode.CORE_DUMP_PROTECTION_FAILED

    def test_windows_no_lever_does_not_abort_the_command(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Windows has no `resource` module and no dumpable bit — no lever exists,
        so there is nothing to confirm. Raising here would hard-fail lock/unlock
        on every native-Windows run (they have no fail_if_windows() guard)."""
        from worthless.cli import process as proc_mod

        monkeypatch.setattr(proc_mod, "resource", None)
        monkeypatch.setattr(proc_mod.sys, "platform", "win32")
        monkeypatch.setattr(proc_mod._hardening, "set_dumpable_zero_or_log", lambda: None)
        monkeypatch.setattr(proc_mod._hardening, "get_dumpable", lambda: None)

        disable_core_dumps(strict=True)  # must NOT raise

    @NEEDS_RLIMIT
    def test_rlimit_readback_confirms_not_just_the_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """setrlimit succeeding is not proof: the helper must read the limit back."""
        from worthless.cli import process as proc_mod

        monkeypatch.setattr(proc_mod.resource, "setrlimit", lambda *_a: None)
        monkeypatch.setattr(proc_mod.resource, "getrlimit", lambda *_a: (1024, 1024))
        assert proc_mod._set_rlimit_core_zero() is False

    def test_linux_none_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """F1: on Linux, None means the setter never ran (libc unreachable) — a
        known failure on a platform that HAS the bit, not 'indeterminate'. Must
        fail closed under strict, never silently proceed with dumpable=1."""
        from worthless.cli import process as proc_mod

        monkeypatch.setattr(proc_mod.sys, "platform", "linux")
        monkeypatch.setattr(proc_mod._hardening, "set_dumpable_zero_or_log", lambda: None)
        monkeypatch.setattr(proc_mod._hardening, "get_dumpable", lambda: None)
        with pytest.raises(WorthlessError) as exc:
            disable_core_dumps(strict=True)
        assert exc.value.code is ErrorCode.CORE_DUMP_PROTECTION_FAILED


class TestFailureModes:
    """Fail closed for key-holding commands, warn-only for the rest."""

    def test_strict_raises_when_kernel_refuses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from worthless.cli import process as proc_mod

        monkeypatch.setattr(proc_mod._hardening, "set_dumpable_zero_or_log", lambda: None)
        monkeypatch.setattr(proc_mod._hardening, "get_dumpable", lambda: 1)

        with pytest.raises(WorthlessError) as exc:
            disable_core_dumps(strict=True)
        assert exc.value.code is ErrorCode.CORE_DUMP_PROTECTION_FAILED

    def test_non_strict_warns_but_returns(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        from worthless.cli import process as proc_mod

        monkeypatch.setattr(proc_mod._hardening, "set_dumpable_zero_or_log", lambda: None)
        monkeypatch.setattr(proc_mod._hardening, "get_dumpable", lambda: 1)

        with caplog.at_level(logging.WARNING):
            disable_core_dumps(strict=False)  # must not raise
        assert "core dump" in caplog.text.lower()

    def test_strict_is_the_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A caller that forgets the flag gets the safe behavior."""
        from worthless.cli import process as proc_mod

        monkeypatch.setattr(proc_mod._hardening, "set_dumpable_zero_or_log", lambda: None)
        monkeypatch.setattr(proc_mod._hardening, "get_dumpable", lambda: 1)

        with pytest.raises(WorthlessError):
            disable_core_dumps()


# ---------------------------------------------------------------------------
# Ordering guard (R4): protection must be applied BEFORE key material is read.
# ---------------------------------------------------------------------------

_CMD_DIR = Path(__file__).resolve().parents[1] / "src" / "worthless" / "cli" / "commands"


def _call_names(fn: ast.AST) -> list[tuple[str, int]]:
    """Calls in this function's own scope, NOT in nested defs.

    The command modules wrap every subcommand in a ``register_*_commands``
    registrar, so descending into nested scopes would compare one
    subcommand's ``get_home()`` against a *different* subcommand's
    ``disable_core_dumps()``. Nested functions are visited separately by the
    caller's ``ast.walk``.
    """
    out: list[tuple[str, int]] = []
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            continue
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name:
                out.append((name, node.lineno))
        stack.extend(ast.iter_child_nodes(node))
    return out


@pytest.mark.parametrize("module", sorted(p.name for p in _CMD_DIR.glob("*.py")))
def test_core_dump_protection_precedes_key_load(module: str) -> None:
    """In any function doing both, disable_core_dumps() must precede get_home().

    get_home() reads home.fernet_key into memory. Hardening after that leaves a
    window where the key is resident and cores are still enabled.
    """
    tree = ast.parse((_CMD_DIR / module).read_text(encoding="utf-8"))
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        calls = _call_names(fn)
        harden = [ln for name, ln in calls if name == "disable_core_dumps"]
        loads = [ln for name, ln in calls if name == "get_home"]
        if not harden or not loads:
            continue
        assert min(harden) < min(loads), (
            f"{module}::{fn.name} loads the key at line {min(loads)} before "
            f"disabling core dumps at line {min(harden)} — the key is resident "
            f"while cores are still enabled"
        )


@pytest.mark.parametrize("module", ["lock.py", "unlock.py", "up.py", "wrap.py"])
def test_key_holding_command_calls_disable_core_dumps(module: str) -> None:
    """Presence guard: the ordering test skips a file with no call at all, so a
    deleted disable_core_dumps() would pass silently. This fails on deletion."""
    src = (_CMD_DIR / module).read_text(encoding="utf-8")
    assert "disable_core_dumps(" in src, (
        f"{module} no longer calls disable_core_dumps() — a key-holding command "
        f"must harden before it loads the Fernet key"
    )


@NEEDS_RLIMIT
def test_rlimit_failure_does_not_stop_dumpable_hardening(monkeypatch: pytest.MonkeyPatch) -> None:
    """If setrlimit raises (some CI/sandbox), the PR_SET_DUMPABLE path must still run."""
    from worthless.cli import process as proc_mod

    def _boom(*_a: object, **_k: object) -> None:
        raise OSError("setrlimit denied")

    monkeypatch.setattr(proc_mod.resource, "setrlimit", _boom)
    calls: list[str] = []
    monkeypatch.setattr(
        proc_mod._hardening, "set_dumpable_zero_or_log", lambda: calls.append("set")
    )
    monkeypatch.setattr(proc_mod._hardening, "get_dumpable", lambda: 0)

    disable_core_dumps()  # must not propagate the OSError
    assert calls == ["set"], "dumpable hardening skipped when setrlimit failed"


def test_scan_hardens_without_failing_the_command() -> None:
    """scan never reconstructs a key, so it must warn rather than abort."""
    src = (_CMD_DIR / "scan.py").read_text(encoding="utf-8")
    assert "disable_core_dumps(strict=False)" in src


def test_doctor_home_check_does_not_false_warn_when_proc_unreadable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Regression: PR_SET_DUMPABLE=0 on the daemon makes /proc/<pid> root-owned,
    so doctor's read_process_env returns {}. It must treat that as indeterminate
    (return False), not default to _DEFAULT_BASE and cry mismatch for custom homes.
    """
    from worthless.cli.commands import doctor as doctor_mod

    monkeypatch.setattr(doctor_mod, "read_pid", lambda _p: (4242, 8787))
    monkeypatch.setattr(doctor_mod, "read_process_env", lambda _pid: {})

    class _Home:
        base_dir = tmp_path / "custom-home"  # deliberately NOT the default base

    assert doctor_mod._check_home_mismatch(_Home()) is False
