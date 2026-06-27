"""Sidecar hardening primitives — RED tests (WOR-310 Phase A).

The two-uid Docker topology defends against ``ptrace`` and
``/proc/<pid>/mem`` reads via the uid wall. On bare metal (single uid),
the same defenses are delivered by **kernel-level** controls instead:

* ``PR_SET_DUMPABLE=0`` on the sidecar process: blocks core dumps and
  blocks ``ptrace`` from any non-parent process regardless of YAMA. Set
  via ``libc.prctl`` (Linux only — silent no-op on Darwin/Windows).
* ``YAMA ptrace_scope >= 1``: kernel-enforced restriction on cross-uid
  ``ptrace``. ``0`` permits any same-uid process to attach to any other,
  which defeats the proxy-can't-read-sidecar-memory invariant. Sidecar
  refuses to start when ``ptrace_scope == 0``. Missing file (Mac/dev
  path or rootless kernels without YAMA) is treated as warn-not-fatal.

This file pins the API and the call order. Phase A GREEN ships
``src/worthless/sidecar/_hardening.py`` and wires both primitives into
``__main__.main()`` ahead of ``asyncio.run(_run())``.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.sidecar import _hardening


# ---------------------------------------------------------------------------
# ErrorCode allocation — pin the integer so tests can assert on WRTLS-NNN
# ---------------------------------------------------------------------------


def test_yama_error_code_is_116() -> None:
    """``YAMA_PTRACE_SCOPE_TOO_LOW`` slots immediately after ``DAEMON_NOT_SUPPORTED=115``.

    Anti-renumber assertion: a future code added in the wrong slot would
    silently break parsers grepping for ``WRTLS-116`` in operator logs.
    """
    assert ErrorCode.YAMA_PTRACE_SCOPE_TOO_LOW.value == 116


# ---------------------------------------------------------------------------
# set_dumpable_zero
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="prctl is Linux-only")
def test_set_dumpable_zero_invokes_prctl_with_zero() -> None:
    """``libc.prctl(PR_SET_DUMPABLE=4, 0, 0, 0, 0)`` is the one shape that disables core dumps.

    Pinning the call shape so a refactor that drops one of the trailing
    zero args (which Linux requires) silently turns the call into a
    no-op without raising.
    """
    fake_libc = MagicMock()
    fake_libc.prctl.return_value = 0
    with (
        patch("worthless.sidecar._hardening.ctypes.util.find_library", return_value="libc.so.6"),
        patch("worthless.sidecar._hardening.ctypes.CDLL", return_value=fake_libc),
    ):
        _hardening.set_dumpable_zero()
    fake_libc.prctl.assert_called_once_with(_hardening.PR_SET_DUMPABLE, 0, 0, 0, 0)


def test_set_dumpable_zero_is_noop_on_non_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    """Darwin/Windows have no ``prctl``; the helper must skip without raising.

    On macOS the developer-mode bare-metal path runs the sidecar as the
    current user; the dumpable bit doesn't exist there. Ensuring the
    helper is silent on non-Linux keeps the dev experience clean.
    """
    monkeypatch.setattr(_hardening.sys, "platform", "darwin")
    sentinel_cdll = MagicMock(side_effect=AssertionError("CDLL must not be invoked on non-Linux"))
    sentinel_find = MagicMock(side_effect=AssertionError("find_library must not be invoked"))
    monkeypatch.setattr(_hardening.ctypes, "CDLL", sentinel_cdll)
    monkeypatch.setattr(_hardening.ctypes.util, "find_library", sentinel_find)
    _hardening.set_dumpable_zero()  # must not raise


@pytest.mark.skipif(sys.platform != "linux", reason="prctl is Linux-only")
def test_set_dumpable_zero_raises_on_prctl_failure() -> None:
    """A non-zero return from ``prctl`` is a hard error — never silently ignored.

    If the kernel refuses ``PR_SET_DUMPABLE`` (seccomp filter, custom LSM)
    the sidecar must NOT proceed thinking core dumps are off. The error
    is surfaced as ``SIDECAR_NOT_READY`` so the operator sees a structured
    WRTLS-114 in logs.
    """
    fake_libc = MagicMock()
    fake_libc.prctl.return_value = -1
    with (
        patch("worthless.sidecar._hardening.ctypes.util.find_library", return_value="libc.so.6"),
        patch("worthless.sidecar._hardening.ctypes.CDLL", return_value=fake_libc),
        pytest.raises(WorthlessError) as exc_info,
    ):
        _hardening.set_dumpable_zero()
    assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
    assert "PR_SET_DUMPABLE" in exc_info.value.message or "dumpable" in exc_info.value.message


@pytest.mark.skipif(sys.platform != "linux", reason="prctl is Linux-only")
def test_set_dumpable_zero_raises_when_libc_unreachable() -> None:
    """``_load_libc`` returning ``None`` is a hard error.

    On Linux this is exotic (statically-linked Python? broken
    ldconfig?), but if it happens the sidecar cannot set
    ``PR_SET_DUMPABLE=0`` and the security claim is silently broken.
    Refuse to start with a structured WRTLS-114 instead.

    Patch ``_load_libc`` directly: it probes ``libc.so.6`` /
    ``libc.musl-*.so.1`` via ``CDLL`` BEFORE consulting
    ``find_library`` (so distroless without ``ldconfig`` works), so on
    glibc CI runners patching only ``find_library`` never reaches the
    None branch — same trap CodeRabbit caught in the C1 fork-child-safe
    test.
    """
    with (
        patch("worthless.sidecar._hardening._load_libc", return_value=None),
        pytest.raises(WorthlessError) as exc_info,
    ):
        _hardening.set_dumpable_zero()
    assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
    assert "find_library" in exc_info.value.message or "libc" in exc_info.value.message


# ---------------------------------------------------------------------------
# check_yama_ptrace_scope
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scope_value",
    ["1", "2", "3", "1\n", "  2  \n"],
    ids=["scope=1", "scope=2", "scope=3", "trailing-newline", "surrounding-whitespace"],
)
def test_check_yama_ptrace_scope_accepts_value_at_or_above_1(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, scope_value: str
) -> None:
    """``ptrace_scope`` ∈ {1,2,3} all permit safe operation.

    * ``1`` = restricted (parent-only)
    * ``2`` = admin-only
    * ``3`` = ptrace disabled

    Whitespace/newline tolerance avoids surprise rc=1 on kernels with
    quirky ``/proc`` formatting.
    """
    fake = tmp_path / "ptrace_scope"
    fake.write_text(scope_value)
    monkeypatch.setattr(_hardening, "YAMA_FILE", fake)
    _hardening.check_yama_ptrace_scope()  # must not raise


def test_check_yama_ptrace_scope_refuses_when_value_is_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``ptrace_scope=0`` lets any same-uid process attach — sidecar must refuse to start.

    This is the v1.1 ship-gate row 1 ("proxy RCE → read Fernet key")
    delivered at the kernel layer for the bare-metal path. Without this
    check the proxy-process can read the sidecar's memory directly.
    """
    fake = tmp_path / "ptrace_scope"
    fake.write_text("0\n")
    monkeypatch.setattr(_hardening, "YAMA_FILE", fake)
    with pytest.raises(WorthlessError) as exc_info:
        _hardening.check_yama_ptrace_scope()
    assert exc_info.value.code == ErrorCode.YAMA_PTRACE_SCOPE_TOO_LOW
    # Operator-actionable message: name the file + the required value
    assert "ptrace_scope" in exc_info.value.message


def test_check_yama_ptrace_scope_warn_not_fatal_when_file_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Missing ``/proc/sys/kernel/yama/ptrace_scope`` (Mac, custom kernel) is a warn-pass.

    Hard-failing on Mac would block every developer running the sidecar
    locally — they'd be forced into Docker for an unrelated reason.
    Document the gap, don't refuse to run.
    """
    monkeypatch.setattr(_hardening, "YAMA_FILE", tmp_path / "definitely-not-here")
    _hardening.check_yama_ptrace_scope()  # must not raise


def test_check_yama_ptrace_scope_warn_not_fatal_when_garbled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Malformed ``/proc`` content (custom kernel weirdness) is a warn-pass.

    The check is a security advisory, not a kernel-version detector.
    A non-numeric value means we can't make a claim either way — log
    and move on.
    """
    fake = tmp_path / "ptrace_scope"
    fake.write_text("garbage\n")
    monkeypatch.setattr(_hardening, "YAMA_FILE", fake)
    _hardening.check_yama_ptrace_scope()  # must not raise


# ---------------------------------------------------------------------------
# Wiring — main() must call hardening before _run() touches share bytes
# ---------------------------------------------------------------------------


def test_main_invokes_hardening_before_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hardening calls (set_dumpable, check_yama, assert_hardening) precede ``_run``.

    Pinning the order so a future refactor cannot move share-loading
    above the dumpable+YAMA+assertion checks. ``PR_SET_DUMPABLE=0``
    must be in effect before any secret material enters the process
    address space; YAMA must be verified before we bind the IPC
    socket; the post-spawn assertion is the LAST check.
    """
    from worthless.sidecar import __main__ as sidecar_main

    calls: list[str] = []

    def record_dumpable() -> None:
        calls.append("set_dumpable_zero")

    def record_yama() -> None:
        calls.append("check_yama_ptrace_scope")

    def record_assert() -> None:
        calls.append("assert_hardening_applied")

    async def fake_run() -> int:
        calls.append("_run")
        return 0

    monkeypatch.setattr(_hardening, "set_dumpable_zero", record_dumpable)
    monkeypatch.setattr(_hardening, "check_yama_ptrace_scope", record_yama)
    monkeypatch.setattr(_hardening, "assert_hardening_applied", record_assert)
    monkeypatch.setattr(sidecar_main, "_run", fake_run)
    monkeypatch.delenv("WORTHLESS_LOG_LEVEL", raising=False)

    rc = sidecar_main.main()

    assert rc == 0, f"expected rc=0 with mocked _run; got {rc}"
    assert calls == [
        "set_dumpable_zero",
        "check_yama_ptrace_scope",
        "assert_hardening_applied",
        "_run",
    ], f"hardening must run before _run; got order: {calls}"


def test_main_returns_rc_1_when_yama_check_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A YAMA refusal short-circuits ``main()`` with rc=1 — no socket bind, no share read.

    The proxy depends on this: WOR-309 makes the proxy hard-fail when
    the sidecar isn't reachable. Better to die early at sidecar startup
    with a clear WRTLS-116 than to bind a socket and then refuse traffic.
    """
    from worthless.sidecar import __main__ as sidecar_main

    def raise_yama() -> None:
        raise WorthlessError(
            ErrorCode.YAMA_PTRACE_SCOPE_TOO_LOW,
            "ptrace_scope=0; refusing to start",
        )

    async def fake_run() -> int:
        raise AssertionError("_run must NOT be called when hardening fails")

    monkeypatch.setattr(_hardening, "set_dumpable_zero", lambda: None)
    monkeypatch.setattr(_hardening, "check_yama_ptrace_scope", raise_yama)
    monkeypatch.setattr(sidecar_main, "_run", fake_run)
    monkeypatch.delenv("WORTHLESS_LOG_LEVEL", raising=False)
    # CR-3198976791: explicitly clear the Docker priv-drop env so a
    # leaky CI matrix entry (Docker matrix) cannot accidentally
    # downgrade the YAMA refusal to a warning, then have main() return
    # rc=1 for an unrelated reason — the test would pass for the wrong
    # reason and silently break the "rc=1 implies YAMA-was-fatal" contract.
    monkeypatch.delenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", raising=False)

    rc = sidecar_main.main()
    assert rc == 1, f"expected rc=1 on YAMA refusal; got {rc}"


def test_main_downgrades_yama_refusal_to_warning_in_docker_two_uid_mode(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """In Docker two-uid mode, YAMA ptrace_scope=0 is warning-only.

    CodeRabbit fix (line 317): when ``WORTHLESS_DOCKER_PRIVDROP_REQUIRED=1``
    is set, the kernel uid wall (proxy_uid != crypto_uid) blocks ptrace
    and ``/proc/<pid>/mem`` regardless of YAMA scope. A host with
    ``ptrace_scope=0`` still gives us the security claim — refusing
    startup there would block legitimate boots on Render/Fly/managed
    Kubernetes hosts we cannot tune. YAMA stays mandatory in bare-metal
    same-uid mode (covered by the prior test).
    """
    import logging

    from worthless.sidecar import __main__ as sidecar_main

    def raise_yama() -> None:
        raise WorthlessError(
            ErrorCode.YAMA_PTRACE_SCOPE_TOO_LOW,
            "ptrace_scope=0",
        )

    async def fake_run() -> int:
        return 0

    monkeypatch.setattr(_hardening, "set_dumpable_zero", lambda: None)
    monkeypatch.setattr(_hardening, "check_yama_ptrace_scope", raise_yama)
    monkeypatch.setattr(_hardening, "assert_hardening_applied", lambda: None)
    monkeypatch.setattr(sidecar_main, "_run", fake_run)
    monkeypatch.delenv("WORTHLESS_LOG_LEVEL", raising=False)
    monkeypatch.setenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", "1")

    with caplog.at_level(logging.WARNING, logger="worthless.sidecar"):
        rc = sidecar_main.main()

    assert rc == 0, f"expected rc=0 in Docker mode (uid wall protects ptrace); got {rc}"
    assert any(
        "YAMA" in rec.message and "defense-in-depth" in rec.message for rec in caplog.records
    ), "Docker mode must emit a defense-in-depth WARNING when YAMA scope is permissive"


def test_main_keeps_yama_refusal_fatal_when_docker_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bare-metal mode: YAMA scope=0 stays a hard refusal.

    The complement of the prior test. When ``WORTHLESS_DOCKER_PRIVDROP_REQUIRED``
    is unset/empty (install.sh path or someone running the sidecar
    directly), there is no uid wall — YAMA *is* the primary defense.
    Refusal must stay loud.
    """
    from worthless.sidecar import __main__ as sidecar_main

    def raise_yama() -> None:
        raise WorthlessError(
            ErrorCode.YAMA_PTRACE_SCOPE_TOO_LOW,
            "ptrace_scope=0",
        )

    async def fake_run() -> int:
        raise AssertionError("_run must NOT be called when YAMA refusal stands")

    monkeypatch.setattr(_hardening, "set_dumpable_zero", lambda: None)
    monkeypatch.setattr(_hardening, "check_yama_ptrace_scope", raise_yama)
    monkeypatch.setattr(_hardening, "assert_hardening_applied", lambda: None)
    monkeypatch.setattr(sidecar_main, "_run", fake_run)
    monkeypatch.delenv("WORTHLESS_LOG_LEVEL", raising=False)
    monkeypatch.delenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", raising=False)

    rc = sidecar_main.main()
    assert rc == 1, f"expected rc=1 in bare-metal mode on YAMA refusal; got {rc}"
