"""Privilege-drop tests for ``spawn_sidecar`` (WOR-310 Phase C).

Phase C wires a runtime ``setresgid → setgroups([]) → PR_SET_NO_NEW_PRIVS
→ setresuid → PR_SET_DUMPABLE=0`` dance into ``deploy/start.py`` so the
single-container Docker topology runs:

* ``worthless-crypto`` (uid 10002) — sidecar process
* ``worthless-proxy`` (uid 10001) — uvicorn process

Both inside one container, neither root, kernel-enforced uid wall.

The dance is split across the lifecycle module (``spawn_sidecar``
gains a ``service_uids`` kwarg + a private ``_make_priv_drop_preexec``
factory) and ``deploy/start.py`` (parent drops self after spawn).

This file pins the **foundation** (Segment C1):

* ``ServiceUids`` NamedTuple — immutable, single Optional through
  ``spawn_sidecar`` (no ``target_uid + target_gid`` invalid-state pair).
* ``subprocess.Popen(close_fds=True, pass_fds=())`` — every spawn,
  not just when dropping privs. Closes brutus's weakest-link FD-leak.
* ``_hardening.set_dumpable_zero_or_log()`` — fork-child-safe variant
  that logs instead of raising. Phase C2's ``preexec_fn`` calls this
  inside the forked child where raising loses partial-drop state.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import worthless.cli.sidecar_lifecycle as _sidecar_lifecycle
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.cli.sidecar_lifecycle import ServiceUids, ShareFiles, spawn_sidecar
from worthless.sidecar import _hardening

# Linux prctl constant — pinned at module scope so a future refactor
# that quietly changes the value (e.g. shadows ``PR_SET_NO_NEW_PRIVS``
# with a different code) is caught by the test that compares to this
# literal. man prctl(2): PR_SET_NO_NEW_PRIVS = 38.
PR_SET_NO_NEW_PRIVS = 38


# ---------------------------------------------------------------------------
# ServiceUids — pinned NamedTuple shape
# ---------------------------------------------------------------------------


def test_service_uids_is_immutable_namedtuple() -> None:
    """``ServiceUids`` must be a NamedTuple with three int fields.

    The `target_uid + target_gid` two-Optional API was rejected by the
    architect review (invalid `(set, None)` state representable). One
    NamedTuple, one Optional through `spawn_sidecar`. Pinning the shape
    here so a future refactor to a dataclass — which would be mutable —
    is caught.
    """
    uids = ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)
    assert uids.proxy_uid == 10001
    assert uids.crypto_uid == 10002
    assert uids.worthless_gid == 10001
    # NamedTuples raise AttributeError on attribute assignment.
    with pytest.raises(AttributeError):
        uids.proxy_uid = 9999  # type: ignore[misc]


def test_service_uids_field_order_is_proxy_crypto_gid() -> None:
    """Pin positional order so ``ServiceUids(10001, 10002, 10001)`` reads correctly.

    Positional construction is allowed (it's a NamedTuple) — the field
    order pins the meaning. A future reorder would silently shift uids
    if any caller used positional args.
    """
    assert ServiceUids._fields == ("proxy_uid", "crypto_uid", "worthless_gid")


@pytest.mark.parametrize(
    ("proxy_uid", "crypto_uid", "worthless_gid"),
    [
        (0, 10002, 10001),  # proxy=root → no-op drop
        (10001, 0, 10001),  # crypto=root → silently breaks claim
        (10001, 10002, 0),  # gid=root group → group-permission escape
        (-1, 10002, 10001),  # negative uid (impossible but defensive)
    ],
)
def test_spawn_sidecar_rejects_service_uids_with_root_or_negative_id(
    _share_files: ShareFiles, proxy_uid: int, crypto_uid: int, worthless_gid: int
) -> None:
    """``spawn_sidecar`` refuses to start when any id is < 1 (root or negative).

    A future Dockerfile drift / shadowed ``/etc/passwd`` that resolves
    ``worthless-proxy`` to uid 0 would silently no-op the privilege drop
    in C2 — the sidecar would still run as root, killing the v1.1
    security claim with no log line. Eager validation at the spawn
    boundary turns the silent failure into a structured WRTLS-114.
    """
    import uuid

    socket_path = Path(f"/tmp/wor310-c1-{uuid.uuid4().hex[:8]}.sock")  # noqa: S108
    bad_uids = ServiceUids(proxy_uid=proxy_uid, crypto_uid=crypto_uid, worthless_gid=worthless_gid)
    with pytest.raises(WorthlessError) as exc_info:
        spawn_sidecar(
            socket_path=socket_path,
            shares=_share_files,
            allowed_uid=1000,
            service_uids=bad_uids,
        )
    assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
    assert "non-root" in exc_info.value.message


# ---------------------------------------------------------------------------
# spawn_sidecar — Popen kwargs
# ---------------------------------------------------------------------------


@pytest.fixture
def _share_files(tmp_path: Path) -> ShareFiles:
    """Minimal ShareFiles for spawn_sidecar to consume.

    The Popen call is mocked, so the share contents never matter — but
    the dataclass needs valid Path types. Real bytes match the WOR-307
    contract (44-byte b64 fernet key) so a future schema check on
    ShareFiles construction wouldn't fail this fixture spuriously.
    """
    run_dir = tmp_path / "run" / "12345"
    run_dir.mkdir(parents=True)
    a_path = run_dir / "share_a"
    b_path = run_dir / "share_b"
    a_path.write_bytes(b"a" * 44)
    b_path.write_bytes(b"b" * 44)
    return ShareFiles(
        run_dir=run_dir,
        share_a_path=a_path,
        share_b_path=b_path,
        shard_a=bytearray(b"a" * 44),
        shard_b=bytearray(b"b" * 44),
    )


def test_spawn_sidecar_passes_close_fds_and_empty_pass_fds(
    _share_files: ShareFiles,
) -> None:
    """``Popen`` must always get ``close_fds=True, pass_fds=()`` (WOR-310 brutus).

    Without this, the SQLite handle, log fds, prometheus socket, and
    any other open descriptor in the parent process inherit into the
    sidecar. RCE in the sidecar = read everything. Pinning the kwargs
    here is the foundation of the uid-wall security claim — kernel
    isolation only matters if the FDs aren't already shared.

    Applies on EVERY spawn, not just when dropping privs (defense in
    depth on bare-metal where uid wall doesn't exist).
    """
    # AF_UNIX sun_path limit (104 on macOS) — pytest's nested tmp_path on
    # macOS exceeds it, so we use a short ``/tmp`` path.  Process is fully
    # mocked; the inode is never created.
    import uuid

    socket_path = Path(f"/tmp/wor310-c1-{uuid.uuid4().hex[:8]}.sock")  # noqa: S108
    captured_kwargs: dict[str, object] = {}

    fake_proc = MagicMock()
    fake_proc.pid = 12345
    fake_proc.poll.return_value = None

    def fake_popen(*_args: object, **kwargs: object) -> MagicMock:
        captured_kwargs.update(kwargs)
        return fake_proc

    with (
        patch.object(_sidecar_lifecycle.subprocess, "Popen", fake_popen),
        patch.object(_sidecar_lifecycle, "_wait_for_ready", return_value=True),
        patch.object(_sidecar_lifecycle, "_verify_socket_inode", lambda _p: None),
    ):
        spawn_sidecar(
            socket_path=socket_path,
            shares=_share_files,
            allowed_uid=1000,
        )

    assert captured_kwargs.get("close_fds") is True, (
        "WOR-310 C1: Popen must close_fds=True to prevent FD inheritance into the sidecar process"
    )
    assert captured_kwargs.get("pass_fds") == (), (
        "WOR-310 C1: Popen must pass_fds=() — empty tuple, not unset — so no FD ever inherits"
    )


# ---------------------------------------------------------------------------
# set_dumpable_zero_or_log — fork-child-safe variant
# ---------------------------------------------------------------------------


def test_set_dumpable_zero_or_log_exists_as_separate_function() -> None:
    """The ``_or_log`` variant must be its own callable.

    Phase A's ``set_dumpable_zero`` raises ``WorthlessError`` on
    failure. Phase C2's preexec_fn cannot raise cleanly (the forked
    child between fork and exec has no exception path back to the
    parent). The architect review required a child-safe variant.
    """
    assert callable(_hardening.set_dumpable_zero_or_log), (
        "WOR-310 C1: _hardening.set_dumpable_zero_or_log must exist as a "
        "fork-child-safe variant of set_dumpable_zero"
    )
    assert _hardening.set_dumpable_zero_or_log is not _hardening.set_dumpable_zero, (
        "WOR-310 C1: _or_log variant must be a distinct function, not an alias"
    )


def test_set_dumpable_zero_or_log_logs_and_returns_on_prctl_failure(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_or_log`` must swallow ``prctl != 0`` and log instead of raising.

    Inside ``preexec_fn`` the forked child has no clean way to surface
    a Python exception back to the parent — it crashes the child,
    leaving the parent with a child that may have already partially
    dropped privs. The ``_or_log`` variant logs at ERROR and returns
    so the spawn either completes (uvicorn sees the dropped child) or
    fails at exec, never mid-drop.
    """
    # Force the Linux path so the test runs cross-platform; the test's
    # subject is the failure-handling branch, not the platform gate.
    monkeypatch.setattr(_hardening.sys, "platform", "linux")
    fake_libc = MagicMock()
    fake_libc.prctl.return_value = -1

    with (
        patch("worthless.sidecar._hardening.ctypes.util.find_library", return_value="libc.so.6"),
        patch("worthless.sidecar._hardening.ctypes.CDLL", return_value=fake_libc),
        caplog.at_level(logging.ERROR, logger="worthless.sidecar.hardening"),
    ):
        _hardening.set_dumpable_zero_or_log()  # must not raise

    assert any(
        "PR_SET_DUMPABLE" in rec.message or "dumpable" in rec.message for rec in caplog.records
    ), "WOR-310 C1: _or_log variant must emit an ERROR log when prctl fails"


def test_set_dumpable_zero_or_log_logs_when_libc_unreachable(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_or_log`` swallows ``_load_libc`` returning None.

    Same rationale as the prctl-failure case: any Linux failure path
    inside preexec_fn must log + return, never raise.

    CodeRabbit fix: patch ``_load_libc`` directly. The original test
    patched only ``find_library``, but ``_load_libc`` probes
    ``libc.so.6``/``libc.musl-*.so.1`` directly via ``CDLL`` BEFORE
    consulting ``find_library`` (so distroless without ``ldconfig``
    still works). On glibc CI runners ``CDLL("libc.so.6")`` succeeds
    and the ``find_library`` patch is never reached — the test passed
    locally on macOS only because the platform-gate short-circuited.
    """
    monkeypatch.setattr(_hardening.sys, "platform", "linux")
    with (
        patch("worthless.sidecar._hardening._load_libc", return_value=None),
        caplog.at_level(logging.ERROR, logger="worthless.sidecar.hardening"),
    ):
        _hardening.set_dumpable_zero_or_log()  # must not raise

    assert any("libc" in rec.message or "find_library" in rec.message for rec in caplog.records), (
        "WOR-310 C1: _or_log must log when libc is unreachable"
    )


def test_set_dumpable_zero_or_log_is_noop_on_non_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-Linux short-circuits before any ctypes interaction.

    Same Darwin/Windows behavior as Phase A's ``set_dumpable_zero``:
    silent no-op. The dev path on macOS must NEVER hit libc.
    """
    monkeypatch.setattr(_hardening.sys, "platform", "darwin")
    sentinel = MagicMock(side_effect=AssertionError("CDLL must not run on non-Linux"))
    monkeypatch.setattr(_hardening.ctypes, "CDLL", sentinel)
    monkeypatch.setattr(_hardening.ctypes.util, "find_library", sentinel)
    _hardening.set_dumpable_zero_or_log()  # must not raise


# ---------------------------------------------------------------------------
# _make_priv_drop_preexec — syscall ORDER + correctness (Segment C2)
# ---------------------------------------------------------------------------


def test_make_priv_drop_preexec_calls_in_correct_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The preexec_fn must call syscalls in exactly this order:

      1. ``os.setresgid(gid, gid, gid)``       — first, still has CAP_SETGID
      2. ``os.setgroups([])``                  — clear inherited groups
      3. ``_hardening.set_no_new_privs_or_log()`` — locks before uid drop
      4. ``os.setresuid(uid, uid, uid)``       — last, drops cap_set*
      5. ``_hardening.set_dumpable_zero_or_log()`` — applies to dropped process

    A swap (e.g. setresuid before setgroups) breaks the kernel-enforced
    capability model: setgroups() requires CAP_SETGID, which setresuid()
    drops. Pinning the exact order here so a future refactor can't
    silently rearrange and turn the security claim into theater.
    """
    calls: list[str] = []

    monkeypatch.setattr(
        _sidecar_lifecycle.os,
        "setresgid",
        lambda r, e, s: calls.append(f"setresgid({r},{e},{s})"),
        raising=False,
    )
    monkeypatch.setattr(
        _sidecar_lifecycle.os,
        "setgroups",
        lambda groups: calls.append(f"setgroups({list(groups)})"),
        raising=False,
    )
    monkeypatch.setattr(
        _sidecar_lifecycle.os,
        "setresuid",
        lambda r, e, s: calls.append(f"setresuid({r},{e},{s})"),
        raising=False,
    )
    monkeypatch.setattr(
        _hardening,
        "set_no_new_privs_or_log",
        lambda: calls.append("set_no_new_privs_or_log"),
    )
    monkeypatch.setattr(
        _hardening,
        "set_capbset_drop_or_log",
        lambda: calls.append("set_capbset_drop_or_log"),
    )
    monkeypatch.setattr(
        _hardening,
        "set_dumpable_zero_or_log",
        lambda: calls.append("set_dumpable_zero_or_log"),
    )

    uids = ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)
    preexec = _sidecar_lifecycle._make_priv_drop_preexec(uids)
    preexec()  # invoke as if inside the forked child

    assert calls == [
        "setresgid(10001,10001,10001)",
        "setgroups([])",
        "set_no_new_privs_or_log",
        "set_capbset_drop_or_log",
        "setresuid(10002,10002,10002)",
        "set_dumpable_zero_or_log",
    ], f"WOR-310 C2: priv-drop syscall order is wrong: {calls}"


def test_make_priv_drop_preexec_uses_setresgid_not_setgid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``setresgid`` is required, NOT ``setgid`` — saved-gid leak guard.

    ``os.setgid(gid)`` only sets effective gid (when euid=0 it sets all
    three on Linux, but that's glibc behavior, not kernel ABI). The
    saved gid being left as 0 means a post-RCE attacker that gains
    CAP_SETGID can swap back. ``setresgid(gid, gid, gid)`` locks all
    three atomically.
    """
    sentinel_setgid = MagicMock(
        side_effect=AssertionError("WOR-310 C2: must use setresgid, not setgid")
    )
    monkeypatch.setattr(_sidecar_lifecycle.os, "setgid", sentinel_setgid, raising=False)
    monkeypatch.setattr(_sidecar_lifecycle.os, "setresgid", lambda r, e, s: None, raising=False)
    monkeypatch.setattr(_sidecar_lifecycle.os, "setgroups", lambda g: None, raising=False)
    monkeypatch.setattr(_sidecar_lifecycle.os, "setresuid", lambda r, e, s: None, raising=False)
    monkeypatch.setattr(_hardening, "set_no_new_privs_or_log", lambda: None)
    monkeypatch.setattr(_hardening, "set_capbset_drop_or_log", lambda: None)
    monkeypatch.setattr(_hardening, "set_dumpable_zero_or_log", lambda: None)

    uids = ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)
    _sidecar_lifecycle._make_priv_drop_preexec(uids)()  # must not raise


def test_setgroups_passed_empty_list_not_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``os.setgroups([])`` — empty *list*, not tuple.

    glibc accepts either, but musl (Alpine, in the install matrix)
    historically had quirks with non-list iterables. Pin the type so a
    future refactor to ``setgroups(())`` doesn't bite us at runtime on
    a customer's Alpine deployment.
    """
    captured: list[object] = []
    monkeypatch.setattr(_sidecar_lifecycle.os, "setresgid", lambda r, e, s: None, raising=False)
    monkeypatch.setattr(
        _sidecar_lifecycle.os, "setgroups", lambda g: captured.append(g), raising=False
    )
    monkeypatch.setattr(_sidecar_lifecycle.os, "setresuid", lambda r, e, s: None, raising=False)
    monkeypatch.setattr(_hardening, "set_no_new_privs_or_log", lambda: None)
    monkeypatch.setattr(_hardening, "set_capbset_drop_or_log", lambda: None)
    monkeypatch.setattr(_hardening, "set_dumpable_zero_or_log", lambda: None)

    uids = ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)
    _sidecar_lifecycle._make_priv_drop_preexec(uids)()

    assert captured == [[]], f"WOR-310 C2: setgroups must be called with [], got {captured}"
    assert isinstance(captured[0], list), (
        f"WOR-310 C2: setgroups arg must be a list, got {type(captured[0]).__name__}"
    )


def test_no_new_privs_called_before_setresuid(monkeypatch: pytest.MonkeyPatch) -> None:
    """``PR_SET_NO_NEW_PRIVS`` must be set BEFORE ``setresuid`` drops privs.

    If we drop uid first, then try to set NO_NEW_PRIVS, the syscall
    still works but the order pin protects the rationale: setting it
    pre-drop means the bit is locked under root's CAP_SYS_ADMIN
    (cleaner audit), and protects against a future bug where a
    seccomp filter or LSM might restrict prctl post-drop on some
    kernels.
    """
    calls: list[str] = []
    monkeypatch.setattr(_sidecar_lifecycle.os, "setresgid", lambda r, e, s: None, raising=False)
    monkeypatch.setattr(_sidecar_lifecycle.os, "setgroups", lambda g: None, raising=False)
    monkeypatch.setattr(
        _sidecar_lifecycle.os,
        "setresuid",
        lambda r, e, s: calls.append("setresuid"),
        raising=False,
    )
    monkeypatch.setattr(
        _hardening,
        "set_no_new_privs_or_log",
        lambda: calls.append("no_new_privs"),
    )
    monkeypatch.setattr(_hardening, "set_dumpable_zero_or_log", lambda: None)
    monkeypatch.setattr(_hardening, "set_capbset_drop_or_log", lambda: None)

    uids = ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)
    _sidecar_lifecycle._make_priv_drop_preexec(uids)()

    assert calls.index("no_new_privs") < calls.index("setresuid"), (
        f"WOR-310 C2: no_new_privs must precede setresuid; got {calls}"
    )


# ---------------------------------------------------------------------------
# spawn_sidecar wiring: preexec_fn only when service_uids set
# ---------------------------------------------------------------------------


def test_spawn_sidecar_passes_preexec_fn_when_service_uids_set(
    _share_files: ShareFiles,
) -> None:
    """When ``service_uids`` is set, ``Popen`` must receive a callable ``preexec_fn``.

    The forked child runs the callable to drop privs before exec.
    Without ``preexec_fn``, the sidecar inherits the parent's uid
    (root in Docker) and the security claim collapses.
    """
    import uuid

    socket_path = Path(f"/tmp/wor310-c2-{uuid.uuid4().hex[:8]}.sock")  # noqa: S108
    captured_kwargs: dict[str, object] = {}

    fake_proc = MagicMock()
    fake_proc.pid = 12345
    fake_proc.poll.return_value = None

    def fake_popen(*_args: object, **kwargs: object) -> MagicMock:
        captured_kwargs.update(kwargs)
        return fake_proc

    uids = ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)
    with (
        patch.object(_sidecar_lifecycle.subprocess, "Popen", fake_popen),
        patch.object(_sidecar_lifecycle, "_wait_for_ready", return_value=True),
        patch.object(_sidecar_lifecycle, "_verify_socket_inode", lambda _p: None),
    ):
        spawn_sidecar(
            socket_path=socket_path,
            shares=_share_files,
            allowed_uid=10001,
            service_uids=uids,
        )

    preexec_fn = captured_kwargs.get("preexec_fn")
    assert callable(preexec_fn), (
        f"WOR-310 C2: Popen must receive preexec_fn callable when service_uids "
        f"is set; got {preexec_fn!r}"
    )


def test_spawn_sidecar_omits_preexec_fn_when_service_uids_is_none(
    _share_files: ShareFiles,
) -> None:
    """Bare-metal path: ``service_uids=None`` → no ``preexec_fn`` at all.

    The bare-metal install never modifies the host. ``preexec_fn``
    setting it to anything would force a non-trivial fork-child
    callback that does nothing useful and risks the threading
    deadlock from BPO-34394. Cleaner to omit entirely.
    """
    import uuid

    socket_path = Path(f"/tmp/wor310-c2-{uuid.uuid4().hex[:8]}.sock")  # noqa: S108
    captured_kwargs: dict[str, object] = {}

    fake_proc = MagicMock()
    fake_proc.pid = 12345
    fake_proc.poll.return_value = None

    def fake_popen(*_args: object, **kwargs: object) -> MagicMock:
        captured_kwargs.update(kwargs)
        return fake_proc

    with (
        patch.object(_sidecar_lifecycle.subprocess, "Popen", fake_popen),
        patch.object(_sidecar_lifecycle, "_wait_for_ready", return_value=True),
        patch.object(_sidecar_lifecycle, "_verify_socket_inode", lambda _p: None),
    ):
        spawn_sidecar(
            socket_path=socket_path,
            shares=_share_files,
            allowed_uid=1000,
            service_uids=None,
        )

    # Either absent, or explicitly None — both are equivalent semantically.
    preexec = captured_kwargs.get("preexec_fn")
    assert preexec is None, (
        f"WOR-310 C2: bare-metal path (service_uids=None) must not set preexec_fn; got {preexec!r}"
    )


# ---------------------------------------------------------------------------
# set_no_new_privs_or_log — fork-child-safe variant of NO_NEW_PRIVS
# ---------------------------------------------------------------------------


def test_set_no_new_privs_or_log_exists_as_callable() -> None:
    """The C2 NO_NEW_PRIVS helper must exist as a fork-child-safe callable.

    Same shape as ``set_dumpable_zero_or_log``: log on failure, never
    raise inside the forked child. PR_SET_NO_NEW_PRIVS = 38 (Linux
    kernel uapi).
    """
    assert callable(_hardening.set_no_new_privs_or_log), (
        "WOR-310 C2: _hardening.set_no_new_privs_or_log must exist"
    )


def test_set_no_new_privs_or_log_invokes_prctl_with_38(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``prctl(PR_SET_NO_NEW_PRIVS=38, 1, 0, 0, 0)`` is the kernel call shape.

    Pinned literal 38 here so a future refactor that replaces with
    ``ctypes.c_int(some_const)`` doesn't silently change the call.
    """
    monkeypatch.setattr(_hardening.sys, "platform", "linux")
    fake_libc = MagicMock()
    fake_libc.prctl.return_value = 0
    with (
        patch("worthless.sidecar._hardening.ctypes.util.find_library", return_value="libc.so.6"),
        patch("worthless.sidecar._hardening.ctypes.CDLL", return_value=fake_libc),
    ):
        _hardening.set_no_new_privs_or_log()
    fake_libc.prctl.assert_called_once_with(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)


def test_set_no_new_privs_or_log_logs_on_failure(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``prctl != 0`` must log at ERROR and return — never raise from preexec_fn."""
    monkeypatch.setattr(_hardening.sys, "platform", "linux")
    fake_libc = MagicMock()
    fake_libc.prctl.return_value = -1
    with (
        patch("worthless.sidecar._hardening.ctypes.util.find_library", return_value="libc.so.6"),
        patch("worthless.sidecar._hardening.ctypes.CDLL", return_value=fake_libc),
        caplog.at_level(logging.ERROR, logger="worthless.sidecar.hardening"),
    ):
        _hardening.set_no_new_privs_or_log()  # must not raise

    assert any(
        "NO_NEW_PRIVS" in rec.message or "no_new_privs" in rec.message for rec in caplog.records
    ), "WOR-310 C2: failure must log at ERROR"


def test_set_no_new_privs_or_log_is_noop_on_non_linux(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-Linux short-circuits before any libc interaction (parity with set_dumpable)."""
    monkeypatch.setattr(_hardening.sys, "platform", "darwin")
    sentinel = MagicMock(side_effect=AssertionError("CDLL must not run on non-Linux"))
    monkeypatch.setattr(_hardening.ctypes, "CDLL", sentinel)
    monkeypatch.setattr(_hardening.ctypes.util, "find_library", sentinel)
    _hardening.set_no_new_privs_or_log()  # must not raise


# ---------------------------------------------------------------------------
# Segment C2b — Real-fork integration tests (Linux-only).
#
# Mocks prove our code calls the right syscalls. They cannot prove the
# kernel ENFORCES what we claim. These tests fork real children and
# observe ``/proc/self/status`` after the syscall, proving the bit was
# actually set by the kernel — not just that Python emitted the call.
#
# Linux-only: ``/proc/self/status`` is Linux, ``setres*`` is glibc-
# specific, ``prctl`` is a Linux syscall.
# ---------------------------------------------------------------------------


def _read_proc_status_field(pid: int, field_prefix: str) -> str | None:
    """Return the first line of ``/proc/<pid>/status`` starting with *field_prefix*.

    Returns the literal string ``"<no-match: ...>"`` if the prefix is
    absent (so CI failures show what fields ARE present, not just
    ``MISSING``). Returns ``"<read-error: ...>"`` on filesystem error.
    Used by C2b real-fork tests to observe kernel state.
    """
    status_path = Path(f"/proc/{pid}/status")
    try:
        text = status_path.read_text(errors="replace")
    except OSError as exc:
        return f"<read-error: {exc.__class__.__name__}: {exc}>"
    for line in text.splitlines():
        if line.startswith(field_prefix):
            return line
    # Diagnostic: surface the field names that ARE present so a CI
    # failure tells us whether the field was renamed, removed, or just
    # mis-cased rather than dumping ``MISSING`` blindly.
    field_names = sorted({line.split(":", 1)[0] for line in text.splitlines() if ":" in line})
    return f"<no-match for {field_prefix!r}; fields present: {field_names}>"


@pytest.mark.skipif(sys.platform != "linux", reason="real-fork test requires Linux prctl + setres*")
@pytest.mark.real_ipc  # os.fork + os.waitpid; xdist threads -> deadlock (WOR-582)
def test_set_dumpable_zero_or_log_actually_sets_dumpable_in_forked_child() -> None:
    """In a forked child, ``set_dumpable_zero_or_log()`` makes ``prctl(PR_GET_DUMPABLE) == 0``.

    Mocks proved we CALL prctl(PR_SET_DUMPABLE, 0); this test proves the
    kernel HONORS the call. If a future LSM/seccomp filter silently
    no-ops the syscall, ``PR_GET_DUMPABLE`` returns 1 and the test fails loud.

    CodeRabbit fix: read back via ``prctl(PR_GET_DUMPABLE)`` rather than
    parsing ``/proc/<pid>/status::Dumpable``. The procfs field is not
    exposed on every kernel (verified absent on Linux 6.9.12 — this is
    why CI was failing under Ubuntu py3.13). ``prctl`` is the portable
    kernel API.
    """
    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        try:
            _hardening.set_dumpable_zero_or_log()
            value = _hardening.get_dumpable()
            os.write(w_fd, str(value).encode())
        finally:
            os.close(w_fd)
            os._exit(0)
    os.close(w_fd)
    output = os.read(r_fd, 4096).decode()
    os.close(r_fd)
    os.waitpid(pid, 0)
    assert output == "0", (
        f"WOR-310 C2b: prctl(PR_GET_DUMPABLE) != 0 after set_dumpable_zero; got {output!r}"
    )


@pytest.mark.skipif(sys.platform != "linux", reason="real-fork test requires Linux /proc + prctl")
@pytest.mark.real_ipc  # os.fork + os.waitpid; xdist threads -> deadlock (WOR-582)
def test_set_no_new_privs_or_log_actually_sets_no_new_privs_in_forked_child() -> None:
    """In a forked child, ``set_no_new_privs_or_log()`` makes ``NoNewPrivs: 1``."""
    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        try:
            _hardening.set_no_new_privs_or_log()
            line = _read_proc_status_field(os.getpid(), "NoNewPrivs:")
            os.write(w_fd, (line or "MISSING").encode())
        finally:
            os.close(w_fd)
            os._exit(0)
    os.close(w_fd)
    output = os.read(r_fd, 4096).decode()
    os.close(r_fd)
    os.waitpid(pid, 0)
    assert "NoNewPrivs:\t1" in output, (
        f"WOR-310 C2b: kernel did not set NoNewPrivs=1; got {output!r}"
    )


@pytest.mark.skipif(sys.platform != "linux", reason="real-fork test requires Linux setresuid")
@pytest.mark.real_ipc  # os.fork + os.waitpid; xdist threads -> deadlock (WOR-582)
def test_preexec_fn_eperms_in_forked_child_when_non_root() -> None:
    """In a forked NON-ROOT child, ``preexec_fn`` raises EPERM from setresuid.

    Sanity check the kernel enforces what we claim. ``setresuid`` requires
    CAP_SETUID; non-root gets EPERM. If the kernel ever silently allowed
    the syscall, the security model would be quietly broken — this catches
    that.

    Skipped if running AS root (CI container under uid 0). Phase E Docker
    integration handles the root-success path.
    """
    if os.geteuid() == 0:
        pytest.skip("test requires non-root euid to observe EPERM")

    pid = os.fork()
    if pid == 0:
        try:
            uids = ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)
            preexec = _sidecar_lifecycle._make_priv_drop_preexec(uids)
            preexec()
            os._exit(99)  # SHOULD NOT reach here as non-root
        except PermissionError:
            os._exit(42)  # expected EPERM
        except OSError:
            os._exit(43)  # other OSError variant — kernel still rejected
        except BaseException:
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    code = os.WEXITSTATUS(status)
    assert code in (42, 43), (
        f"WOR-310 C2b: expected PermissionError/OSError exit (42/43) "
        f"from setresuid as non-root; got {code}"
    )


@pytest.mark.skipif(sys.platform != "linux", reason="real-fork test requires Linux fork semantics")
@pytest.mark.real_ipc  # real fork via Popen; xdist threads -> deadlock (WOR-582)
def test_preexec_fn_runs_in_forked_child_via_subprocess(tmp_path: Path) -> None:
    """``Popen(preexec_fn=cb)`` actually executes the callable in the child.

    Side-effect proof: the callback writes a marker file that the parent
    can observe. Guards against future Python/libc changes (e.g.,
    posix_spawn migration) silently dropping the preexec_fn contract.
    """
    marker = tmp_path / "preexec-ran.marker"

    def _marker_preexec() -> None:
        marker.write_text("preexec ran\n")

    proc = subprocess.Popen(  # noqa: S603 — args are our own, no shell
        [sys.executable, "-c", "import sys; sys.exit(0)"],
        preexec_fn=_marker_preexec,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    proc.wait(timeout=5)
    assert marker.is_file(), (
        f"WOR-310 C2b: preexec_fn did not execute in forked child; "
        f"marker {marker} not created — Popen preexec contract broken."
    )


# ---------------------------------------------------------------------------
# Segment C2c — Chaos injection (failure mid-drop, partial-drop semantics).
#
# The preexec_fn is a sequence of 5 syscalls. Each can fail (kernel
# under load, seccomp filter, custom LSM, kernel bug). Tests here pin
# the partial-drop semantics: when an OSError raises mid-sequence, the
# function MUST halt — never silently proceed with the wrong privilege
# state. Tests for the ``_or_log`` variants pin the "log don't raise"
# contract that keeps preexec_fn deterministic for forked children.
# ---------------------------------------------------------------------------


def test_chaos_setresgid_eperm_halts_preexec_no_partial_drop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``setresgid`` raising EPERM must halt — setgroups/setresuid NOT reached.

    If setresgid fails (kernel under seccomp, no CAP_SETGID), the gid
    state is unchanged. Continuing to setgroups([]) (which needs
    CAP_SETGID) or setresuid (which would lock saved-gid as root)
    leaves the process in a worse state than before the attempted
    drop. The preexec must halt — Python OSError propagates, subprocess
    fails the spawn with a clear error.
    """
    calls: list[str] = []
    eperm = OSError(1, "Operation not permitted")

    def _setresgid_eperm(r: int, e: int, s: int) -> None:
        calls.append("setresgid")
        raise eperm

    def _track(name: str) -> MagicMock:
        m = MagicMock(side_effect=lambda *a, **k: calls.append(name))
        return m

    monkeypatch.setattr(_sidecar_lifecycle.os, "setresgid", _setresgid_eperm, raising=False)
    monkeypatch.setattr(_sidecar_lifecycle.os, "setgroups", _track("setgroups"), raising=False)
    monkeypatch.setattr(_sidecar_lifecycle.os, "setresuid", _track("setresuid"), raising=False)
    monkeypatch.setattr(_hardening, "set_no_new_privs_or_log", _track("no_new_privs"))
    monkeypatch.setattr(_hardening, "set_dumpable_zero_or_log", _track("dumpable"))
    monkeypatch.setattr(_hardening, "set_capbset_drop_or_log", lambda: None)

    uids = ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)
    preexec = _sidecar_lifecycle._make_priv_drop_preexec(uids)
    with pytest.raises(OSError, match="not permitted"):
        preexec()

    assert calls == ["setresgid"], (
        f"WOR-310 C2c: after setresgid EPERM, NO subsequent syscall must run; got {calls}"
    )


def test_chaos_setgroups_eperm_halts_before_setresuid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``setgroups`` failing after successful setresgid must halt the dance.

    Partial-drop scenario: gid is locked (good), but supplementary
    groups are still inherited from root (bad). Continuing to
    setresuid would let the dropped uid retain root's supplementary
    group memberships — a real escalation path. Halt instead.
    """
    calls: list[str] = []

    def _track(name: str, raise_exc: BaseException | None = None) -> MagicMock:
        def _impl(*_a: object, **_k: object) -> None:
            calls.append(name)
            if raise_exc is not None:
                raise raise_exc

        return MagicMock(side_effect=_impl)

    monkeypatch.setattr(_sidecar_lifecycle.os, "setresgid", _track("setresgid"), raising=False)
    monkeypatch.setattr(
        _sidecar_lifecycle.os,
        "setgroups",
        _track("setgroups", OSError(1, "no perm")),
        raising=False,
    )
    monkeypatch.setattr(_sidecar_lifecycle.os, "setresuid", _track("setresuid"), raising=False)
    monkeypatch.setattr(_hardening, "set_no_new_privs_or_log", _track("no_new_privs"))
    monkeypatch.setattr(_hardening, "set_dumpable_zero_or_log", _track("dumpable"))
    monkeypatch.setattr(_hardening, "set_capbset_drop_or_log", lambda: None)

    uids = ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)
    with pytest.raises(OSError):
        _sidecar_lifecycle._make_priv_drop_preexec(uids)()

    assert calls == ["setresgid", "setgroups"], (
        f"WOR-310 C2c: after setgroups EPERM, no_new_privs/setresuid must NOT run; got {calls}"
    )


def test_chaos_setresuid_eperm_halts_before_dumpable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``setresuid`` failure leaves us with no_new_privs but old uid.

    Worst partial-drop: gid + groups cleared, no_new_privs locked,
    BUT the uid is still root. The dumpable bit hasn't been set.
    Halting here is correct — the parent process Popen() will see
    the spawn fail, and the security model is preserved (we never
    run as root with sidecar code).
    """
    calls: list[str] = []

    def _track(name: str, raise_exc: BaseException | None = None) -> MagicMock:
        def _impl(*_a: object, **_k: object) -> None:
            calls.append(name)
            if raise_exc is not None:
                raise raise_exc

        return MagicMock(side_effect=_impl)

    monkeypatch.setattr(_sidecar_lifecycle.os, "setresgid", _track("setresgid"), raising=False)
    monkeypatch.setattr(_sidecar_lifecycle.os, "setgroups", _track("setgroups"), raising=False)
    monkeypatch.setattr(
        _sidecar_lifecycle.os,
        "setresuid",
        _track("setresuid", OSError(1, "no perm")),
        raising=False,
    )
    monkeypatch.setattr(_hardening, "set_no_new_privs_or_log", _track("no_new_privs"))
    monkeypatch.setattr(_hardening, "set_dumpable_zero_or_log", _track("dumpable"))
    monkeypatch.setattr(_hardening, "set_capbset_drop_or_log", lambda: None)

    uids = ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)
    with pytest.raises(OSError):
        _sidecar_lifecycle._make_priv_drop_preexec(uids)()

    assert calls == ["setresgid", "setgroups", "no_new_privs", "setresuid"], (
        f"WOR-310 C2c: after setresuid EPERM, dumpable must NOT run; got {calls}"
    )


def test_chaos_no_new_privs_failure_does_not_halt_drop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``set_no_new_privs_or_log`` failure must NOT halt the drop.

    The ``_or_log`` variant logs and returns; never raises. This is
    DESIGN: a NO_NEW_PRIVS failure inside preexec_fn shouldn't crash
    the spawn — the uid drop is more important. We log loudly and
    proceed to setresuid + dumpable. Phase E's red-team smoke catches
    if NoNewPrivs ever stays 0 in the running container.
    """
    calls: list[str] = []

    def _track(name: str) -> MagicMock:
        return MagicMock(side_effect=lambda *a, **k: calls.append(name))

    monkeypatch.setattr(_sidecar_lifecycle.os, "setresgid", _track("setresgid"), raising=False)
    monkeypatch.setattr(_sidecar_lifecycle.os, "setgroups", _track("setgroups"), raising=False)
    monkeypatch.setattr(_sidecar_lifecycle.os, "setresuid", _track("setresuid"), raising=False)
    # Real ``set_no_new_privs_or_log`` swallows; simulate by appending then no-op.
    monkeypatch.setattr(
        _hardening,
        "set_no_new_privs_or_log",
        lambda: calls.append("no_new_privs (logged-failure)"),
    )
    monkeypatch.setattr(_hardening, "set_dumpable_zero_or_log", _track("dumpable"))
    monkeypatch.setattr(_hardening, "set_capbset_drop_or_log", lambda: None)

    uids = ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)
    _sidecar_lifecycle._make_priv_drop_preexec(uids)()  # must not raise

    assert calls == [
        "setresgid",
        "setgroups",
        "no_new_privs (logged-failure)",
        "setresuid",
        "dumpable",
    ], f"WOR-310 C2c: drop must complete despite NO_NEW_PRIVS log-failure; got {calls}"


def test_chaos_dumpable_failure_does_not_break_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Final-step ``set_dumpable_zero_or_log`` failure must be a clean return.

    DUMPABLE is the last syscall in the dance. A logged failure here
    doesn't undo earlier success — the preexec_fn returns normally,
    Popen continues to exec, and the resulting child has the gid+uid
    drop in effect even if dumpable was unable to be set. (Unlikely
    but possible: a custom LSM that allows setresuid but blocks
    PR_SET_DUMPABLE.)
    """
    monkeypatch.setattr(_sidecar_lifecycle.os, "setresgid", lambda r, e, s: None, raising=False)
    monkeypatch.setattr(_sidecar_lifecycle.os, "setgroups", lambda g: None, raising=False)
    monkeypatch.setattr(_sidecar_lifecycle.os, "setresuid", lambda r, e, s: None, raising=False)
    monkeypatch.setattr(_hardening, "set_no_new_privs_or_log", lambda: None)
    # Real ``set_dumpable_zero_or_log`` would log here; we simulate by no-op.
    monkeypatch.setattr(_hardening, "set_dumpable_zero_or_log", lambda: None)
    monkeypatch.setattr(_hardening, "set_capbset_drop_or_log", lambda: None)

    uids = ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)
    # No exception, no return value.
    result = _sidecar_lifecycle._make_priv_drop_preexec(uids)()
    assert result is None, (
        f"WOR-310 C2c: preexec_fn must return None for Popen contract; got {result!r}"
    )


# ---------------------------------------------------------------------------
# Segment C2d — Order-dependence proof.
#
# C2a's mocked tests pin the order WE chose; C2d proves that order is
# the only one the KERNEL allows. Required to refute "the order is
# arbitrary" — without this, the security claim would just be tribal
# knowledge rather than kernel-enforced.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="kernel order-enforcement is Linux-only")
@pytest.mark.real_ipc  # os.fork + os.waitpid; xdist threads -> deadlock (WOR-582)
def test_kernel_rejects_setgroups_after_setresuid_when_root() -> None:
    """ROOT + Linux only: prove the kernel rejects ``setgroups([])`` after ``setresuid``.

    Our chosen order puts ``setgroups`` BEFORE ``setresuid``. The reason
    is kernel-enforced: ``setgroups`` requires CAP_SETGID, and ``setresuid``
    drops it. This test forks; in the child, runs the WRONG order
    (setresuid → setgroups); expects setgroups to EPERM.

    Skipped unless running as root (CI under uid 0). When not skipped,
    this is the proof that our order is the ONLY working order — any
    refactor swapping these two would fail at runtime in production.
    """
    if os.geteuid() != 0:
        pytest.skip("test requires root euid to actually drop and observe kernel rejection")

    pid = os.fork()
    if pid == 0:
        try:
            # WRONG ORDER on purpose: drop uid first, then try to clear groups
            os.setresgid(99, 99, 99)  # nogroup-ish
            os.setresuid(99, 99, 99)  # nobody-ish — DROPS CAP_SETGID
            os.setgroups([])  # SHOULD EPERM here
            os._exit(99)  # SHOULD NOT reach here on a correct kernel
        except PermissionError:
            os._exit(42)  # expected: kernel rejected setgroups post-uid-drop
        except OSError:
            os._exit(43)  # other rejection — still proves order matters
        except BaseException:
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    code = os.WEXITSTATUS(status)
    assert code in (42, 43), (
        f"WOR-310 C2d: kernel did NOT reject setgroups after setresuid drop "
        f"(exit {code}). Either our order rationale is wrong, or the kernel "
        f"silently no-ops setgroups for non-root — both break the security claim."
    )


def test_drop_in_child_source_lists_steps_in_documented_order() -> None:
    """Meta test: the source of ``_make_priv_drop_preexec`` lists the 5 syscalls
    in the documented order.

    Cross-platform regression catch. C2a's mocked test pins runtime
    order; this test pins the SOURCE order (a refactor that re-orders
    the source but maintains runtime equivalence — say, by extracting
    helpers — would still pass C2a's test but might surprise a human
    auditor reading the function. Pinning the visible order keeps the
    code honest.
    """
    import inspect

    src = inspect.getsource(_sidecar_lifecycle._make_priv_drop_preexec)

    # The 5 calls must appear in this exact order in the function body.
    # Use fully-qualified names so the docstring's bare references (which
    # also list the steps for human readers) don't fool the search.
    documented_order = [
        "os.setresgid(",
        "os.setgroups(",
        "_hardening.set_no_new_privs_or_log(",
        "_hardening.set_capbset_drop_or_log(",
        "os.setresuid(",
        "_hardening.set_dumpable_zero_or_log(",
    ]
    positions = [src.find(call) for call in documented_order]
    assert all(p != -1 for p in positions), (
        f"WOR-310 C2d: a documented step is missing from "
        f"_make_priv_drop_preexec source: positions={dict(zip(documented_order, positions))}"
    )
    assert positions == sorted(positions), (
        f"WOR-310 C2d: source order does not match documented order. "
        f"Found {dict(zip(documented_order, positions))}. The 5 syscalls must "
        f"appear in source in the order: setresgid → setgroups → "
        f"set_no_new_privs_or_log → setresuid → set_dumpable_zero_or_log."
    )


def test_drop_in_child_does_not_call_setgid_or_setuid() -> None:
    """The non-``setres*`` variants must never appear in production code.

    ``os.setgid()`` / ``os.setuid()`` leave the saved id unlocked (Linux
    glibc semantics). Even if a future refactor adds a "convenience"
    call to setgid before the setres calls, the saved-gid leak is back.
    Pinning that the source NEVER mentions these names — the regression
    is impossible to slip in without touching this assertion.

    Architect A2: walks the AST of the inner ``_drop_in_child`` so a
    tab-indented or newline-leading ``os.setgid(`` doesn't slip through
    the prior substring check. AST-grounded means the test catches
    semantically-real ``Call(Attribute(Name('os'), 'setgid'))`` regardless
    of whitespace.
    """
    import ast
    import inspect

    src = inspect.getsource(_sidecar_lifecycle._make_priv_drop_preexec)
    tree = ast.parse(src)
    forbidden = {"setgid", "setuid"}
    found: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
            and func.attr in forbidden
        ):
            found.append(f"os.{func.attr}")

    assert found == [], (
        f"WOR-310 C2d/A2: forbidden saved-id-leak calls found in "
        f"_make_priv_drop_preexec: {found}. Use os.setresgid/setresuid which "
        f"lock all three (real/effective/saved) atomically."
    )


def test_pr_set_no_new_privs_constant_matches_kernel_abi() -> None:
    """``_hardening.PR_SET_NO_NEW_PRIVS`` MUST equal 38 (Linux kernel ABI).

    Architect A1: the test file's local ``PR_SET_NO_NEW_PRIVS = 38``
    pin only catches a refactor that drops the test's literal — it does
    NOT catch a refactor that drifts the production constant. This
    cross-module assertion pins the linkage: prod constant == kernel
    ABI value (38) AND the test's view matches.
    """
    assert _hardening.PR_SET_NO_NEW_PRIVS == 38, (
        f"WOR-310 A1: production PR_SET_NO_NEW_PRIVS={_hardening.PR_SET_NO_NEW_PRIVS} "
        f"!= kernel ABI value 38. Drift here means the prctl call does the wrong thing "
        f"silently — a different prctl OPTION instead of NO_NEW_PRIVS."
    )
    assert PR_SET_NO_NEW_PRIVS == _hardening.PR_SET_NO_NEW_PRIVS, (
        f"WOR-310 A1: test-local PR_SET_NO_NEW_PRIVS={PR_SET_NO_NEW_PRIVS} "
        f"!= prod constant {_hardening.PR_SET_NO_NEW_PRIVS}. Update the test "
        f"constant if the kernel ever introduces a new code (it won't, but "
        f"this test forces a deliberate ack)."
    )


def test_pr_set_dumpable_constant_matches_kernel_abi() -> None:
    """``_hardening.PR_SET_DUMPABLE`` MUST equal 4 (Linux kernel ABI).

    Same rationale as PR_SET_NO_NEW_PRIVS: the prctl OPTION integer is
    a kernel ABI literal. Drift means we'd be calling a different
    prctl operation entirely.
    """
    assert _hardening.PR_SET_DUMPABLE == 4, (
        f"WOR-310 A1: production PR_SET_DUMPABLE={_hardening.PR_SET_DUMPABLE} "
        f"!= kernel ABI value 4."
    )


def test_pr_capbset_drop_constant_matches_kernel_abi() -> None:
    """``_hardening.PR_CAPBSET_DROP`` MUST equal 24 (Linux kernel ABI)."""
    assert _hardening.PR_CAPBSET_DROP == 24, (
        f"WOR-310 A1: production PR_CAPBSET_DROP={_hardening.PR_CAPBSET_DROP} "
        f"!= kernel ABI value 24."
    )


# ---------------------------------------------------------------------------
# Segment C2e — Property-based (Hypothesis) tests.
#
# Parametrized tests pin specific cases (uid 0, negative); Hypothesis
# searches the full space — uid_max boundaries, large values,
# combinations the parametrize list didn't enumerate. Catches the
# "we forgot one edge case" class of bugs that bites every parameter
# matrix.
# ---------------------------------------------------------------------------

from hypothesis import HealthCheck, given  # noqa: E402  (kept here so C2a–C2d don't need hypothesis to run)
from hypothesis import settings as hsettings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

# Function-scoped fixtures (``_share_files``, ``monkeypatch``) are safe
# to share across Hypothesis-generated inputs here: the fixture state is
# independent of the strategy values (no path-specific or uid-specific
# state captured). Suppressing the health check is the documented
# escape hatch for this exact case.
_FIXTURE_SAFE = hsettings(
    max_examples=20, suppress_health_check=[HealthCheck.function_scoped_fixture]
)

# Linux uid_t / gid_t are uint32; max is 4_294_967_295. Real systems
# reserve ranges, but the kernel itself accepts any uint32. Hypothesis
# explores the full positive range above 0 (root is rejected by our
# validation, see C1).
_VALID_UID = st.integers(min_value=1, max_value=4_294_967_295)
_INVALID_UID = st.integers(min_value=-(2**31), max_value=0)  # negative + zero (root)


@given(
    proxy_uid=_VALID_UID,
    crypto_uid=_VALID_UID,
    worthless_gid=_VALID_UID,
)
@hsettings(max_examples=50)
def test_property_service_uids_accepts_any_positive_id_triple(
    proxy_uid: int, crypto_uid: int, worthless_gid: int
) -> None:
    """Hypothesis: any non-root uid/gid triple constructs a valid ServiceUids.

    No kernel-imposed upper bound below uint32_max — our code shouldn't
    add one accidentally either. If a future refactor caps uids at
    65535 (forgetting modern Linux supports uid > that), this test
    finds it.
    """
    uids = ServiceUids(proxy_uid=proxy_uid, crypto_uid=crypto_uid, worthless_gid=worthless_gid)
    assert uids.proxy_uid == proxy_uid
    assert uids.crypto_uid == crypto_uid
    assert uids.worthless_gid == worthless_gid


@given(
    proxy_uid=_VALID_UID,
    crypto_uid=_VALID_UID,
    worthless_gid=_VALID_UID,
)
@hsettings(
    # Same as _FIXTURE_SAFE (share _share_files / monkeypatch across
    # iterations, state-independent) PLUS deadline=None. WOR-658 follow-up:
    # real spawn_sidecar dispatch can exceed Hypothesis's 200 ms per-example
    # deadline under xdist parallel load (10 workers contending for CPU + fs).
    # The test is about validation acceptance, not throughput, so timing
    # variance shouldn't fail it. Inlined (rather than stacked on
    # @_FIXTURE_SAFE) because Hypothesis rejects multiple @settings
    # decorators on the same test.
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_property_spawn_sidecar_accepts_any_valid_uid_triple(
    _share_files: ShareFiles, proxy_uid: int, crypto_uid: int, worthless_gid: int
) -> None:
    """Any valid (>=1) uid triple WITH proxy != crypto lets ``spawn_sidecar`` proceed.

    Hypothesis explores the boundary at 1 and the upper end at
    4_294_967_295. Validation must accept ALL positive ids, not silently
    cap at e.g. 65535. C2f3's distinctness check requires proxy != crypto;
    the test filters via ``assume`` so the property is "any DISTINCT pair
    is accepted" rather than "any pair".
    """
    from hypothesis import assume

    assume(proxy_uid != crypto_uid)  # C2f3 distinctness — handled separately

    import uuid

    socket_path = Path(f"/tmp/wor310-c2e-{uuid.uuid4().hex[:8]}.sock")  # noqa: S108
    uids = ServiceUids(proxy_uid=proxy_uid, crypto_uid=crypto_uid, worthless_gid=worthless_gid)
    fake_proc = MagicMock()
    fake_proc.pid = 12345
    fake_proc.poll.return_value = None

    with (
        patch.object(_sidecar_lifecycle.subprocess, "Popen", return_value=fake_proc),
        patch.object(_sidecar_lifecycle, "_wait_for_ready", return_value=True),
        patch.object(_sidecar_lifecycle, "_verify_socket_inode", lambda _p: None),
    ):
        # Should NOT raise — any positive distinct uid pair is valid.
        spawn_sidecar(
            socket_path=socket_path,
            shares=_share_files,
            allowed_uid=proxy_uid,
            service_uids=uids,
        )


@given(
    proxy_uid=_INVALID_UID,
    crypto_uid=_VALID_UID,
    worthless_gid=_VALID_UID,
)
@_FIXTURE_SAFE
def test_property_spawn_sidecar_rejects_any_non_positive_proxy_uid(
    _share_files: ShareFiles, proxy_uid: int, crypto_uid: int, worthless_gid: int
) -> None:
    """Any non-positive (<=0) proxy_uid is refused — no exception escapes."""
    import uuid

    socket_path = Path(f"/tmp/wor310-c2e-{uuid.uuid4().hex[:8]}.sock")  # noqa: S108
    uids = ServiceUids(proxy_uid=proxy_uid, crypto_uid=crypto_uid, worthless_gid=worthless_gid)
    with pytest.raises(WorthlessError) as exc_info:
        spawn_sidecar(
            socket_path=socket_path,
            shares=_share_files,
            allowed_uid=1000,
            service_uids=uids,
        )
    assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
    assert "non-root" in exc_info.value.message


@given(
    crypto_uid=_INVALID_UID,
    proxy_uid=_VALID_UID,
    worthless_gid=_VALID_UID,
)
@_FIXTURE_SAFE
def test_property_spawn_sidecar_rejects_any_non_positive_crypto_uid(
    _share_files: ShareFiles, proxy_uid: int, crypto_uid: int, worthless_gid: int
) -> None:
    """Any non-positive crypto_uid is refused — sidecar must never run as root."""
    import uuid

    socket_path = Path(f"/tmp/wor310-c2e-{uuid.uuid4().hex[:8]}.sock")  # noqa: S108
    uids = ServiceUids(proxy_uid=proxy_uid, crypto_uid=crypto_uid, worthless_gid=worthless_gid)
    with pytest.raises(WorthlessError) as exc_info:
        spawn_sidecar(
            socket_path=socket_path,
            shares=_share_files,
            allowed_uid=1000,
            service_uids=uids,
        )
    assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
    assert "non-root" in exc_info.value.message


@given(
    proxy_uid=_VALID_UID,
    crypto_uid=_VALID_UID,
    worthless_gid=_VALID_UID,
)
@_FIXTURE_SAFE
def test_property_preexec_calls_in_pinned_order_for_any_valid_uids(
    monkeypatch: pytest.MonkeyPatch,
    proxy_uid: int,
    crypto_uid: int,
    worthless_gid: int,
) -> None:
    """The syscall order is invariant under any valid uid/gid combination.

    Mocked execution; we don't observe kernel state. Hypothesis explores
    that the chosen order doesn't accidentally depend on specific values
    (e.g., a future bug "if proxy_uid == 0xFFFF, skip setgroups").
    """
    calls: list[str] = []

    monkeypatch.setattr(
        _sidecar_lifecycle.os,
        "setresgid",
        lambda r, e, s: calls.append("setresgid"),
        raising=False,
    )
    monkeypatch.setattr(
        _sidecar_lifecycle.os,
        "setgroups",
        lambda g: calls.append("setgroups"),
        raising=False,
    )
    monkeypatch.setattr(
        _sidecar_lifecycle.os,
        "setresuid",
        lambda r, e, s: calls.append("setresuid"),
        raising=False,
    )
    monkeypatch.setattr(_hardening, "set_no_new_privs_or_log", lambda: calls.append("nnp"))
    monkeypatch.setattr(_hardening, "set_capbset_drop_or_log", lambda: calls.append("capbset"))
    monkeypatch.setattr(_hardening, "set_dumpable_zero_or_log", lambda: calls.append("dump"))

    uids = ServiceUids(proxy_uid=proxy_uid, crypto_uid=crypto_uid, worthless_gid=worthless_gid)
    _sidecar_lifecycle._make_priv_drop_preexec(uids)()

    assert calls == ["setresgid", "setgroups", "nnp", "capbset", "setresuid", "dump"], (
        f"WOR-310 C2e: order broken for uids={uids}; got {calls}"
    )


# ---------------------------------------------------------------------------
# Segment C2f — Post-review additions: libc fallback, CAPBSET_DROP,
# distinctness validation, source-meta robustness.
# ---------------------------------------------------------------------------


def test_load_libc_tries_libc_so_6_first_for_distroless(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_load_libc`` must try ``libc.so.6`` BEFORE ``find_library('c')``.

    Distroless final stages (Google distroless, scratch + glibc bundles)
    have no ``gcc``/``ld``/``ldconfig`` — ``ctypes.util.find_library``
    returns None there. Direct-by-name CDLL lookup works because the
    dynamic linker doesn't need ldconfig. Tries libc.so.6 (glibc) then
    libc.musl-x86_64.so.1 (Alpine) then falls back to find_library.
    """
    monkeypatch.setattr(_hardening.sys, "platform", "linux")

    cdll_attempts: list[str] = []
    fake_libc = MagicMock()

    def fake_cdll(soname: str, **_kwargs: object) -> MagicMock:
        cdll_attempts.append(soname)
        if soname == "libc.so.6":
            return fake_libc
        raise OSError(f"unexpected CDLL call: {soname}")

    monkeypatch.setattr(_hardening.ctypes, "CDLL", fake_cdll)
    sentinel = MagicMock(
        side_effect=AssertionError("find_library MUST NOT be called when libc.so.6 loads")
    )
    monkeypatch.setattr(_hardening.ctypes.util, "find_library", sentinel)

    result = _hardening._load_libc()
    assert result is fake_libc
    assert cdll_attempts == ["libc.so.6"], (
        f"WOR-310 C2f: libc.so.6 must be tried first; got {cdll_attempts}"
    )


def test_load_libc_falls_back_to_musl_when_glibc_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """When ``libc.so.6`` fails on Alpine x86_64, ``_load_libc`` tries the musl x86_64 soname."""
    monkeypatch.setattr(_hardening.sys, "platform", "linux")

    cdll_attempts: list[str] = []
    fake_musl = MagicMock()

    def fake_cdll(soname: str, **_kwargs: object) -> MagicMock:
        cdll_attempts.append(soname)
        if soname == "libc.musl-x86_64.so.1":
            return fake_musl
        raise OSError("not glibc")

    monkeypatch.setattr(_hardening.ctypes, "CDLL", fake_cdll)
    monkeypatch.setattr(_hardening.ctypes.util, "find_library", lambda _name: None)

    result = _hardening._load_libc()
    assert result is fake_musl
    assert cdll_attempts == ["libc.so.6", "libc.musl-x86_64.so.1"], (
        f"WOR-310 C2f: musl fallback must come after libc.so.6; got {cdll_attempts}"
    )


def test_load_libc_falls_back_to_musl_aarch64_on_arm64_alpine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On aarch64 Alpine, ``_load_libc`` falls through to ``libc.musl-aarch64.so.1``.

    CodeRabbit caught: musl uses architecture-specific sonames, so the
    x86_64-only fallback would silently degrade Alpine ARM64 (now common
    on Apple Silicon CI runners and AWS Graviton) to the
    ``find_library`` shell-out path — which fails on distroless. With
    the aarch64 soname in the chain, the dynamic loader finds it
    directly without ldconfig.
    """
    monkeypatch.setattr(_hardening.sys, "platform", "linux")

    cdll_attempts: list[str] = []
    fake_musl = MagicMock()

    def fake_cdll(soname: str, **_kwargs: object) -> MagicMock:
        cdll_attempts.append(soname)
        if soname == "libc.musl-aarch64.so.1":
            return fake_musl
        raise OSError("not glibc, not musl-x86_64")

    monkeypatch.setattr(_hardening.ctypes, "CDLL", fake_cdll)
    sentinel = MagicMock(
        side_effect=AssertionError("find_library MUST NOT be called when musl-aarch64 loads")
    )
    monkeypatch.setattr(_hardening.ctypes.util, "find_library", sentinel)

    result = _hardening._load_libc()
    assert result is fake_musl
    assert cdll_attempts == [
        "libc.so.6",
        "libc.musl-x86_64.so.1",
        "libc.musl-aarch64.so.1",
    ], f"WOR-310 C2f: musl-aarch64 must be tried after musl-x86_64; got {cdll_attempts}"


def test_load_libc_returns_none_when_all_paths_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """If both direct lookups AND find_library fail, ``_load_libc`` returns None.

    Operator-visible event: the calling helper logs at ERROR. Caller
    contract: ``_load_libc() is None`` triggers the log-and-skip path.
    """
    monkeypatch.setattr(_hardening.sys, "platform", "linux")
    monkeypatch.setattr(_hardening.ctypes, "CDLL", MagicMock(side_effect=OSError("no libc")))
    monkeypatch.setattr(_hardening.ctypes.util, "find_library", lambda _name: None)

    assert _hardening._load_libc() is None


def test_set_capbset_drop_or_log_exists_as_callable() -> None:
    """``set_capbset_drop_or_log`` must exist (security-engineer M3 / brutus #15)."""
    assert callable(_hardening.set_capbset_drop_or_log), (
        "WOR-310 C2f: _hardening.set_capbset_drop_or_log must exist"
    )


def test_set_capbset_drop_or_log_calls_prctl_for_each_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``set_capbset_drop_or_log`` iterates ``prctl(PR_CAPBSET_DROP, cap)`` for cap 0..63."""
    monkeypatch.setattr(_hardening.sys, "platform", "linux")
    fake_libc = MagicMock()
    fake_libc.prctl.return_value = 0
    monkeypatch.setattr("worthless.sidecar._hardening._load_libc", lambda **_kw: fake_libc)

    _hardening.set_capbset_drop_or_log()

    # Should have called prctl 64 times, each with PR_CAPBSET_DROP=24 and a cap in 0..63
    assert fake_libc.prctl.call_count == 64, (
        f"WOR-310 C2f: expected 64 prctl calls (caps 0..63); got {fake_libc.prctl.call_count}"
    )
    cap_args = [call.args[1] for call in fake_libc.prctl.call_args_list]
    assert cap_args == list(range(64)), (
        f"WOR-310 C2f: must iterate caps 0..63 in order; got {cap_args}"
    )


def test_set_capbset_drop_or_log_logs_only_non_einval_failures(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EINVAL on unknown cap numbers is expected (kernel < 5.15 doesn't know cap 41+).

    Real failures (EPERM, EACCES) on KNOWN caps are logged loudly. EINVAL
    on cap numbers the running kernel doesn't recognize is normal — we
    don't log those (would spam every startup).
    """
    import ctypes as _ctypes

    monkeypatch.setattr(_hardening.sys, "platform", "linux")

    # Track which cap was last passed to prctl, then make get_errno()
    # report EINVAL for caps >= 40 and 0 (no error) for caps < 40.
    last_cap: list[int] = [0]

    def fake_prctl(option: int, cap: int, *_: int) -> int:
        last_cap[0] = cap
        return -1 if cap >= 40 else 0

    def fake_get_errno() -> int:
        return 22 if last_cap[0] >= 40 else 0  # 22 = EINVAL

    fake_libc = MagicMock()
    fake_libc.prctl.side_effect = fake_prctl
    monkeypatch.setattr("worthless.sidecar._hardening._load_libc", lambda **_kw: fake_libc)
    monkeypatch.setattr(_ctypes, "get_errno", fake_get_errno)

    with caplog.at_level(logging.ERROR, logger="worthless.sidecar.hardening"):
        _hardening.set_capbset_drop_or_log()

    # Should NOT log — all failures were EINVAL on unknown caps.
    error_records = [r for r in caplog.records if r.levelname == "ERROR"]
    assert error_records == [], (
        f"WOR-310 C2f: EINVAL on unknown caps must NOT log at ERROR; got {error_records}"
    )


def test_set_capbset_drop_or_log_is_noop_on_non_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-Linux short-circuits before any libc work."""
    monkeypatch.setattr(_hardening.sys, "platform", "darwin")
    sentinel = MagicMock(side_effect=AssertionError("CDLL must not run on non-Linux"))
    monkeypatch.setattr("worthless.sidecar._hardening._load_libc", sentinel)
    _hardening.set_capbset_drop_or_log()  # must not raise


# ---------------------------------------------------------------------------
# assert_hardening_applied — post-spawn /proc/self/status verification
# ---------------------------------------------------------------------------


def test_assert_hardening_applied_passes_in_bare_metal_when_dumpable_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``assert_hardening_applied`` returns silently when prctl(PR_GET_DUMPABLE)=0.

    Bare-metal mode: only Dumpable is required (NoNewPrivs is preexec-only).
    """
    monkeypatch.setattr(_hardening.sys, "platform", "linux")
    monkeypatch.delenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", raising=False)
    monkeypatch.setattr(_hardening, "get_dumpable", lambda: 0)
    _hardening.assert_hardening_applied()  # must not raise


def test_assert_hardening_applied_passes_in_docker_mode_when_both_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Docker mode: NNP=1 (prctl) AND Dumpable=0 (prctl) → return silently.

    CR-3204010104: NNP is now read via prctl(PR_GET_NO_NEW_PRIVS),
    not procfs.  Mock the prctl helper directly.
    """
    monkeypatch.setattr(_hardening.sys, "platform", "linux")
    monkeypatch.setenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", "1")
    monkeypatch.setattr(_hardening, "get_no_new_privs", lambda: 1)
    monkeypatch.setattr(_hardening, "get_dumpable", lambda: 0)
    _hardening.assert_hardening_applied()  # must not raise


def test_assert_hardening_applied_raises_when_no_new_privs_is_zero_in_docker_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """In Docker mode, LSM/seccomp filter silently no-op'd PR_SET_NO_NEW_PRIVS → refuse to bind.

    NoNewPrivs is a preexec_fn-only primitive; in Docker mode the
    parent's preexec_fn must have set it, so NNP=0 here means the
    kernel silently dropped a security primitive.  Refuse loudly.

    CR-3204010104: read via prctl(PR_GET_NO_NEW_PRIVS) (preferred over
    procfs since it's available since kernel 3.5 vs procfs's 4.10
    and works in rootless containers with partial /proc bind-mounts).
    """
    monkeypatch.setattr(_hardening.sys, "platform", "linux")
    monkeypatch.setenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", "1")
    monkeypatch.setattr(_hardening, "get_no_new_privs", lambda: 0)
    monkeypatch.setattr(_hardening, "get_dumpable", lambda: 0)

    with pytest.raises(WorthlessError) as exc_info:
        _hardening.assert_hardening_applied()
    assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
    assert "NO_NEW_PRIVS" in exc_info.value.message or "NoNewPrivs" in exc_info.value.message


def test_assert_hardening_applied_allows_no_new_privs_zero_in_bare_metal_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """In bare-metal/dev mode, NoNewPrivs=0 is expected — no preexec_fn ran.

    ``set_no_new_privs`` is invoked only inside the Docker preexec_fn
    (before exec), so the bare-metal sidecar path inherits whatever
    NNP the parent had — almost always 0.  Asserting NNP=1 here would
    refuse every legitimate bare-metal sidecar boot, which is exactly
    what was breaking the real-sidecar CI tests.  Dumpable=0 stays
    mandatory because ``set_dumpable_zero`` IS called inline in
    ``__main__.main()`` on every path.
    """
    monkeypatch.setattr(_hardening.sys, "platform", "linux")
    monkeypatch.delenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", raising=False)
    monkeypatch.setattr(_hardening, "get_dumpable", lambda: 0)

    _hardening.assert_hardening_applied()  # must not raise


def test_assert_hardening_applied_raises_when_dumpable_is_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dumpable=1 means core dumps + cross-process ptrace are possible.

    Read via ``prctl(PR_GET_DUMPABLE)`` (portable across kernels — the
    procfs ``Dumpable:`` field is missing on Linux 6.9.12+).
    """
    monkeypatch.setattr(_hardening.sys, "platform", "linux")
    monkeypatch.delenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", raising=False)
    monkeypatch.setattr(_hardening, "get_dumpable", lambda: 1)

    with pytest.raises(WorthlessError) as exc_info:
        _hardening.assert_hardening_applied()
    assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
    assert "PR_GET_DUMPABLE" in exc_info.value.message


def test_assert_hardening_applied_raises_when_get_dumpable_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """libc unreachable / prctl failed → fail loud, not open.

    A None from get_dumpable means we cannot verify the kernel's view
    of the dumpable bit. This is a security check; best-effort skip
    would let a misconfigured sidecar ship with Dumpable=1 silently.
    """
    monkeypatch.setattr(_hardening.sys, "platform", "linux")
    monkeypatch.delenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", raising=False)
    monkeypatch.setattr(_hardening, "get_dumpable", lambda: None)

    with pytest.raises(WorthlessError) as exc_info:
        _hardening.assert_hardening_applied()
    assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
    assert "PR_GET_DUMPABLE" in exc_info.value.message


def test_assert_hardening_applied_raises_when_procfs_unreadable_and_prctl_indeterminate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Docker mode + prctl unreachable + /proc bind-mounted out → fail loud.

    CR-3204010104: prctl is the primary source of truth for NNP; we
    only fall back to procfs if get_no_new_privs() returns None
    (libc unreachable).  This test pins the failure path: BOTH
    sources unavailable → WorthlessError.  In normal Docker
    deployments prctl is always reachable (libc.so.6 is present);
    this models the pathological "rootless + distroless without libc"
    edge case where we must still fail loud.
    """
    monkeypatch.setattr(_hardening.sys, "platform", "linux")
    monkeypatch.setenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", "1")
    monkeypatch.setattr(_hardening, "get_no_new_privs", lambda: None)  # libc missing
    nonexistent = tmp_path / "does-not-exist"
    monkeypatch.setattr("worthless.sidecar._hardening.Path", lambda p: nonexistent)
    monkeypatch.setattr(_hardening, "get_dumpable", lambda: 0)

    with pytest.raises(WorthlessError) as exc_info:
        _hardening.assert_hardening_applied()
    assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
    assert "could not read" in exc_info.value.message


def test_assert_hardening_applied_is_noop_on_non_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mac dev path: /proc doesn't exist; the check is a no-op."""
    monkeypatch.setattr(_hardening.sys, "platform", "darwin")
    sentinel = MagicMock(side_effect=AssertionError("get_dumpable must not run on non-Linux"))
    monkeypatch.setattr(_hardening, "get_dumpable", sentinel)
    _hardening.assert_hardening_applied()  # must not raise


def test_main_invokes_assert_hardening_applied_after_other_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``__main__.main()`` must call assert_hardening_applied AFTER the other two.

    Order: set_dumpable_zero → check_yama → assert_hardening_applied.
    The assertion is the LAST hardening step so it can verify everything
    the prior steps requested actually took effect.
    """
    from worthless.sidecar import __main__ as sidecar_main

    calls: list[str] = []

    monkeypatch.setattr(_hardening, "set_dumpable_zero", lambda: calls.append("dump"))
    monkeypatch.setattr(_hardening, "check_yama_ptrace_scope", lambda: calls.append("yama"))
    monkeypatch.setattr(_hardening, "assert_hardening_applied", lambda: calls.append("assert"))

    async def fake_run() -> int:
        calls.append("_run")
        return 0

    monkeypatch.setattr(sidecar_main, "_run", fake_run)
    monkeypatch.delenv("WORTHLESS_LOG_LEVEL", raising=False)

    rc = sidecar_main.main()
    assert rc == 0
    assert calls == ["dump", "yama", "assert", "_run"], (
        f"WOR-310 C2f2: hardening order broken; got {calls}"
    )


# ---------------------------------------------------------------------------
# C2f3 — Distinctness validation: proxy_uid != crypto_uid (brutus #6)
# ---------------------------------------------------------------------------


def test_spawn_sidecar_rejects_when_proxy_uid_equals_crypto_uid(
    _share_files: ShareFiles,
) -> None:
    """If proxy_uid == crypto_uid the uid-wall claim collapses.

    Same-uid ptrace and same-uid kill() are kernel-allowed; both
    processes can read each other's memory and signal each other.
    Validating distinctness at the spawn boundary catches a future
    Dockerfile drift OR a shadowed /etc/passwd that resolves both
    names to the same uid.
    """
    import uuid

    socket_path = Path(f"/tmp/wor310-c2f3-{uuid.uuid4().hex[:8]}.sock")  # noqa: S108
    same_uids = ServiceUids(proxy_uid=10001, crypto_uid=10001, worthless_gid=10001)
    with pytest.raises(WorthlessError) as exc_info:
        spawn_sidecar(
            socket_path=socket_path,
            shares=_share_files,
            allowed_uid=10001,
            service_uids=same_uids,
        )
    assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
    assert "distinct uids" in exc_info.value.message


def test_spawn_sidecar_lstats_socket_after_ready_and_rejects_symlink(
    _share_files: ShareFiles, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Post-ready ``lstat`` rejects a non-socket inode at the rendezvous path.

    Brutus C2f Q8: defense-in-depth against a future symlink-redirect
    where a same-group attacker swaps the socket between bind and the
    proxy's first connect. The TOCTOU window is simulated by having
    ``_wait_for_ready`` (mocked) plant a symlink at ``socket_path`` as
    a side effect — same shape as a real attacker who races between
    sidecar bind and parent lstat.
    """
    import uuid

    socket_path = Path(f"/tmp/wor310-c4-{uuid.uuid4().hex[:8]}.sock")  # noqa: S108
    decoy = tmp_path / "decoy.txt"
    decoy.write_text("not a socket")

    def _fake_ready_with_symlink_swap(*_a: object) -> bool:
        # Simulates an attacker swapping the inode between bind and lstat.
        socket_path.unlink(missing_ok=True)
        socket_path.symlink_to(decoy)
        return True

    monkeypatch.setattr(_sidecar_lifecycle, "_wait_for_ready", _fake_ready_with_symlink_swap)
    monkeypatch.setattr(
        _sidecar_lifecycle.subprocess,
        "Popen",
        lambda *_a, **_kw: MagicMock(pid=12345, poll=lambda: None),
    )

    try:
        with pytest.raises(WorthlessError) as exc_info:
            spawn_sidecar(
                socket_path=socket_path,
                shares=_share_files,
                allowed_uid=1000,
            )
        assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
        assert "socket" in exc_info.value.message.lower()
    finally:
        try:
            socket_path.unlink()
        except OSError:
            pass


def test_spawn_sidecar_lstat_passes_when_socket_is_real_socket(
    _share_files: ShareFiles, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Happy path: a real AF_UNIX socket at the rendezvous passes lstat.

    Counterpoint to the symlink-rejection test — proves the lstat check
    isn't accidentally raising on legitimate sockets.
    """
    import socket as socket_mod
    import uuid

    socket_path = Path(f"/tmp/wor310-c4-{uuid.uuid4().hex[:8]}.sock")  # noqa: S108

    def _fake_ready_with_real_socket(*_a: object) -> bool:
        # Real AF_UNIX socket bind so lstat sees S_ISSOCK.
        socket_path.unlink(missing_ok=True)
        sock = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
        sock.bind(str(socket_path))
        sock.close()
        return True

    monkeypatch.setattr(_sidecar_lifecycle, "_wait_for_ready", _fake_ready_with_real_socket)
    monkeypatch.setattr(
        _sidecar_lifecycle.subprocess,
        "Popen",
        lambda *_a, **_kw: MagicMock(pid=12345, poll=lambda: None),
    )

    try:
        spawn_sidecar(
            socket_path=socket_path,
            shares=_share_files,
            allowed_uid=1000,
        )  # must not raise
    finally:
        try:
            socket_path.unlink()
        except OSError:
            pass


def test_spawn_sidecar_accepts_when_proxy_and_crypto_share_gid(
    _share_files: ShareFiles,
) -> None:
    """Sharing a GID is the WHOLE POINT — they're in the worthless group together.

    Distinctness applies to UIDs only. ``worthless_gid`` IS shared
    between proxy and crypto so they can both connect to /run/worthless.
    A test that pinned ALL three to be distinct would be wrong.
    """
    import uuid

    socket_path = Path(f"/tmp/wor310-c2f3-{uuid.uuid4().hex[:8]}.sock")  # noqa: S108
    # proxy_uid == worthless_gid is fine (10001 in the production Dockerfile).
    uids = ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)
    fake_proc = MagicMock()
    fake_proc.pid = 12345
    fake_proc.poll.return_value = None

    with (
        patch.object(_sidecar_lifecycle.subprocess, "Popen", return_value=fake_proc),
        patch.object(_sidecar_lifecycle, "_wait_for_ready", return_value=True),
        patch.object(_sidecar_lifecycle, "_verify_socket_inode", lambda _p: None),
    ):
        # MUST NOT raise — gid sharing is intentional.
        spawn_sidecar(
            socket_path=socket_path,
            shares=_share_files,
            allowed_uid=10001,
            service_uids=uids,
        )
