"""Pin the SR-02 (zero key material) contract for ``deploy/start.py``.

``deploy/start.py`` is the single-container Docker entrypoint. It:
    1. reads the fernet key from disk,
    2. ``split_to_tmpfs`` to disk-backed shares,
    3. ``spawn_sidecar``,
    4. ``os.execvp`` to replace itself with uvicorn.

Between steps 1 and 4 the process holds plaintext key material in memory.
SR-02 requires that the bytes be zeroed before the process replaces itself.
``up.py`` has equivalent coverage in ``test_up_with_sidecar.py``; this is
``deploy/start.py``'s parity test.

Regression target: the cleanup commit (24f6e4c) added the zero_buf calls to
match up.py. Without these tests, anyone removing them would only be caught
by reading the diff.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_START = REPO_ROOT / "deploy" / "start.py"


@pytest.fixture
def deploy_start_module():
    """Import ``deploy/start.py`` as a module without invoking ``main()``."""
    spec = importlib.util.spec_from_file_location("_deploy_start_under_test", DEPLOY_START)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_deploy_start_under_test"] = mod
    spec.loader.exec_module(mod)
    yield mod
    sys.modules.pop("_deploy_start_under_test", None)


@pytest.fixture(autouse=True)
def _pin_single_threaded_entry(deploy_start_module, monkeypatch: pytest.MonkeyPatch):
    """Pin ``threading.active_count() -> 1`` for every test in this module.

    These tests mock ``spawn_sidecar`` — no real fork ever happens, so the
    BPO-34394 single-threaded-entry guard in ``main()`` is moot here. But
    under pytest-xdist the worker process carries background threads (incl.
    leaked ``worthless-run_sync`` workers from ``test_async.py``), which would
    trip the guard and fail these unrelated tests nondeterministically by
    scheduling order. Pinning the count to 1 makes them order-independent.

    The dedicated guard test re-patches ``active_count`` to >1 in its own body
    (which runs after this autouse fixture), so guard coverage is preserved.
    """
    monkeypatch.setattr(deploy_start_module.threading, "active_count", lambda: 1)


def _make_fake_shares(shard_a_seed: bytes, shard_b_seed: bytes) -> MagicMock:
    """Build a ShareFiles-shaped mock with mutable bytearray shards."""
    return MagicMock(
        shard_a=bytearray(shard_a_seed),
        shard_b=bytearray(shard_b_seed),
        run_dir=Path("/tmp/wor-test-deploy-start"),  # noqa: S108
        share_a_path=Path("/tmp/wor-test-deploy-start/share_a.bin"),  # noqa: S108
        share_b_path=Path("/tmp/wor-test-deploy-start/share_b.bin"),  # noqa: S108
    )


class TestDeployStartZeroizesOnSuccess:
    """Happy path: split + spawn succeed; both fernet bytes and shard bytes
    must be zeroed before ``os.execvp`` replaces the process.

    If ``os.execvp`` ran for real these assertions would never execute —
    that's the point: we mock ``execvp`` to a no-op so we can inspect memory
    state at the moment of process replacement.
    """

    def test_fernet_key_zeroed_after_split(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_fernet = bytearray(b"FERNET-PLAINTEXT-KEY-30-BYTES!")
        fake_shares = _make_fake_shares(b"shardA-data", b"shardB-data")
        fake_home = MagicMock(
            fernet_key=fake_fernet,
            base_dir=Path("/tmp/wor-test-home"),  # noqa: S108
        )

        monkeypatch.setattr(deploy_start_module, "ensure_home", lambda _: fake_home)
        monkeypatch.setattr(deploy_start_module, "split_to_tmpfs", lambda _k, _h: fake_shares)
        monkeypatch.setattr(deploy_start_module, "spawn_sidecar", lambda *_a, **_kw: MagicMock())
        monkeypatch.setattr(deploy_start_module.os, "execvp", lambda *_a: None)

        deploy_start_module.main()

        assert fake_fernet == bytearray(len(fake_fernet)), (
            f"SR-02 violation: fernet key bytes not zeroed, got {bytes(fake_fernet)!r}"
        )

    def test_sidecar_socket_env_set_before_execvp(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The exec'd uvicorn process MUST see WORTHLESS_SIDECAR_SOCKET in
        its environment, otherwise the proxy can't find its IPC peer and
        refuses to bind. This is the deploy-side analogue of the wrap bug
        that became worthless-r67t."""
        fake_shares = _make_fake_shares(b"a" * 8, b"b" * 8)
        fake_home = MagicMock(
            fernet_key=bytearray(b"x" * 32),
            base_dir=Path("/tmp/wor-test-home"),  # noqa: S108
        )

        env_at_execvp: dict = {}

        def _capture_env_at_execvp(*_a):
            # Snapshot at exec time — that's the env the new process inherits.
            env_at_execvp.update(os.environ)

        monkeypatch.setattr(deploy_start_module, "ensure_home", lambda _: fake_home)
        monkeypatch.setattr(deploy_start_module, "split_to_tmpfs", lambda _k, _h: fake_shares)
        monkeypatch.setattr(deploy_start_module, "spawn_sidecar", lambda *_a, **_kw: MagicMock())
        monkeypatch.setattr(deploy_start_module.os, "execvp", _capture_env_at_execvp)

        deploy_start_module.main()

        assert "WORTHLESS_SIDECAR_SOCKET" in env_at_execvp, (
            "exec'd uvicorn missing WORTHLESS_SIDECAR_SOCKET — proxy can't "
            "find IPC peer, will refuse to bind. Same bug class as worthless-r67t."
        )
        assert env_at_execvp["WORTHLESS_SIDECAR_SOCKET"] == str(
            fake_shares.run_dir / "sidecar.sock"
        ), (
            f"socket path mismatch: env={env_at_execvp['WORTHLESS_SIDECAR_SOCKET']!r}, "
            f"expected={fake_shares.run_dir / 'sidecar.sock'!r}"
        )

    def test_shards_zeroed_before_execvp(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_shares = _make_fake_shares(
            b"\x11\x22\x33\x44\x55\x66\x77\x88",
            b"\x99\xaa\xbb\xcc\xdd\xee\xff\x00",
        )
        fake_home = MagicMock(
            fernet_key=bytearray(b"x" * 32),
            base_dir=Path("/tmp/wor-test-home"),  # noqa: S108
        )
        # Snapshot the bytearray identities so we can assert on the SAME objects.
        shard_a_ref = fake_shares.shard_a
        shard_b_ref = fake_shares.shard_b

        execvp_called: list[bool] = []

        def _record_execvp(*_a):
            # Critical: shards MUST already be zeroed by the time execvp runs.
            execvp_called.append(True)

        monkeypatch.setattr(deploy_start_module, "ensure_home", lambda _: fake_home)
        monkeypatch.setattr(deploy_start_module, "split_to_tmpfs", lambda _k, _h: fake_shares)
        monkeypatch.setattr(deploy_start_module, "spawn_sidecar", lambda *_a, **_kw: MagicMock())
        monkeypatch.setattr(deploy_start_module.os, "execvp", _record_execvp)

        deploy_start_module.main()

        assert execvp_called, "execvp was never reached — main() didn't complete"
        assert shard_a_ref == bytearray(len(shard_a_ref)), (
            f"SR-02: shard_a not zeroed, got {bytes(shard_a_ref)!r}"
        )
        assert shard_b_ref == bytearray(len(shard_b_ref)), (
            f"SR-02: shard_b not zeroed, got {bytes(shard_b_ref)!r}"
        )


class TestDeployStartZeroizesOnSpawnFailure:
    """Failure path: ``spawn_sidecar`` raises after ``split_to_tmpfs``
    succeeded. The cleanup branch must zero shard bytes AND remove the
    on-disk share files before re-raising.
    """

    def test_shards_zeroed_when_spawn_sidecar_raises(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        fake_shares = MagicMock(
            shard_a=bytearray(b"AAAAA"),
            shard_b=bytearray(b"BBBBB"),
            run_dir=tmp_path / "run",
            share_a_path=tmp_path / "run" / "share_a.bin",
            share_b_path=tmp_path / "run" / "share_b.bin",
        )
        (tmp_path / "run").mkdir()
        fake_shares.share_a_path.write_bytes(b"AAAAA")
        fake_shares.share_b_path.write_bytes(b"BBBBB")

        shard_a_ref = fake_shares.shard_a
        shard_b_ref = fake_shares.shard_b

        fake_home = MagicMock(fernet_key=bytearray(b"f" * 32), base_dir=tmp_path)

        def _failing_spawn(*_a, **_kw):
            raise RuntimeError("simulated sidecar spawn failure")

        monkeypatch.setattr(deploy_start_module, "ensure_home", lambda _: fake_home)
        monkeypatch.setattr(deploy_start_module, "split_to_tmpfs", lambda _k, _h: fake_shares)
        monkeypatch.setattr(deploy_start_module, "spawn_sidecar", _failing_spawn)
        # execvp must never be reached on the failure path.
        execvp_calls: list[tuple] = []
        monkeypatch.setattr(
            deploy_start_module.os,
            "execvp",
            lambda *a: execvp_calls.append(a),
        )

        with pytest.raises(RuntimeError, match="simulated sidecar spawn failure"):
            deploy_start_module.main()

        assert not execvp_calls, "execvp ran despite spawn_sidecar failure"
        assert shard_a_ref == bytearray(len(shard_a_ref)), (
            f"SR-02: shard_a not zeroed on failure path, got {bytes(shard_a_ref)!r}"
        )
        assert shard_b_ref == bytearray(len(shard_b_ref)), (
            f"SR-02: shard_b not zeroed on failure path, got {bytes(shard_b_ref)!r}"
        )
        # Disk-side cleanup: share files unlinked, run dir rmdir'd.
        assert not fake_shares.share_a_path.exists(), "share_a not unlinked"
        assert not fake_shares.share_b_path.exists(), "share_b not unlinked"
        assert not fake_shares.run_dir.exists(), "run_dir not rmdir'd"


# ---------------------------------------------------------------------------
# WOR-310 C3 — _resolve_service_uids: gateway between bare-metal and Docker
#
# bare metal (env unset, any euid)        → return None  (no drop)
# Docker (env=1) + euid==0 + uids match   → return ServiceUids
# Docker (env=1) + euid != 0              → raise (silent-degrade guard)
# Docker (env=1) + getpwnam KeyError      → raise (Dockerfile bug)
# Docker (env=1) + getpwnam returns wrong uid → raise (literal pin)
# ---------------------------------------------------------------------------


from worthless.cli.errors import ErrorCode, WorthlessError  # noqa: E402
from worthless.cli.sidecar_lifecycle import ServiceUids  # noqa: E402


def _make_pwnam_record(uid: int, gid: int) -> MagicMock:
    """Stand-in for ``pwd.struct_passwd`` with the fields ``getpwnam`` returns."""
    rec = MagicMock()
    rec.pw_uid = uid
    rec.pw_gid = gid
    return rec


class TestResolveServiceUids:
    """Pin the env-signal + euid + literal-uid gating contract."""

    def test_returns_none_when_env_unset_regardless_of_euid(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bare metal path: WORTHLESS_DOCKER_PRIVDROP_REQUIRED unset → no drop.

        Even ``sudo worthless up`` on bare-metal Linux (where euid is 0)
        must NOT attempt the drop — the entrypoint.sh sets the env var
        only inside the Docker container. Absence of the signal means
        bare-metal, no matter what euid says.
        """
        monkeypatch.delenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", raising=False)
        monkeypatch.setattr(deploy_start_module.os, "geteuid", lambda: 0)
        assert deploy_start_module._resolve_service_uids() is None

    def test_returns_none_when_env_set_to_zero(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``WORTHLESS_DOCKER_PRIVDROP_REQUIRED=0`` is treated as unset.

        Honest-bool semantics: only the literal ``"1"`` enables the drop.
        ``"0"``, ``"false"``, empty string all return None.
        """
        monkeypatch.setenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", "0")
        monkeypatch.setattr(deploy_start_module.os, "geteuid", lambda: 0)
        assert deploy_start_module._resolve_service_uids() is None

    def test_returns_uids_when_env_set_and_root(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Docker happy path: env=1, euid=0, getpwnam returns 10001/10002 → ServiceUids."""
        monkeypatch.setenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", "1")
        monkeypatch.setattr(deploy_start_module.os, "geteuid", lambda: 0)

        proxy_record = _make_pwnam_record(uid=10001, gid=10001)
        crypto_record = _make_pwnam_record(uid=10002, gid=10001)
        getpwnam = MagicMock(
            side_effect=lambda name: {
                "worthless-proxy": proxy_record,
                "worthless-crypto": crypto_record,
            }[name]
        )
        monkeypatch.setattr(deploy_start_module.pwd, "getpwnam", getpwnam)

        result = deploy_start_module._resolve_service_uids()
        assert result == ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001)

    def test_raises_when_env_set_but_not_root(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``docker run -u 10001:10001`` would silently degrade — must fail loud.

        If the entrypoint.sh set the env signal (we ARE in Docker) but
        we're somehow not euid=0, the priv-drop dance can't run and the
        security claim collapses silently. Refuse to start.
        """
        monkeypatch.setenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", "1")
        monkeypatch.setattr(deploy_start_module.os, "geteuid", lambda: 1000)

        with pytest.raises(WorthlessError) as exc_info:
            deploy_start_module._resolve_service_uids()
        assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
        assert "non-root" in exc_info.value.message or "euid" in exc_info.value.message

    def test_raises_when_user_missing(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """getpwnam KeyError = Dockerfile drift (the user wasn't created)."""
        monkeypatch.setenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", "1")
        monkeypatch.setattr(deploy_start_module.os, "geteuid", lambda: 0)
        monkeypatch.setattr(
            deploy_start_module.pwd,
            "getpwnam",
            MagicMock(side_effect=KeyError("worthless-proxy")),
        )

        with pytest.raises(WorthlessError) as exc_info:
            deploy_start_module._resolve_service_uids()
        assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
        assert "worthless-proxy" in exc_info.value.message or "missing" in exc_info.value.message

    def test_raises_when_proxy_uid_does_not_match_dockerfile_literal(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``getpwnam`` returning uid != 10001 means /etc/passwd was shadowed."""
        monkeypatch.setenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", "1")
        monkeypatch.setattr(deploy_start_module.os, "geteuid", lambda: 0)

        proxy_record = _make_pwnam_record(uid=999, gid=10001)  # WRONG uid
        crypto_record = _make_pwnam_record(uid=10002, gid=10001)
        getpwnam = MagicMock(
            side_effect=lambda name: {
                "worthless-proxy": proxy_record,
                "worthless-crypto": crypto_record,
            }[name]
        )
        monkeypatch.setattr(deploy_start_module.pwd, "getpwnam", getpwnam)

        with pytest.raises(WorthlessError) as exc_info:
            deploy_start_module._resolve_service_uids()
        assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
        assert "10001" in exc_info.value.message or "uid" in exc_info.value.message

    def test_raises_when_crypto_uid_does_not_match_dockerfile_literal(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same literal pin for crypto uid (10002)."""
        monkeypatch.setenv("WORTHLESS_DOCKER_PRIVDROP_REQUIRED", "1")
        monkeypatch.setattr(deploy_start_module.os, "geteuid", lambda: 0)

        proxy_record = _make_pwnam_record(uid=10001, gid=10001)
        crypto_record = _make_pwnam_record(uid=999, gid=10001)  # WRONG
        getpwnam = MagicMock(
            side_effect=lambda name: {
                "worthless-proxy": proxy_record,
                "worthless-crypto": crypto_record,
            }[name]
        )
        monkeypatch.setattr(deploy_start_module.pwd, "getpwnam", getpwnam)

        with pytest.raises(WorthlessError) as exc_info:
            deploy_start_module._resolve_service_uids()
        assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY


# ---------------------------------------------------------------------------
# WOR-310 C3 — main() integration: passes service_uids, drops self post-spawn
# ---------------------------------------------------------------------------


class TestMainPrivilegeDrop:
    """Pin that ``main()`` uses ServiceUids and drops self before execvp."""

    def _wire_minimal_main(self, mod, monkeypatch: pytest.MonkeyPatch) -> None:
        """Minimal mocks so main() runs to execvp without touching disk."""
        fake_home = MagicMock()
        fake_home.fernet_key = bytearray(b"k" * 44)
        fake_home.base_dir = Path("/data")
        fake_shares = _make_fake_shares(b"a" * 44, b"b" * 44)
        monkeypatch.setattr(mod, "ensure_home", lambda _: fake_home)
        monkeypatch.setattr(mod, "split_to_tmpfs", lambda _k, _h: fake_shares)
        monkeypatch.setattr(mod.os, "execvp", lambda *_a: None)
        # C4: main() chown's share files in the Docker path. Without
        # mocking, chown would hit the fake /tmp/wor-test-deploy-start path
        # and FileNotFoundError. Tests that need to OBSERVE chown override
        # this in-place; the default no-op preserves backward compatibility
        # for C3-era tests.
        monkeypatch.setattr(mod.os, "chown", lambda *_a, **_kw: None, raising=False)
        # C4 follow-up: main() also chmods the parent run_dir so the
        # forked sidecar (worthless gid) can traverse it. The test path
        # would resolve parent_run_dir to /tmp on macOS where chmod
        # raises EPERM. No-op os.chmod so tests don't actually mutate
        # filesystem permissions.
        monkeypatch.setattr(mod.os, "chmod", lambda *_a, **_kw: None, raising=False)

    def test_main_passes_service_uids_to_spawn_sidecar_when_docker(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Docker path: spawn_sidecar gets ServiceUids."""
        self._wire_minimal_main(deploy_start_module, monkeypatch)
        captured: dict[str, object] = {}

        def fake_spawn(*_a: object, **kw: object) -> MagicMock:
            captured.update(kw)
            return MagicMock()

        monkeypatch.setattr(deploy_start_module, "spawn_sidecar", fake_spawn)
        monkeypatch.setattr(
            deploy_start_module,
            "_resolve_service_uids",
            lambda: ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001),
        )
        # Mock the post-spawn priv-drop syscalls to no-ops.
        monkeypatch.setattr(
            deploy_start_module.os, "setresgid", lambda r, e, s: None, raising=False
        )
        monkeypatch.setattr(deploy_start_module.os, "setgroups", lambda g: None, raising=False)
        monkeypatch.setattr(
            deploy_start_module.os, "setresuid", lambda r, e, s: None, raising=False
        )
        monkeypatch.setattr(
            deploy_start_module.os, "getresuid", lambda: (10001, 10001, 10001), raising=False
        )
        monkeypatch.setattr(
            deploy_start_module.os, "getresgid", lambda: (10001, 10001, 10001), raising=False
        )
        monkeypatch.setattr(deploy_start_module.os, "getgroups", lambda: [], raising=False)

        deploy_start_module.main()

        assert captured.get("service_uids") == ServiceUids(10001, 10002, 10001), (
            f"WOR-310 C3: spawn_sidecar must receive service_uids; got {captured}"
        )

    def test_main_passes_service_uids_none_on_bare_metal(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bare-metal path: spawn_sidecar gets service_uids=None."""
        self._wire_minimal_main(deploy_start_module, monkeypatch)
        captured: dict[str, object] = {}

        def fake_spawn(*_a: object, **kw: object) -> MagicMock:
            captured.update(kw)
            return MagicMock()

        monkeypatch.setattr(deploy_start_module, "spawn_sidecar", fake_spawn)
        monkeypatch.setattr(deploy_start_module, "_resolve_service_uids", lambda: None)

        deploy_start_module.main()

        assert captured.get("service_uids") is None, (
            f"WOR-310 C3: bare-metal must pass service_uids=None; got {captured}"
        )

    def test_main_drops_self_to_proxy_uid_after_spawn_when_docker(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Docker path: parent process must drop to proxy_uid before execvp.

        Pinning the call sequence (setresgid → setgroups → setresuid)
        AFTER spawn returns. Mirror of the preexec_fn dance, in the
        parent process this time.
        """
        self._wire_minimal_main(deploy_start_module, monkeypatch)
        calls: list[str] = []

        monkeypatch.setattr(
            deploy_start_module,
            "spawn_sidecar",
            lambda *_a, **_kw: calls.append("spawn") or MagicMock(),
        )
        monkeypatch.setattr(
            deploy_start_module,
            "_resolve_service_uids",
            lambda: ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001),
        )
        monkeypatch.setattr(
            deploy_start_module.os,
            "setresgid",
            lambda r, e, s: calls.append(f"setresgid({r})"),
            raising=False,
        )
        monkeypatch.setattr(
            deploy_start_module.os, "setgroups", lambda g: calls.append("setgroups"), raising=False
        )
        monkeypatch.setattr(
            deploy_start_module.os,
            "setresuid",
            lambda r, e, s: calls.append(f"setresuid({r})"),
            raising=False,
        )
        monkeypatch.setattr(
            deploy_start_module.os, "getresuid", lambda: (10001, 10001, 10001), raising=False
        )
        monkeypatch.setattr(
            deploy_start_module.os, "getresgid", lambda: (10001, 10001, 10001), raising=False
        )
        monkeypatch.setattr(deploy_start_module.os, "getgroups", lambda: [], raising=False)

        deploy_start_module.main()

        # spawn first, then parent drops privs. Order: gid → groups → uid.
        spawn_idx = calls.index("spawn")
        gid_idx = calls.index("setresgid(10001)")
        groups_idx = calls.index("setgroups")
        uid_idx = calls.index("setresuid(10001)")
        assert spawn_idx < gid_idx < groups_idx < uid_idx, (
            f"WOR-310 C3: parent drop must follow spawn in order spawn→gid→groups→uid; got {calls}"
        )

    def test_main_skips_drop_on_bare_metal(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bare metal: NO setresgid/setresuid called in parent."""
        self._wire_minimal_main(deploy_start_module, monkeypatch)
        calls: list[str] = []

        monkeypatch.setattr(deploy_start_module, "spawn_sidecar", lambda *_a, **_kw: MagicMock())
        monkeypatch.setattr(deploy_start_module, "_resolve_service_uids", lambda: None)
        monkeypatch.setattr(
            deploy_start_module.os,
            "setresgid",
            lambda r, e, s: calls.append("setresgid"),
            raising=False,
        )
        monkeypatch.setattr(
            deploy_start_module.os,
            "setresuid",
            lambda r, e, s: calls.append("setresuid"),
            raising=False,
        )

        deploy_start_module.main()

        assert calls == [], f"WOR-310 C3: bare-metal must skip the parent priv-drop; got {calls}"

    def test_main_uses_getresuid_post_drop_check_not_getuid(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Post-drop verification must use ``os.getresuid()`` (3-tuple), not getuid.

        ``getuid()`` only returns real uid; saved uid could still be 0.
        ``getresuid() == (proxy, proxy, proxy)`` proves all three locked.
        """
        self._wire_minimal_main(deploy_start_module, monkeypatch)
        getresuid_calls: list[tuple[int, ...]] = []

        def fake_getresuid() -> tuple[int, int, int]:
            getresuid_calls.append((10001, 10001, 10001))
            return (10001, 10001, 10001)

        monkeypatch.setattr(deploy_start_module, "spawn_sidecar", lambda *_a, **_kw: MagicMock())
        monkeypatch.setattr(
            deploy_start_module,
            "_resolve_service_uids",
            lambda: ServiceUids(10001, 10002, 10001),
        )
        monkeypatch.setattr(
            deploy_start_module.os, "setresgid", lambda r, e, s: None, raising=False
        )
        monkeypatch.setattr(deploy_start_module.os, "setgroups", lambda g: None, raising=False)
        monkeypatch.setattr(
            deploy_start_module.os, "setresuid", lambda r, e, s: None, raising=False
        )
        monkeypatch.setattr(deploy_start_module.os, "getresuid", fake_getresuid, raising=False)
        monkeypatch.setattr(
            deploy_start_module.os, "getresgid", lambda: (10001, 10001, 10001), raising=False
        )
        monkeypatch.setattr(deploy_start_module.os, "getgroups", lambda: [], raising=False)

        deploy_start_module.main()
        assert getresuid_calls == [(10001, 10001, 10001)], (
            "WOR-310 C3: main() must call os.getresuid() exactly once post-drop"
        )

    def test_main_raises_when_post_drop_resuid_does_not_match_proxy(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If getresuid != (proxy, proxy, proxy) the drop didn't take — refuse."""
        self._wire_minimal_main(deploy_start_module, monkeypatch)

        monkeypatch.setattr(deploy_start_module, "spawn_sidecar", lambda *_a, **_kw: MagicMock())
        monkeypatch.setattr(
            deploy_start_module,
            "_resolve_service_uids",
            lambda: ServiceUids(10001, 10002, 10001),
        )
        monkeypatch.setattr(
            deploy_start_module.os, "setresgid", lambda r, e, s: None, raising=False
        )
        monkeypatch.setattr(deploy_start_module.os, "setgroups", lambda g: None, raising=False)
        monkeypatch.setattr(
            deploy_start_module.os, "setresuid", lambda r, e, s: None, raising=False
        )
        # Saved uid still root — drop didn't lock.
        monkeypatch.setattr(
            deploy_start_module.os, "getresuid", lambda: (10001, 10001, 0), raising=False
        )

        with pytest.raises(WorthlessError) as exc_info:
            deploy_start_module.main()
        assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY
        assert "drop" in exc_info.value.message.lower() or "10001" in exc_info.value.message

    def test_main_wraps_setresuid_oserror_as_worthless_error(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``OSError`` from setresuid (kernel rejection) → WorthlessError, not raw OSError.

        Without the wrap, the parent process crashes with a stack trace
        instead of a structured WRTLS-114 — which is what Docker's
        restart loop / orchestrator log will see.
        """
        self._wire_minimal_main(deploy_start_module, monkeypatch)

        monkeypatch.setattr(deploy_start_module, "spawn_sidecar", lambda *_a, **_kw: MagicMock())
        monkeypatch.setattr(
            deploy_start_module,
            "_resolve_service_uids",
            lambda: ServiceUids(10001, 10002, 10001),
        )
        monkeypatch.setattr(
            deploy_start_module.os, "setresgid", lambda r, e, s: None, raising=False
        )
        monkeypatch.setattr(deploy_start_module.os, "setgroups", lambda g: None, raising=False)

        def fake_setresuid(*_a: int) -> None:
            raise OSError(1, "Operation not permitted")

        monkeypatch.setattr(deploy_start_module.os, "setresuid", fake_setresuid, raising=False)

        with pytest.raises(WorthlessError) as exc_info:
            deploy_start_module.main()
        assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY

    def test_main_refuses_multi_threaded_before_spawn(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """BPO-34394: forking from a multi-threaded process is undefined behavior.

        ``preexec_fn`` calls glibc-allocator-using helpers (ctypes, logger)
        that can deadlock if any thread held the dynamic-linker mutex
        at fork. main() must hard-fail multi-threaded entry before spawn.

        CR-3197215771: previously this used ``assert``, which is stripped
        under ``python -O``.  Now raises ``WorthlessError(SIDECAR_NOT_READY)``
        so the invariant survives optimization.
        """
        self._wire_minimal_main(deploy_start_module, monkeypatch)

        monkeypatch.setattr(deploy_start_module, "spawn_sidecar", lambda *_a, **_kw: MagicMock())
        monkeypatch.setattr(deploy_start_module, "_resolve_service_uids", lambda: None)
        # Pretend pytest started a side thread before main().
        monkeypatch.setattr(deploy_start_module.threading, "active_count", lambda: 4)

        with pytest.raises(WorthlessError, match="single-threaded") as exc_info:
            deploy_start_module.main()
        assert exc_info.value.code == ErrorCode.SIDECAR_NOT_READY


# ---------------------------------------------------------------------------
# WOR-310 C4 — share file ownership chown + socket lstat integrity
# ---------------------------------------------------------------------------


class TestShareFileOwnership:
    """Pin that share files become readable by the crypto uid (Docker only)."""

    def _wire_minimal_main(self, mod, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_home = MagicMock()
        fake_home.fernet_key = bytearray(b"k" * 44)
        fake_home.base_dir = Path("/data")
        fake_shares = _make_fake_shares(b"a" * 44, b"b" * 44)
        monkeypatch.setattr(mod, "ensure_home", lambda _: fake_home)
        monkeypatch.setattr(mod, "split_to_tmpfs", lambda _k, _h: fake_shares)
        monkeypatch.setattr(mod, "spawn_sidecar", lambda *_a, **_kw: MagicMock())
        monkeypatch.setattr(mod.os, "execvp", lambda *_a: None)
        monkeypatch.setattr(mod.os, "setresgid", lambda r, e, s: None, raising=False)
        monkeypatch.setattr(mod.os, "setgroups", lambda g: None, raising=False)
        monkeypatch.setattr(mod.os, "setresuid", lambda r, e, s: None, raising=False)
        monkeypatch.setattr(mod.os, "getresuid", lambda: (10001, 10001, 10001), raising=False)
        # CR-3197215782: post-drop verification now also reads getresgid
        # and getgroups; mock both. macOS lacks os.getresgid (Linux-only),
        # hence raising=False.
        monkeypatch.setattr(mod.os, "getresgid", lambda: (10001, 10001, 10001), raising=False)
        monkeypatch.setattr(mod.os, "getgroups", lambda: [], raising=False)
        # main() chmods the parent run_dir so the forked sidecar (worthless
        # gid) can traverse it.  The fake shares put run_dir at /tmp/...,
        # so parent_run_dir resolves to /tmp where chmod EPERMs on macOS.
        # No-op os.chmod for the same reason os.chown is no-op'd by the
        # callers that need to OBSERVE chown calls.
        monkeypatch.setattr(mod.os, "chmod", lambda *_a, **_kw: None, raising=False)

    def test_main_chowns_share_files_to_crypto_when_docker(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Share files MUST be chown'd to crypto_uid:worthless_gid post-split.

        ``split_to_tmpfs`` creates files at 0o600 owned by root. The sidecar
        runs as crypto_uid (10002). Without chown, the sidecar gets EPERM
        opening its share. The chown happens BEFORE spawn_sidecar so the
        forked sidecar sees readable files at startup.
        """
        self._wire_minimal_main(deploy_start_module, monkeypatch)
        chown_calls: list[tuple[Path, int, int]] = []
        monkeypatch.setattr(
            deploy_start_module.os,
            "chown",
            lambda path, uid, gid: chown_calls.append((Path(path), uid, gid)),
            raising=False,
        )
        monkeypatch.setattr(
            deploy_start_module,
            "_resolve_service_uids",
            lambda: ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001),
        )

        deploy_start_module.main()

        # share_a, share_b, AND run_dir must be chown'd to crypto:worthless.
        chowned_paths = {(p, uid, gid) for p, uid, gid in chown_calls}
        share_a = Path("/tmp/wor-test-deploy-start/share_a.bin")  # noqa: S108
        share_b = Path("/tmp/wor-test-deploy-start/share_b.bin")  # noqa: S108
        run_dir = Path("/tmp/wor-test-deploy-start")  # noqa: S108
        assert (share_a, 10002, 10001) in chowned_paths, (
            f"WOR-310 C4: share_a must be chown'd to crypto:worthless; got {chown_calls}"
        )
        assert (share_b, 10002, 10001) in chowned_paths, (
            f"WOR-310 C4: share_b must be chown'd to crypto:worthless; got {chown_calls}"
        )
        assert (run_dir, 10002, 10001) in chowned_paths, (
            f"WOR-310 C4: run_dir must be chown'd to crypto:worthless; got {chown_calls}"
        )

    def test_main_skips_chown_on_bare_metal(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bare metal: NO chown attempted (would EPERM as non-root anyway)."""
        self._wire_minimal_main(deploy_start_module, monkeypatch)
        chown_calls: list[tuple[Path, int, int]] = []
        monkeypatch.setattr(
            deploy_start_module.os,
            "chown",
            lambda path, uid, gid: chown_calls.append((Path(path), uid, gid)),
            raising=False,
        )
        monkeypatch.setattr(deploy_start_module, "_resolve_service_uids", lambda: None)

        deploy_start_module.main()

        assert chown_calls == [], f"WOR-310 C4: bare-metal path must NOT chown; got {chown_calls}"

    def test_main_full_dance_when_root_pins_complete_call_sequence(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End-to-end pinning of the full Docker-root path through main().

        This is the C5 integration test — the four prior segments
        (C1 type shape, C2 preexec, C3 resolve+drop, C4 chown+lstat)
        each verified their slice in isolation. C5 walks through the
        ENTIRE main() and asserts the call sequence:

            resolve_uids → assert single-threaded → split_to_tmpfs
            → chown × 3 (run_dir, share_a, share_b) → spawn_sidecar
            → setresgid → setgroups → setresuid → getresuid → execvp

        A future refactor that moves chown after spawn_sidecar (race
        between sidecar startup and ownership), or skips the post-drop
        getresuid verification, OR forgets to call execvp — would
        be caught here and only here.
        """
        events: list[str] = []

        fake_home = MagicMock()
        fake_home.fernet_key = bytearray(b"k" * 44)
        fake_home.base_dir = Path("/data")
        fake_shares = _make_fake_shares(b"a" * 44, b"b" * 44)

        def _record(name: str, *_a: object, **_kw: object) -> object:
            events.append(name)
            return MagicMock() if name == "spawn" else None

        monkeypatch.setattr(deploy_start_module, "ensure_home", lambda _: fake_home)
        monkeypatch.setattr(
            deploy_start_module,
            "split_to_tmpfs",
            lambda _k, _h: (events.append("split_to_tmpfs"), fake_shares)[1],
        )
        monkeypatch.setattr(
            deploy_start_module,
            "_resolve_service_uids",
            lambda: (events.append("resolve_uids"), ServiceUids(10001, 10002, 10001))[1],
        )
        monkeypatch.setattr(
            deploy_start_module.os,
            "chown",
            lambda path, uid, gid: events.append(f"chown({Path(path).name},{uid},{gid})"),
            raising=False,
        )
        monkeypatch.setattr(
            deploy_start_module,
            "spawn_sidecar",
            lambda *_a, **_kw: events.append("spawn") or MagicMock(),
        )
        monkeypatch.setattr(
            deploy_start_module.os,
            "setresgid",
            lambda r, e, s: events.append(f"setresgid({r},{e},{s})"),
            raising=False,
        )
        monkeypatch.setattr(
            deploy_start_module.os,
            "setgroups",
            lambda g: events.append(f"setgroups({list(g)})"),
            raising=False,
        )
        monkeypatch.setattr(
            deploy_start_module.os,
            "setresuid",
            lambda r, e, s: events.append(f"setresuid({r},{e},{s})"),
            raising=False,
        )
        monkeypatch.setattr(
            deploy_start_module.os,
            "getresuid",
            lambda: (events.append("getresuid"), (10001, 10001, 10001))[1],
            raising=False,
        )
        monkeypatch.setattr(
            deploy_start_module.os,
            "getresgid",
            lambda: (events.append("getresgid"), (10001, 10001, 10001))[1],
            raising=False,
        )
        monkeypatch.setattr(
            deploy_start_module.os,
            "getgroups",
            lambda: (events.append("getgroups"), [])[1],
            raising=False,
        )
        monkeypatch.setattr(
            deploy_start_module.os,
            "chmod",
            lambda path, mode: events.append(f"chmod({Path(path).name},{oct(mode)})"),
            raising=False,
        )
        monkeypatch.setattr(deploy_start_module.os, "execvp", lambda *_a: events.append("execvp"))

        deploy_start_module.main()

        # Pinned sequence — any reorder catches a regression.
        # The fake shares put run_dir at /tmp/wor-test-deploy-start so its
        # parent is /tmp; that's why parent_run_dir.name renders as "tmp".
        # The fake home base_dir is /data so its name renders as "data".
        assert events == [
            "resolve_uids",
            "chmod(data,0o710)",  # home.base_dir traversable by worthless gid
            "split_to_tmpfs",
            "chown(tmp,0,10001)",  # parent run_dir → root:worthless
            "chmod(tmp,0o710)",  # parent run_dir traversable by worthless gid
            "chown(wor-test-deploy-start,10002,10001)",  # run_dir
            "chmod(wor-test-deploy-start,0o710)",  # run_dir group --x for proxy connect
            "chown(share_a.bin,10002,10001)",
            "chown(share_b.bin,10002,10001)",
            "spawn",
            "setresgid(10001,10001,10001)",
            "setgroups([])",
            "setresuid(10001,10001,10001)",
            "getresuid",
            "getresgid",  # CR-3197215782 — verify saved-gid locked
            "getgroups",  # CR-3197215782 — verify supplementary groups cleared
            "execvp",
        ], f"WOR-310 C5: full main() sequence broken; got {events}"

    def test_main_chowns_before_spawn_sidecar(
        self, deploy_start_module, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Order: chown(shares) → spawn_sidecar → parent drop.

        chown MUST happen before spawn so the forked sidecar sees readable
        files at exec time. If we chowned AFTER spawn, the sidecar would
        race the parent's chown and the open() would EPERM.
        """
        self._wire_minimal_main(deploy_start_module, monkeypatch)
        events: list[str] = []
        monkeypatch.setattr(
            deploy_start_module.os,
            "chown",
            lambda path, uid, gid: events.append(f"chown({Path(path).name})"),
            raising=False,
        )
        monkeypatch.setattr(
            deploy_start_module,
            "spawn_sidecar",
            lambda *_a, **_kw: events.append("spawn") or MagicMock(),
        )
        monkeypatch.setattr(
            deploy_start_module,
            "_resolve_service_uids",
            lambda: ServiceUids(proxy_uid=10001, crypto_uid=10002, worthless_gid=10001),
        )

        deploy_start_module.main()

        # All chowns must precede spawn.
        spawn_idx = events.index("spawn")
        chown_indices = [i for i, e in enumerate(events) if e.startswith("chown")]
        assert chown_indices, "no chown calls observed"
        assert max(chown_indices) < spawn_idx, (
            f"WOR-310 C4: every chown must precede spawn_sidecar; got {events}"
        )
