"""worthless-7qb6: a stopped proxy's run/<pid>/ folder still holding both key shares.

A proxy that exits cleanly deletes ``run/<pid>/``. One that is killed or
crashes leaves ``share_a.bin`` + ``share_b.bin`` behind, and together they
rebuild the secret. ``doctor`` must report such folders and ``--fix`` must
delete them, while never touching a folder whose process is still alive.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import ensure_home
from worthless.cli.commands import doctor as doctor_module
from worthless.cli.commands.doctor.checks import dead_proxy_run_dirs
from worthless.cli.commands.doctor.registry import CheckContext
from worthless.storage.repository import ShardRepository

runner = CliRunner()


@pytest.fixture
def fake_home(tmp_path: Path):
    return ensure_home(tmp_path / ".worthless")


@pytest.fixture
def ctx(fake_home):
    repo = ShardRepository(str(fake_home.db_path), bytes(fake_home.fernet_key))
    return CheckContext(home=fake_home, repo=repo, fix=False, dry_run=False)


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def _run_dir(home, pid: int) -> Path:
    run_dir = home.base_dir / "run" / str(pid)
    run_dir.mkdir(parents=True, mode=0o700)
    (run_dir / "share_a.bin").write_bytes(b"a" * 44)
    (run_dir / "share_b.bin").write_bytes(b"b" * 44)
    return run_dir


def test_no_run_folder_is_ok(ctx) -> None:
    result = dead_proxy_run_dirs.run(ctx)
    assert result["status"] == "ok"
    assert result["findings"] == []


def test_a_stopped_proxys_folder_is_reported(ctx, fake_home) -> None:
    pid = _dead_pid()
    stale = _run_dir(fake_home, pid)

    result = dead_proxy_run_dirs.run(ctx)

    assert result["status"] == "warn"
    assert result["findings"] == [{"run_dir": str(stale), "pid": pid}]


def test_a_running_processs_folder_is_left_alone(ctx, fake_home) -> None:
    live = _run_dir(fake_home, os.getpid())
    (fake_home.base_dir / "run" / "not-a-pid").mkdir()

    ctx.fix = True
    result = dead_proxy_run_dirs.run(ctx)

    assert result["findings"] == []
    assert live.exists()


def test_fix_deletes_only_the_stopped_proxys_folder(ctx, fake_home) -> None:
    stale = _run_dir(fake_home, _dead_pid())
    live = _run_dir(fake_home, os.getpid())

    ctx.fix = True
    result = dead_proxy_run_dirs.run(ctx)

    assert not stale.exists()
    assert live.exists()
    assert result["status"] == "ok"
    assert result["fixed"] == [{"run_dir": str(stale)}]


def test_dry_run_deletes_nothing(ctx, fake_home) -> None:
    stale = _run_dir(fake_home, _dead_pid())

    ctx.fix = True
    ctx.dry_run = True
    dead_proxy_run_dirs.run(ctx)

    assert stale.exists()


def test_a_folder_whose_sidecar_still_answers_is_left_alone(ctx, fake_home, monkeypatch) -> None:
    # `worthless up` kill -9'd: its PID is dead, but the sidecar + proxy it
    # spawned keep serving from this folder (brutus repro on PR 699).
    stale = _run_dir(fake_home, _dead_pid())
    monkeypatch.setattr(
        dead_proxy_run_dirs, "probe_socket", lambda path, **kw: path == stale / "sidecar.sock"
    )

    ctx.fix = True
    result = dead_proxy_run_dirs.run(ctx)

    assert result["findings"] == []
    assert stale.exists()


def test_a_pid_1_folder_is_never_treated_as_dead(ctx, fake_home) -> None:
    # `wrap` as a container's PID 1 writes run/1/; check_pid() says False for
    # PID <= 1 by design (never signal init), which must not read as "dead".
    init_dir = _run_dir(fake_home, 1)

    ctx.fix = True
    result = dead_proxy_run_dirs.run(ctx)

    assert result["findings"] == []
    assert init_dir.exists()


def test_probing_a_crash_leftover_socket_prints_nothing(capsys) -> None:
    # A crash leaves a sidecar.sock nobody listens on; the health probe
    # behind the check writes "health: ..." to stderr when it fails.
    # Short home: AF_UNIX paths are capped at 104 bytes on macOS.
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="wl") as short:
        home = ensure_home(Path(short) / "h")
        stale = _run_dir(home, _dead_pid())
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(stale / "sidecar.sock"))
        sock.close()
        repo = ShardRepository(str(home.db_path), bytes(home.fernet_key))
        ctx = CheckContext(home=home, repo=repo, fix=False, dry_run=False)

        result = dead_proxy_run_dirs.run(ctx)

        assert result["findings"] == [{"run_dir": str(stale), "pid": int(stale.name)}]
        assert "health:" not in capsys.readouterr().err


def _record_running_proxy(home) -> None:
    (home.base_dir / "proxy.pid").write_text(f"{os.getpid()}\n8787\n")


def test_nothing_is_deleted_while_a_proxy_is_running(ctx, fake_home) -> None:
    # A running proxy may use a fallback socket outside run/, so its folder
    # can't be told apart from a dead one: report, but never delete.
    stale = _run_dir(fake_home, _dead_pid())
    _record_running_proxy(fake_home)

    ctx.fix = True
    result = dead_proxy_run_dirs.run(ctx)

    assert stale.exists()
    assert result["findings"] == [{"run_dir": str(stale), "pid": int(stale.name)}]
    assert result["fixed"] == []
    assert "worthless down" in result["skipped_reason"]


def test_plain_doctor_says_stop_the_proxy_first(monkeypatch, fake_home) -> None:
    _quiet_other_checks(monkeypatch, fake_home)
    stale = _run_dir(fake_home, _dead_pid())
    _record_running_proxy(fake_home)

    result = runner.invoke(app, ["doctor", "--fix", "--yes"])
    flat = "".join(result.output.split())

    assert stale.exists(), result.output
    assert "worthlessdown" in flat, result.output


def test_delete_rechecks_and_skips_a_folder_that_is_alive_again(fake_home) -> None:
    live = _run_dir(fake_home, os.getpid())

    assert dead_proxy_run_dirs.remove_run_dirs(fake_home, [live]) == []
    assert live.exists()


def _quiet_other_checks(monkeypatch, fake_home) -> None:
    async def _no_orphans(_repo):
        return [], []

    monkeypatch.setattr(doctor_module, "get_home", lambda: fake_home)
    monkeypatch.setattr(doctor_module, "_list_orphans", _no_orphans)
    monkeypatch.setattr(doctor_module, "_list_synced_keychain_entries", lambda: [])
    monkeypatch.setattr(doctor_module, "_check_openclaw_section", lambda *a, **kw: False)
    monkeypatch.setattr(doctor_module, "_check_home_mismatch", lambda *a, **kw: False)
    monkeypatch.setattr(doctor_module, "_check_alias_not_in_db", lambda *a, **kw: False)


def test_plain_doctor_names_the_folder_instead_of_no_issues(monkeypatch, fake_home) -> None:
    _quiet_other_checks(monkeypatch, fake_home)
    stale = _run_dir(fake_home, _dead_pid())

    result = runner.invoke(app, ["doctor"])
    flat = "".join(result.output.split())

    assert "No issues found" not in result.output, result.output
    assert str(stale) in flat, result.output
    assert "worthlessdoctor--fix" in flat, result.output
    assert stale.exists()


def test_doctor_fix_yes_deletes_the_folder(monkeypatch, fake_home) -> None:
    _quiet_other_checks(monkeypatch, fake_home)
    stale = _run_dir(fake_home, _dead_pid())

    result = runner.invoke(app, ["doctor", "--fix", "--yes"])

    assert result.exit_code == 0, result.output
    assert not stale.exists(), result.output
