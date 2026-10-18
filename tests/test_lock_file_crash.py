"""WOR-962: a lock held by a process that was killed never blocks the next command.

A ``kill -9`` mid-operation leaves ``.lock-in-progress`` behind. Before this
fix it blocked every locked command for 5 minutes, including the ``worthless
lock`` repair that ``status`` tells the user to run after a cut-off lock.
These tests use a real child process and a real SIGKILL.
"""

from __future__ import annotations

import errno
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

from worthless.cli import bootstrap
from worthless.cli.bootstrap import _unlink_if_same_file, acquire_lock, ensure_home
from worthless.cli.errors import WorthlessError

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")

_HOLDER = """
import sys, time
from pathlib import Path
from worthless.cli.bootstrap import WorthlessHome, acquire_lock
with acquire_lock(WorthlessHome(base_dir=Path(sys.argv[1]))):
    print("held", flush=True)
    time.sleep(60)
"""


def _hold_lock(base: Path) -> subprocess.Popen:
    child = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, str(base)],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert child.stdout is not None
    assert child.stdout.readline().strip() == "held", "holder never took the lock"
    return child


def test_lock_left_by_a_killed_holder_is_taken_at_once(tmp_path: Path) -> None:
    home = ensure_home(base_dir=tmp_path / ".worthless")
    child = _hold_lock(home.base_dir)
    os.kill(child.pid, signal.SIGKILL)
    child.wait(timeout=10)
    assert home.lock_file.exists(), "precondition: the kill left the lock file"

    with acquire_lock(home):  # was: WRTLS-105 for 5 minutes
        pass


def test_a_live_holder_is_still_respected(tmp_path: Path) -> None:
    home = ensure_home(base_dir=tmp_path / ".worthless")
    child = _hold_lock(home.base_dir)
    os.kill(child.pid, signal.SIGSTOP)  # alive, just not running
    try:
        with pytest.raises(WorthlessError) as exc:
            with acquire_lock(home):
                pass  # pragma: no cover
        assert exc.value.code.value == 105
    finally:
        os.kill(child.pid, signal.SIGKILL)
        child.wait(timeout=10)


_CONTENDER = """
import sys, time
from pathlib import Path
from worthless.cli.bootstrap import WorthlessHome, acquire_lock
from worthless.cli.errors import WorthlessError
try:
    with acquire_lock(WorthlessHome(base_dir=Path(sys.argv[1]))):
        print("won", flush=True)
        time.sleep(60)  # held until the test kills it: no timing window
except WorthlessError:
    print("busy", flush=True)
"""


def test_racers_on_a_dead_holders_lock_get_one_winner(tmp_path: Path) -> None:
    """Two processes reclaiming the same dead lock must never both win."""
    home = ensure_home(base_dir=tmp_path / ".worthless")
    child = _hold_lock(home.base_dir)
    os.kill(child.pid, signal.SIGKILL)
    child.wait(timeout=10)

    racers = [
        subprocess.Popen(
            [sys.executable, "-c", _CONTENDER, str(home.base_dir)],
            stdout=subprocess.PIPE,
            text=True,
        )
        for _ in range(6)
    ]
    try:
        results = [r.stdout.readline().strip() for r in racers]  # type: ignore[union-attr]
    finally:
        for r in racers:
            r.kill()
            r.wait(timeout=10)

    assert results.count("won") == 1, results


def test_a_late_reclaimer_never_deletes_the_new_live_lock(tmp_path: Path) -> None:
    """Forces the interleaving the racers above only hit by luck.

    B opens the dead holder's file; A reclaims it and takes a fresh lock;
    B's reclaim, through its stale handle, must leave A's lock alone.
    """
    home = ensure_home(base_dir=tmp_path / ".worthless")
    child = _hold_lock(home.base_dir)
    os.kill(child.pid, signal.SIGKILL)
    child.wait(timeout=10)
    stale_fd = os.open(home.lock_file, os.O_RDONLY)  # B, before A acts
    try:
        with acquire_lock(home):  # A reclaims and holds a new lock file
            _unlink_if_same_file(home.lock_file, stale_fd)  # B, late
            assert home.lock_file.exists(), "B deleted A's live lock"
    finally:
        os.close(stale_fd)


def test_a_live_holder_is_never_stolen_however_old(tmp_path: Path) -> None:
    """Before: any lock older than 5 minutes was taken, even from a running command."""
    home = ensure_home(base_dir=tmp_path / ".worthless")
    child = _hold_lock(home.base_dir)
    os.kill(child.pid, signal.SIGSTOP)
    old = time.time() - 400
    os.utime(home.lock_file, (old, old))
    try:
        with pytest.raises(WorthlessError) as exc:
            with acquire_lock(home):
                pass  # pragma: no cover
        assert exc.value.code.value == 105
        assert home.lock_file.exists(), "the live holder's lock was deleted"
    finally:
        os.kill(child.pid, signal.SIGKILL)
        child.wait(timeout=10)


def test_a_filesystem_without_flock_keeps_working(tmp_path: Path, monkeypatch) -> None:
    """NFS/SMB/FUSE can refuse flock (ENOLCK): fall back to the 5-minute rule."""
    home = ensure_home(base_dir=tmp_path / ".worthless")

    def _no_flock(*_a: object) -> None:
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(bootstrap._fcntl, "flock", _no_flock)
    with acquire_lock(home):
        with pytest.raises(WorthlessError) as exc:
            with acquire_lock(home):
                pass  # pragma: no cover
        assert exc.value.code.value == 105
    assert not home.lock_file.exists()


def test_no_flock_still_reclaims_an_old_lock(tmp_path: Path, monkeypatch) -> None:
    """The fallback is the full 5-minute rule: old files go, not only fresh ones block."""
    home = ensure_home(base_dir=tmp_path / ".worthless")

    def _no_flock(*_a: object) -> None:
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(bootstrap._fcntl, "flock", _no_flock)
    home.lock_file.touch()
    old = time.time() - 400
    os.utime(home.lock_file, (old, old))

    with acquire_lock(home):
        pass


def _open_paths() -> set[str]:
    return {os.path.realpath(f.path) for f in psutil.Process().open_files()}


def test_windows_never_deletes_the_lock_while_it_is_open(tmp_path: Path, monkeypatch) -> None:
    """Cursor: Windows can't unlink an open file. No fcntl means no fd held."""
    home = ensure_home(base_dir=tmp_path / ".worthless")
    monkeypatch.setattr(bootstrap, "_fcntl", None)

    with acquire_lock(home):
        assert os.path.realpath(home.lock_file) not in _open_paths()
    assert not home.lock_file.exists()


def test_windows_reclaims_an_old_lock_without_opening_it(tmp_path: Path, monkeypatch) -> None:
    home = ensure_home(base_dir=tmp_path / ".worthless")
    monkeypatch.setattr(bootstrap, "_fcntl", None)
    home.lock_file.touch()
    old = time.time() - 400
    os.utime(home.lock_file, (old, old))
    real_open = os.open
    opened: list[str] = []

    def _spy(path, *a, **k):  # noqa: ANN001, ANN002, ANN003
        opened.append(os.path.realpath(path))
        return real_open(path, *a, **k)

    monkeypatch.setattr(bootstrap.os, "open", _spy)
    bootstrap.check_stale_lock(home)

    assert not home.lock_file.exists()
    assert os.path.realpath(home.lock_file) not in opened, "opened before unlink"
