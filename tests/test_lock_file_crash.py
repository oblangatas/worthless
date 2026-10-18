"""WOR-962: a lock held by a process that was killed never blocks the next command.

A ``kill -9`` mid-operation leaves ``.lock-in-progress`` behind. Before this
fix it blocked every locked command for 5 minutes, including the ``worthless
lock`` repair that ``status`` tells the user to run after a cut-off lock.
These tests use a real child process and a real SIGKILL.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

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
        time.sleep(2)
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
    results = [r.communicate(timeout=30)[0].strip() for r in racers]

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
