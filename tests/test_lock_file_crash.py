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
import threading
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


def _kill(child: subprocess.Popen) -> None:
    os.kill(child.pid, signal.SIGKILL)
    child.wait(timeout=10)


@pytest.fixture
def no_flock(monkeypatch):
    """A filesystem that refuses flock (NFS/SMB/FUSE): ENOLCK."""

    def _refuse(*_a: object) -> None:
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(bootstrap._fcntl, "flock", _refuse)


def test_lock_left_by_a_killed_holder_is_taken_at_once(tmp_path: Path) -> None:
    home = ensure_home(base_dir=tmp_path / ".worthless")
    child = _hold_lock(home.base_dir)
    _kill(child)
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
        _kill(child)


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
    _kill(child)

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
    _kill(child)
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
        _kill(child)


def test_a_filesystem_without_flock_keeps_working(tmp_path: Path, no_flock) -> None:
    """NFS/SMB/FUSE can refuse flock (ENOLCK): fall back to the 5-minute rule."""
    home = ensure_home(base_dir=tmp_path / ".worthless")
    with acquire_lock(home):
        with pytest.raises(WorthlessError) as exc:
            with acquire_lock(home):
                pass  # pragma: no cover
        assert exc.value.code.value == 105
    assert not home.lock_file.exists()


def test_no_flock_still_reclaims_an_old_lock(tmp_path: Path, no_flock) -> None:
    """The fallback is the full 5-minute rule: old files go, not only fresh ones block."""
    home = ensure_home(base_dir=tmp_path / ".worthless")
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


def _age(path: Path, seconds: float) -> None:
    old = time.time() - seconds
    os.utime(path, (old, old))


def test_another_users_lock_file_never_crashes(tmp_path: Path, monkeypatch) -> None:
    """Security: root's lock in a proxy-owned Docker volume can't be opened by us."""
    home = ensure_home(base_dir=tmp_path / ".worthless")
    home.lock_file.write_text("otherhost 1\n")
    real_open = os.open

    def _denied(path, flags, *a, **k):  # noqa: ANN001, ANN002, ANN003
        if Path(path) == home.lock_file and not flags & os.O_CREAT:
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(bootstrap.os, "open", _denied)
    with pytest.raises(WorthlessError) as exc:
        bootstrap.check_stale_lock(home)
    assert exc.value.code.value == 105  # was: a raw PermissionError, forever
    _age(home.lock_file, 400)
    bootstrap.check_stale_lock(home)  # old: the 5-minute rule still heals it
    assert not home.lock_file.exists()


def test_a_lock_from_another_host_keeps_the_5_minute_rule(tmp_path: Path) -> None:
    """Chaos: a shared mount whose flock is local-only must never look 'dead'."""
    home = ensure_home(base_dir=tmp_path / ".worthless")
    child = _hold_lock(home.base_dir)
    _kill(child)
    home.lock_file.write_text("some-other-host 4242\n")  # written over there

    with pytest.raises(WorthlessError) as exc:
        with acquire_lock(home):
            pass  # pragma: no cover
    assert exc.value.code.value == 105
    _age(home.lock_file, 400)
    with acquire_lock(home):
        pass


def _finishes(fn, seconds: float = 8) -> BaseException | None:  # noqa: ANN001
    """Run *fn* in a thread; fail the test if it is still running after *seconds*."""
    box: list[BaseException | None] = [None]

    def _run() -> None:
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001
            box[0] = exc

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(seconds)
    assert not t.is_alive(), f"{fn.__name__} hung"
    return box[0]


def test_a_fifo_at_the_lock_path_never_hangs(tmp_path: Path) -> None:
    home = ensure_home(base_dir=tmp_path / ".worthless")
    os.mkfifo(home.lock_file)

    def check() -> None:
        bootstrap.check_stale_lock(home)

    exc = _finishes(check)
    assert isinstance(exc, WorthlessError)
    assert exc.code.value == 105


def test_the_holder_never_waits_forever_for_its_own_flock(tmp_path: Path, monkeypatch) -> None:
    """A reclaimer stopped while holding the new file's flock must not hang us."""
    home = ensure_home(base_dir=tmp_path / ".worthless")
    real_flock = bootstrap._fcntl.flock

    def _always_busy(fd, op):  # noqa: ANN001
        if op & bootstrap._fcntl.LOCK_NB:
            raise BlockingIOError(errno.EWOULDBLOCK, "busy")
        time.sleep(60)  # a blocking call never returns
        return real_flock(fd, op)

    monkeypatch.setattr(bootstrap._fcntl, "flock", _always_busy)

    def take() -> None:
        with acquire_lock(home):
            pass

    assert _finishes(take) is None


def test_worthless_doctor_runs_right_after_a_killed_holder(tmp_path: Path) -> None:
    """The user-visible promise, through the real CLI binary."""
    home = ensure_home(base_dir=tmp_path / ".worthless")
    _kill(_hold_lock(home.base_dir))
    assert home.lock_file.exists()

    env = {k: v for k, v in os.environ.items() if not k.startswith("WORTHLESS_")}
    env.update(
        HOME=str(tmp_path),
        WORTHLESS_HOME=str(home.base_dir),
        XDG_DATA_HOME=str(tmp_path / "xdg"),
        WORTHLESS_KEYRING_BACKEND="null",
    )
    result = subprocess.run(
        [str(Path(sys.executable).parent / "worthless"), "doctor"],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
    )

    out = result.stdout + result.stderr
    assert "WRTLS-105" not in out, out
    assert result.returncode == 0, out


def test_a_failed_unlink_still_releases_the_lock(tmp_path: Path, monkeypatch) -> None:
    """Cursor: an unlink error must not skip the close, or the flock stays held."""
    home = ensure_home(base_dir=tmp_path / ".worthless")
    lock = os.path.realpath(home.lock_file)
    real_unlink = Path.unlink

    def _refuse(self, *a, **k):  # noqa: ANN001, ANN002, ANN003
        if os.path.realpath(self) == lock:
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_unlink(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", _refuse)
    with pytest.raises(PermissionError):
        with acquire_lock(home):
            pass

    assert lock not in _open_paths(), "the lock's fd (and its flock) leaked"


def test_a_nested_acquire_in_the_same_process_is_refused(tmp_path: Path) -> None:
    """Cursor: flock is per open file on macOS too, so a second fd is refused.

    Pinned here because the macOS CI job runs this file, not test_bootstrap.
    """
    home = ensure_home(base_dir=tmp_path / ".worthless")
    with acquire_lock(home):
        with pytest.raises(WorthlessError) as exc:
            with acquire_lock(home):
                pass  # pragma: no cover
        assert exc.value.code.value == 105
        assert home.lock_file.exists(), "the live lock was taken over"


def test_two_threads_never_hold_the_lock_at_once(tmp_path: Path) -> None:
    home = ensure_home(base_dir=tmp_path / ".worthless")
    held, release = threading.Event(), threading.Event()

    def holder() -> None:
        with acquire_lock(home):
            held.set()
            release.wait(10)

    t = threading.Thread(target=holder, daemon=True)
    t.start()
    assert held.wait(10)
    try:
        with pytest.raises(WorthlessError) as exc:
            with acquire_lock(home):
                pass  # pragma: no cover
        assert exc.value.code.value == 105
    finally:
        release.set()
        t.join(10)


def test_the_busy_message_never_says_to_delete_the_lock(tmp_path: Path, monkeypatch) -> None:
    """WOR-965: deleting a live lock by hand lets two commands write at once.

    A dead holder's lock is reclaimed automatically (WOR-962), so there is
    never a reason to tell the user to delete it.
    """
    home = ensure_home(base_dir=tmp_path / ".worthless")
    home.lock_file.write_text("this-host 1\n")  # created by a racing command
    monkeypatch.setattr(bootstrap, "check_stale_lock", lambda _home: None)

    with pytest.raises(WorthlessError) as exc:
        with acquire_lock(home):
            pass  # pragma: no cover

    msg = exc.value.message.lower()
    assert exc.value.code.value == 105
    assert "lock-in-progress" not in msg, msg
    assert not any(w in msg for w in ("remove", "delete", "rm ")), msg
    assert "wait" in msg, msg


def test_the_5_minute_message_says_the_lock_clears_by_itself(tmp_path: Path) -> None:
    """WOR-965: a lock that can't be proven dead (empty, other host, no flock)
    waits out the 5-minute rule. Say when it clears; never suggest deleting it.
    """
    home = ensure_home(base_dir=tmp_path / ".worthless")
    home.lock_file.touch()
    _age(home.lock_file, 100)  # ~200s left

    with pytest.raises(WorthlessError) as exc:
        bootstrap.check_stale_lock(home)

    msg = exc.value.message.lower()
    assert exc.value.code.value == 105
    assert "clears by itself" in msg and "wait" in msg, msg
    assert any(f"{s}s" in msg for s in range(190, 205)), msg  # seconds left
    assert not any(w in msg for w in ("remove", "delete", "rm ")), msg
