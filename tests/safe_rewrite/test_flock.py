"""Concurrency-lock invariants via ``fcntl.flock(LOCK_EX | LOCK_NB)``.

Red-first test 5: two in-process attempts to ``safe_rewrite`` the same
target serialize — the second must refuse with ``reason=LOCKED`` while
the first is mid-flight.
"""

from __future__ import annotations

import errno
import fcntl
import os
import sys

import pytest

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.safe_rewrite import safe_rewrite


pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="flock semantics are POSIX-only",
)


def test_refuses_concurrent_lock(tmp_path, make_env_file, sha256_of) -> None:
    """If another holder has an exclusive flock on ``.env``, we refuse fast.

    We simulate a concurrent holder by opening the target and acquiring
    ``LOCK_EX | LOCK_NB`` ourselves, then calling ``safe_rewrite`` from
    the same process on a *different* fd. The function must open its
    own fd, fail to acquire the flock, and raise
    ``UnsafeRewriteRefused(reason=LOCKED)``.
    """
    env = make_env_file(tmp_path / ".env", b"OPENAI_API_KEY=sk-aaa\n")
    baseline = sha256_of(env)

    holder_fd = os.open(str(env), os.O_RDONLY)
    try:
        fcntl.flock(holder_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        with pytest.raises(UnsafeRewriteRefused) as exc_info:
            safe_rewrite(
                env,
                b"OPENAI_API_KEY=sk-bbb\n",
                original_user_arg=env,
            )

        assert exc_info.value.reason == UnsafeReason.LOCKED
        assert sha256_of(env) == baseline
    finally:
        try:
            fcntl.flock(holder_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(holder_fd)


def test_lock_nb_fails_fast_no_block(tmp_path, make_env_file) -> None:
    """A contended lock refuses in O(1); must not block on LOCK_EX without NB.

    We monkey-patch ``fcntl.flock`` to record whether ``LOCK_NB`` was
    present in the flags. The implementation must always use the
    non-blocking variant.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    recorded_flags: list[int] = []

    real_flock = fcntl.flock

    def _record(fd, flags, *a, **kw):  # noqa: ANN001, ANN003
        recorded_flags.append(flags)
        return real_flock(fd, flags, *a, **kw)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(fcntl, "flock", _record)
        try:
            safe_rewrite(env, b"KEY=new\n", original_user_arg=env)
        except Exception:
            pass

    # At least one LOCK_EX call must have included LOCK_NB.
    acquire_calls = [f for f in recorded_flags if f & fcntl.LOCK_EX]
    assert acquire_calls, "safe_rewrite never called flock(LOCK_EX)"
    assert all(f & fcntl.LOCK_NB for f in acquire_calls), (
        f"flock(LOCK_EX) missing LOCK_NB: {acquire_calls!r}"
    )


def test_lock_released_on_exception(tmp_path, make_env_file) -> None:
    """If safe_rewrite raises mid-op, the flock is released.

    We verify by attempting to re-acquire the lock ourselves after the
    refused call returns: the acquisition must succeed immediately,
    which is only possible if the implementation released its own lock.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")

    class _Boom(Exception):
        """Distinct exception type so we can detect real hook-fired failure."""

    def _boom() -> None:
        raise _Boom("fail mid-op")

    with pytest.raises((_Boom, UnsafeRewriteRefused)) as exc_info:
        safe_rewrite(
            env,
            b"KEY=new\n",
            original_user_arg=env,
            _hook_before_replace=_boom,
        )
    # Must NOT be a swallowed stub NotImplementedError.
    assert not isinstance(exc_info.value, NotImplementedError)

    # We should be able to acquire LOCK_EX | LOCK_NB now.
    fd = os.open(str(env), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Success == lock was released by safe_rewrite.
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError as e:
        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            pytest.fail("safe_rewrite leaked its flock after exception")
        raise
    finally:
        os.close(fd)


def test_lock_released_on_success(tmp_path, make_env_file) -> None:
    """After a successful rewrite, the flock is released."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")

    safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    fd = os.open(str(env), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError as e:
        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            pytest.fail("safe_rewrite leaked its flock on success")
        raise
    finally:
        os.close(fd)
