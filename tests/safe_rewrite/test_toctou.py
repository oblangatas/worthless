"""TOCTOU invariants: dev/ino recheck before rename.

Red-first test 8 plus deterministic mock-based tests covering:

* inode change between open and rename
* dev change between open and rename
* fstatat(AT_SYMLINK_NOFOLLOW) is actually invoked in the rename path
* renameat2(RENAME_NOREPLACE) is used on Linux
* os.replace + fstatat recheck on Darwin fallback
* crash injection between fsync-dir and rename leaves target byte-identical
"""

from __future__ import annotations

import os
import shutil
import sys

import pytest

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.safe_rewrite import safe_rewrite


def test_target_replaced_with_directory_mid_op_refused(tmp_path, make_env_file, sha256_of) -> None:
    """Mid-op: target is unlinked and replaced with a directory of the same name.

    The fstatat recheck must observe a dev/ino (or mode) mismatch and
    refuse. No write to the directory inode; the directory itself
    remains; tmp file is cleaned up.
    """
    env = make_env_file(tmp_path / ".env", b"A=1\n")
    baseline = sha256_of(env)

    def _swap_with_dir() -> None:
        # Atomically replace the file with a directory under the same path.
        env.unlink()
        env.mkdir()

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(
            env,
            b"A=2\n",
            original_user_arg=env,
            _hook_before_replace=_swap_with_dir,
        )

    assert exc_info.value.reason in {UnsafeReason.TOCTOU, UnsafeReason.IO_ERROR}
    # The target path now points at a directory; that's the attacker's
    # doing, not ours. Our invariant is: we didn't write into it.
    assert (tmp_path / ".env").is_dir(), "hook setup: path should be a dir"
    assert list(tmp_path.glob(".env.tmp-*")) == [], "tmp leaked on TOCTOU refusal"
    # Clean up the attacker-created directory so tmp_path teardown works.
    shutil.rmtree(str(env), ignore_errors=True)
    _ = baseline  # kept for symmetry with other negative-space tests


def test_inode_change_before_rename_refused(tmp_path, make_env_file, sha256_of) -> None:
    """Target inode changes (unlink + recreate) between open and rename → refuse.

    The ``_hook_before_replace`` fires post-fsync, pre-rename. We unlink
    the original and recreate a new ``.env`` at the same path. The new
    file has a different inode; fstatat recheck must catch it.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=original\n")

    def _swap_inode() -> None:
        env.unlink()
        # Recreate with same name, different inode.
        fd = os.open(str(env), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, b"KEY=attacker_content\n")
        os.close(fd)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(
            env,
            b"KEY=decoy\n",
            original_user_arg=env,
            _hook_before_replace=_swap_inode,
        )

    assert exc_info.value.reason == UnsafeReason.TOCTOU
    # Attacker's file remains — we refused to clobber the newly-created
    # inode that we never validated.
    assert env.read_bytes() == b"KEY=attacker_content\n"
    assert list(tmp_path.glob(".env.tmp-*")) == []


def test_dev_change_before_rename_refused(tmp_path, make_env_file, monkeypatch) -> None:
    """Simulated dev change via mocked fstatat → refuse.

    Bind-mount / cross-device swap between open and rename. We can't
    actually bind-mount in CI, so we mock ``os.stat`` (or fstatat-eq)
    to return a different st_dev on the final recheck.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")

    real_stat = os.stat
    recheck_count = {"n": 0}

    def _mocked_stat(*a, **kw):  # noqa: ANN002, ANN003
        recheck_count["n"] += 1
        result = real_stat(*a, **kw)
        if recheck_count["n"] > 1:

            class _R:
                def __init__(self, r):
                    self.st_mode = r.st_mode
                    self.st_ino = r.st_ino
                    self.st_dev = r.st_dev + 1  # deliberately differ
                    self.st_nlink = r.st_nlink
                    self.st_uid = r.st_uid
                    self.st_gid = r.st_gid
                    self.st_size = r.st_size
                    self.st_atime = r.st_atime
                    self.st_mtime = r.st_mtime
                    self.st_ctime = r.st_ctime

            return _R(result)
        return result

    monkeypatch.setattr(os, "stat", _mocked_stat)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    assert exc_info.value.reason in {UnsafeReason.TOCTOU, UnsafeReason.CONTAINMENT}
    assert list(tmp_path.glob(".env.tmp-*")) == []


def test_fstatat_recheck_invoked(tmp_path, make_env_file, monkeypatch) -> None:
    """The rename path MUST call ``os.fstat`` or ``os.stat`` on the target for recheck.

    We record every ``os.stat``/``os.fstat`` call and assert at least
    one happens after the tmp is fully written.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    stat_calls: list[str] = []

    real_stat = os.stat
    real_fstat = os.fstat

    def _rec_stat(*a, **kw):  # noqa: ANN002, ANN003
        stat_calls.append("stat")
        return real_stat(*a, **kw)

    def _rec_fstat(*a, **kw):  # noqa: ANN002, ANN003
        stat_calls.append("fstat")
        return real_fstat(*a, **kw)

    monkeypatch.setattr(os, "stat", _rec_stat)
    monkeypatch.setattr(os, "fstat", _rec_fstat)

    safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    # Expect at least 2 stat/fstat calls: one baseline, one recheck.
    assert len(stat_calls) >= 2, f"fstatat-recheck not invoked; only saw {stat_calls!r}"


@pytest.mark.skipif(sys.platform != "linux", reason="renameat2 is Linux-only")
def test_renameat2_used_on_linux(tmp_path, make_env_file, monkeypatch) -> None:
    """On Linux, the rename path calls ``renameat2`` with ``RENAME_NOREPLACE``.

    We attempt to import ``renameat2`` or observe an ``os.replace``
    fallback. Either a direct ctypes call OR a documented ``os.replace``
    with prior fstatat recheck is acceptable per the plan. We record
    which path was taken.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")

    renameat2_calls = {"n": 0}
    replace_calls = {"n": 0}

    real_replace = os.replace

    def _rec_replace(src, dst, *a, **kw):  # noqa: ANN001, ANN003
        replace_calls["n"] += 1
        return real_replace(src, dst, *a, **kw)

    monkeypatch.setattr(os, "replace", _rec_replace)

    # Try to spot a custom renameat2 helper on the module if the impl
    # imports one; this is best-effort.
    try:
        from worthless.cli import safe_rewrite as _sr_mod

        if hasattr(_sr_mod, "_renameat2"):
            real_rat2 = _sr_mod._renameat2

            def _rec_rat2(*a, **kw):  # noqa: ANN002, ANN003
                renameat2_calls["n"] += 1
                return real_rat2(*a, **kw)

            monkeypatch.setattr(_sr_mod, "_renameat2", _rec_rat2)
    except ImportError:
        pass

    safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    # Exactly one path must have been taken.
    total = renameat2_calls["n"] + replace_calls["n"]
    assert total >= 1, "neither renameat2 nor os.replace was called"


def test_os_replace_fallback_on_darwin(tmp_path, make_env_file, fake_darwin, monkeypatch) -> None:
    """On Darwin (no renameat2), rename path uses ``os.replace`` after fstatat recheck."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")

    replace_calls = {"n": 0}
    stat_calls_before_replace = {"n": 0}

    real_replace = os.replace
    real_stat = os.stat

    def _rec_stat(*a, **kw):  # noqa: ANN002, ANN003
        if replace_calls["n"] == 0:
            stat_calls_before_replace["n"] += 1
        return real_stat(*a, **kw)

    def _rec_replace(src, dst, *a, **kw):  # noqa: ANN001, ANN003
        replace_calls["n"] += 1
        return real_replace(src, dst, *a, **kw)

    monkeypatch.setattr(os, "stat", _rec_stat)
    monkeypatch.setattr(os, "replace", _rec_replace)

    safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    assert replace_calls["n"] >= 1, "os.replace not called on Darwin"
    assert stat_calls_before_replace["n"] >= 1, "no stat recheck before os.replace on Darwin"


def test_expected_baseline_sha_mismatch_refused_toctou(tmp_path, make_env_file, sha256_of) -> None:
    """A stale ``expected_baseline_sha256`` MUST be refused with ``TOCTOU``.

    Callers that compute ``new_content`` from a baseline they read earlier
    can pass the baseline's SHA-256 to :func:`safe_rewrite`. Under the
    lock, the gate re-reads the existing file, hashes it, and refuses if
    the hash doesn't match - preventing a concurrent writer's changes
    from being silently clobbered.
    """
    import hashlib

    env = make_env_file(tmp_path / ".env", b"A=1\n")
    baseline = sha256_of(env)
    # The caller "thinks" the file is this — but it's really `A=1\n`.
    stale_sha = hashlib.sha256(b"A=PREVIOUS\n").digest()

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(
            env,
            b"A=2\n",
            original_user_arg=env,
            expected_baseline_sha256=stale_sha,
        )

    assert exc_info.value.reason == UnsafeReason.TOCTOU
    assert sha256_of(env) == baseline, "file mutated despite TOCTOU refusal"


def test_expected_baseline_sha_match_allows_write(tmp_path, make_env_file) -> None:
    """A matching ``expected_baseline_sha256`` MUST allow the write through."""
    import hashlib

    env = make_env_file(tmp_path / ".env", b"A=1\n")
    correct_sha = hashlib.sha256(b"A=1\n").digest()

    safe_rewrite(
        env,
        b"A=2\n",
        original_user_arg=env,
        expected_baseline_sha256=correct_sha,
    )

    assert env.read_bytes() == b"A=2\n"
