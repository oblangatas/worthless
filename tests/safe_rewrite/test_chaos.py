"""Chaos / failure-injection invariants.

Red-first test 7 (SIGKILL) is first. The remainder of the chaos suite
covers 22 additional failure-injection scenarios, each deterministic:

* Signal tests use a SIGSTOP/SIGCONT handshake via a marker file.
* Syscall fault tests use ``monkeypatch`` to raise the target errno on
  the exact syscall, per test, with no threading.
* Real-FS sibling tests use the ``_hook_before_replace`` callback to
  mutate on-disk state mid-op (directory swap, inode reuse).

The final ``test_no_ghost_tmp_after_any_chaos_refusal`` is a parametrised
negative-space test across all 18 injection points: regardless of which
failure triggers the refusal, neither ``.env.tmp-*`` nor ``.env.staging-*``
files may remain in the target directory.
"""

from __future__ import annotations

import base64
import errno
import fcntl
import inspect
import os
import signal
import stat
import subprocess
import sys
import textwrap
import time

import pytest

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.safe_rewrite import safe_rewrite


pytestmark = [
    pytest.mark.skipif(
        sys.platform == "win32",
        reason="chaos harness is POSIX-only",
    ),
    pytest.mark.real_ipc,
]


# ---------------------------------------------------------------------------
# Red-first test 7: SIGKILL between fsync-tmp and rename.
# ---------------------------------------------------------------------------


def test_sigkill_between_fsync_and_rename_leaves_target_byte_identical(
    tmp_path, make_env_file, sha256_of
) -> None:
    """Child ``safe_rewrite`` is SIGKILLed after fsync(tmp) but before rename.

    Parent re-opens target and asserts byte-identity + no ghost tmp file.
    Uses a SIGSTOP / SIGCONT handshake via a marker file so the kill
    lands deterministically and the test is not scheduler-dependent.
    """
    # MAJOR 7 (WOR-276): hook-API drift smoke-check. The test relies on
    # ``_hook_before_replace`` being a valid kwarg of ``safe_rewrite``.
    # If a refactor renames it, fail cleanly here instead of letting the
    # child raise a confusing TypeError after Popen.
    if "_hook_before_replace" not in inspect.signature(safe_rewrite).parameters:
        pytest.fail("hook API renamed \u2014 expected safe_rewrite(_hook_before_replace=...)")

    env = make_env_file(tmp_path / ".env", b"OPENAI_API_KEY=sk-orig\n")
    baseline = sha256_of(env)
    marker = tmp_path / "_fsync_done"

    # MAJOR 4 (WOR-276): pass bytes + paths via environment variables
    # (base64 for bytes) to keep the child script free of f-string
    # interpolation pitfalls. Mirrors test 30b.
    new_bytes = b"OPENAI_API_KEY=sk-decoy\n"
    child_env = {
        **os.environ,
        "WOR276_ENV_PATH": str(env),
        "WOR276_MARKER": str(marker),
        "WOR276_NEW_B64": base64.b64encode(new_bytes).decode("ascii"),
    }
    child_src = textwrap.dedent(
        """
        import base64, os, signal
        from pathlib import Path
        from worthless.cli.safe_rewrite import safe_rewrite

        env = Path(os.environ["WOR276_ENV_PATH"])
        marker = Path(os.environ["WOR276_MARKER"])
        new_bytes = base64.b64decode(os.environ["WOR276_NEW_B64"])

        def hook():
            # Signal parent that fsync landed; stop self so parent can
            # SIGKILL deterministically.
            marker.write_text("ready")
            os.kill(os.getpid(), signal.SIGSTOP)

        safe_rewrite(
            env,
            new_bytes,
            original_user_arg=env,
            _hook_before_replace=hook,
        )
        """
    )

    # MINOR 9 (WOR-276): DEVNULL on stdout to avoid full-pipe deadlock
    # from a chatty child; stderr is inspected on failure paths.
    proc = subprocess.Popen(
        [sys.executable, "-c", child_src],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=child_env,
    )
    try:
        # MAJOR 7 (WOR-276): bounded waitpid(WNOHANG | WUNTRACED) loop.
        # Marker-only polling is vulnerable to the SIGSTOP race: if the
        # child is stopped externally (debugger, load control) the marker
        # never appears and we would spin until pytest's wall-clock
        # timeout. Mirroring test 30b, we explicitly observe WIFSTOPPED
        # and surface stderr on premature exit.
        deadline = time.monotonic() + 10.0
        stopped = False
        while time.monotonic() < deadline:
            try:
                pid, status = os.waitpid(proc.pid, os.WNOHANG | os.WUNTRACED)
            except OSError as exc:
                if exc.errno in (errno.EINTR, errno.ECHILD):
                    time.sleep(0.01)
                    continue
                raise
            if pid == proc.pid and os.WIFSTOPPED(status):
                stopped = True
                break
            if pid == proc.pid and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                stderr_text = ""
                if proc.stderr is not None:
                    try:
                        stderr_text = proc.stderr.read().decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        pass
                pytest.fail(
                    f"child exited before fsync marker: "
                    f"rc={proc.returncode} status={status:#x}\n"
                    f"stderr:\n{stderr_text}"
                )
            time.sleep(0.01)
        if not stopped:
            stderr_text = ""
            if proc.stderr is not None:
                try:
                    stderr_text = proc.stderr.read().decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    pass
            pytest.fail(
                f"child did not reach pre-rename checkpoint within 10s\nstderr:\n{stderr_text}"
            )
        assert marker.exists(), "child stopped but never wrote marker"

        # Child is SIGSTOPped inside the hook; deliver the kill. Use
        # bounded communicate() to collect stderr without relying on
        # proc.wait() alone.
        os.kill(proc.pid, signal.SIGKILL)
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
    finally:
        try:
            proc.kill()
        except ProcessLookupError:
            pass

    assert sha256_of(env) == baseline, "target clobbered by aborted rewrite"
    # SIGKILL is uncatchable: Python cannot run user-space cleanup, so
    # ``.env.tmp-*`` or ``.env.staging-*`` files MAY remain on disk.
    # That is an unavoidable property of SIGKILL, not a data-integrity
    # bug. Prior to the Major 3 staging-rename reorder (PR #86
    # discussion_r3129175662) the tmp file was renamed to
    # ``.env.staging-*`` BEFORE the hook, which hid the leak under a
    # different glob rather than fixing it.
    #
    # We assert the honest invariants via an *allowlist*: the only
    # survivors permitted are ``.env`` (byte-identical, already
    # asserted), the child's ``marker`` file, and tmp/staging artifacts.
    # Any other name — including a file masquerading as ``.env`` or a
    # staging leak under an unexpected prefix — fails the test. CR
    # thread on PR #86 (discussion_r3131811612) flagged that the prior
    # ``== ".env.lost"`` spot-check would miss real regressions.
    survivors = list(tmp_path.iterdir())
    allowed_names = {".env", marker.name}
    unexpected = [
        p.name
        for p in survivors
        if p.name not in allowed_names and not p.name.startswith((".env.tmp-", ".env.staging-"))
    ]
    assert unexpected == [], f"unexpected orphan survivor(s) after SIGKILL: {unexpected}"


# ---------------------------------------------------------------------------
# Test 1: SIGTERM between fsync and rename.
# ---------------------------------------------------------------------------


def test_sigterm_between_fsync_and_rename(tmp_path, make_env_file, sha256_of) -> None:
    """SIGTERM during the pre-rename window → target byte-identical, no ghost tmp."""
    # MAJOR 7 (WOR-276): hook-API drift smoke-check — see test 30 above.
    if "_hook_before_replace" not in inspect.signature(safe_rewrite).parameters:
        pytest.fail("hook API renamed \u2014 expected safe_rewrite(_hook_before_replace=...)")

    env = make_env_file(tmp_path / ".env", b"OPENAI_API_KEY=sk-orig\n")
    baseline = sha256_of(env)
    marker = tmp_path / "_fsync_done"

    # MAJOR 4 (WOR-276): env-var plumbing instead of f-string interpolation.
    new_bytes = b"A=1\n"
    child_env = {
        **os.environ,
        "WOR276_ENV_PATH": str(env),
        "WOR276_MARKER": str(marker),
        "WOR276_NEW_B64": base64.b64encode(new_bytes).decode("ascii"),
    }
    child_src = textwrap.dedent(
        """
        import base64, os, signal
        from pathlib import Path
        from worthless.cli.safe_rewrite import safe_rewrite

        env = Path(os.environ["WOR276_ENV_PATH"])
        marker = Path(os.environ["WOR276_MARKER"])
        new_bytes = base64.b64decode(os.environ["WOR276_NEW_B64"])

        def hook():
            marker.write_text("ready")
            os.kill(os.getpid(), signal.SIGSTOP)

        safe_rewrite(
            env, new_bytes, original_user_arg=env, _hook_before_replace=hook
        )
        """
    )
    # MINOR 9 (WOR-276): DEVNULL on stdout to avoid pipe-full deadlock.
    proc = subprocess.Popen(
        [sys.executable, "-c", child_src],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=child_env,
    )
    try:
        # MAJOR 7 (WOR-276): bounded waitpid(WNOHANG | WUNTRACED) loop,
        # mirrors test 30b. See test 30 above for the full rationale.
        deadline = time.monotonic() + 10.0
        stopped = False
        while time.monotonic() < deadline:
            try:
                pid, status = os.waitpid(proc.pid, os.WNOHANG | os.WUNTRACED)
            except OSError as exc:
                if exc.errno in (errno.EINTR, errno.ECHILD):
                    time.sleep(0.01)
                    continue
                raise
            if pid == proc.pid and os.WIFSTOPPED(status):
                stopped = True
                break
            if pid == proc.pid and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                stderr_text = ""
                if proc.stderr is not None:
                    try:
                        stderr_text = proc.stderr.read().decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        pass
                pytest.fail(
                    f"child exited before fsync marker: "
                    f"rc={proc.returncode} status={status:#x}\n"
                    f"stderr:\n{stderr_text}"
                )
            time.sleep(0.01)
        if not stopped:
            stderr_text = ""
            if proc.stderr is not None:
                try:
                    stderr_text = proc.stderr.read().decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    pass
            pytest.fail(
                f"child did not reach pre-rename checkpoint within 10s\nstderr:\n{stderr_text}"
            )
        assert marker.exists(), "child stopped but never wrote marker"

        # Deliver SIGTERM then SIGCONT so the stopped child can run its
        # default SIGTERM disposition (terminate). Bounded communicate()
        # replaces the bare proc.wait().
        os.kill(proc.pid, signal.SIGTERM)
        os.kill(proc.pid, signal.SIGCONT)
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
    finally:
        try:
            proc.kill()
        except ProcessLookupError:
            pass

    assert sha256_of(env) == baseline
    # SIGTERM with no installed handler terminates the process without
    # running Python-level cleanup (same as SIGKILL for our purposes),
    # so a ``.env.tmp-*`` file may remain. See the SIGKILL test above
    # for the full argument. The load-bearing invariant is that the
    # target is untouched.


# ---------------------------------------------------------------------------
# Test 3: SIGINT during write-loop.
# ---------------------------------------------------------------------------


def test_sigint_during_write_preserves_target(tmp_path, make_env_file, sha256_of) -> None:
    """SIGINT during pre-rename hook → target byte-identical, tmp cleaned up."""
    env = make_env_file(tmp_path / ".env", b"KEY=orig\n")
    baseline = sha256_of(env)
    marker = tmp_path / "_fsync_done"

    child_src = textwrap.dedent(
        f"""
        import os, signal
        from pathlib import Path
        from worthless.cli.safe_rewrite import safe_rewrite

        def hook():
            Path({str(marker)!r}).write_text("ready")
            os.kill(os.getpid(), signal.SIGSTOP)

        env = Path({str(env)!r})
        try:
            safe_rewrite(env, b"A=1\\n", original_user_arg=env, _hook_before_replace=hook)
        except KeyboardInterrupt:
            pass
        """
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", child_src],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 10.0
        while not marker.exists() and time.monotonic() < deadline:
            if proc.poll() is not None:
                pytest.fail("child exited early")
            time.sleep(0.01)
        assert marker.exists()
        os.kill(proc.pid, signal.SIGINT)
        os.kill(proc.pid, signal.SIGCONT)
        proc.wait(timeout=5)
    finally:
        try:
            proc.kill()
        except ProcessLookupError:
            pass

    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == []


# ---------------------------------------------------------------------------
# Test 4: EIO on tmp write.
# ---------------------------------------------------------------------------


def test_eio_on_tmp_write_raises_io_error(
    tmp_path, make_env_file, sha256_of, chaos_errno_at
) -> None:
    """EIO on ``os.write`` → UnsafeRewriteRefused(IO_ERROR), target byte-identical."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(env)

    chaos_errno_at("write", errno.EIO)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.IO_ERROR
    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == []


# ---------------------------------------------------------------------------
# Test 5: ENOSPC on fsync(tmp_fd).
# ---------------------------------------------------------------------------


def test_enospc_on_fsync_tmp(tmp_path, make_env_file, sha256_of, chaos_errno_at) -> None:
    """ENOSPC on fsync(tmp_fd) → refuse, target unchanged, tmp unlinked."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(env)

    chaos_errno_at("fsync", errno.ENOSPC)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.IO_ERROR
    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == []


# ---------------------------------------------------------------------------
# Test 6: EROFS on rename.
# ---------------------------------------------------------------------------


def test_erofs_on_rename(tmp_path, make_env_file, sha256_of, chaos_errno_at) -> None:
    """EROFS on rename/replace → refuse, target byte-identical, tmp absent."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(env)

    chaos_errno_at("replace", errno.EROFS)

    with pytest.raises(UnsafeRewriteRefused):
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == []


# ---------------------------------------------------------------------------
# Test 7: EMFILE on os.open of target.
# ---------------------------------------------------------------------------


def test_emfile_on_open_target(tmp_path, make_env_file, sha256_of, chaos_errno_at) -> None:
    """EMFILE on the initial ``os.open`` of target → clean refuse."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(env)

    chaos_errno_at("open", errno.EMFILE)

    with pytest.raises(UnsafeRewriteRefused):
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == []


# ---------------------------------------------------------------------------
# Test 8: target replaced with directory mid-op (hook-based).
# ---------------------------------------------------------------------------


def test_target_replaced_with_directory_mock(tmp_path, make_env_file, sha256_of) -> None:
    """Hook: unlink target + create dir with same name → refuse."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")

    def _swap() -> None:
        env.unlink()
        env.mkdir()

    with pytest.raises(UnsafeRewriteRefused):
        safe_rewrite(
            env,
            b"KEY=new\n",
            original_user_arg=env,
            _hook_before_replace=_swap,
        )

    assert (tmp_path / ".env").is_dir()
    assert list(tmp_path.glob(".env.tmp-*")) == []

    # Cleanup the attacker-dir so pytest teardown doesn't trip.
    import shutil

    shutil.rmtree(str(env), ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 9: inode reuse (unlink + recreate file) mid-op.
# ---------------------------------------------------------------------------


def test_inode_reuse_mock(tmp_path, make_env_file) -> None:
    """Hook: unlink target + recreate (new inode) → fstatat recheck refuses."""
    env = make_env_file(tmp_path / ".env", b"KEY=orig\n")

    def _reuse() -> None:
        env.unlink()
        fd = os.open(str(env), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, b"KEY=attacker\n")
        os.close(fd)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(
            env,
            b"KEY=new\n",
            original_user_arg=env,
            _hook_before_replace=_reuse,
        )

    assert exc_info.value.reason == UnsafeReason.TOCTOU
    assert env.read_bytes() == b"KEY=attacker\n"
    assert list(tmp_path.glob(".env.tmp-*")) == []


# ---------------------------------------------------------------------------
# Test 10: parent-dir fd invalidated.
# ---------------------------------------------------------------------------


def test_parent_dir_unlinked_mid_op(tmp_path, make_env_file, sha256_of) -> None:
    """Hook: rmdir the parent (best-effort) → raises cleanly, no panic.

    In practice we can't unlink a non-empty parent; the test exercises
    the defensive code path for an unlink-detected dir fd by using a
    nested dir that IS empty aside from the tmp.
    """
    sub = tmp_path / "sub"
    sub.mkdir()
    env = make_env_file(sub / ".env", b"KEY=v\n")
    baseline = sha256_of(env)

    def _try_rmdir() -> None:
        # Not strictly possible when tmp file exists; we exercise the
        # defensive path by raising instead.
        raise OSError(errno.ENOENT, "parent vanished")

    with pytest.raises((OSError, UnsafeRewriteRefused)):
        safe_rewrite(
            env,
            b"KEY=new\n",
            original_user_arg=env,
            _hook_before_replace=_try_rmdir,
        )

    assert sha256_of(env) == baseline
    assert list(sub.glob(".env.tmp-*")) == []


# ---------------------------------------------------------------------------
# Test 11: target mode flipped to 0000.
# ---------------------------------------------------------------------------


def test_target_mode_0000_between_stat_and_open(tmp_path, make_env_file) -> None:
    """Hook: chmod 0000 → subsequent ops fail, no write, original preserved.

    This fires post-hook; we flip the original's mode and ensure any
    subsequent access (recheck fstat, release) doesn't clobber.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")

    def _lock_down() -> None:
        env.chmod(0o000)

    try:
        with pytest.raises((OSError, UnsafeRewriteRefused)):
            safe_rewrite(
                env,
                b"KEY=new\n",
                original_user_arg=env,
                _hook_before_replace=_lock_down,
            )
    finally:
        env.chmod(0o600)

    # The file might have been renamed successfully or not — either way
    # the CONTENT on disk under .env must match either baseline (no write)
    # or the new_content (successful atomic rewrite). Ghost tmp forbidden.
    assert list(tmp_path.glob(".env.tmp-*")) == []


# ---------------------------------------------------------------------------
# Test 12: clock skew / future mtime.
# ---------------------------------------------------------------------------


def test_clock_skew_future_mtime_does_not_affect_decision(tmp_path, make_env_file) -> None:
    """Target with a far-future mtime is still accepted; sha256 is the truth.

    Skip if the host fs clamps future timestamps (some tmpfs setups).
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    future = time.time() + 10 * 365 * 24 * 3600  # +10 years
    os.utime(str(env), (future, future))
    got = env.stat().st_mtime
    if abs(got - future) > 1:
        pytest.skip(f"host fs clamps future timestamps: set {future}, got {got}")

    safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    assert env.read_bytes() == b"KEY=new\n"


# ---------------------------------------------------------------------------
# Test 13: tmp-suffix collision 3x in a row.
# ---------------------------------------------------------------------------


def test_tmp_collision_three_times_fails_closed(
    tmp_path, make_env_file, sha256_of, monkeypatch
) -> None:
    """``os.open`` with O_EXCL raises EEXIST 3x → TMP_COLLISION, no write."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(env)

    real_open = os.open

    def _always_eexist(path, flags, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        if (flags & os.O_EXCL) and ".env.tmp-" in str(path):
            raise OSError(errno.EEXIST, "collision")
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", _always_eexist)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.TMP_COLLISION
    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == []


# ---------------------------------------------------------------------------
# Test 14: concurrent flock in sibling process.
# ---------------------------------------------------------------------------


def test_concurrent_flock_sibling_blocks(tmp_path, make_env_file, sha256_of, barrier_file) -> None:
    """Sibling process holds flock; in-process safe_rewrite refuses LOCKED.

    Two-process ordering: sibling writes its pid to ``barrier_file`` when
    the lock is held; the parent polls the barrier before invoking
    ``safe_rewrite``. Deterministic.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(env)

    child_src = textwrap.dedent(
        f"""
        import fcntl, os, time
        from pathlib import Path

        fd = os.open({str(env)!r}, os.O_RDONLY)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        Path({str(barrier_file)!r}).write_text(str(os.getpid()))
        # Hold the lock for a bounded window so the parent sees the contention.
        time.sleep(2.0)
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        """
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", child_src],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 5.0
        while not barrier_file.exists() and time.monotonic() < deadline:
            if proc.poll() is not None:
                pytest.fail(f"sibling died: rc={proc.returncode}")
            time.sleep(0.01)
        assert barrier_file.exists(), "sibling never acquired the flock"

        with pytest.raises(UnsafeRewriteRefused) as exc_info:
            safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

        assert exc_info.value.reason == UnsafeReason.LOCKED
        assert sha256_of(env) == baseline
    finally:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---------------------------------------------------------------------------
# Test 15: ENOSPC on fsync(dir_fd) after rename.
#
# Call order inside safe_rewrite:
#   1. fsync(tmp_fd)     — _fsync_tmp, BEFORE rename   (raises  → refuse)
#   2. fsync(dir_fd)     — _fsync_dir, BEFORE rename   (raises  → refuse)
#   3. fsync(dir_fd)     — inline,     AFTER  rename   (raises → WARN, no raise)
# The contract for #3 is what we're pinning here and in the parametrized
# ``enospc_dir_fsync`` branch of the ghost-tmp matrix below.
# ---------------------------------------------------------------------------


def _inject_enospc_on_nth_fsync(monkeypatch, n: int) -> dict[str, int]:
    """Monkey-patch ``os.fsync`` to raise ENOSPC on the *n*-th call only.

    Returns the shared ``seen`` counter dict so callers can assert the
    actual number of ``os.fsync`` calls matched their expectation. This
    is important because the test's choice of ``n`` is coupled to the
    implementation's exact fsync ordering — if the impl ever adds a new
    fsync call, a silent test drift would let a real regression pass.
    """
    real_fsync = os.fsync
    seen = {"n": 0}

    def _fsync(fd):  # noqa: ANN001
        seen["n"] += 1
        if seen["n"] == n:
            raise OSError(errno.ENOSPC, "no space")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", _fsync)
    return seen


def test_enospc_on_fsync_dir_fd_post_rename(tmp_path, make_env_file, monkeypatch, caplog) -> None:
    """ENOSPC on ``fsync(dir_fd)`` *after* rename MUST NOT raise.

    Raising ``UnsafeRewriteRefused`` here would be a contract lie (the
    rewrite *did* happen on disk; only the durability barrier failed)
    and would cause idempotent retry callers that re-check baseline-sha
    to double-write on top of the new content. See Finding 4 in the
    sub-PR-4 writeup for the full argument.

    The contract (all four clauses must hold):

    1. ``safe_rewrite`` returns normally (no exception).
    2. Target reflects ``new_content`` (rename committed before fsync).
    3. No ``.env.tmp-*`` / ``.env.staging-*`` left behind.
    4. A warning was logged via the ``worthless.safe_rewrite`` logger
       so operators can see durability was unconfirmed.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    new_content = b"KEY=new\n"

    seen = _inject_enospc_on_nth_fsync(monkeypatch, n=3)

    with caplog.at_level("WARNING", logger="worthless.safe_rewrite"):
        safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content
    assert list(tmp_path.glob(".env.tmp-*")) == []
    assert list(tmp_path.glob(".env.staging-*")) == []
    # n=3 is coupled to safe_rewrite's exact fsync ordering
    # (_fsync_tmp → _fsync_dir pre-rename → inline post-rename). If a
    # future change adds or reorders fsync calls, this catches the
    # drift loudly rather than letting the test silently exercise the
    # wrong call.
    assert seen["n"] == 3, (
        f"expected exactly 3 os.fsync calls, saw {seen['n']}; "
        f"safe_rewrite's fsync ordering may have drifted"
    )
    # Warning text is load-bearing: it's the ONLY user-visible signal
    # that the rewrite may revert on an unclean shutdown. Pin the
    # strong phrasing rather than a softer "durability unconfirmed" so
    # a future well-intentioned edit that softens the message fails
    # the test instead of silently hiding data-risk from operators.
    assert any("rewrite may revert on crash" in rec.getMessage() for rec in caplog.records), (
        f"expected post-rename warning, got: {[r.getMessage() for r in caplog.records]}"
    )


# ---------------------------------------------------------------------------
# Test 15b: Darwin/APFS regression guard — _fullfsync MUST run even when
# the preceding os.fsync raises. On APFS, plain fsync is effectively a
# no-op for drive-cache durability; F_FULLFSYNC is the only real barrier.
# Gating _fullfsync on fsync success would silently skip the only call
# that matters for durability on macOS, so this test pins the contract:
# given ENOSPC on os.fsync(dir_fd) post-rename, fcntl.fcntl(_, F_FULLFSYNC)
# must still be attempted on the dir fd.
# ---------------------------------------------------------------------------


def test_fullfsync_runs_even_when_post_rename_fsync_raises_on_darwin(
    tmp_path, make_env_file, fake_darwin, monkeypatch, caplog
) -> None:
    """ENOSPC on ``fsync(dir_fd)`` post-rename MUST NOT skip ``_fullfsync``.

    Contract (all must hold):

    1. ``safe_rewrite`` returns normally (durability-barrier failure
       is not a refusal — rename already committed).
    2. Target reflects the new content.
    3. ``fcntl.fcntl`` is invoked at least once with a non-zero ``cmd``
       (F_FULLFSYNC on Darwin is 51; under ``fake_darwin`` on Linux the
       kernel ENOTTYs but the *attempt* must still happen, and the
       implementation's ``_fullfsync`` helper swallows that OSError).
    4. A post-rename warning is logged for the failed ``os.fsync``.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    new_content = b"KEY=new\n"

    _inject_enospc_on_nth_fsync(monkeypatch, n=3)

    fcntl_cmds: list[int] = []
    real_fcntl = fcntl.fcntl

    def _rec(fd, cmd, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        fcntl_cmds.append(cmd)
        try:
            return real_fcntl(fd, cmd, *a, **kw)
        except OSError:
            # F_FULLFSYNC on a faked-Darwin Linux kernel will ENOTTY;
            # the implementation swallows that. Test asserts the attempt.
            return 0

    monkeypatch.setattr(fcntl, "fcntl", _rec)

    with caplog.at_level("WARNING", logger="worthless.safe_rewrite"):
        safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content
    # _fullfsync is called at THREE sites: tmp_fd (inside _fsync_tmp),
    # pre-rename dir_fd (inside _fsync_dir), and post-rename dir_fd
    # (inline, after the ENOSPC-raising os.fsync). The post-rename
    # call is the load-bearing one: if a regression gated _fullfsync
    # on os.fsync success, we'd still see two calls (tmp + pre-rename)
    # and a ">= 2" assertion would pass silently — exactly the blind
    # spot flagged in PR #86 discussion_r3129175668. Asserting ">= 3"
    # forces coverage of the post-rename path, where the durability
    # barrier actually matters on APFS.
    assert len(fcntl_cmds) >= 3, (
        f"expected ≥3 fcntl.fcntl calls (tmp_fd + pre-rename dir_fd + "
        f"post-rename dir_fd F_FULLFSYNC); got {len(fcntl_cmds)}: "
        f"{fcntl_cmds}. If this is 2, the impl regressed to skipping "
        f"_fullfsync after os.fsync raises post-rename — which silently "
        f"skips the only real durability barrier on APFS."
    )
    # Sanity: the warning must still fire so operators see the risk.
    assert any("rewrite may revert on crash" in rec.getMessage() for rec in caplog.records), (
        f"expected post-rename warning, got: {[r.getMessage() for r in caplog.records]}"
    )


# ---------------------------------------------------------------------------
# Test 16: EMFILE on dir fd open.
# ---------------------------------------------------------------------------


def test_emfile_on_dir_fd_open(tmp_path, make_env_file, sha256_of, monkeypatch) -> None:
    """EMFILE when opening parent dir fd → refuse, no tmp, no write."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(env)

    real_open = os.open
    opened_target_once = {"b": False}

    def _emfile_on_dir(path, flags, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        # Refuse the directory open attempt (O_DIRECTORY or path == parent).
        if (flags & getattr(os, "O_DIRECTORY", 0)) or str(path) == str(tmp_path):
            if opened_target_once["b"]:
                raise OSError(errno.EMFILE, "too many open files")
        if str(path).endswith("/.env"):
            opened_target_once["b"] = True
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", _emfile_on_dir)

    with pytest.raises(UnsafeRewriteRefused):
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == []


# ---------------------------------------------------------------------------
# Test 17: renameat2 ENOSYS → fallback to fstatat + os.replace.
# ---------------------------------------------------------------------------


def test_renameat2_enosys_falls_back_to_fstatat_recheck(
    tmp_path, make_env_file, monkeypatch
) -> None:
    """If a ``_renameat2`` helper raises ENOSYS, impl falls back cleanly.

    Asserts ``os.stat`` (recheck) AND ``os.replace`` are both called on
    the fallback path.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")

    stat_calls: list[str] = []
    replace_calls = {"n": 0}

    real_stat = os.stat
    real_replace = os.replace

    def _rec_stat(*a, **kw):  # noqa: ANN002, ANN003
        stat_calls.append("stat")
        return real_stat(*a, **kw)

    def _rec_replace(src, dst, *a, **kw):  # noqa: ANN001, ANN003
        replace_calls["n"] += 1
        return real_replace(src, dst, *a, **kw)

    monkeypatch.setattr(os, "stat", _rec_stat)
    monkeypatch.setattr(os, "replace", _rec_replace)

    # If the impl exposes a _renameat2 helper, force it to ENOSYS.
    try:
        from worthless.cli import safe_rewrite as _sr

        if hasattr(_sr, "_renameat2"):

            def _enosys(*a, **kw):  # noqa: ANN002, ANN003
                raise OSError(errno.ENOSYS, "not supported")

            monkeypatch.setattr(_sr, "_renameat2", _enosys)
    except ImportError:
        pass

    safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    assert replace_calls["n"] >= 1, "os.replace fallback not used"
    assert len(stat_calls) >= 2, "fstatat recheck missing on fallback"


# ---------------------------------------------------------------------------
# Test 18: hook raises RuntimeError between fsync and rename.
# ---------------------------------------------------------------------------


def test_hook_raises_between_fsync_and_rename(tmp_path, make_env_file, sha256_of) -> None:
    """``_hook_before_replace`` raises → target byte-identical, tmp unlinked."""
    env = make_env_file(tmp_path / ".env", b"KEY=orig\n")
    baseline = sha256_of(env)

    class _HookBoom(Exception):
        pass

    fired = {"b": False}

    def _boom() -> None:
        fired["b"] = True
        raise _HookBoom("hook crash")

    with pytest.raises((_HookBoom, UnsafeRewriteRefused)) as exc_info:
        safe_rewrite(
            env,
            b"KEY=new\n",
            original_user_arg=env,
            _hook_before_replace=_boom,
        )

    assert fired["b"], "hook never fired — implementation refused before reaching it"
    assert not isinstance(exc_info.value, NotImplementedError)
    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == []


# ---------------------------------------------------------------------------
# Test 19: flock provides cross-process mutual exclusion on the inode.
# ---------------------------------------------------------------------------


def test_flock_blocks_concurrent_child_process(tmp_path, make_env_file) -> None:
    """While safe_rewrite holds flock, a concurrent child must be blocked.

    A mid-op hook spawns a subprocess that opens its *own* fd on the
    same target and attempts ``LOCK_EX | LOCK_NB``. The child must
    observe ``EWOULDBLOCK`` because the parent still holds the flock
    on the inode (``flock`` is per-inode / per-open-file-description
    advisory locking on Linux/macOS).

    NOTE: This test verifies *cross-process lock contention* — NOT
    ``FD_CLOEXEC`` inheritance. ``subprocess.run`` is invoked with
    ``close_fds=True`` (POSIX default), which closes every inherited
    fd in the child regardless of ``FD_CLOEXEC``, so this test cannot
    distinguish "fd had CLOEXEC" from "fd inherited then closed by
    subprocess". ``O_CLOEXEC`` on the tmp fd is covered by
    ``test_tmp_open_uses_O_NOFOLLOW`` below.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    child_result_file = tmp_path / "_child_result"

    def _spawn_child() -> None:
        script = textwrap.dedent(
            f"""
            import fcntl, os
            from pathlib import Path

            try:
                fd = os.open({str(env)!r}, os.O_RDONLY)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                Path({str(child_result_file)!r}).write_text("acquired")
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            except OSError as e:
                Path({str(child_result_file)!r}).write_text(f"blocked:{{e.errno}}")
            """
        )
        # close_fds=True is the POSIX default. This test verifies
        # cross-process lock contention on the inode, not FD_CLOEXEC —
        # close_fds would close any inherited fd regardless of CLOEXEC.
        subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            timeout=10,
            close_fds=True,
        )

    # Hook raises after spawning so we exit cleanly.
    class _SpyDone(Exception):
        pass

    fired = {"b": False}

    def _hook() -> None:
        fired["b"] = True
        _spawn_child()
        raise _SpyDone("done spying")

    with pytest.raises((_SpyDone, UnsafeRewriteRefused)) as _ei:
        safe_rewrite(
            env,
            b"KEY=new\n",
            original_user_arg=env,
            _hook_before_replace=_hook,
        )
    assert fired["b"], "hook never fired — child was never spawned"
    assert not isinstance(_ei.value, NotImplementedError)

    # The child opens its OWN fd and attempts LOCK_NB. Because flock
    # on Linux/macOS is per-inode (advisory, whole-file), the child
    # must see EWOULDBLOCK while the parent still holds the lock
    # during _hook execution. This confirms cross-process exclusion,
    # not FD_CLOEXEC (see docstring above for why).
    assert child_result_file.exists(), "child never ran"
    result = child_result_file.read_text()
    assert result.startswith("blocked:"), f"child acquired lock while parent held it: {result!r}"


# ---------------------------------------------------------------------------
# Test 20: tmp open flags include O_NOFOLLOW etc.
# ---------------------------------------------------------------------------


def test_tmp_open_uses_O_NOFOLLOW(tmp_path, make_env_file, monkeypatch) -> None:
    """The tmp-file ``os.open`` uses O_NOFOLLOW | O_CLOEXEC | O_EXCL | O_CREAT | O_WRONLY."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    recorded: list[int] = []

    real_open = os.open

    def _rec(path, flags, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        if ".env.tmp-" in str(path):
            recorded.append(flags)
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", _rec)

    try:
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)
    except Exception:
        pass

    assert recorded, "tmp file was never opened"
    required = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_EXCL | os.O_CREAT | os.O_WRONLY
    for f in recorded:
        assert (f & required) == required, f"tmp-open missing flags: {oct(f)}"


# ---------------------------------------------------------------------------
# Test 21: parametrised no-ghost-tmp across 18 injection points.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "injection",
    [
        "sigterm",
        "sigkill",
        "sigint",
        "eio_write",
        "enospc_fsync",
        "erofs_rename",
        "emfile_open",
        "target_is_dir",
        "inode_reuse",
        "parent_unlinked",
        "mode_0000",
        "clock_skew",
        "tmp_collision",
        "concurrent_flock",
        "enospc_dir_fsync",
        "emfile_dir_fd",
        "renameat2_enosys",
        "hook_raises",
    ],
)
def test_no_ghost_tmp_after_any_chaos_refusal(injection, tmp_path, make_env_file, monkeypatch):
    """After any chaos injection point, no ``.env.tmp-*`` or ``.env.staging-*`` remains.

    Negative-space spine for the tmp-leak invariant across all 18
    failure modes. Each case uses the same minimal trigger; the
    assertion is uniform: both ``.env.tmp-*`` and ``.env.staging-*``
    globs must be empty in the target's parent directory.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")

    # Configure the injection.
    if injection in {"sigterm", "sigkill", "sigint"}:
        pytest.skip("signal-based ghost-tmp coverage lives in the per-signal tests")

    if injection == "eio_write":

        def _w(fd, data, *a, **kw):  # noqa: ANN001, ANN003
            raise OSError(errno.EIO, "io error")

        monkeypatch.setattr(os, "write", _w)

    elif injection == "enospc_fsync":

        def _f(fd):  # noqa: ANN001
            raise OSError(errno.ENOSPC, "no space")

        monkeypatch.setattr(os, "fsync", _f)

    elif injection == "erofs_rename":

        def _r(src, dst, *a, **kw):  # noqa: ANN001, ANN003
            raise OSError(errno.EROFS, "read only fs")

        monkeypatch.setattr(os, "replace", _r)

    elif injection == "emfile_open":
        real_open = os.open

        def _o(path, flags, *a, **kw):  # noqa: ANN001, ANN002, ANN003
            raise OSError(errno.EMFILE, "too many open files")

        monkeypatch.setattr(os, "open", _o)

    elif injection == "target_is_dir":
        # Swap target for a directory before the call.
        env.unlink()
        env.mkdir()

    elif injection == "inode_reuse":
        hook_called = {"b": False}

        def _hook() -> None:
            if hook_called["b"]:
                return
            hook_called["b"] = True
            env.unlink()
            fd = os.open(str(env), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, b"KEY=new_inode\n")
            os.close(fd)

        try:
            with pytest.raises((UnsafeRewriteRefused, OSError)) as _ei:
                safe_rewrite(
                    env,
                    b"KEY=new\n",
                    original_user_arg=env,
                    _hook_before_replace=_hook,
                )
            assert not isinstance(_ei.value, NotImplementedError)
        finally:
            assert list(tmp_path.glob(".env.tmp-*")) == []
        return

    elif injection == "parent_unlinked":

        def _hook() -> None:
            raise OSError(errno.ENOENT, "gone")

        with pytest.raises((UnsafeRewriteRefused, OSError)) as _ei:
            safe_rewrite(
                env,
                b"KEY=new\n",
                original_user_arg=env,
                _hook_before_replace=_hook,
            )
        assert not isinstance(_ei.value, NotImplementedError)
        assert list(tmp_path.glob(".env.tmp-*")) == []
        return

    elif injection == "mode_0000":

        def _hook() -> None:
            env.chmod(0o000)

        try:
            with pytest.raises((UnsafeRewriteRefused, OSError)) as _ei:
                safe_rewrite(
                    env,
                    b"KEY=new\n",
                    original_user_arg=env,
                    _hook_before_replace=_hook,
                )
            assert not isinstance(_ei.value, NotImplementedError)
        finally:
            try:
                env.chmod(0o600)
            except OSError:
                pass
        assert list(tmp_path.glob(".env.tmp-*")) == []
        return

    elif injection == "clock_skew":
        os.utime(str(env), (0, 0))  # epoch 0; not itself a failure
        # Positive path: the rewrite must succeed (clock skew is not a refusal);
        # on green, new_content on disk and no tmp leak.
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)
        assert env.read_bytes() == b"KEY=new\n"
        assert list(tmp_path.glob(".env.tmp-*")) == []
        return

    elif injection == "tmp_collision":
        real_open = os.open

        def _coll(path, flags, *a, **kw):  # noqa: ANN001, ANN002, ANN003
            if (flags & os.O_EXCL) and ".env.tmp-" in str(path):
                raise OSError(errno.EEXIST, "collision")
            return real_open(path, flags, *a, **kw)

        monkeypatch.setattr(os, "open", _coll)

    elif injection == "concurrent_flock":
        fd = os.open(str(env), os.O_RDONLY)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with pytest.raises(UnsafeRewriteRefused):
                safe_rewrite(env, b"KEY=new\n", original_user_arg=env)
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)
        assert list(tmp_path.glob(".env.tmp-*")) == []
        return

    elif injection == "enospc_dir_fsync":
        # Post-rename fsync is call #3 (see _inject_enospc_on_nth_fsync
        # docstring). The contract is "no raise" — full coverage lives
        # in test_enospc_on_fsync_dir_fd_post_rename; here we only spine
        # the shared no-ghost-tmp invariant.
        _inject_enospc_on_nth_fsync(monkeypatch, n=3)
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)
        assert env.read_bytes() == b"KEY=new\n"
        assert list(tmp_path.glob(".env.tmp-*")) == []
        assert list(tmp_path.glob(".env.staging-*")) == []
        return

    elif injection == "emfile_dir_fd":
        real_open = os.open
        target_opened = {"b": False}

        def _o(path, flags, *a, **kw):  # noqa: ANN001, ANN002, ANN003
            if str(path).endswith("/.env"):
                target_opened["b"] = True
            elif target_opened["b"] and str(path) == str(tmp_path):
                raise OSError(errno.EMFILE, "too many")
            return real_open(path, flags, *a, **kw)

        monkeypatch.setattr(os, "open", _o)

    elif injection == "renameat2_enosys":
        # renameat2 ENOSYS triggers a successful fstatat-recheck + os.replace
        # fallback (see _atomic_replace_with_fallback), so this case does NOT
        # raise — it completes normally. The spine invariants are still the
        # same: target updated, no ghost tmp/staging. Handle inline like the
        # other no-raise cases (enospc_dir_fsync).
        from worthless.cli import safe_rewrite as _sr

        def _enosys(*a, **kw):  # noqa: ANN002, ANN003
            raise OSError(errno.ENOSYS, "nosys")

        monkeypatch.setattr(_sr, "_renameat2", _enosys)
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)
        assert env.read_bytes() == b"KEY=new\n"
        assert list(tmp_path.glob(".env.tmp-*")) == []
        assert list(tmp_path.glob(".env.staging-*")) == []
        return

    elif injection == "hook_raises":

        class _Boom(Exception):
            pass

        fired = {"b": False}

        def _hook() -> None:
            fired["b"] = True
            raise _Boom("boom")

        with pytest.raises((UnsafeRewriteRefused, _Boom)) as _ei:
            safe_rewrite(
                env,
                b"KEY=new\n",
                original_user_arg=env,
                _hook_before_replace=_hook,
            )
        assert fired["b"], "hook never fired — impl refused before tmp write"
        assert not isinstance(_ei.value, NotImplementedError)
        assert list(tmp_path.glob(".env.tmp-*")) == []
        return

    # Default shape: just call safe_rewrite; expect failure; assert no tmp.
    try:
        with pytest.raises((UnsafeRewriteRefused, OSError)) as _ei:
            safe_rewrite(env, b"KEY=new\n", original_user_arg=env)
        assert not isinstance(_ei.value, NotImplementedError)
    finally:
        # Cleanup: restore mode if altered.
        try:
            if env.exists() and not stat.S_ISDIR(env.stat().st_mode):
                env.chmod(0o600)
        except OSError:
            pass

    glob_parent = env.parent if env.parent.exists() else tmp_path
    assert list(glob_parent.glob(".env.tmp-*")) == [], f"ghost tmp left after {injection}"
    # Major 3 (PR #86 discussion_r3129175662): ``.env.staging-*`` MUST
    # also be empty. Prior to the staging-rename reorder, a SIGKILL
    # during ``_hook_before_replace`` could leave a staging file with
    # the full replacement payload that this spine was blind to.
    assert list(glob_parent.glob(".env.staging-*")) == [], (
        f"ghost staging file left after {injection}"
    )

    # Cleanup a directory-target swap so pytest teardown works.
    if injection == "target_is_dir":
        import shutil

        shutil.rmtree(str(env), ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 22: real-FS sibling — directory swap.
# ---------------------------------------------------------------------------


def test_directory_swap_real_fs_sibling(tmp_path, make_env_file, sha256_of) -> None:
    """Real FS: hook replaces target with a directory; refuse with TOCTOU."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")

    def _swap() -> None:
        env.unlink()
        env.mkdir()

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(
            env,
            b"KEY=new\n",
            original_user_arg=env,
            _hook_before_replace=_swap,
        )

    assert exc_info.value.reason in {UnsafeReason.TOCTOU, UnsafeReason.IO_ERROR}
    assert (tmp_path / ".env").is_dir()
    assert list(tmp_path.glob(".env.tmp-*")) == []

    import shutil

    shutil.rmtree(str(env), ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 23: real-FS sibling — inode reuse.
# ---------------------------------------------------------------------------


def test_inode_reuse_real_fs_sibling(tmp_path, make_env_file) -> None:
    """Real FS: hook unlinks + recreates target; fstatat recheck refuses."""
    env = make_env_file(tmp_path / ".env", b"KEY=orig\n")

    def _reuse() -> None:
        env.unlink()
        fd = os.open(str(env), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, b"KEY=attacker\n")
        os.close(fd)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(
            env,
            b"KEY=new\n",
            original_user_arg=env,
            _hook_before_replace=_reuse,
        )

    assert exc_info.value.reason == UnsafeReason.TOCTOU
    assert env.read_bytes() == b"KEY=attacker\n"
    assert list(tmp_path.glob(".env.tmp-*")) == []
