"""Atomic-write invariants.

Covers the rename/tmp/mode/O_EXCL path plus failure-mode regressions:
tmp cleanup on hook crash, mode 0600, same inode-dir anchoring, O_EXCL
retry-then-fail, umask isolation, and O_NOFOLLOW/O_CLOEXEC on tmp open.
"""

from __future__ import annotations

import errno
import os
import stat

import pytest

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.safe_rewrite import safe_rewrite


# ---------------------------------------------------------------------------
# Red-first test 6.
# ---------------------------------------------------------------------------


def test_atomic_replace_leaves_target_byte_identical_on_crash(
    tmp_path, make_env_file, sha256_of
) -> None:
    """Hook raises → target is byte-identical, no ghost ``.env.tmp-*`` file."""
    env = make_env_file(tmp_path / ".env", b"KEY=original\n")
    baseline = sha256_of(env)

    class _BoomHook:
        def __init__(self) -> None:
            self.called = False

        def __call__(self) -> None:
            self.called = True
            raise RuntimeError("synthetic crash after fsync, before rename")

    hook = _BoomHook()

    with pytest.raises((RuntimeError, UnsafeRewriteRefused)) as exc_info:
        safe_rewrite(
            env,
            b"KEY=replacement_value_please\n",
            original_user_arg=env,
            _hook_before_replace=hook,
        )

    # The hook MUST have fired — this is what "mid-op crash" means. A
    # stubbed or early-refusing implementation that never reaches the
    # pre-rename phase fails this assertion, keeping the test RED until
    # the real atomic-write path lands.
    assert hook.called, "implementation never reached the pre-rename hook"
    # And it must be the synthetic RuntimeError we raised (or a
    # UnsafeRewriteRefused wrapping it) — not NotImplementedError.
    assert not isinstance(exc_info.value, NotImplementedError)

    assert sha256_of(env) == baseline, "target must not change on mid-op crash"
    assert list(tmp_path.glob(".env.tmp-*")) == [], "tmp must be cleaned up on failure"


# ---------------------------------------------------------------------------
# Happy-path coverage.
# ---------------------------------------------------------------------------


def test_happy_path_writes_new_content(tmp_path, make_env_file) -> None:
    """End-to-end: valid ``.env`` + valid new_content → target updated."""
    env = make_env_file(tmp_path / ".env", b"KEY=old\n")
    new_content = b"KEY=new\n"

    safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content
    assert list(tmp_path.glob(".env.tmp-*")) == []


def test_target_mode_is_0600_after_rewrite(tmp_path, make_env_file) -> None:
    """After rewrite, ``.env`` mode is 0600 (owner read/write, nothing else)."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n", mode=0o600)

    safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    st = env.stat()
    mode_bits = stat.S_IMODE(st.st_mode)
    assert mode_bits == 0o600, f"expected 0600, got {oct(mode_bits)}"


def test_target_inode_dir_preserved(tmp_path, make_env_file) -> None:
    """The target's parent directory must be the same post-rewrite.

    Atomic replace stays within the same directory; the rename operates
    on the target's directory fd so tmp and target share the same parent
    inode.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    parent_ino_before = tmp_path.stat().st_ino

    safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    parent_ino_after = env.parent.stat().st_ino
    assert parent_ino_after == parent_ino_before


def test_o_excl_collision_retry_then_fail_closed(
    tmp_path, make_env_file, sha256_of, monkeypatch
) -> None:
    """O_EXCL collides 3 retries → fails closed with TMP_COLLISION, no write.

    Force ``os.open`` to raise EEXIST whenever called with O_EXCL on the
    tmp path. After 3 retries (per ``_TMP_RETRIES``), the implementation
    must refuse with ``UnsafeReason.TMP_COLLISION``.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(env)

    real_open = os.open

    def _collide(path, flags, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        if (
            (flags & os.O_EXCL)
            and str(path).endswith(".env.tmp-") is False
            and ".env.tmp-" in str(path)
        ):
            raise OSError(errno.EEXIST, "collision")
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", _collide)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.TMP_COLLISION
    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == []


def test_tmp_cleanup_on_generic_failure(tmp_path, make_env_file, sha256_of) -> None:
    """Any failure after tmp open → tmp is unlinked, target unchanged."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(env)

    class _Boom(Exception):
        """Distinct exception type so we can detect the real hook firing."""

    fired = {"b": False}

    def _boom() -> None:
        fired["b"] = True
        raise _Boom("boom")

    with pytest.raises((_Boom, UnsafeRewriteRefused)) as exc_info:
        safe_rewrite(
            env,
            b"KEY=new\n",
            original_user_arg=env,
            _hook_before_replace=_boom,
        )

    assert fired["b"], "hook never fired; impl refused before reaching tmp-write"
    assert not isinstance(exc_info.value, NotImplementedError)
    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == []


def test_parent_dir_eacces_refuses_cleanly(tmp_path, make_env_file, sha256_of) -> None:
    """Parent dir without write permission → refused, target untouched."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(env)
    parent_mode = tmp_path.stat().st_mode

    # Remove write bit from parent dir so tmp open fails.
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(UnsafeRewriteRefused) as exc_info:
            safe_rewrite(env, b"KEY=new\n", original_user_arg=env)

        assert exc_info.value.reason == UnsafeReason.IO_ERROR
        # Target bytes unchanged.
        tmp_path.chmod(parent_mode)
        assert sha256_of(env) == baseline
    finally:
        tmp_path.chmod(parent_mode)


def test_target_missing_refused(tmp_path) -> None:
    """A nonexistent target is refused — this is a rewrite, not a create."""
    env = tmp_path / ".env"
    assert not env.exists()

    with pytest.raises(UnsafeRewriteRefused):
        safe_rewrite(env, b"KEY=v\n", original_user_arg=env)

    assert not env.exists(), "no file may be created on refusal"
    assert list(tmp_path.glob(".env.tmp-*")) == []


def test_enospc_on_tmp_write_refuses(tmp_path, make_env_file, sha256_of, monkeypatch) -> None:
    """ENOSPC raised on ``os.write`` of tmp → refuse, target byte-identical."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(env)

    real_write = os.write
    state = {"fired": False}

    def _faulty_write(fd, data, *a, **kw):  # noqa: ANN001, ANN003
        if not state["fired"]:
            state["fired"] = True
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(fd, data, *a, **kw)

    monkeypatch.setattr(os, "write", _faulty_write)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, b"KEY=new_value_longer\n", original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.IO_ERROR
    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == []


def test_partial_write_keeps_target_byte_identical(
    tmp_path, make_env_file, sha256_of, monkeypatch
) -> None:
    """If write() returns short, implementation must handle it; target unchanged.

    We raise mid-write after N bytes to simulate a short write that
    escalates into an error. Target must not be partially replaced.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=original\n")
    baseline = sha256_of(env)

    real_write = os.write
    seen_bytes = {"n": 0}

    def _short_then_fail(fd, data, *a, **kw):  # noqa: ANN001, ANN003
        # Let the first chunk succeed partially, then fail the second.
        if seen_bytes["n"] == 0 and isinstance(data, bytes | bytearray):
            seen_bytes["n"] += len(data)
            if len(data) > 4:
                # Write just 4 bytes to simulate a short write; impl must loop.
                return real_write(fd, data[:4])
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(os, "write", _short_then_fail)

    with pytest.raises((UnsafeRewriteRefused, OSError)) as exc_info:
        safe_rewrite(env, b"KEY=brand_new_value\n", original_user_arg=env)
    assert not isinstance(exc_info.value, NotImplementedError)

    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == []


def test_umask_zero_does_not_leak_mode(tmp_path, make_env_file) -> None:
    """Even with ``umask(0)``, the target retains mode 0600 after rewrite."""
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")

    previous = os.umask(0)
    try:
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)
    finally:
        os.umask(previous)

    mode_bits = stat.S_IMODE(env.stat().st_mode)
    assert mode_bits == 0o600, f"umask leak: got {oct(mode_bits)}"


def test_tmp_open_flags_include_nofollow_cloexec(tmp_path, make_env_file, monkeypatch) -> None:
    """``os.open`` on the tmp path uses ``O_NOFOLLOW | O_CLOEXEC | O_EXCL | O_CREAT | O_WRONLY``.

    Mock ``os.open`` and record the flag value for any call whose path
    ends in ``.env.tmp-*``. Assert the required flag set.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    recorded_flags: list[int] = []

    real_open = os.open

    def _recording_open(path, flags, *a, **kw):  # noqa: ANN001, ANN003
        sp = str(path)
        if ".env.tmp-" in sp:
            recorded_flags.append(flags)
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", _recording_open)

    # Use a hook that fires mid-op so we definitely reach the tmp-open
    # even if something later fails; happy-path is fine too.
    try:
        safe_rewrite(env, b"KEY=new\n", original_user_arg=env)
    except Exception:
        pass

    assert recorded_flags, "tmp path was never opened"
    required = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_EXCL | os.O_CREAT | os.O_WRONLY
    for flags in recorded_flags:
        assert (flags & required) == required, f"tmp-open missing required flags: got {oct(flags)}"


# ---------------------------------------------------------------------------
# Staging-rename ordering — Major 3 (CR thread on PR #86, discussion_r3129175662).
#
# Before this fix, ``_stage_tmp`` ran BEFORE ``_hook_before_replace``. A
# SIGKILL/SIGTERM during the hook thus left a ``.env.staging-*`` file on
# disk with the full replacement payload — an uncatchable-signal leak
# that the existing ``.env.tmp-*`` glob asserts could not see.
#
# The fix is to keep the tmp file named ``.env.tmp-*`` while the hook
# runs, so the existing ghost-tmp spine covers that window, and only
# rename to the staging path immediately before the atomic replace.
# Both tests below lock the new ordering contract.
# ---------------------------------------------------------------------------


def test_hook_runs_before_staging_rename(tmp_path, make_env_file) -> None:
    """While the hook runs, no ``.env.staging-*`` file exists yet.

    This is the load-bearing structural assertion for Major 3: the hook
    must execute against the on-disk state where only ``.env.tmp-*``
    exists. If the staging rename leaks into the hook window, a SIGKILL
    during the hook leaves a ``.env.staging-*`` artifact that the
    existing ghost-tmp spine cannot see.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    observed: dict[str, list[str]] = {"staging": [], "tmp": []}

    def _hook() -> None:
        observed["staging"] = [p.name for p in tmp_path.glob(".env.staging-*")]
        observed["tmp"] = [p.name for p in tmp_path.glob(".env.tmp-*")]

    safe_rewrite(env, b"KEY=new\n", original_user_arg=env, _hook_before_replace=_hook)

    assert observed["staging"] == [], (
        f"staging file existed during hook execution: {observed['staging']}. "
        "Staging rename must occur AFTER the hook so the existing "
        "ghost-tmp spine covers the hook-kill window."
    )
    # Sanity check: the hook must have actually run against a pre-rename
    # on-disk state — i.e. a .env.tmp-* file existed at hook time.
    assert observed["tmp"], (
        "hook ran but no .env.tmp-* was present; the write path may "
        "have skipped the staging step entirely"
    )


def test_hook_raising_leaves_no_staging_or_tmp(tmp_path, make_env_file, sha256_of) -> None:
    """Hook raises → no ``.env.staging-*`` AND no ``.env.tmp-*`` survive.

    Complements the existing ``.env.tmp-*`` cleanup test; explicit
    coverage of the ``.env.staging-*`` glob closes the blind spot
    flagged in the CR thread.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=original\n")
    baseline = sha256_of(env)

    def _boom() -> None:
        raise RuntimeError("synthetic hook crash")

    with pytest.raises((RuntimeError, UnsafeRewriteRefused)):
        safe_rewrite(env, b"KEY=replacement\n", original_user_arg=env, _hook_before_replace=_boom)

    assert sha256_of(env) == baseline
    assert list(tmp_path.glob(".env.tmp-*")) == [], "tmp leaked after hook raise"
    assert list(tmp_path.glob(".env.staging-*")) == [], "staging leaked after hook raise"
