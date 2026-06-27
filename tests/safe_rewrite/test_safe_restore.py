"""Recovery-path invariants: ``safe_restore`` bypasses DELTA, nothing else.

WOR-276 Phase 3 introduces a narrow recovery entry point for the lock
checkpoint restore path: ``safe_restore`` dispatches to
``_safe_rewrite_core(skip_delta=True, ...)`` so that large decoy -> original
swaps (which the DELTA gate would otherwise refuse as unrealistic blowups)
can complete. The invariant being tested is that DELTA is the *only* gate
``safe_restore`` bypasses — SYMLINK, SIZE, TOCTOU, and CONTAINMENT must
still fire — and that the ``skip_delta`` escape hatch is not reachable
through the public ``safe_rewrite`` signature.
"""

from __future__ import annotations

import inspect
import os
import sys
from pathlib import Path

import pytest

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.safe_rewrite import safe_rewrite


pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="safe_rewrite suite is macOS + Linux only",
)


_ONE_MIB: int = 1 << 20
_OVER_LIMIT_BYTES: int = _ONE_MIB + 1


# ---------------------------------------------------------------------------
# Module-scope setup helpers for the parametrised non-DELTA gate matrix.
#
# Each helper mutates the filesystem to stage the gate's precondition and
# returns the ``(target, new_content)`` pair that ``safe_restore`` should
# then be asked to rewrite. The returned target is always the path the
# caller should pass as ``original_user_arg``.
# ---------------------------------------------------------------------------


def _setup_symlink(tmp_path: Path) -> tuple[Path, bytes]:
    """Stage a symlink at ``.env`` pointing to ``/dev/null``."""
    env_link = tmp_path / ".env"
    env_link.symlink_to("/dev/null")
    return env_link, b"KEY=restored\n"


def _setup_oversize_target(tmp_path: Path) -> tuple[Path, bytes]:
    """Stage an existing target whose ``st_size`` exceeds the 1 MiB gate.

    Uses ``os.ftruncate`` to produce a sparse file so the test does not
    actually allocate >1 MiB of disk. The SIZE gate reads ``st_size`` from
    fstat, so the sparse hole is indistinguishable from a real file for
    gate purposes.
    """
    env = tmp_path / ".env"
    fd = os.open(str(env), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.ftruncate(fd, _OVER_LIMIT_BYTES)
    finally:
        os.close(fd)
    return env, b"KEY=restored\n"


def _setup_toctou_swap(tmp_path: Path) -> tuple[Path, bytes, object]:
    """Stage a legitimate ``.env`` plus a hook that swaps the inode mid-op."""
    env = tmp_path / ".env"
    fd = os.open(str(env), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, b"KEY=original\n")
    finally:
        os.close(fd)
    env.chmod(0o600)

    def _swap_inode() -> None:
        env.unlink()
        swap_fd = os.open(str(env), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(swap_fd, b"KEY=attacker\n")
        finally:
            os.close(swap_fd)

    return env, b"KEY=restored\n", _swap_inode


def _setup_outside_repo(tmp_path: Path) -> tuple[Path, bytes, Path]:
    """Stage a ``.env`` outside the fake repo root.

    The repo is ``tmp_path / "repo"`` (with a ``.git`` marker), and the
    target lives at ``tmp_path / "elsewhere" / ".env"`` — a sibling of
    the repo, so containment must refuse.
    """
    repo_root = tmp_path / "repo"
    (repo_root / ".git").mkdir(parents=True)

    outside_dir = tmp_path / "elsewhere"
    outside_dir.mkdir()
    env = outside_dir / ".env"
    fd = os.open(str(env), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, b"KEY=v\n")
    finally:
        os.close(fd)
    env.chmod(0o600)
    return env, b"KEY=restored\n", repo_root


# ---------------------------------------------------------------------------
# Test 36: DELTA bypass is the whole point of ``safe_restore``.
# ---------------------------------------------------------------------------


def test_safe_restore_bypasses_delta_only(tmp_path, make_env_file) -> None:
    """Invariant: ``safe_restore`` succeeds where ``safe_rewrite`` refuses on DELTA.

    A 10-byte decoy being swapped back to a 10 KiB original is a 1024x
    blowup — ``safe_rewrite`` must refuse with ``UnsafeReason.DELTA``;
    ``safe_restore`` must accept the same rewrite byte-for-byte.
    """
    from worthless.cli.safe_rewrite import safe_restore  # RED: doesn't exist yet

    env = make_env_file(tmp_path / ".env", b"KEY=old\n\n")
    original_content = b"x" * 10_240

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, original_content, original_user_arg=env)
    assert exc_info.value.reason == UnsafeReason.DELTA

    safe_restore(env, original_content, original_user_arg=env)

    assert env.read_bytes() == original_content
    assert len(env.read_bytes()) == 10_240


# ---------------------------------------------------------------------------
# Test 37: every non-DELTA gate still fires through ``safe_restore``.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "gate",
    ["symlink", "size_over_limit", "toctou_swap", "containment_outside_repo"],
)
def test_safe_restore_still_enforces_symlink_size_toctou_containment(tmp_path, gate: str) -> None:
    """Invariant: ``safe_restore`` bypasses DELTA only — every other gate fires.

    Parametrised over the four gates that callers of the recovery path
    could conceivably trip with a malicious or broken on-disk state.
    Each case must refuse with the gate-appropriate ``UnsafeReason``.
    """
    from worthless.cli.safe_rewrite import safe_restore  # RED: doesn't exist yet

    expected_reasons: dict[str, set[UnsafeReason]]
    expected_reasons = {
        "symlink": {UnsafeReason.SYMLINK},
        "size_over_limit": {UnsafeReason.SIZE},
        "toctou_swap": {UnsafeReason.TOCTOU, UnsafeReason.IO_ERROR},
        "containment_outside_repo": {UnsafeReason.CONTAINMENT},
    }

    if gate == "symlink":
        target, new_content = _setup_symlink(tmp_path)
        with pytest.raises(UnsafeRewriteRefused) as exc_info:
            safe_restore(target, new_content, original_user_arg=target)
    elif gate == "size_over_limit":
        target, new_content = _setup_oversize_target(tmp_path)
        with pytest.raises(UnsafeRewriteRefused) as exc_info:
            safe_restore(target, new_content, original_user_arg=target)
    elif gate == "toctou_swap":
        target, new_content, hook = _setup_toctou_swap(tmp_path)
        with pytest.raises(UnsafeRewriteRefused) as exc_info:
            safe_restore(
                target,
                new_content,
                original_user_arg=target,
                _hook_before_replace=hook,
            )
    elif gate == "containment_outside_repo":
        target, new_content, repo_root = _setup_outside_repo(tmp_path)
        with pytest.raises(UnsafeRewriteRefused) as exc_info:
            safe_restore(
                target,
                new_content,
                original_user_arg=target,
                repo_root=repo_root,
            )
    else:  # pragma: no cover — parametrise guards this
        pytest.fail(f"unknown gate: {gate}")

    assert exc_info.value.reason in expected_reasons[gate], (
        f"gate={gate}: got {exc_info.value.reason}, expected one of {expected_reasons[gate]}"
    )


# ---------------------------------------------------------------------------
# Test 37b: public-surface guard — ``skip_delta`` must not leak out.
# ---------------------------------------------------------------------------


def test_safe_rewrite_public_surface_has_no_skip_delta() -> None:
    """Invariant: ``skip_delta`` is a private core-only knob.

    Exposing ``skip_delta`` on ``safe_rewrite`` would let any caller
    bypass the DELTA gate — the whole point of routing recovery through
    a separate ``safe_restore`` entry point is to keep DELTA non-optional
    on the normal write path.
    """
    sig = inspect.signature(safe_rewrite)
    assert "skip_delta" not in sig.parameters, (
        "safe_rewrite() must not expose skip_delta — only safe_restore() bypasses DELTA"
    )


def test_safe_rewrite_core_is_private_and_accepts_skip_delta() -> None:
    """Invariant: ``_safe_rewrite_core`` is the private seam, parameterised by ``skip_delta``.

    The refactor splits gate pipeline from public entry points: both
    ``safe_rewrite`` and ``safe_restore`` dispatch to ``_safe_rewrite_core``,
    differing only in ``skip_delta``. This guard fails until the core
    exists with the documented knob.
    """
    from worthless.cli.safe_rewrite import _safe_rewrite_core  # RED: doesn't exist yet

    sig = inspect.signature(_safe_rewrite_core)
    assert "skip_delta" in sig.parameters, (
        "_safe_rewrite_core must accept skip_delta so safe_restore can opt out of DELTA"
    )
