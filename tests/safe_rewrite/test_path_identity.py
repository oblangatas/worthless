"""Path-identity invariants: symlinks, hardlinks, and realpath checks.

Note: the trailing-slash attack vector is structurally neutralized by
pathlib.Path normalization at the API boundary; no test needed at this layer.

Contains the three RED-FIRST tests that justify the entire ticket:

* ``test_refuses_symlink_to_zshrc`` — the literal ".zshrc lock bug"
* ``test_refusal_preserves_zshrc_sha256`` — sha256 negative-space spine
* ``test_refuses_hardlink_to_denylisted_inode``

Remaining tests cover: symlink to another ``.env``, ``original_user_arg``
mismatch against the resolved target, positive regular-file acceptance,
``//`` double-slash normalisation, and ``../.env`` traversal.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.safe_rewrite import safe_rewrite


# ---------------------------------------------------------------------------
# Red test 1 — the user's red line.
# ---------------------------------------------------------------------------


def test_refuses_symlink_to_zshrc(tmp_path, make_env_file, sha256_of) -> None:
    """A ``.env`` symlink pointing at ``~/.zshrc`` must be refused.

    This is the literal bug the ticket exists to prevent. Four invariants
    can fire: symlink check, basename refuse-on-resolve, path-identity,
    and (defence-in-depth) O_NOFOLLOW open. Any of them is acceptable;
    what matters is that the rewrite is refused AND the zshrc file
    remains byte-identical.
    """
    real_zshrc = make_env_file(tmp_path / "home" / ".zshrc", b"# my zsh rc\nexport PS1='$ '\n")
    baseline = sha256_of(real_zshrc)

    env_link = tmp_path / "project" / ".env"
    env_link.parent.mkdir(parents=True, exist_ok=True)
    env_link.symlink_to(real_zshrc)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(
            env_link,
            b"DECOY=value\n",
            original_user_arg=env_link,
        )

    assert exc_info.value.reason in {
        UnsafeReason.SYMLINK,
        UnsafeReason.PATH_IDENTITY,
        UnsafeReason.BASENAME,
    }
    assert sha256_of(real_zshrc) == baseline


# ---------------------------------------------------------------------------
# Red test 2 — sha256-preserved negative-space spine.
# ---------------------------------------------------------------------------


def test_refusal_preserves_zshrc_sha256(tmp_path, make_env_file, sha256_of) -> None:
    """On refusal, no write of any kind touches the resolved target."""
    real_zshrc = make_env_file(
        tmp_path / "home" / ".zshrc",
        b"# critical shell configuration\nsource ~/.zprofile\n",
    )
    baseline = sha256_of(real_zshrc)

    env_link = tmp_path / "project" / ".env"
    env_link.parent.mkdir(parents=True, exist_ok=True)
    env_link.symlink_to(real_zshrc)

    with pytest.raises(UnsafeRewriteRefused):
        safe_rewrite(
            env_link,
            b"A=1\n",
            original_user_arg=env_link,
        )

    assert sha256_of(real_zshrc) == baseline, "zshrc must be byte-identical after refusal"


# ---------------------------------------------------------------------------
# Red test 4 — hardlink to a denylisted inode.
# ---------------------------------------------------------------------------


def test_refuses_hardlink_to_denylisted_inode(tmp_path, make_env_file, sha256_of) -> None:
    """A ``.env`` hardlinked to a ``.zshrc`` inode must be refused.

    Hardlinks defeat ``realpath``/``lstat`` symlink checks (both paths
    resolve to themselves). The containment / path-identity gate must
    still refuse via the fstat(dev, ino) comparison.
    """
    real_zshrc = make_env_file(tmp_path / ".zshrc", b"export ZDOTDIR=/tmp\n")
    baseline = sha256_of(real_zshrc)

    env_hardlink = tmp_path / ".env"
    os.link(str(real_zshrc), str(env_hardlink))

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(
            env_hardlink,
            b"KEY=decoy\n",
            original_user_arg=env_hardlink,
        )

    assert exc_info.value.reason in {
        UnsafeReason.PATH_IDENTITY,
        UnsafeReason.BASENAME,
        UnsafeReason.CONTAINMENT,
    }
    assert sha256_of(real_zshrc) == baseline


# ---------------------------------------------------------------------------
# Additional path-identity tests.
# ---------------------------------------------------------------------------


def test_refuses_symlink_to_other_env(tmp_path, make_env_file, sha256_of) -> None:
    """A ``.env`` symlink pointing at a different ``.env`` file is refused.

    Even though both ends are named ``.env``, the symlink gate fires
    (O_NOFOLLOW / lstat) because we refuse *all* symlinks for this
    operation — the linked file may be outside the repo, under another
    user, or otherwise surprising.
    """
    real_env = make_env_file(tmp_path / "other" / ".env", b"OPENAI_API_KEY=sk-xxx\n")
    baseline = sha256_of(real_env)

    env_link = tmp_path / "project" / ".env"
    env_link.parent.mkdir(parents=True, exist_ok=True)
    env_link.symlink_to(real_env)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(
            env_link,
            b"A=1\n",
            original_user_arg=env_link,
        )

    assert exc_info.value.reason in {
        UnsafeReason.SYMLINK,
        UnsafeReason.PATH_IDENTITY,
    }
    assert sha256_of(real_env) == baseline


def test_refuses_original_user_arg_mismatch(tmp_path, make_env_file, sha256_of) -> None:
    """If ``original_user_arg`` resolves differently than ``target`` → refuse.

    Imagine a caller that has already followed a symlink for convenience
    and passes the resolved path as ``target`` but the pre-resolution
    user input as ``original_user_arg``. The path-identity gate must
    notice and refuse, even if the resolved path is a safe ``.env``.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(env)

    # original_user_arg points somewhere else entirely (different inode,
    # different name). The identity check must refuse.
    other = make_env_file(tmp_path / "other" / ".env", b"OTHER=v\n")

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(
            env,
            b"A=1\n",
            original_user_arg=other,
        )

    assert exc_info.value.reason in {
        UnsafeReason.PATH_IDENTITY,
        UnsafeReason.CONTAINMENT,
    }
    assert sha256_of(env) == baseline


def test_accepts_regular_file_env(tmp_path, make_env_file) -> None:
    """Positive control: a regular-file ``.env`` with matching args is accepted.

    No symlinks, no hardlinks, basename is literal ``.env``, original arg
    matches target → path-identity gate passes.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=original\n")
    new_content = b"KEY=updated\n"

    safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content


def test_accepts_double_slash_path(tmp_path, make_env_file) -> None:
    """``/project//.env`` normalises to ``/project/.env`` and is accepted.

    POSIX semantics collapse ``//`` to ``/`` (except leading ``//`` on
    some systems). The path-identity gate must not be tripped by a
    purely cosmetic double-slash in the user input.
    """
    env = make_env_file(tmp_path / ".env", b"KEY=v\n")
    new_content = b"KEY=new\n"

    weird = Path(str(tmp_path) + "//.env")

    safe_rewrite(env, new_content, original_user_arg=weird)

    assert env.read_bytes() == new_content


def test_refuses_dot_dot_traversal(tmp_path, make_env_file, sha256_of) -> None:
    """A ``../.env`` path that escapes the repo root is refused.

    Containment-overlap with path-identity: the realpath of the resolved
    target must not escape ``repo_root``.
    """
    # Build: repo/.git, file lives at parent_of_repo/.env (outside repo).
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    outside = make_env_file(tmp_path / ".env", b"KEY=v\n")
    baseline = sha256_of(outside)

    traversal = repo / ".." / ".env"

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(
            traversal,
            b"A=1\n",
            original_user_arg=traversal,
            repo_root=repo,
        )

    assert exc_info.value.reason in {
        UnsafeReason.CONTAINMENT,
        UnsafeReason.PATH_IDENTITY,
    }
    assert sha256_of(outside) == baseline
