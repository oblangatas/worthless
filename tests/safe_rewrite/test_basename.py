"""Basename-equality invariants.

Contains red-first test 3: a plain ``.zshrc`` file (no symlink) must be
refused even when passed directly as the ``safe_rewrite`` target.

The remainder of this module covers the full denylist plus edge cases
(case sensitivity, trailing whitespace, NUL byte, directory basename,
``..env``, ``.env/`` trailing slash, and positive acceptance of a
well-formed ``.env``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.safe_rewrite import safe_rewrite


# ---------------------------------------------------------------------------
# Denylist refusals — one test per entry, exercised as plain files (no
# symlink) passed directly as the rewrite target. Each must refuse with
# ``reason=BASENAME`` and leave the file byte-identical.
# ---------------------------------------------------------------------------


def test_refuses_dot_zshrc_basename(tmp_path, make_env_file, sha256_of) -> None:
    """Passing ``.zshrc`` directly as the target is refused by the basename gate."""
    zshrc = make_env_file(tmp_path / ".zshrc", b"export FOO=bar\n")
    baseline = sha256_of(zshrc)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(
            zshrc,
            b"A=1\n",
            original_user_arg=zshrc,
        )

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(zshrc) == baseline


def test_refuses_dot_bashrc_basename(tmp_path, make_env_file, sha256_of) -> None:
    """``.bashrc`` is on the denylist."""
    p = make_env_file(tmp_path / ".bashrc", b"export BASH_ENV=/etc/bashrc\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_dot_profile_basename(tmp_path, make_env_file, sha256_of) -> None:
    """``.profile`` is on the denylist."""
    p = make_env_file(tmp_path / ".profile", b"export PATH=$PATH:/usr/local/bin\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_dot_netrc_basename(tmp_path, make_env_file, sha256_of) -> None:
    """``.netrc`` (FTP/HTTP credentials) is on the denylist."""
    p = make_env_file(tmp_path / ".netrc", b"machine example.com login user password p\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_id_rsa_basename(tmp_path, make_env_file, sha256_of) -> None:
    """``id_rsa`` (SSH private key) is on the denylist."""
    p = make_env_file(tmp_path / "id_rsa", b"not-a-real-key\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_id_ed25519_basename(tmp_path, make_env_file, sha256_of) -> None:
    """``id_ed25519`` (SSH private key) is on the denylist."""
    p = make_env_file(tmp_path / "id_ed25519", b"not-a-real-key\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_credentials_basename(tmp_path, make_env_file, sha256_of) -> None:
    """``credentials`` (AWS, etc.) is on the denylist."""
    p = make_env_file(tmp_path / "credentials", b"[default]\naws_access_key_id=AKIA\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_config_basename(tmp_path, make_env_file, sha256_of) -> None:
    """``config`` (SSH config, git config, etc.) is on the denylist."""
    p = make_env_file(tmp_path / "config", b"[user]\n\temail = me@example.com\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_authorized_keys_basename(tmp_path, make_env_file, sha256_of) -> None:
    """``authorized_keys`` is on the denylist."""
    p = make_env_file(tmp_path / "authorized_keys", b"ssh-rsa AAAAB3NzaC1 user@host\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_known_hosts_basename(tmp_path, make_env_file, sha256_of) -> None:
    """``known_hosts`` is on the denylist."""
    p = make_env_file(tmp_path / "known_hosts", b"example.com ssh-rsa AAAAB3Nz\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


# ---------------------------------------------------------------------------
# Basename equality — refuse anything that is not literally ``.env``.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Runtime per-env variants (Next.js / Vite / CRA / Rails / Laravel) MUST be
# accepted. These are legitimate secrets files — refusing them breaks the
# tool for users of every major JS framework.
# ---------------------------------------------------------------------------


def test_accepts_dot_env_local(tmp_path, make_env_file) -> None:
    """``.env.local`` — universal convention for local overrides."""
    p = make_env_file(tmp_path / ".env.local", b"KEY=v\n")
    new_content = b"KEY=decoy\n"

    safe_rewrite(p, new_content, original_user_arg=p)

    assert p.read_bytes() == new_content


def test_accepts_dot_env_development(tmp_path, make_env_file) -> None:
    """``.env.development`` — Next.js / CRA / Vite mode file."""
    p = make_env_file(tmp_path / ".env.development", b"KEY=v\n")
    new_content = b"KEY=decoy\n"

    safe_rewrite(p, new_content, original_user_arg=p)

    assert p.read_bytes() == new_content


def test_accepts_dot_env_development_local(tmp_path, make_env_file) -> None:
    """``.env.development.local`` — Next.js layered convention."""
    p = make_env_file(tmp_path / ".env.development.local", b"KEY=v\n")
    new_content = b"KEY=decoy\n"

    safe_rewrite(p, new_content, original_user_arg=p)

    assert p.read_bytes() == new_content


def test_accepts_dot_env_production(tmp_path, make_env_file) -> None:
    """``.env.production`` — mode file with real secrets."""
    p = make_env_file(tmp_path / ".env.production", b"KEY=v\n")
    new_content = b"KEY=decoy\n"

    safe_rewrite(p, new_content, original_user_arg=p)

    assert p.read_bytes() == new_content


def test_accepts_dot_env_production_local(tmp_path, make_env_file) -> None:
    """``.env.production.local`` — Next.js layered convention."""
    p = make_env_file(tmp_path / ".env.production.local", b"KEY=v\n")
    new_content = b"KEY=decoy\n"

    safe_rewrite(p, new_content, original_user_arg=p)

    assert p.read_bytes() == new_content


def test_accepts_dot_env_test(tmp_path, make_env_file) -> None:
    """``.env.test`` — test env mode file."""
    p = make_env_file(tmp_path / ".env.test", b"KEY=v\n")
    new_content = b"KEY=decoy\n"

    safe_rewrite(p, new_content, original_user_arg=p)

    assert p.read_bytes() == new_content


def test_accepts_dot_env_staging(tmp_path, make_env_file) -> None:
    """``.env.staging`` — staging environment file."""
    p = make_env_file(tmp_path / ".env.staging", b"KEY=v\n")
    new_content = b"KEY=decoy\n"

    safe_rewrite(p, new_content, original_user_arg=p)

    assert p.read_bytes() == new_content


def test_accepts_dot_env_testing(tmp_path, make_env_file) -> None:
    """``.env.testing`` — Laravel convention."""
    p = make_env_file(tmp_path / ".env.testing", b"KEY=v\n")
    new_content = b"KEY=decoy\n"

    safe_rewrite(p, new_content, original_user_arg=p)

    assert p.read_bytes() == new_content


# ---------------------------------------------------------------------------
# Template / backup variants MUST be refused. These are checked-into-git
# placeholder files; locking them corrupts the project template.
# ---------------------------------------------------------------------------


def test_refuses_dot_env_example(tmp_path, make_env_file, sha256_of) -> None:
    """``.env.example`` — checked-in template, never real secrets."""
    p = make_env_file(tmp_path / ".env.example", b"KEY=example\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_dot_env_sample(tmp_path, make_env_file, sha256_of) -> None:
    """``.env.sample`` — Rails/Rake convention for placeholders."""
    p = make_env_file(tmp_path / ".env.sample", b"KEY=sample\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_dot_env_template(tmp_path, make_env_file, sha256_of) -> None:
    """``.env.template`` — explicit template marker."""
    p = make_env_file(tmp_path / ".env.template", b"KEY=template\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_dot_env_dist(tmp_path, make_env_file, sha256_of) -> None:
    """``.env.dist`` — Symfony convention for distributed defaults."""
    p = make_env_file(tmp_path / ".env.dist", b"KEY=dist\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_dot_env_defaults(tmp_path, make_env_file, sha256_of) -> None:
    """``.env.defaults`` — checked-in default values, not real secrets."""
    p = make_env_file(tmp_path / ".env.defaults", b"KEY=default\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_dot_env_bak(tmp_path, make_env_file, sha256_of) -> None:
    """``.env.bak`` — user-made backup, not in allowlist."""
    p = make_env_file(tmp_path / ".env.bak", b"KEY=v\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_dot_ENV_case_sensitive(tmp_path, make_env_file, sha256_of) -> None:
    """``.ENV`` (uppercase) must be refused even on case-insensitive filesystems."""
    # On APFS / HFS+ the kernel may happily resolve ``.ENV`` and ``.env`` to the
    # same inode; the basename check is case-sensitive regardless.
    p = make_env_file(tmp_path / ".ENV", b"KEY=v\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_accepts_literal_dot_env(tmp_path, make_env_file) -> None:
    """Positive control: a plain ``.env`` passes the basename gate."""
    p = make_env_file(tmp_path / ".env", b"KEY=value\n")
    new_content = b"KEY=replacement\n"

    # Must not raise: the basename is the only explicitly-accepted value.
    safe_rewrite(p, new_content, original_user_arg=p)

    assert p.read_bytes() == new_content


def test_refuses_notes_txt(tmp_path, make_env_file, sha256_of) -> None:
    """``notes.txt`` is not ``.env`` and not on the denylist, still refused."""
    p = make_env_file(tmp_path / "notes.txt", b"hello world\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_double_dot_env(tmp_path, make_env_file, sha256_of) -> None:
    """``..env`` (double leading dot) is not ``.env`` → refused."""
    p = make_env_file(tmp_path / "..env", b"KEY=v\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_dot_env_directory(tmp_path) -> None:
    """A directory named ``.env`` (not a file) is refused.

    The special-file / stat gate will fire; what matters is we refuse
    before any write happens. Accept any refusal reason: the directory
    stat itself is the signal.
    """
    env_dir = tmp_path / ".env"
    env_dir.mkdir()

    with pytest.raises(UnsafeRewriteRefused):
        safe_rewrite(env_dir, b"A=1\n", original_user_arg=env_dir)

    # Directory still exists, untouched, no tmp leak.
    assert env_dir.is_dir()
    assert list(tmp_path.glob(".env.tmp-*")) == []


def test_refuses_dot_env_trailing_space(tmp_path, make_env_file, sha256_of) -> None:
    """A basename ``.env `` with trailing space is not ``.env`` → refused."""
    # Some filesystems preserve trailing spaces in filenames.
    p = make_env_file(tmp_path / ".env ", b"KEY=v\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.BASENAME
    assert sha256_of(p) == baseline


def test_refuses_nul_byte_in_path(tmp_path) -> None:
    """A path containing an embedded NUL byte is refused cleanly, no crash.

    ``pathlib.Path`` may itself reject this at construction. The contract
    is: we do not crash with a C-level abort and we never write anything.
    Any refusal (typed as ``UnsafeRewriteRefused`` or a clean
    ``ValueError``) is acceptable.
    """
    env = tmp_path / ".env"
    env.write_bytes(b"KEY=v\n")

    poisoned = Path(str(env) + "\x00.zshrc")

    with pytest.raises((UnsafeRewriteRefused, ValueError, OSError)):
        safe_rewrite(
            poisoned,
            b"A=1\n",
            original_user_arg=poisoned,
        )

    # Sibling ``.env`` is untouched.
    assert env.read_bytes() == b"KEY=v\n"
    assert list(tmp_path.glob(".env.tmp-*")) == []
