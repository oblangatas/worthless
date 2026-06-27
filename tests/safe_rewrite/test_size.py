"""Size-bound invariants: ``.env`` must be <= 1 MiB and <= 500 lines.

Covers the exact boundaries on both axes plus trailing-newline edge
cases. Size gate sees ``st_size`` from fstat; line gate counts newlines
in the full read buffer.
"""

from __future__ import annotations

import pytest

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.safe_rewrite import safe_rewrite


_ONE_MIB = 1 << 20


def test_accepts_zero_byte_env(tmp_path, make_env_file) -> None:
    """Empty ``.env`` is a valid starting shape; accept."""
    env = make_env_file(tmp_path / ".env", b"")
    new_content = b"KEY=v\n"

    safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content


def test_accepts_one_byte_env(tmp_path, make_env_file) -> None:
    """1-byte ``.env`` (just a newline) is accepted."""
    env = make_env_file(tmp_path / ".env", b"\n")
    new_content = b"KEY=v\n"

    safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content


def test_accepts_1_MiB_exact(tmp_path, make_env_file) -> None:
    """Exactly 1 MiB (at the upper bound) is accepted.

    Structure: ``KEY=`` prefix plus valid dotenv values separated by
    newlines. We pad with a single key-value pair that totals exactly
    1 MiB when combined with its newline.
    """
    # Simplest-valid-dotenv shape of exactly 1 MiB: one key, padded value.
    prefix = b"A="
    remainder = _ONE_MIB - len(prefix) - 1  # -1 for trailing newline
    content = prefix + (b"x" * remainder) + b"\n"
    assert len(content) == _ONE_MIB
    env = make_env_file(tmp_path / ".env", content)

    new_content = b"A=small\n"

    safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content


def test_refuses_1_MiB_plus_one(tmp_path, make_env_file, sha256_of) -> None:
    """1 MiB + 1 byte is over the bound → refused."""
    prefix = b"A="
    # prefix + body fill exactly 1 MiB; the trailing newline pushes us 1 byte over.
    remainder = _ONE_MIB - len(prefix)
    content = prefix + (b"x" * remainder) + b"\n"
    assert len(content) == _ONE_MIB + 1
    env = make_env_file(tmp_path / ".env", content)
    baseline = sha256_of(env)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, b"A=v\n", original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.SIZE
    assert sha256_of(env) == baseline


def test_accepts_499_lines(tmp_path, make_env_file) -> None:
    """499 lines is under the 500-line bound; accepted."""
    content = b"".join(f"K{i}=v\n".encode() for i in range(499))
    env = make_env_file(tmp_path / ".env", content)

    new_content = b"K=v\n"
    safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content


def test_accepts_500_lines_exact(tmp_path, make_env_file) -> None:
    """500 lines exactly is at the bound; accepted."""
    content = b"".join(f"K{i}=v\n".encode() for i in range(500))
    env = make_env_file(tmp_path / ".env", content)

    new_content = b"K=v\n"
    safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content


def test_refuses_501_lines(tmp_path, make_env_file, sha256_of) -> None:
    """501 lines exceeds the 500-line bound; refused."""
    content = b"".join(f"K{i}=v\n".encode() for i in range(501))
    env = make_env_file(tmp_path / ".env", content)
    baseline = sha256_of(env)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, b"K=v\n", original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.SIZE
    assert sha256_of(env) == baseline


def test_500_lines_no_trailing_newline_boundary(tmp_path, make_env_file) -> None:
    """500 entries separated by 499 newlines (no trailing newline) is accepted.

    Counts 500 "logical lines" whether or not the last is newline-terminated.
    The implementation must not miscount the final partial line as a 501st
    line.
    """
    parts = [f"K{i}=v".encode() for i in range(500)]
    content = b"\n".join(parts)  # 499 newlines, no trailing one
    env = make_env_file(tmp_path / ".env", content)

    new_content = b"K=v\n"
    safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content
