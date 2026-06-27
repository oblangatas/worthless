"""Size-delta invariant: blowup-only ceiling (new/old <= 4x) for single-line files.

Shrinks are accepted regardless of ratio — locking a long real key with a
short decoy shrinks the file 4x-8x and is the product's primary use case.
Attack value of single-line truncation is near-zero because basename,
path-identity, and sniff invariants already block content substitution.
"""

from __future__ import annotations

import pytest

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.safe_rewrite import safe_rewrite


def test_refuses_10x_blowup(tmp_path, make_env_file, sha256_of) -> None:
    """A 10x larger new_content is refused as unrealistic for a ``.env`` edit."""
    original = b"KEY=" + b"a" * 96 + b"\n"  # 101 bytes
    env = make_env_file(tmp_path / ".env", original)
    baseline = sha256_of(env)

    blown_up = b"KEY=" + b"x" * (len(original) * 10) + b"\n"

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(
            env,
            blown_up,
            original_user_arg=env,
        )

    assert exc_info.value.reason == UnsafeReason.DELTA
    assert sha256_of(env) == baseline


def test_accepts_5x_shrink_first_run(tmp_path, make_env_file, sha256_of) -> None:
    """200-char real API key -> 40-char decoy is a 5x shrink; accepted post-v2."""
    # Realistic first-run: a long provider key being replaced by a short decoy.
    original_key = b"sk-" + b"A" * 197  # 200 bytes
    assert len(original_key) == 200
    original = b"OPENAI_API_KEY=" + original_key + b"\n"
    env = make_env_file(tmp_path / ".env", original)

    # Decoy roughly 1/5 of the original size.
    decoy_value = b"sk-decoy-" + b"0" * 31  # 40 bytes
    assert len(decoy_value) == 40
    new_content = b"OPENAI_API_KEY=" + decoy_value + b"\n"

    # Must NOT raise — this is the first-run shape we explicitly widened
    # the delta bounds to accommodate.
    safe_rewrite(
        env,
        new_content,
        original_user_arg=env,
    )

    assert env.read_bytes() == new_content


def test_accepts_realistic_openai_sk_proj_shrink(tmp_path, make_env_file) -> None:
    """Real scenario: 165-char OpenAI sk-proj- key -> 24-char decoy.

    Ratio ~0.22 — below the former 0.25 floor. Must be accepted because
    this is exactly what ``worthless lock`` does to a single-key .env.
    """
    original = b"OPENAI_API_KEY=sk-proj-" + b"A" * 157 + b"\n"  # ~181 B
    assert len(original) == 181
    env = make_env_file(tmp_path / ".env", original)

    decoy = b"OPENAI_API_KEY=" + b"0" * 24 + b"\n"  # 40 B
    assert len(decoy) / len(original) < 0.25  # below former floor

    safe_rewrite(env, decoy, original_user_arg=env)

    assert env.read_bytes() == decoy


def test_accepts_extreme_shrink_single_line(tmp_path, make_env_file) -> None:
    """Single-line file may shrink arbitrarily; only blowups are attacks."""
    original = b"KEY=" + b"a" * 996 + b"\n"  # ~1001 bytes
    env = make_env_file(tmp_path / ".env", original)

    tiny = b"A=b\n"  # 4 bytes, ~0.004x of original

    safe_rewrite(env, tiny, original_user_arg=env)

    assert env.read_bytes() == tiny


def test_accepts_empty_to_anything(tmp_path, make_env_file) -> None:
    """An empty starting ``.env`` accepts any (valid-dotenv) new_content.

    Delta is undefined when old_size == 0; the implementation must skip
    the ratio check in that case.
    """
    env = make_env_file(tmp_path / ".env", b"")
    new_content = b"OPENAI_API_KEY=sk-decoy-1234\n"

    safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content


def test_accepts_exact_4x_bound(tmp_path, make_env_file) -> None:
    """4x exactly (upper bound inclusive) is accepted."""
    # Use a size that doesn't also trip the sniff or line-count gates.
    original = b"A=" + b"x" * 7 + b"\n"  # 10 bytes
    env = make_env_file(tmp_path / ".env", original)

    # Exactly 4x => 40 bytes.
    new_content = b"A=" + b"y" * 37 + b"\n"
    assert len(new_content) == 4 * len(original)

    safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content


def test_refuses_just_over_4x(tmp_path, make_env_file, sha256_of) -> None:
    """4x + 1 byte is over the upper bound → refused (off-by-one check)."""
    original = b"A=" + b"x" * 7 + b"\n"  # 10 bytes
    env = make_env_file(tmp_path / ".env", original)
    baseline = sha256_of(env)

    new_content = b"A=" + b"y" * 38 + b"\n"  # 41 bytes = 4.1x
    assert len(new_content) == 4 * len(original) + 1

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, new_content, original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.DELTA
    assert sha256_of(env) == baseline


def test_accepts_just_under_quarter(tmp_path, make_env_file) -> None:
    """Below the former 0.25x floor is now accepted — shrink floor removed."""
    # Original: 100 bytes. 0.25x = 25; just under = 24.
    original = b"A=" + b"x" * 97 + b"\n"  # 100 bytes
    env = make_env_file(tmp_path / ".env", original)

    new_content = b"A=" + b"y" * 21 + b"\n"  # 24 bytes
    assert len(new_content) * 4 < len(original)  # strictly under 0.25x

    safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content
