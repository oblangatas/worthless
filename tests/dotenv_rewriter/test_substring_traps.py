"""Exact-key matching tests: substrings must never collide with the target.

A naive "line contains KEY=" implementation collides with:

* ``MY_API_KEY`` when the target is ``API_KEY`` (longer key containing target).
* ``OTHER=API_KEY=hidden`` (target name appearing inside another value).
* ``# API_KEY=oldvalue`` (target appearing in a comment).
* ``NOT_API_KEY=x`` (target appearing as a suffix of another key).

The logical-line scanner MUST do exact left-of-``=`` match after
stripping the optional ``export`` prefix and leading whitespace.
"""

from __future__ import annotations

from pathlib import Path


def test_does_not_match_key_when_target_is_substring(tmp_path: Path, make_env_file) -> None:
    """``API_KEY`` rewrite MUST NOT touch ``MY_API_KEY`` (substring collision)."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"MY_API_KEY=do_not_touch\nAPI_KEY=old\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    # MY_API_KEY must survive byte-for-byte; only API_KEY's value changed.
    assert b"MY_API_KEY=do_not_touch\n" in after, (
        f"substring collision clobbered MY_API_KEY:\n  before={before!r}\n  after ={after!r}"
    )
    assert b"API_KEY=new\n" in after


def test_does_not_match_key_inside_value(tmp_path: Path, make_env_file) -> None:
    """The target name appearing *inside* another value MUST NOT match."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    # OTHER's value literally contains the substring "API_KEY=hidden".
    before = b"OTHER=API_KEY=hidden\nAPI_KEY=old\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    # OTHER's raw bytes unchanged; only the real API_KEY line mutated.
    assert b"OTHER=API_KEY=hidden\n" in after, (
        f"target matched inside another value:\n  before={before!r}\n  after ={after!r}"
    )
    assert b"API_KEY=new\n" in after


def test_does_not_match_commented_out_assignment(tmp_path: Path, make_env_file) -> None:
    """A ``# API_KEY=oldvalue`` comment MUST NOT match the rewrite target."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"# API_KEY=commented_out_value\nAPI_KEY=real_old\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    # The comment must survive verbatim.
    assert b"# API_KEY=commented_out_value\n" in after, (
        f"comment treated as assignment:\n  before={before!r}\n  after ={after!r}"
    )
    assert b"API_KEY=new\n" in after
    assert b"real_old" not in after


def test_does_not_match_assignment_to_different_prefixed_key(tmp_path: Path, make_env_file) -> None:
    """A sibling key like ``NOT_API_KEY`` MUST NOT collide with ``API_KEY``.

    Tests the other end of the substring trap: target appearing as a
    suffix (rather than prefix) of another key name.
    """
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"NOT_API_KEY=do_not_touch\nAPI_KEY=old\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    assert b"NOT_API_KEY=do_not_touch\n" in after, (
        f"suffix collision clobbered NOT_API_KEY:\n  before={before!r}\n  after ={after!r}"
    )
    assert b"API_KEY=new\n" in after
