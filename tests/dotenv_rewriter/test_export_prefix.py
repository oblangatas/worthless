"""Export-prefix preservation tests.

The dotenv spec allows ``export KEY=value`` lines for shell-sourceable
files. The rewriter must preserve the ``export`` prefix on a value change,
drop the entire line (prefix and all) on remove, and NOT add ``export``
to brand-new keys.
"""

from __future__ import annotations

from pathlib import Path


def test_rewrite_preserves_export_prefix(tmp_path: Path, make_env_file) -> None:
    """``rewrite_env_key`` on an ``export KEY=...`` line MUST keep the prefix."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"export API_KEY=old_value\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new_value")

    after = env.read_bytes()
    assert after == b"export API_KEY=new_value\n", (
        f"export prefix lost:\n  before={before!r}\n  after ={after!r}"
    )


def test_remove_drops_exported_line_and_nothing_else(tmp_path: Path, make_env_file) -> None:
    """``remove_env_key`` on an ``export`` line MUST drop the entire line."""
    from worthless.cli.dotenv_rewriter import remove_env_key

    before = b"FIRST=one\nexport API_KEY=secret\nLAST=tail\n"
    env = make_env_file(tmp_path / ".env", content=before)

    remove_env_key(env, "API_KEY")

    after = env.read_bytes()
    assert after == b"FIRST=one\nLAST=tail\n", (
        f"remove damage:\n  before={before!r}\n  after ={after!r}"
    )


def test_add_does_not_add_export_prefix_to_new_keys(tmp_path: Path, make_env_file) -> None:
    """``add_or_rewrite_env_key`` for a NEW key MUST NOT emit ``export``.

    The prefix is a caller concern; the rewriter never assumes it on
    append.
    """
    from worthless.cli.dotenv_rewriter import add_or_rewrite_env_key

    before = b"EXISTING=keep\n"
    env = make_env_file(tmp_path / ".env", content=before)

    add_or_rewrite_env_key(env, "NEW_KEY", "new_value")

    after = env.read_bytes()
    assert b"export NEW_KEY" not in after, f"export added to new key spuriously: {after!r}"
    assert after == b"EXISTING=keep\nNEW_KEY=new_value\n"


def test_export_with_unusual_whitespace_preserved(tmp_path: Path, make_env_file) -> None:
    """``export   KEY=value`` (unusual whitespace) MUST round-trip byte-identical.

    The rewriter tracks raw line bytes, not a reconstructed
    ``export KEY=value`` canonical form, so exotic whitespace between
    ``export`` and the key name is preserved even across a value change.
    """
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    # Three spaces between `export` and the key; one tab after the `=`.
    before = b"export   API_KEY=old_value\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new_value")

    after = env.read_bytes()
    assert after == b"export   API_KEY=new_value\n", (
        f"export whitespace not preserved byte-identically:\n"
        f"  before={before!r}\n  after ={after!r}"
    )
