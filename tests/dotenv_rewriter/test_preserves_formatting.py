"""Formatting-preservation tests: one byte changes, every other byte stays.

A line-preserving rewriter routes single-key edits through the safety
gate without losing comments, blank lines, key ordering, EOL style, or
BOM. These tests pin the serializer's output byte-for-byte on a
representative set of dotenv shapes.

Each test builds an explicit ``before`` byte string, calls the
rewriter, and asserts the exact ``after`` byte string. Hexdump-on-fail
makes regressions obvious.
"""

from __future__ import annotations

from pathlib import Path


def test_preserves_leading_comments(tmp_path: Path, make_env_file) -> None:
    """Leading ``# comment`` lines MUST survive a value-change byte-for-byte."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"# leading comment one\n# leading comment two\nAPI_KEY=old\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    assert after == b"# leading comment one\n# leading comment two\nAPI_KEY=new\n", (
        f"leading comments lost:\n  before={before!r}\n  after ={after!r}"
    )


def test_preserves_trailing_comments(tmp_path: Path, make_env_file) -> None:
    """Trailing ``# comment`` lines MUST survive a value-change byte-for-byte."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"API_KEY=old\n# trailing comment\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    assert after == b"API_KEY=new\n# trailing comment\n", (
        f"trailing comment lost:\n  before={before!r}\n  after ={after!r}"
    )


def test_preserves_blank_lines(tmp_path: Path, make_env_file) -> None:
    """Blank lines between entries MUST survive a value-change byte-for-byte."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"FIRST=one\n\nAPI_KEY=old\n\nLAST=tail\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    assert after == b"FIRST=one\n\nAPI_KEY=new\n\nLAST=tail\n", (
        f"blank lines lost:\n  before={before!r}\n  after ={after!r}"
    )


def test_preserves_inline_comments_on_other_lines(tmp_path: Path, make_env_file) -> None:
    """A ``# comment`` mid-file on an unrelated line MUST survive intact."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"FIRST=one\n# a lonely comment\nAPI_KEY=old\nLAST=tail\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    assert after == b"FIRST=one\n# a lonely comment\nAPI_KEY=new\nLAST=tail\n"


def test_preserves_key_ordering(tmp_path: Path, make_env_file) -> None:
    """Key order MUST be preserved across a single-value rewrite."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"Z_KEY=z\nA_KEY=a\nAPI_KEY=old\nM_KEY=m\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    assert after == b"Z_KEY=z\nA_KEY=a\nAPI_KEY=new\nM_KEY=m\n"


def test_preserves_lf_eol(tmp_path: Path, make_env_file) -> None:
    """LF-only line endings MUST NOT be promoted to CRLF."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"FIRST=one\nAPI_KEY=old\nLAST=tail\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    assert b"\r\n" not in after, f"LF was promoted to CRLF: {after!r}"
    assert after == b"FIRST=one\nAPI_KEY=new\nLAST=tail\n"


def test_preserves_crlf_eol(tmp_path: Path, make_env_file) -> None:
    """CRLF line endings MUST be preserved (Windows-edited .env files)."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"FIRST=one\r\nAPI_KEY=old\r\nLAST=tail\r\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    assert after == b"FIRST=one\r\nAPI_KEY=new\r\nLAST=tail\r\n", (
        f"CRLF not preserved:\n  before={before!r}\n  after ={after!r}"
    )


def test_preserves_no_trailing_newline_then_appends_one_with_new_key(
    tmp_path: Path, make_env_file
) -> None:
    """Appending to a file without a trailing newline MUST add the EOL first."""
    from worthless.cli.dotenv_rewriter import add_or_rewrite_env_key

    before = b"EXISTING=keep"  # no trailing newline
    env = make_env_file(tmp_path / ".env", content=before)

    add_or_rewrite_env_key(env, "NEW_KEY", "new_value")

    after = env.read_bytes()
    # Previous line must get its trailing newline; new line ends with one too.
    assert after == b"EXISTING=keep\nNEW_KEY=new_value\n", (
        f"missing trailing newline before append:\n  before={before!r}\n  after ={after!r}"
    )


def test_preserves_utf8_bom_at_file_start(tmp_path: Path, make_env_file) -> None:
    """A UTF-8 BOM prefix MUST round-trip through a value rewrite intact."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    bom = b"\xef\xbb\xbf"
    before = bom + b"API_KEY=old\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    assert after.startswith(bom), f"UTF-8 BOM stripped: {after!r}"
    assert after == bom + b"API_KEY=new\n"


def test_byte_diff_minimal_for_single_value_change(tmp_path: Path, make_env_file) -> None:
    """A single-value rewrite MUST touch exactly the matched line.

    Build a richly-formatted file, rewrite one key, and assert that
    every other line is byte-identical between before and after.
    """
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = (
        b"# Production keys\n"
        b"OPENAI_API_KEY=sk-real-1234\n"
        b"\n"
        b"DATABASE_URL=postgres://localhost/db\n"
        b'ANTHROPIC_API_KEY="sk-ant-real"\n'
    )
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "ANTHROPIC_API_KEY", "sk-ant-decoy-0001")

    after = env.read_bytes()
    before_lines = before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)
    assert len(before_lines) == len(after_lines), (
        f"line count changed: {len(before_lines)} -> {len(after_lines)}"
    )
    diffs = [(i, b, a) for i, (b, a) in enumerate(zip(before_lines, after_lines)) if b != a]
    assert len(diffs) == 1, f"expected exactly one line to change, got {len(diffs)}: {diffs}"
    changed_index, _, changed_after = diffs[0]
    assert b"ANTHROPIC_API_KEY" in changed_after
    assert b"sk-ant-decoy-0001" in changed_after
    _ = changed_index  # anchor for readability


def test_idempotent_rewrite_with_same_value(tmp_path: Path, make_env_file) -> None:
    """Calling ``rewrite_env_key`` with the existing value MUST be byte-identical.

    Idempotency is non-trivial because the safety gate's delta check can
    refuse near-equal rewrites. The serializer must emit the exact same
    bytes when asked to "rewrite" a value to its current value.
    """
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"# header\nAPI_KEY=same_value\nTAIL=end\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "same_value")

    after = env.read_bytes()
    assert after == before, (
        f"idempotent rewrite changed bytes:\n  before={before!r}\n  after ={after!r}"
    )


def test_rewrite_preserves_double_quotes(tmp_path: Path, make_env_file) -> None:
    """``KEY="old"`` rewrite MUST keep the surrounding double quotes.

    A line's original quote style is part of its formatting. A rewrite
    that strips ``"`` silently mutates every quoted var on its first
    touch - a regression from the "one byte changes, the rest stays"
    goal.
    """
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b'API_KEY="old"\nOTHER=keep\n'
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    assert after == b'API_KEY="new"\nOTHER=keep\n', (
        f"double quotes lost on rewrite:\n  before={before!r}\n  after ={after!r}"
    )


def test_rewrite_preserves_single_quotes(tmp_path: Path, make_env_file) -> None:
    """``KEY='old'`` rewrite MUST keep the surrounding single quotes."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"API_KEY='old'\nOTHER=keep\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    assert after == b"API_KEY='new'\nOTHER=keep\n", (
        f"single quotes lost on rewrite:\n  before={before!r}\n  after ={after!r}"
    )


def test_rewrite_preserves_trailing_inline_comment(tmp_path: Path, make_env_file) -> None:
    """``KEY=old  # note`` rewrite MUST keep the inline comment byte-for-byte.

    Trailing ``# comment`` on the same physical line is a common dotenv
    pattern. Dropping it on rewrite destroys documentation humans left
    in the file.
    """
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b"API_KEY=old  # keep this note\nOTHER=keep\n"
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    assert after == b"API_KEY=new  # keep this note\nOTHER=keep\n", (
        f"inline comment lost on rewrite:\n  before={before!r}\n  after ={after!r}"
    )
