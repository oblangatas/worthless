"""Multiline and quoted-value tests.

dotenv allows quoted values that embed literal newlines, escaped quotes,
and shell-meta characters. The rewriter must:

1. Correctly replace a multiline value's entire span on rewrite.
2. Drop every line of a multiline block on remove.
3. Refuse value-injection via raw newline in ``add`` calls.
4. Preserve escaped quotes inside an unrelated value on a sibling edit.
5. Treat ``$VAR`` inside a value as a literal (no shell expansion).
"""

from __future__ import annotations

from pathlib import Path

import pytest


def test_rewrite_replaces_multiline_value_with_single_line(tmp_path: Path, make_env_file) -> None:
    """Rewriting a double-quoted multiline value MUST replace the full block.

    ``python-dotenv`` semantics: a value opened with ``"`` and containing
    literal newlines is a single logical assignment whose value spans
    multiple physical lines. The rewriter must replace the whole span,
    not just the first physical line.
    """
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b'KEY="line1\nline2\nline3"\nOTHER=keep\n'
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "KEY", "decoy")

    # Byte-exact assertion: the quoted multiline span must collapse to a
    # single-line double-quoted assignment, and the sibling ``OTHER=keep``
    # must survive untouched. Substring-only checks would miss regressions
    # like an orphaned closing quote, stray blank lines, or lost quoting.
    after = env.read_bytes()
    assert after == b'KEY="decoy"\nOTHER=keep\n', (
        f"multiline rewrite produced unexpected bytes:\n  before={before!r}\n  after ={after!r}"
    )


def test_remove_drops_multiline_block_completely(tmp_path: Path, make_env_file) -> None:
    """``remove_env_key`` on a multiline-quoted value MUST drop the whole block."""
    from worthless.cli.dotenv_rewriter import remove_env_key

    before = b'FIRST=one\nKEY="line1\nline2\nline3"\nLAST=tail\n'
    env = make_env_file(tmp_path / ".env", content=before)

    remove_env_key(env, "KEY")

    after = env.read_bytes()
    assert after == b"FIRST=one\nLAST=tail\n", (
        f"multiline remove failed:\n  before={before!r}\n  after ={after!r}"
    )


def test_add_with_value_containing_literal_newline_refused(
    tmp_path: Path, make_env_file, sha256_of, assert_byte_identical
) -> None:
    """A literal ``\\n`` byte in a new value MUST be refused (injection guard).

    Parallels ``test_add_with_value_containing_newline_refused`` but
    framed from the multiline-value angle: even if a caller "meant" to
    pass a multiline value, the rewriter must reject to prevent
    ``KEY=value1\\nEVIL=injected`` smuggling.
    """
    from worthless.cli.dotenv_rewriter import add_or_rewrite_env_key
    from worthless.cli.errors import UnsafeRewriteRefused

    env = make_env_file(tmp_path / ".env", content=b"KEEP=yes\n")
    baseline = sha256_of(env)

    with pytest.raises((UnsafeRewriteRefused, ValueError)):
        add_or_rewrite_env_key(env, "INJECTED", "first_line\nsecond_line")

    assert_byte_identical(env, baseline)


def test_quoted_value_with_escaped_quote_preserved_on_unrelated_change(
    tmp_path: Path, make_env_file
) -> None:
    """A sibling rewrite MUST preserve an unrelated value's escaped quote."""
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    # OTHER holds a double-quoted value containing an escaped quote.
    before = b'OTHER="he said \\"hi\\""\nAPI_KEY=old\n'
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "API_KEY", "new")

    after = env.read_bytes()
    # OTHER's raw bytes must survive verbatim.
    assert b'OTHER="he said \\"hi\\""\n' in after, (
        f"escaped-quote value mutated:\n  before={before!r}\n  after ={after!r}"
    )
    assert b"API_KEY=new" in after


def test_bare_quote_in_unquoted_value_does_not_start_multiline(
    tmp_path: Path, make_env_file
) -> None:
    """A literal quote char inside an unquoted value MUST NOT trigger multiline mode.

    dotenv semantics: a value is only quoted when the first non-whitespace
    byte after ``=`` is ``"`` or ``'``. ``KEY=plain"value`` is a plain
    unquoted string whose value happens to contain a ``"``; the logical
    line ends at the EOL, not on the next quote char.

    Regression: the splitter previously entered quote-tracking on any
    ``"``/``'`` anywhere after ``=``, so ``KEY=plain"nope\\nNEXT=x\\n``
    would swallow ``NEXT=x`` into a phantom multiline value, and a rewrite
    of ``NEXT`` would either fail to find it or corrupt the file.
    """
    from worthless.cli.dotenv_rewriter import rewrite_env_key

    before = b'KEY=plain"nope\nNEXT=original\n'
    env = make_env_file(tmp_path / ".env", content=before)

    rewrite_env_key(env, "NEXT", "updated")

    after = env.read_bytes()
    assert b"NEXT=updated" in after, f"NEXT not rewritten: {after!r}"
    assert b'KEY=plain"nope' in after, f"KEY's bytes mangled: {after!r}"


def test_dollar_sign_value_not_expanded(tmp_path: Path, make_env_file) -> None:
    """A ``$VAR`` in a value MUST be stored as the literal bytes.

    No shell-style expansion on write. The rewriter treats the value as
    opaque text.
    """
    from worthless.cli.dotenv_rewriter import add_or_rewrite_env_key

    env = make_env_file(tmp_path / ".env", content=b"EXISTING=keep\n")

    add_or_rewrite_env_key(env, "DOLLAR", "$HOME/secret")

    after = env.read_bytes()
    assert b"DOLLAR=$HOME/secret" in after, f"dollar-sign value mangled: {after!r}"
