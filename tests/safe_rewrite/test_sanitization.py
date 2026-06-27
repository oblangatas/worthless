"""Error-sanitisation invariants.

The public exception carries an opaque message; the granular reason is
available via ``.reason`` and the DEBUG log. Absolute paths and environment
contents must never leak into ``str(exc)`` or the traceback.

Includes a parametrized negative-space test that asserts sha256 of the
target is preserved across every refusal reason.
"""

from __future__ import annotations

import logging
import os

import pytest

from worthless.cli.errors import ErrorCode, UnsafeReason, UnsafeRewriteRefused
from worthless.cli.safe_rewrite import safe_rewrite


def test_public_error_code_is_unsafe_rewrite_refused(tmp_path, make_env_file) -> None:
    """Every refusal surfaces as ``ErrorCode.UNSAFE_REWRITE_REFUSED`` — single public code."""
    p = make_env_file(tmp_path / ".zshrc", b"export FOO=bar\n")

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert exc_info.value.code == ErrorCode.UNSAFE_REWRITE_REFUSED


def test_granular_reason_on_exception_attribute(tmp_path, make_env_file) -> None:
    """The granular cause lives on ``.reason`` for programmatic inspection."""
    p = make_env_file(tmp_path / ".zshrc", b"export FOO=bar\n")

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    assert isinstance(exc_info.value.reason, UnsafeReason)
    assert exc_info.value.reason == UnsafeReason.BASENAME


def test_granular_reason_logged_at_debug(tmp_path, make_env_file, caplog) -> None:
    """The granular reason is written to DEBUG logs, never to user-facing output."""
    p = make_env_file(tmp_path / ".zshrc", b"export FOO=bar\n")

    with caplog.at_level(logging.DEBUG, logger="worthless.cli.errors"):
        with pytest.raises(UnsafeRewriteRefused):
            safe_rewrite(p, b"A=1\n", original_user_arg=p)

    # The reason string is present in at least one DEBUG record.
    assert any(
        UnsafeReason.BASENAME.value in rec.getMessage()
        for rec in caplog.records
        if rec.levelno == logging.DEBUG
    ), f"BASENAME reason not logged at DEBUG; records={caplog.records!r}"


def test_no_absolute_paths_in_public_message(tmp_path, make_env_file) -> None:
    """The path never appears in ``str(exc)`` — we ship generic text."""
    p = make_env_file(tmp_path / ".zshrc", b"export FOO=bar\n")

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    msg = str(exc_info.value)
    assert str(p) not in msg
    assert str(p.parent) not in msg
    assert ".zshrc" not in msg


def test_no_environ_in_traceback(tmp_path, make_env_file, monkeypatch) -> None:
    """No os.environ values should leak into exception attributes or args.

    We seed the process environment with a distinctive secret, trigger
    a refusal, and assert the secret does not appear anywhere in the
    exception's public surface.
    """
    monkeypatch.setenv("WORTHLESS_TEST_SECRET", "ZYXABC123SHOULDNOTAPPEAR")
    p = make_env_file(tmp_path / ".zshrc", b"export FOO=bar\n")

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        safe_rewrite(p, b"A=1\n", original_user_arg=p)

    for s in (str(exc_info.value), repr(exc_info.value.args), str(exc_info.value.message)):
        assert "ZYXABC123SHOULDNOTAPPEAR" not in s, f"environ leaked into exception surface: {s!r}"


@pytest.mark.parametrize(
    "trigger",
    [
        pytest.param("basename", id="reason=basename"),
        pytest.param("symlink", id="reason=symlink"),
        pytest.param("special_file", id="reason=special_file"),
        pytest.param("size", id="reason=size"),
        pytest.param("sniff", id="reason=sniff"),
        pytest.param("delta", id="reason=delta"),
        pytest.param("platform", id="reason=platform"),
        pytest.param("containment", id="reason=containment"),
        pytest.param("locked", id="reason=locked"),
    ],
)
def test_sha256_preserved_across_all_refusal_reasons(
    trigger, tmp_path, make_env_file, sha256_of, monkeypatch, request
):
    """Parametrized negative-space spine: no refusal reason writes to target.

    Each parameter seeds a minimal scenario that triggers a distinct
    ``UnsafeReason`` and asserts the on-disk sha256 of the would-be
    target is preserved.
    """
    if trigger == "basename":
        target = make_env_file(tmp_path / ".zshrc", b"export FOO=bar\n")
        baseline = sha256_of(target)
        with pytest.raises(UnsafeRewriteRefused):
            safe_rewrite(target, b"A=1\n", original_user_arg=target)
        assert sha256_of(target) == baseline

    elif trigger == "symlink":
        real = make_env_file(tmp_path / "inner" / ".env", b"KEY=v\n")
        baseline = sha256_of(real)
        link = tmp_path / "outer" / ".env"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(real)
        with pytest.raises(UnsafeRewriteRefused):
            safe_rewrite(link, b"A=1\n", original_user_arg=link)
        assert sha256_of(real) == baseline

    elif trigger == "special_file":
        fifo = tmp_path / ".env"
        os.mkfifo(str(fifo))
        # Baseline: directory listing before call.
        before = sorted(p.name for p in tmp_path.iterdir())
        with pytest.raises(UnsafeRewriteRefused):
            safe_rewrite(fifo, b"A=1\n", original_user_arg=fifo)
        after = sorted(p.name for p in tmp_path.iterdir())
        assert before == after

    elif trigger == "size":
        # Exactly ``_MAX_SIZE + 1`` bytes: 2 ("A=") + (1 MiB - 2) + 1 ("\n").
        # The prior literal ``(1 << 20) - 1`` produced 1 MiB + 2, a latent
        # off-by-one that made the test less precise than its comment claimed
        # (PR #86 discussion).
        one_mib = 1 << 20
        content = b"A=" + b"x" * (one_mib - 2) + b"\n"
        assert len(content) == one_mib + 1
        target = make_env_file(tmp_path / ".env", content)
        baseline = sha256_of(target)
        with pytest.raises(UnsafeRewriteRefused):
            safe_rewrite(target, b"A=1\n", original_user_arg=target)
        assert sha256_of(target) == baseline

    elif trigger == "sniff":
        target = make_env_file(tmp_path / ".env", b"#!/bin/sh\necho hi\n")
        baseline = sha256_of(target)
        with pytest.raises(UnsafeRewriteRefused):
            safe_rewrite(target, b"A=1\n", original_user_arg=target)
        assert sha256_of(target) == baseline

    elif trigger == "delta":
        target = make_env_file(tmp_path / ".env", b"KEY=" + b"a" * 96 + b"\n")
        baseline = sha256_of(target)
        huge = b"KEY=" + b"x" * 10_000 + b"\n"
        with pytest.raises(UnsafeRewriteRefused):
            safe_rewrite(target, huge, original_user_arg=target)
        assert sha256_of(target) == baseline

    elif trigger == "platform":
        import sys as _sys

        monkeypatch.setattr(_sys, "platform", "win32", raising=False)
        target = make_env_file(tmp_path / ".env", b"KEY=v\n")
        baseline = sha256_of(target)
        with pytest.raises(UnsafeRewriteRefused):
            safe_rewrite(target, b"A=1\n", original_user_arg=target)
        assert sha256_of(target) == baseline

    elif trigger == "containment":
        # Build: repo/.git, .env outside the repo.
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        target = make_env_file(tmp_path / "outside" / ".env", b"KEY=v\n")
        baseline = sha256_of(target)
        with pytest.raises(UnsafeRewriteRefused):
            safe_rewrite(target, b"A=1\n", original_user_arg=target, repo_root=repo)
        assert sha256_of(target) == baseline

    elif trigger == "locked":
        import fcntl

        target = make_env_file(tmp_path / ".env", b"KEY=v\n")
        baseline = sha256_of(target)
        fd = os.open(str(target), os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with pytest.raises(UnsafeRewriteRefused):
                safe_rewrite(target, b"A=1\n", original_user_arg=target)
            assert sha256_of(target) == baseline
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)

    else:  # pragma: no cover — defensive
        pytest.fail(f"unknown trigger: {trigger}")
