"""Safety-invariant tests for the ``dotenv_rewriter`` public API.

Each test proves that one of the ``safe_rewrite`` invariants fires when
the public ``add_or_rewrite_env_key`` / ``rewrite_env_key`` /
``remove_env_key`` entry points are called against a hostile target.

The headline test - ``test_add_to_symlink_pointing_at_zshrc_refused`` -
is the entire ticket's justification in one assertion: locking a `.env`
that is actually a symlink to the user's `~/.zshrc` must not nuke their
shell config.
"""

from __future__ import annotations

import os
import stat as _stat
from pathlib import Path

import pytest

from worthless.cli import dotenv_rewriter as _dotenv_rewriter
from worthless.cli.dotenv_rewriter import (
    add_or_rewrite_env_key,
    remove_env_key,
    rewrite_env_key,
)
from worthless.cli.errors import UnsafeReason, UnsafeRewriteRefused
from worthless.cli.safe_rewrite import _BASENAME_DENYLIST


@pytest.fixture
def forbid_safe_rewrite(monkeypatch):
    """Make any `safe_rewrite` call from the dotenv_rewriter module fail the test.

    Used to prove refusal branches raise `UnsafeRewriteRefused` directly
    rather than trampolining through `safe_rewrite(path, b"", ...)` — the
    historical wipe vector.
    """

    def _spy(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("safe_rewrite was invoked on a refusal path")

    monkeypatch.setattr(_dotenv_rewriter, "safe_rewrite", _spy)
    return _spy


def test_add_to_symlink_pointing_at_zshrc_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """A `.env` that is a symlink to ``~/.zshrc`` MUST be refused, byte-identical.

    Reproduces the historical "zshrc lock bug": an attacker (or an unlucky
    user) creates ``foo/.env`` as a symlink to ``~/.zshrc``. The previous
    rewriter happily wrote through the symlink and clobbered the shell rc.
    After wiring ``safe_rewrite`` in, the call must raise
    ``UnsafeRewriteRefused`` and leave the zshrc bytes untouched.
    """
    home = tmp_path / "home"
    home.mkdir()
    zshrc = home / ".zshrc"
    zshrc_content = b"# user's precious shell config\nexport PATH=/usr/bin\n"
    make_env_file(zshrc, content=zshrc_content)
    zshrc_sha = sha256_of(zshrc)

    env_dir = tmp_path / "project"
    env_dir.mkdir()
    env_path = env_dir / ".env"
    env_path.symlink_to(zshrc)

    with pytest.raises(UnsafeRewriteRefused):
        add_or_rewrite_env_key(env_path, "DECOY_KEY", "sk-decoy-0001")

    assert_byte_identical(zshrc, zshrc_sha)


def test_rewrite_to_symlink_pointing_at_zshrc_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """``rewrite_env_key`` through a zshrc symlink MUST be refused."""
    home = tmp_path / "home"
    home.mkdir()
    zshrc = home / ".zshrc"
    zshrc_content = b"# precious shell config\nalias ll='ls -la'\n"
    make_env_file(zshrc, content=zshrc_content)
    zshrc_sha = sha256_of(zshrc)

    env_dir = tmp_path / "project"
    env_dir.mkdir()
    env_path = env_dir / ".env"
    env_path.symlink_to(zshrc)

    with pytest.raises(UnsafeRewriteRefused):
        rewrite_env_key(env_path, "EXISTING_KEY", "sk-decoy-0001")

    assert_byte_identical(zshrc, zshrc_sha)


def test_remove_to_symlink_pointing_at_zshrc_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """``remove_env_key`` through a zshrc symlink MUST be refused."""
    home = tmp_path / "home"
    home.mkdir()
    zshrc = home / ".zshrc"
    zshrc_content = b"# precious shell config\nexport EDITOR=vim\n"
    make_env_file(zshrc, content=zshrc_content)
    zshrc_sha = sha256_of(zshrc)

    env_dir = tmp_path / "project"
    env_dir.mkdir()
    env_path = env_dir / ".env"
    env_path.symlink_to(zshrc)

    with pytest.raises(UnsafeRewriteRefused):
        remove_env_key(env_path, "SOME_KEY")

    assert_byte_identical(zshrc, zshrc_sha)


def test_add_to_basename_dot_zshrc_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """Passing a literal ``.zshrc`` path (no symlink) MUST be refused on basename.

    The basename denylist in ``safe_rewrite`` refuses any target whose
    basename is not literally ``.env``.
    """
    zshrc = tmp_path / ".zshrc"
    zshrc_content = b"# direct zshrc target\nexport FOO=bar\n"
    make_env_file(zshrc, content=zshrc_content)
    zshrc_sha = sha256_of(zshrc)

    with pytest.raises(UnsafeRewriteRefused):
        add_or_rewrite_env_key(zshrc, "DECOY_KEY", "sk-decoy-0001")

    assert_byte_identical(zshrc, zshrc_sha)


def test_rewrite_to_fifo_refused(tmp_path: Path) -> None:
    """A FIFO at the target path MUST be refused (special-file gate)."""
    fifo = tmp_path / ".env"
    os.mkfifo(str(fifo))

    with pytest.raises(UnsafeRewriteRefused):
        rewrite_env_key(fifo, "SOME_KEY", "new_value")

    # FIFO still present; no tmp file leaked.
    import stat as _stat

    assert _stat.S_ISFIFO(os.lstat(str(fifo)).st_mode)
    assert list(tmp_path.glob(".env.tmp-*")) == []


def test_add_outside_repo_with_default_settings_succeeds(
    tmp_path: Path,
    make_env_file,
) -> None:
    """Default (no containment configured) → write lands even outside any repo.

    Sub-PR 2's public helpers do not forward ``repo_root``; this test pins
    the contract that the default caller path has no implicit containment
    gate. Making the happy path observable (by asserting the new key lands
    on disk and the pre-existing key is preserved) ensures the test fails
    loudly if the rewriter ever regresses to refusing outside-repo writes
    under default settings — rather than vacuously passing because no
    exception was raised.
    """
    env = make_env_file(tmp_path / "outside" / ".env", content=b"KEY=value\n")

    add_or_rewrite_env_key(env, "NEW_KEY", "new_value")

    contents = env.read_bytes()
    assert b"NEW_KEY=new_value" in contents, (
        "default caller settings must permit writes outside any repo"
    )
    assert b"KEY=value" in contents, "pre-existing key must be preserved"


def test_add_with_value_containing_newline_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """A value containing an embedded newline MUST be refused (value validation).

    Newlines in values would allow injecting a second ``KEY=value`` line
    into the file. The rewriter must reject before any write happens.
    """
    env = make_env_file(tmp_path / ".env", content=b"KEY=value\n")
    baseline = sha256_of(env)

    with pytest.raises((UnsafeRewriteRefused, ValueError)):
        add_or_rewrite_env_key(env, "INJECTED", "line1\nEVIL=attacker_controlled")

    assert_byte_identical(env, baseline)


def test_add_with_value_containing_nul_byte_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """A value containing a NUL byte MUST be refused.

    NUL bytes terminate C strings and routinely cause downstream tools
    to mis-parse the file. Reject at the rewriter boundary.
    """
    env = make_env_file(tmp_path / ".env", content=b"KEY=value\n")
    baseline = sha256_of(env)

    with pytest.raises((UnsafeRewriteRefused, ValueError)):
        add_or_rewrite_env_key(env, "NULLED", "before\x00after")

    assert_byte_identical(env, baseline)


def test_add_with_newline_in_var_name_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """A ``var_name`` containing a newline MUST be refused.

    Without key validation, ``var_name="FOO\\nBAR=evil"`` would produce
    two assignment lines in the file: ``FOO`` and ``BAR=evil``. The
    rewriter must reject before any write happens.
    """
    env = make_env_file(tmp_path / ".env", content=b"KEY=value\n")
    baseline = sha256_of(env)

    with pytest.raises((UnsafeRewriteRefused, ValueError)):
        add_or_rewrite_env_key(env, "FOO\nBAR=evil", "real_value")

    assert_byte_identical(env, baseline)


def test_add_with_equals_in_var_name_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """A ``var_name`` containing ``=`` MUST be refused.

    ``FOO=injected`` as a key would produce ``FOO=injected=real_value``,
    which dotenv parses as ``FOO=injected=real_value`` (one key with an
    odd value) - off-semantics. Reject at the boundary.
    """
    env = make_env_file(tmp_path / ".env", content=b"KEY=value\n")
    baseline = sha256_of(env)

    with pytest.raises((UnsafeRewriteRefused, ValueError)):
        add_or_rewrite_env_key(env, "FOO=injected", "real")

    assert_byte_identical(env, baseline)


def test_add_with_non_posix_var_name_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """Keys outside POSIX env-var syntax MUST be refused.

    POSIX env names match ``[A-Za-z_][A-Za-z0-9_]*``. Keys like
    ``KEY-WITH-DASH`` or ``1LEADING_DIGIT`` would land in the file but
    cannot be ``export``ed by a shell. Reject them so the file stays
    shell-usable.
    """
    env = make_env_file(tmp_path / ".env", content=b"KEY=value\n")
    baseline = sha256_of(env)

    with pytest.raises((UnsafeRewriteRefused, ValueError)):
        add_or_rewrite_env_key(env, "KEY-WITH-DASH", "x")
    assert_byte_identical(env, baseline)

    with pytest.raises((UnsafeRewriteRefused, ValueError)):
        add_or_rewrite_env_key(env, "1LEADING_DIGIT", "x")
    assert_byte_identical(env, baseline)

    with pytest.raises((UnsafeRewriteRefused, ValueError)):
        add_or_rewrite_env_key(env, "", "x")
    assert_byte_identical(env, baseline)


def test_add_to_one_mib_plus_one_file_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """A ``.env`` larger than 1 MiB MUST be refused (size gate fires via gate).

    The rewriter routes through ``safe_rewrite``, which enforces the
    1 MiB bound on the *existing* file. Adding a key to a 1 MiB+1 file
    must be refused without any write.
    """
    one_mib = 1 << 20
    prefix = b"A="
    remainder = one_mib - len(prefix)  # leaves no room for newline → +1 over
    content = prefix + (b"x" * remainder) + b"\n"
    assert len(content) == one_mib + 1
    env = make_env_file(tmp_path / ".env", content=content)
    baseline = sha256_of(env)

    with pytest.raises(UnsafeRewriteRefused):
        add_or_rewrite_env_key(env, "NEW_KEY", "small")

    assert_byte_identical(env, baseline)


# ---------------------------------------------------------------------------
# Round-trip-stability guards: reject values that would silently corrupt
# when read back by a standard dotenv parser.
# ---------------------------------------------------------------------------


def test_add_with_space_hash_in_value_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """A value containing ``' #'`` MUST be refused.

    dotenv parsers treat ``space + #`` as the start of an inline comment;
    on read-back everything after the space would be stripped, silently
    losing data. Reject at the rewriter boundary.
    """
    env = make_env_file(tmp_path / ".env", content=b"KEY=value\n")
    baseline = sha256_of(env)

    with pytest.raises(ValueError, match=r"inline[- ]comment"):
        add_or_rewrite_env_key(env, "API_KEY", "sk-new #leaked-note")

    assert_byte_identical(env, baseline)


def test_add_with_tab_hash_in_value_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """A value containing ``'\\t#'`` MUST be refused — same inline-comment hazard as `' #'`."""
    env = make_env_file(tmp_path / ".env", content=b"KEY=value\n")
    baseline = sha256_of(env)

    with pytest.raises(ValueError, match=r"inline[- ]comment"):
        add_or_rewrite_env_key(env, "API_KEY", "sk-new\t#leaked-note")

    assert_byte_identical(env, baseline)


def test_add_with_value_starting_with_double_quote_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """A value starting with ``"`` MUST be refused.

    dotenv parsers treat a leading quote as an opening delimiter and strip
    it on read-back, corrupting the stored value.
    """
    env = make_env_file(tmp_path / ".env", content=b"KEY=value\n")
    baseline = sha256_of(env)

    with pytest.raises(ValueError, match=r"quote"):
        add_or_rewrite_env_key(env, "API_KEY", '"abc')

    assert_byte_identical(env, baseline)


def test_add_with_value_starting_with_single_quote_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """A value starting with ``'`` MUST be refused (same reason as ``"``)."""
    env = make_env_file(tmp_path / ".env", content=b"KEY=value\n")
    baseline = sha256_of(env)

    with pytest.raises(ValueError, match=r"quote"):
        add_or_rewrite_env_key(env, "API_KEY", "'abc")

    assert_byte_identical(env, baseline)


def test_add_with_leading_whitespace_in_value_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """A value with leading whitespace MUST be refused.

    Unquoted dotenv values are whitespace-stripped on read; leading
    whitespace would silently disappear.
    """
    env = make_env_file(tmp_path / ".env", content=b"KEY=value\n")
    baseline = sha256_of(env)

    with pytest.raises(ValueError, match=r"whitespace"):
        add_or_rewrite_env_key(env, "API_KEY", " sk-abc")

    assert_byte_identical(env, baseline)


def test_add_with_trailing_whitespace_in_value_refused(
    tmp_path: Path,
    make_env_file,
    sha256_of,
    assert_byte_identical,
) -> None:
    """A value with trailing whitespace MUST be refused (same reason)."""
    env = make_env_file(tmp_path / ".env", content=b"KEY=value\n")
    baseline = sha256_of(env)

    with pytest.raises(ValueError, match=r"whitespace"):
        add_or_rewrite_env_key(env, "API_KEY", "sk-abc ")

    assert_byte_identical(env, baseline)


def test_add_with_hash_not_preceded_by_space_allowed(
    tmp_path: Path,
    make_env_file,
) -> None:
    """``sk-abc#tag`` (no space before ``#``) is a legal unquoted value.

    Ensures the inline-comment guard is narrow: only ``space + #`` is
    rejected; a literal ``#`` inside the value is fine because dotenv
    parsers only treat ``#`` as a comment when preceded by whitespace.
    """
    env = make_env_file(tmp_path / ".env", content=b"KEY=value\n")

    add_or_rewrite_env_key(env, "API_KEY", "sk-abc#tag")

    assert b"API_KEY=sk-abc#tag\n" in env.read_bytes()


# NOTE: a predecessor test here asserted "quote mid-value is allowed".
# Finding 1 from CR on PR #86 tightened that contract: embedded ``"``
# or ``'`` in a value is now refused globally (python-dotenv mis-parses
# ``KEY="abc"def"`` as a syntax error the next time it reads the file,
# so "refuse, don't mangle" applies). See
# ``test_rewrite_refuses_values_with_embedded_quotes`` below for the
# positive-space coverage of the new contract.


# ---------------------------------------------------------------------------
# Refusal-dispatch safety: _safe_read_existing_bytes must raise
# UnsafeRewriteRefused directly, NOT funnel through safe_rewrite(path, b"").
#
# Motivation: safe_rewrite performs its own fresh lstat/size/sniff under its
# lock. If the hostile condition clears between our check and its check
# (oversized file truncated, symlink swapped for regular file, EPERM
# cleared), the gate would *succeed* on an empty payload and wipe the
# file. Raising UnsafeRewriteRefused directly eliminates that race window
# entirely — no write path is reached at all.
# ---------------------------------------------------------------------------


def test_refuse_symlink_does_not_invoke_safe_rewrite(
    tmp_path: Path,
    make_env_file,
    forbid_safe_rewrite,
) -> None:
    """Symlink refusal MUST raise directly; safe_rewrite MUST NOT be called."""
    target = make_env_file(tmp_path / "real.env", content=b"KEY=value\n")
    env_path = tmp_path / ".env"
    env_path.symlink_to(target)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        add_or_rewrite_env_key(env_path, "NEW", "v")

    assert exc_info.value.reason == UnsafeReason.SYMLINK


def test_refuse_fifo_does_not_invoke_safe_rewrite(
    tmp_path: Path,
    forbid_safe_rewrite,
) -> None:
    """FIFO refusal MUST raise directly; safe_rewrite MUST NOT be called."""
    fifo_path = tmp_path / ".env"
    os.mkfifo(str(fifo_path))

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        add_or_rewrite_env_key(fifo_path, "NEW", "v")

    assert exc_info.value.reason == UnsafeReason.SPECIAL_FILE


def test_refuse_oversized_does_not_invoke_safe_rewrite(
    tmp_path: Path,
    make_env_file,
    forbid_safe_rewrite,
) -> None:
    """Oversize refusal MUST raise directly; safe_rewrite MUST NOT be called.

    This is the headline race: between our ``lst.st_size`` check and the
    gate's own size check, a concurrent truncator could shrink the file
    under us — if we funnelled through ``safe_rewrite(path, b"")``, the
    gate would accept the empty payload and write it, wiping the file.
    Raising ``UnsafeRewriteRefused`` directly closes the window.
    """
    one_mib = 1 << 20
    content = b"KEY=" + b"a" * (one_mib - len(b"KEY=\n")) + b"\n"
    assert len(content) == one_mib
    content += b"b"
    assert len(content) == one_mib + 1
    env_path = make_env_file(tmp_path / ".env", content=content)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        add_or_rewrite_env_key(env_path, "NEW", "v")

    assert exc_info.value.reason == UnsafeReason.SIZE


def test_refuse_lstat_error_does_not_invoke_safe_rewrite(
    tmp_path: Path,
    make_env_file,
    monkeypatch,
    forbid_safe_rewrite,
) -> None:
    """An ``lstat`` ``OSError`` MUST raise ``UnsafeRewriteRefused`` directly.

    Transient EACCES/EIO that clears between our lstat and the gate's
    lstat would otherwise let safe_rewrite proceed on our empty-payload
    call and wipe the file.
    """
    env_path = make_env_file(tmp_path / ".env", content=b"KEY=value\n")
    real_lstat = os.lstat
    target_str = str(env_path)

    def _boom_lstat(path, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        if str(path) == target_str:
            raise PermissionError(13, "Permission denied")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", _boom_lstat)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        add_or_rewrite_env_key(env_path, "NEW", "v")

    assert exc_info.value.reason == UnsafeReason.IO_ERROR


def test_refuse_open_error_does_not_invoke_safe_rewrite(
    tmp_path: Path,
    make_env_file,
    monkeypatch,
    forbid_safe_rewrite,
) -> None:
    """An ``os.open`` ``OSError`` after a successful ``lstat`` MUST raise directly.

    Covers the TOCTOU case where ``lstat`` shows a regular file but
    ``open`` fails (e.g., attacker swaps to a non-readable node between
    the two syscalls).
    """
    env_path = make_env_file(tmp_path / ".env", content=b"KEY=value\n")
    real_open = os.open
    target_str = str(env_path)

    def _boom_open(path, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        if str(path) == target_str:
            raise PermissionError(13, "Permission denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", _boom_open)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        add_or_rewrite_env_key(env_path, "NEW", "v")

    assert exc_info.value.reason == UnsafeReason.IO_ERROR


def test_refuse_real_rename_race_between_lstat_and_open(
    tmp_path: Path,
    monkeypatch,
    forbid_safe_rewrite,
) -> None:
    """A real ``rename(2)`` swap between ``lstat`` and ``os.open`` MUST refuse.

    ``O_NOFOLLOW`` on the open blocks symlink-flips, but an attacker who
    can atomically rename a different regular file over the path between
    the ``lstat`` check and the ``os.open`` call would otherwise read a
    file we never validated. Performs a genuine atomic rename of a
    different regular file over the victim path, then runs unmocked
    through ``lstat`` → ``os.open`` → ``os.fstat``. The real identity
    check must detect the inode swap and raise
    ``UnsafeRewriteRefused(TOCTOU)`` directly — no ``safe_rewrite`` call,
    no data exposure.
    """
    victim = tmp_path / ".env"
    victim.write_bytes(b"VICTIM_CONTENT=legitimate\n")

    adversary_src = tmp_path / "adversary_source.env"
    adversary_src.write_bytes(b"ADVERSARY_CONTENT=should_never_be_read\n")

    real_lstat = os.lstat
    swap_done = {"did": False}

    def _racing_lstat(path, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        result = real_lstat(path, *args, **kwargs)
        if str(path) == str(victim) and not swap_done["did"]:
            adversary_src.rename(victim)
            swap_done["did"] = True
        return result

    monkeypatch.setattr(os, "lstat", _racing_lstat)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        add_or_rewrite_env_key(victim, "NEW", "v")

    assert exc_info.value.reason == UnsafeReason.TOCTOU
    # Post-swap, the path points at adversary_src's inode. Its bytes must
    # never have been read, hashed, or written back.
    assert victim.read_bytes() == b"ADVERSARY_CONTENT=should_never_be_read\n"


def test_allow_matching_fstat_after_open(
    tmp_path: Path,
    make_env_file,
) -> None:
    """Negative control: matching ``fstat`` identity must NOT refuse.

    Guards against an over-broad TOCTOU check that rejects the happy
    path. A normal regular file whose inode/dev don't change between
    ``lstat`` and ``fstat`` must succeed, AND the pre-existing line
    must be preserved — proving the read baseline came from the real
    file, not a swapped-in one.
    """
    env_path = make_env_file(tmp_path / ".env", content=b"EXISTING=old\n")

    add_or_rewrite_env_key(env_path, "NEW", "fresh")

    assert env_path.read_bytes() == b"EXISTING=old\nNEW=fresh\n"


@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(lambda p: rewrite_env_key(p, "KEY", "newvalue"), id="rewrite_env_key"),
        pytest.param(lambda p: remove_env_key(p, "KEY"), id="remove_env_key"),
    ],
)
def test_refuse_symlink_via_sister_apis(
    tmp_path: Path,
    make_env_file,
    forbid_safe_rewrite,
    operation,
) -> None:
    """Sister APIs on a symlink MUST refuse directly (trip-wire for direct-raise dispatch)."""
    target = make_env_file(tmp_path / "real.env", content=b"KEY=value\n")
    env_path = tmp_path / ".env"
    env_path.symlink_to(target)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        operation(env_path)

    assert exc_info.value.reason == UnsafeReason.SYMLINK


# ---------------------------------------------------------------------------
# CR PR #86 / sub-PR-4 — embedded-quote and missing-file coverage.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_value",
    [
        pytest.param('abc"def', id="embedded-double-quote"),
        pytest.param("abc'def", id="embedded-single-quote"),
        # Deliberately no leading quote: a value that STARTS with `"`
        # would trip the leading-quote check first, short-circuiting the
        # embedded-quote path we actually want to exercise.
        pytest.param('foo"bar"baz', id="trailing-doubles"),
        pytest.param("has'single'", id="embedded-singles"),
    ],
)
def test_rewrite_refuses_values_with_embedded_quotes(
    tmp_path: Path, make_env_file, sha256_of, bad_value
) -> None:
    """Values with embedded quotes must be refused.

    Rewriting ``KEY="old"`` with such a value would produce a line
    whose embedded quote closes the surrounding quote and leaves the
    rest as noise, mis-parsed on read-back (python-dotenv flags the
    line as unparsable). ``_validate_value`` refuses the value before
    any rewrite can emit it.
    """
    env = make_env_file(tmp_path / ".env", content=b'KEY="old"\n')
    baseline = sha256_of(env)

    with pytest.raises(ValueError):
        rewrite_env_key(env, "KEY", bad_value)

    assert sha256_of(env) == baseline


def test_add_or_rewrite_refuses_embedded_double_quote(
    tmp_path: Path, make_env_file, sha256_of
) -> None:
    """``add_or_rewrite_env_key`` also refuses embedded-quote values."""
    env = make_env_file(tmp_path / ".env", content=b'KEY="old"\n')
    baseline = sha256_of(env)

    with pytest.raises(ValueError):
        add_or_rewrite_env_key(env, "KEY", 'abc"def')

    assert sha256_of(env) == baseline


def test_add_or_rewrite_creates_missing_env_file(tmp_path: Path) -> None:
    """Missing ``.env`` MUST be created atomically with mode 0600.

    ``safe_rewrite`` refuses missing targets by contract, so the
    ``add_or_rewrite_env_key`` public docstring's "creating or updating"
    promise requires a separate atomic-create path
    (``O_CREAT|O_EXCL|O_NOFOLLOW`` + ``fsync``).
    """
    env = tmp_path / ".env"
    assert not env.exists()

    add_or_rewrite_env_key(env, "KEY", "value")

    assert env.read_bytes() == b"KEY=value\n"
    assert _stat.S_IMODE(env.stat().st_mode) == 0o600


def test_add_or_rewrite_create_refuses_symlink_race(tmp_path: Path) -> None:
    """A symlink at the target path must not be dereferenced on create.

    ``O_NOFOLLOW`` ensures that if a racing symlink appears between the
    "does ``.env`` exist?" check and the ``os.open`` call, the open
    fails rather than silently writing through to the decoy.
    """
    decoy = tmp_path / "decoy"
    decoy.write_text("")
    link = tmp_path / ".env"
    link.symlink_to(decoy)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        add_or_rewrite_env_key(link, "KEY", "value")

    # Reason breakdown: with the decoy created *before* the symlink,
    # ``add_or_rewrite_env_key``'s ``env_path.exists()`` check sees an
    # existing target and routes to ``_safe_read_existing_bytes``, which
    # refuses with ``UnsafeReason.SYMLINK`` via ``safe_rewrite``'s
    # symlink gate. A truly interleaved TOCTOU (symlink appears AFTER
    # the exists check but BEFORE the ``os.open`` in
    # ``_create_new_env_file``) would route to the create branch and
    # refuse with ``TOCTOU`` via ``O_NOFOLLOW``. Both are accepted here
    # so the test remains green if we later harden the ordering or add
    # an explicit TOCTOU probe.
    assert exc_info.value.reason in {
        UnsafeReason.SYMLINK,
        UnsafeReason.TOCTOU,
    }
    # Decoy must be untouched.
    assert decoy.read_text() == ""


def test_add_or_rewrite_create_fsyncs_parent_directory(tmp_path: Path, monkeypatch) -> None:
    """Create path MUST fsync the parent directory so the dirent is durable.

    POSIX: a rename or a newly-created file enters a parent directory
    whose entry isn't on disk until the parent dir is fsynced. Without
    this, a power-loss between create+fsync(file) and dir-fsync can
    leave a "ghost file" — the inode exists but the directory entry is
    gone, so the file effectively disappeared.

    Regression guard for reviewer finding B1: originally,
    ``_create_new_env_file`` fsynced the file contents but skipped the
    parent-dir fsync, leaving a durability gap on unclean shutdown.

    We assert the parent directory fd was passed to ``os.fsync`` at
    least once by wrapping ``os.fsync`` and checking ``os.fstat`` for
    ``S_ISDIR``.
    """
    env = tmp_path / ".env"
    assert not env.exists()

    fsynced_dir = {"hit": False}
    real_fsync = os.fsync

    def _rec_fsync(fd):  # noqa: ANN001
        try:
            st = os.fstat(fd)
            if _stat.S_ISDIR(st.st_mode):
                fsynced_dir["hit"] = True
        except OSError:
            pass
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", _rec_fsync)

    add_or_rewrite_env_key(env, "KEY", "value")

    assert env.read_bytes() == b"KEY=value\n"
    assert fsynced_dir["hit"], (
        "parent directory was never fsynced on create — unclean shutdown "
        "could lose the dirent and leave a 'ghost file' (reviewer B1)"
    )


@pytest.mark.parametrize("denylisted_basename", sorted(_BASENAME_DENYLIST))
def test_add_or_rewrite_refuses_to_create_denylisted_basename(
    tmp_path: Path, denylisted_basename: str
) -> None:
    """``add_or_rewrite_env_key`` on a non-existent denylisted path MUST refuse.

    The original ``add_or_rewrite_env_key`` funnelled every destructive
    write through ``safe_rewrite``, whose basename gate refuses non-
    allowlisted targets. The sub-PR-4 create path added a direct
    ``_create_new_env_file`` call that *skipped* the gate, meaning
    ``add_or_rewrite_env_key(Path("~/.bashrc"), "PATH", "/attacker/bin")``
    on a host with no ``.bashrc`` would happily create one with
    attacker-controlled content.

    Parametrizing over the live ``_BASENAME_DENYLIST`` frozenset (not a
    hardcoded copy) means any future addition to the source denylist
    automatically grows test coverage — and prevents silent drift
    where the test's mirror and the source disagree.
    """
    target = tmp_path / denylisted_basename
    assert not target.exists(), "precondition: denylisted target must not exist"

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        add_or_rewrite_env_key(target, "PATH", "/attacker/bin")

    assert exc_info.value.reason == UnsafeReason.BASENAME, (
        f"expected BASENAME refusal for missing-file create of "
        f"{denylisted_basename!r}, got {exc_info.value.reason!r}; "
        f"the basename gate was bypassed on the create path (zshrc-lock regression)"
    )
    # File MUST NOT have been created.
    assert not target.exists(), (
        f"denylisted target {target} was created despite basename gate — "
        f"this is the exact zshrc-lock bug reintroduced"
    )


def test_create_path_cleans_up_on_short_write(tmp_path: Path, monkeypatch) -> None:
    """Short ``os.write`` (n<=0) on create MUST unlink the partial file.

    We monkey-patch ``os.write`` to return 0 on the first call for any
    fd opened inside ``_create_new_env_file``. The contract:

    1. ``add_or_rewrite_env_key`` raises ``UnsafeRewriteRefused`` with
       reason ``IO_ERROR``.
    2. The partial file is unlinked — ``env_path.exists()`` is False
       after the refusal. A leaked partial file would confuse the next
       run (``env_path.exists()`` would return True and route to the
       rewrite path, preserving the zero-byte garbage).
    """
    env = tmp_path / ".env"
    assert not env.exists()

    real_write = os.write
    first_write_done = {"done": False}

    def _short_write(fd, data):  # noqa: ANN001
        # Return 0 on the FIRST write only — subsequent writes (e.g.
        # from other test infrastructure) behave normally.
        if not first_write_done["done"]:
            first_write_done["done"] = True
            return 0
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", _short_write)

    with pytest.raises(UnsafeRewriteRefused) as exc_info:
        add_or_rewrite_env_key(env, "KEY", "value")

    assert exc_info.value.reason == UnsafeReason.IO_ERROR
    assert not env.exists(), (
        "partial .env survived a short-write failure — next run would "
        "route to the rewrite path on corrupt zero-byte content"
    )
