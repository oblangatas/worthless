"""Unit tests for ``rewrite_env_keys`` — the batch rewrite helper that
underpins transactional multi-key lock (WOR-276 v2, commits 5+6).

The batch helper MUST:

* Perform exactly one ``safe_rewrite`` call for N updated keys, so the
  atomic ``rename(2)`` is the single commit point for every key.
* Raise ``KeyError`` before any write when any update target is absent
  (all-or-nothing contract — no partial write on a bad input).
* Preserve untouched keys' bytes verbatim (formatting, ``export``,
  quoting, comments).
* Append ``additions`` at the end of the file.
* Forward the ``_hook_before_replace`` callable through to
  ``safe_rewrite`` so the transactional verify runs inside the rename
  window.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from worthless.cli.dotenv_rewriter import rewrite_env_keys


def test_rewrite_env_keys_single_safe_rewrite_call(
    tmp_path: Path, safe_rewrite_spy, make_env_file
) -> None:
    env = make_env_file(tmp_path / ".env", b"A=1\nB=2\nC=3\n")

    rewrite_env_keys(env, {"A": "alpha", "B": "beta", "C": "gamma"})

    assert safe_rewrite_spy.call_count == 1
    content = env.read_bytes()
    assert b"A=alpha\n" in content
    assert b"B=beta\n" in content
    assert b"C=gamma\n" in content


def test_rewrite_env_keys_missing_var_raises_before_any_write(
    tmp_path: Path, safe_rewrite_spy, make_env_file, sha256_of
) -> None:
    env = make_env_file(tmp_path / ".env", b"A=1\nB=2\n")
    pre_sha = sha256_of(env)

    with pytest.raises(KeyError, match="MISSING"):
        rewrite_env_keys(env, {"A": "alpha", "MISSING": "x"})

    assert safe_rewrite_spy.call_count == 0
    assert sha256_of(env) == pre_sha


def test_rewrite_env_keys_preserves_untouched_keys(
    tmp_path: Path, safe_rewrite_spy, make_env_file
) -> None:
    env = make_env_file(
        tmp_path / ".env",
        b'# comment\nexport A=1\nB="quoted"\nC=3\n',
    )

    rewrite_env_keys(env, {"A": "alpha"})

    content = env.read_bytes()
    assert b"# comment\n" in content
    assert b"export A=alpha\n" in content
    assert b'B="quoted"\n' in content
    assert b"C=3\n" in content


def test_rewrite_env_keys_additions_appended_at_end(
    tmp_path: Path, safe_rewrite_spy, make_env_file
) -> None:
    env = make_env_file(tmp_path / ".env", b"A=1\n")

    rewrite_env_keys(env, {"A": "alpha"}, additions={"BASE_URL": "http://x"})

    content = env.read_bytes()
    assert b"A=alpha\n" in content
    assert b"BASE_URL=http://x\n" in content
    assert content.index(b"A=alpha") < content.index(b"BASE_URL")
    assert safe_rewrite_spy.call_count == 1


def test_rewrite_env_keys_forwards_hook_to_safe_rewrite(
    tmp_path: Path, monkeypatch, make_env_file
) -> None:
    env = make_env_file(tmp_path / ".env", b"A=1\n")
    received: dict[str, object] = {}

    def _fake_safe_rewrite(target, new_content, **kwargs):  # type: ignore[no-untyped-def]
        received["hook"] = kwargs.get("_hook_before_replace")
        received["target"] = target

    from worthless.cli import dotenv_rewriter as mod

    monkeypatch.setattr(mod, "safe_rewrite", _fake_safe_rewrite)

    hook_fired: list[bool] = []

    def _hook() -> None:
        hook_fired.append(True)

    rewrite_env_keys(env, {"A": "alpha"}, _hook_before_replace=_hook)

    assert received["hook"] is _hook


def test_rewrite_env_keys_empty_updates_is_noop(
    tmp_path: Path, safe_rewrite_spy, make_env_file, sha256_of
) -> None:
    env = make_env_file(tmp_path / ".env", b"A=1\nB=2\n")
    pre_sha = sha256_of(env)

    rewrite_env_keys(env, {})

    assert safe_rewrite_spy.call_count == 0
    assert sha256_of(env) == pre_sha


def test_rewrite_env_keys_idempotent_same_bytes_is_noop(
    tmp_path: Path, safe_rewrite_spy, make_env_file, sha256_of
) -> None:
    env = make_env_file(tmp_path / ".env", b"A=1\n")
    pre_sha = sha256_of(env)

    rewrite_env_keys(env, {"A": "1"})

    assert safe_rewrite_spy.call_count == 0
    assert sha256_of(env) == pre_sha


# ---------------------------------------------------------------------------
# Overlap rejection — per CodeRabbit nitpick on PR #104.
#
# `_validate_rewrite_args` MUST refuse non-empty intersections across
# (updates, additions, removals). Silent mangling (e.g. updates ∩ removals
# would update then immediately delete) is a worse failure mode than a loud
# ValueError that names the offending keys.
# ---------------------------------------------------------------------------


def test_rewrite_env_keys_rejects_updates_removals_overlap(
    tmp_path: Path, safe_rewrite_spy, make_env_file, sha256_of
) -> None:
    env = make_env_file(tmp_path / ".env", b"A=1\nB=2\n")
    pre_sha = sha256_of(env)

    with pytest.raises(ValueError, match=r"updates and removals overlap"):
        rewrite_env_keys(env, {"A": "new"}, removals={"A"})

    # No write happened — file is byte-identical, no safe_rewrite call.
    assert safe_rewrite_spy.call_count == 0
    assert sha256_of(env) == pre_sha


def test_rewrite_env_keys_rejects_additions_removals_overlap(
    tmp_path: Path, safe_rewrite_spy, make_env_file, sha256_of
) -> None:
    env = make_env_file(tmp_path / ".env", b"A=1\n")
    pre_sha = sha256_of(env)

    with pytest.raises(ValueError, match=r"additions and removals overlap"):
        rewrite_env_keys(env, {}, additions={"NEW": "v"}, removals={"NEW"})

    assert safe_rewrite_spy.call_count == 0
    assert sha256_of(env) == pre_sha


def test_rewrite_env_keys_rejects_updates_additions_overlap(
    tmp_path: Path, safe_rewrite_spy, make_env_file, sha256_of
) -> None:
    env = make_env_file(tmp_path / ".env", b"A=1\n")
    pre_sha = sha256_of(env)

    with pytest.raises(ValueError, match=r"updates and additions overlap"):
        rewrite_env_keys(env, {"A": "x"}, additions={"A": "y"})

    assert safe_rewrite_spy.call_count == 0
    assert sha256_of(env) == pre_sha


def test_rewrite_env_keys_overlap_error_names_offending_keys(
    tmp_path: Path, safe_rewrite_spy, make_env_file
) -> None:
    """Error message MUST list which keys collided so callers can debug."""
    env = make_env_file(tmp_path / ".env", b"A=1\nB=2\nC=3\n")

    with pytest.raises(ValueError, match=r"\['A', 'B'\]"):
        rewrite_env_keys(
            env,
            {"A": "x", "B": "y"},
            removals={"A", "B"},
        )

    assert safe_rewrite_spy.call_count == 0


def test_rewrite_env_keys_disjoint_sets_still_work(
    tmp_path: Path, safe_rewrite_spy, make_env_file
) -> None:
    """Sanity: the validation MUST NOT reject legitimate non-overlapping use."""
    env = make_env_file(tmp_path / ".env", b"A=1\nB=2\nC=3\n")

    # updates A, removes B, adds D — three distinct sets, no overlap.
    rewrite_env_keys(
        env,
        {"A": "new"},
        additions={"D": "4"},
        removals={"B"},
    )

    # Exactly one safe_rewrite call (the all-or-nothing primitive).
    assert safe_rewrite_spy.call_count == 1
    contents = env.read_bytes()
    assert b"A=new" in contents
    assert b"B=" not in contents
    assert b"C=3" in contents
    assert b"D=4" in contents
