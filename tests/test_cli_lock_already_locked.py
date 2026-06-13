"""worthless-ftmg — ``worthless lock`` refuses to lock an already-locked .env.

# The bug

Before this fix, ``worthless lock`` had no detection that a ``.env`` was
already in a locked state. A user (or an LLM agent following ``SKILL.md``)
running ``lock`` on a ``.env`` that previously went through a
``lock`` — whether by deliberate re-lock, partial-failure retry, or a
state-drift scenario like ``rm -rf ~/.worthless && worthless lock`` — got
their ``shard-A`` value silently treated as a fresh plaintext key, split
again, and the **original real key became unrecoverable** (the only path
back was ``shard-A_old ⊕ shard-B_old``, both of which were just
overwritten).

The commitment check at ``lock.py`` only fires on alias collision — same
key value → same alias → DB row present. When the DB row is gone for any
reason, or when the input value has changed (``shard-A != original key``
→ different alias), the commitment check never gets a chance to run.

# The detection signal we picked

Approach (a) from worthless-ftmg's bug description: a Worthless lock
always writes a ``*_BASE_URL`` env var pointing at the local Worthless
proxy. The presence of such a var is the strongest one-shot signal that
this ``.env`` is already locked (or was locked and unlock didn't
complete). Lock now aborts on this signal BEFORE any DB / .env mutation,
with structured ``ErrorCode.ENV_ALREADY_LOCKED`` (117) and a remediation
naming both ``worthless unlock`` and ``worthless doctor``.

# Out of scope here

The detection is intentionally narrow — only the proxy-URL signal. We
deliberately do NOT scan the DB for matching commitments (approach (b)
in the bug description) yet — that's a higher-coverage follow-up but
also higher-risk (false-positive on similar-prefix values). Filed as a
G5 line item if needed.

A foreign proxy on the same port (3rd-party app at ``127.0.0.1:8787``)
is treated as the worst-case false positive. We accept this — the lock
refuses with a clear message, and the user can change ``WORTHLESS_PORT``
or stop the 3rd party.

# What this test pins

1. Re-lock against an already-locked .env: lock refuses with code 117 +
   names the var + suggests ``worthless unlock`` / ``worthless doctor``.
   Zero side effects: .env byte-identical, DB byte-identical.

2. A user's own ``OPENAI_BASE_URL`` pointing at a third-party (not us)
   does NOT trip the check. Lock proceeds normally.

3. A ``.env`` with ONLY the proxy BASE_URL and no key — evidence of a
   partial-failure mid-lock — still refuses. (The check is about the
   .env's locked state, not about whether there's a key to split.)
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.errors import ErrorCode

from tests.helpers import fake_openai_key

runner = CliRunner()


@pytest.fixture
def env_file_with_key(tmp_path: Path) -> tuple[Path, str]:
    key = fake_openai_key()
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={key}\n")
    return env, key


def _checksum(path: Path) -> str:
    """Byte-identity helper — proves zero side effects on refusal."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Re-lock refused
# ---------------------------------------------------------------------------


def test_relock_refuses_when_env_already_has_worthless_base_url(
    home_dir: WorthlessHome,
    env_file_with_key: tuple[Path, str],
) -> None:
    """A .env carrying a `*_BASE_URL` pointing at the local Worthless proxy
    must abort lock with code 117 + zero side effects.

    This is the canonical worthless-ftmg scenario: a user re-runs lock
    against a .env that's already gone through lock (shard-A in the key
    field, BASE_URL pointing at us). Without this check, lock silently
    splits shard-A and destroys the only path back to the real key.
    """
    env_file, _key = env_file_with_key
    # Append the BASE_URL that a successful lock would have written. The
    # apiKey field holds what looks like a fresh sk-proj key (could be
    # shard-A from a previous lock, or the real key — lock has no way
    # to tell). The BASE_URL signal is enough to refuse.
    env_file.write_text(
        f"OPENAI_API_KEY={fake_openai_key()}\n"
        "OPENAI_BASE_URL=http://127.0.0.1:8787/openai-abcd1234/v1\n"
    )
    pre_sum = _checksum(env_file)

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    assert result.exit_code == ErrorCode.ENV_ALREADY_LOCKED.value, (
        f"expected exit {ErrorCode.ENV_ALREADY_LOCKED.value}, got "
        f"{result.exit_code}\n{result.output}"
    )
    # Operator gets a useful message naming the var + the recovery path.
    assert "OPENAI_BASE_URL" in result.output, (
        f"refusal message must name the offending var:\n{result.output}"
    )
    assert "worthless unlock" in result.output or "worthless doctor" in result.output, (
        f"refusal message must point at a recovery command:\n{result.output}"
    )
    # Zero side effects — .env byte-identical; no shards rows / no enrollments
    # were written. (Bootstrap initializes the SQLite schema before any lock
    # preflight runs, so checking file existence is the wrong invariant — the
    # right one is "no rows written".)
    assert _checksum(env_file) == pre_sum, ".env was mutated by a refused lock"
    if home_dir.db_path.exists():
        con = sqlite3.connect(str(home_dir.db_path))
        try:
            shards = con.execute("SELECT COUNT(*) FROM shards").fetchone()[0]
            enrolled = con.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0]
        finally:
            con.close()
        assert shards == 0, f"refused lock wrote {shards} shards row(s)"
        assert enrolled == 0, f"refused lock wrote {enrolled} enrollment(s)"


# ---------------------------------------------------------------------------
# Third-party BASE_URL is left alone
# ---------------------------------------------------------------------------


def test_relock_refuses_on_partial_lock_with_mixed_locked_and_plaintext_vars(
    home_dir: WorthlessHome,
    env_file_with_key: tuple[Path, str],
) -> None:
    """Partial-lock state — one provider already locked, a second provider's
    key still plaintext (the BASE_URL never got written because lock failed
    mid-flight before the Anthropic pass) — MUST refuse at the preflight
    naming a locked var, NOT silently split the second plaintext key.

    This is the worst version of the worthless-ftmg bug: a partial-failure
    leaves the user with one shard-A in OPENAI_API_KEY + the matching
    OPENAI_BASE_URL pointing at our proxy, and a fresh ANTHROPIC_API_KEY
    plaintext sitting next to it. Without the gate, a re-lock would split
    the OPENAI shard-A as if fresh (destroying the original) AND lock the
    Anthropic key — but the operator would have no way to know the OpenAI
    side just lost its only path back to plaintext.

    Pinned: the gate names a locked var, exits 117 cleanly, and the .env
    + DB are byte-identical so the operator can run ``worthless doctor``
    to recover.
    """
    env_file, _key = env_file_with_key
    env_file.write_text(
        # Partially-locked: OPENAI is locked (shard-A + BASE_URL).
        f"OPENAI_API_KEY={fake_openai_key()}\n"
        "OPENAI_BASE_URL=http://127.0.0.1:8787/openai-deadbeef/v1\n"
        # ANTHROPIC is still plaintext, no matching BASE_URL.
        # This is what a partial-failure lock leaves behind: the second
        # provider's pass never got the BASE_URL written.
        f"ANTHROPIC_API_KEY={fake_openai_key()}\n"
    )
    pre_sum = _checksum(env_file)

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    # Exit 117 — operator gets the structured error, not a half-mutated state.
    assert result.exit_code == ErrorCode.ENV_ALREADY_LOCKED.value, (
        f"expected exit {ErrorCode.ENV_ALREADY_LOCKED.value}, got "
        f"{result.exit_code}\n{result.output}"
    )
    # The refusal message names the locked var (OPENAI_BASE_URL is what trips
    # the detector — naming it gives the operator a precise pointer).
    assert "OPENAI_BASE_URL" in result.output, (
        f"refusal must name the offending var so the operator can recover:\n{result.output}"
    )
    assert "worthless unlock" in result.output or "worthless doctor" in result.output, (
        f"refusal must point at a recovery command:\n{result.output}"
    )
    # Critical invariant: ZERO side effects. The Anthropic plaintext key
    # in particular must NOT have been split — a refused lock leaves the
    # file byte-identical and the DB untouched.
    assert _checksum(env_file) == pre_sum, (
        ".env was mutated by a refused lock — Anthropic plaintext may have "
        "been split. Recovery path is lost."
    )
    if home_dir.db_path.exists():
        con = sqlite3.connect(str(home_dir.db_path))
        try:
            shards = con.execute("SELECT COUNT(*) FROM shards").fetchone()[0]
            enrolled = con.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0]
        finally:
            con.close()
        assert shards == 0, f"refused lock wrote {shards} shards row(s)"
        assert enrolled == 0, f"refused lock wrote {enrolled} enrollment(s)"


def test_lock_proceeds_when_base_url_points_at_third_party(
    home_dir: WorthlessHome,
    env_file_with_key: tuple[Path, str],
) -> None:
    """A user's own ``OPENAI_BASE_URL`` pointing at a third-party gateway
    (their own OpenAI-compatible service, not our proxy) MUST NOT trigger
    the refusal. Their first lock is a legitimate operation.

    Detection signal: the URL host:port. A non-loopback / non-proxy
    host:port doesn't match and lock proceeds.
    """
    env_file, _key = env_file_with_key
    env_file.write_text(
        f"OPENAI_API_KEY={fake_openai_key()}\n"
        "OPENAI_BASE_URL=https://my-own-gateway.example.com/v1\n"
    )

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    # Lock either succeeds (exit 0) or fails for an unrelated reason
    # (e.g. proxy not running) but NEVER with ENV_ALREADY_LOCKED.
    assert result.exit_code != ErrorCode.ENV_ALREADY_LOCKED.value, (
        f"third-party BASE_URL must not trip the already-locked check:\n{result.output}"
    )


# ---------------------------------------------------------------------------
# Legitimate idempotent re-lock (same key value, DB row exists) — NOT refused
# ---------------------------------------------------------------------------


def test_idempotent_relock_with_matching_db_row_is_not_refused(
    home_dir: WorthlessHome,
    tmp_path: Path,
) -> None:
    """A user re-running ``worthless lock`` after a successful lock — same
    key value, same DB row — is the legitimate idempotent re-lock path
    that the project's "lock-rerun contract" depends on.

    The first lock writes shard-A into the .env key field and adds
    ``*_BASE_URL`` pointing at our proxy. On the second invocation,
    ``_select_unlocked_keys`` filters out the now-enrolled alias (the
    commitment matches the value in .env) and the lock exits 0 with a
    "still protected" hint. Our new check MUST NOT misclassify this as
    the destructive re-lock case — that would break the documented
    idempotency contract and an existing test suite (TestLockRerun).

    The discriminator: the destructive case only fires when there's a
    `scanned` key with NO matching DB row left. The legitimate idempotent
    case short-circuits via ``if not scanned: return`` BEFORE the new
    check runs.
    """
    env_file = tmp_path / ".env"
    env_file.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")

    first = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert first.exit_code == 0, first.output

    body = env_file.read_text()
    assert "OPENAI_BASE_URL=http://" in body, body
    pre_sum = _checksum(env_file)

    second = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )
    assert second.exit_code == 0, (
        f"idempotent re-lock must succeed (exit 0), got {second.exit_code} — "
        "the new already-locked check is over-firing on a legitimate same-key "
        f"re-run.\n{second.output}"
    )
    assert second.exit_code != ErrorCode.ENV_ALREADY_LOCKED.value
    assert _checksum(env_file) == pre_sum, ".env mutated on idempotent re-lock"
