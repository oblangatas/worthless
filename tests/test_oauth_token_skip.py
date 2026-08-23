"""WOR-837: a Claude Code OAuth token in .env is skipped, not sharded.

Claude Code's OAuth login issues tokens prefixed ``sk-ant-oat01-`` (access)
and ``sk-ant-ort01-`` (refresh). Both collide with Worthless's static
``sk-ant-`` API-key prefix, so ``lock`` currently treats them as static keys
and shards them. But sharding rewrites the ``sk-ant-oat`` marker OpenClaw
matches on, and the proxy cannot restore the OAuth request shape that loss
costs — so a locked token silently breaks the user's Claude Code. ``lock``
must recognize them and skip with an honest warning instead.

Scope: Anthropic only (verified — OpenAI/Google OAuth tokens are JWTs, xAI
has no dev OAuth, OpenRouter OAuth yields a genuine static key).
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from dotenv import dotenv_values
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.key_patterns import KEY_PATTERN, is_oauth_token

from tests.conftest import make_repo as _repo
from tests.helpers import fake_anthropic_key, fake_key, fake_openai_key

runner = CliRunner()


class TestIsOAuthToken:
    """Unit: the classifier tells a Claude Code OAuth token from a static key."""

    def test_access_token_is_oauth(self) -> None:
        assert is_oauth_token(fake_key("sk-ant-oat01-", "wor837-access")) is True

    def test_refresh_token_is_oauth(self) -> None:
        assert is_oauth_token(fake_key("sk-ant-ort01-", "wor837-refresh")) is True

    def test_static_anthropic_key_is_not_oauth(self) -> None:
        # sk-ant-api03- — a real static console key must still lock normally.
        assert is_oauth_token(fake_anthropic_key()) is False

    def test_openai_key_is_not_oauth(self) -> None:
        assert is_oauth_token(fake_openai_key()) is False

    def test_oauth_token_still_matches_redaction_pattern(self) -> None:
        # Design invariant: skipping an OAuth token from *sharding* must NOT
        # stop it being *redacted* from logs — it is still a secret. KEY_PATTERN
        # (which drives log redaction) must keep matching it.
        assert KEY_PATTERN.search(fake_key("sk-ant-oat01-", "wor837-redact")) is not None


class TestLockSkipsOAuthToken:
    """Integration: lock skips the OAuth token, still locks the real key, warns."""

    def test_lock_skips_oauth_but_locks_static_key(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        oauth_token = fake_key("sk-ant-oat01-", "wor837-access")
        static_key = fake_openai_key()
        env = tmp_path / ".env"
        env.write_text(f"ANTHROPIC_API_KEY={oauth_token}\nOPENAI_API_KEY={static_key}\n")

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        parsed = dotenv_values(env)
        # The OAuth token must be left byte-for-byte — never sharded.
        assert parsed["ANTHROPIC_API_KEY"] == oauth_token, (
            "OAuth token was sharded — sharding destroys the sk-ant-oat marker Claude Code "
            "is recognised by"
        )
        # The real static key must still lock (value replaced by shard-A).
        assert parsed["OPENAI_API_KEY"] != static_key, "static key should have been locked"

        # Only the static key is enrolled — the OAuth token was never stored.
        aliases = asyncio.run(_repo(home_dir).list_keys())
        assert len(aliases) == 1, f"expected only the static key enrolled, got {aliases}"

        # And the user was told, loudly.
        assert "oauth" in result.output.lower(), (
            f"lock must warn that it skipped an OAuth token; output:\n{result.output}"
        )

    def test_lock_sanitizes_oauth_var_name_in_warning(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        # A crafted .env var name (dotenv keys are permissive) must not smuggle
        # a bidi-override / control char into the terminal warning — it goes
        # through the same sanitizer lock uses everywhere else.
        bidi = chr(0x202E)  # RIGHT-TO-LEFT OVERRIDE — a terminal-injection primitive
        oauth_token = fake_key("sk-ant-oat01-", "wor837-inject")
        env = tmp_path / ".env"
        env.write_text(f"ANTHROPIC{bidi}_API_KEY={oauth_token}\n")

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output
        # The warning fired (so this isn't a vacuous pass)...
        assert "oauth" in result.output.lower(), result.output
        # ...and the bidi-override was neutralized, never emitted raw.
        assert bidi not in result.output, "unsanitized bidi-override reached the terminal"


def _flat(output: str) -> str:
    """Collapse Rich's soft-wrapping so assertions match sentences, not layout."""
    return " ".join(output.split())


class TestOAuthSkipSuppressesProtectionVerdict:
    """worthless-7jn2: a skipped OAuth token is still a live secret in the file.

    The skip itself is correct (sharding destroys the ``sk-ant-oat`` marker
    OpenClaw tests for). What was wrong is the summary: ``lock`` printed the
    product's headline verdict — "You're protected", ".env no longer contains a
    usable secret" — over a plaintext credential it had just decided to leave
    behind. These assert on the OUTPUT THE USER READS, not an internal flag.
    """

    def test_mixed_env_does_not_claim_protection(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        # One real key (locks) + one OAuth token (skipped, stays in plaintext).
        env = tmp_path / ".env"
        env.write_text(
            f"OPENAI_API_KEY={fake_openai_key()}\n"
            f"ANTHROPIC_API_KEY={fake_key('sk-ant-oat01-', 'wor7jn2-mixed')}\n"
        )

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output
        flat = _flat(result.output)

        # The skip is reported — so this isn't a vacuous pass.
        assert "oauth" in flat.lower(), f"lock must report the skip; output:\n{result.output}"

        # The verdict is NOT earned: a live token is still in that file.
        assert "You're protected" not in flat, (
            f"lock claimed protection over a skipped OAuth token; output:\n{result.output}"
        )
        assert "no longer contains a usable secret" not in flat, (
            f"lock claimed the .env holds no usable secret while a skipped OAuth "
            f"token sits in it; output:\n{result.output}"
        )

        # The factual lines survive — only the derived verdict is suppressed.
        assert "split between this machine" in flat, (
            f"the factual split line must still print; output:\n{result.output}"
        )

    def test_oauth_only_env_is_not_reported_clean(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        # Nothing lockable — but a key WAS found, classified, and skipped.
        env = tmp_path / ".env"
        env.write_text(f"ANTHROPIC_API_KEY={fake_key('sk-ant-oat01-', 'wor7jn2-only')}\n")

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output
        flat = _flat(result.output)

        assert "oauth" in flat.lower(), f"lock must report the skip; output:\n{result.output}"
        assert "No unprotected API keys found" not in flat, (
            f"lock reported a clean file for a key it found and skipped; output:\n{result.output}"
        )
        assert "plaintext" in flat.lower(), (
            f"lock must say the skipped token is still in the file; output:\n{result.output}"
        )

    def test_oauth_only_env_does_not_claim_other_keys_were_locked(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """The skip warning must not offer comfort that only holds for a mixed .env.

        The warning once ended "— your other keys were locked normally." On an
        OAuth-only file there are no other keys and nothing was locked, so that
        clause flatly contradicted the "Nothing was locked" line printed right
        under it. The summary already carries the fact; the warning must not
        restate it falsely.
        """
        env = tmp_path / ".env"
        env.write_text(f"ANTHROPIC_API_KEY={fake_key('sk-ant-oat01-', 'wor837-onlyskip')}\n")

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output
        low = _flat(result.output).lower()

        # Not vacuous: the skip really was reported.
        assert "oauth" in low, f"lock must report the skip; output:\n{result.output}"

        # Match the SHAPE of the false claim, not the one sentence that carried
        # it — a reworded relapse ("the rest of your keys locked fine") is the
        # same lie. Nothing was locked here, so any claim that some *other* key
        # was, or that locking went fine, is false however it is phrased.
        for pattern in (
            r"\b(other|remaining|rest of (?:your|the))\b[^.]*\block",
            r"\block(?:ed)?\s+(?:normally|fine|as usual|successfully|without issue)\b",
            # The house register for this comfort is "Your other keys are safe."
            # (_remediation.py:25,51; uninstall.py:660) — no "lock" word at all,
            # so the patterns above would miss a relapse phrased that way.
            r"\b(?:other|remaining|rest of (?:your|the))\b[^.]*\b(?:safe|protected|secure)\b",
        ):
            assert re.search(pattern, low) is None, (
                f"lock claimed keys were locked on an OAuth-only .env where "
                f"nothing was locked (matched {pattern!r}); output:\n{result.output}"
            )

        # The truthful summary is the one line allowed to speak to what happened.
        assert "nothing was locked" in low, (
            f"the summary must state nothing was locked; output:\n{result.output}"
        )
