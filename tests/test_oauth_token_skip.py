"""WOR-837: a Claude Code OAuth token in .env is skipped, not sharded.

Claude Code's OAuth login issues tokens prefixed ``sk-ant-oat01-`` (access)
and ``sk-ant-ort01-`` (refresh). Both collide with Worthless's static
``sk-ant-`` API-key prefix, so ``lock`` currently treats them as static keys
and shards them. But they rotate every few hours — a frozen shard is a dead
credential within hours, silently breaking the user's Claude Code. ``lock``
must recognize them and skip with an honest warning instead.

Scope: Anthropic only (verified — OpenAI/Google OAuth tokens are JWTs, xAI
has no dev OAuth, OpenRouter OAuth yields a genuine static key).
"""

from __future__ import annotations

import asyncio
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
    """Unit: the classifier tells a rotating OAuth token from a static key."""

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
            "OAuth token was sharded — a frozen shard of a rotating token is dead on arrival"
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
