"""Tests for the lock and enroll CLI commands."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

from tests.conftest import make_repo as _repo
from tests.helpers import (
    fake_anthropic_key,
    fake_key,
    fake_openai_key,
    verify_upstream_response_openai,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# WOR-501: _proxy_base_url host configurability (Docker / LAN deployments)
# ---------------------------------------------------------------------------


class TestProxyBaseUrlDockerHost:
    """``_proxy_base_url`` must respect ``WORTHLESS_PROXY_HOST``.

    Regression tests for the Docker connectivity bug: lock was hardcoding
    ``127.0.0.1`` in the BASE_URL written to ``.env``, so container agents
    that reached the proxy via ``host.docker.internal`` would point at the
    wrong address after locking.
    """

    def test_default_host_is_loopback(self, monkeypatch):
        """Without WORTHLESS_PROXY_HOST the URL contains 127.0.0.1."""
        from worthless.cli.commands.lock import _proxy_base_url

        monkeypatch.delenv("WORTHLESS_PROXY_HOST", raising=False)
        url = _proxy_base_url("openai-abc12345")
        assert "127.0.0.1" in url

    def test_worthless_proxy_host_overrides_hostname(self, monkeypatch):
        """WORTHLESS_PROXY_HOST=host.docker.internal is written into the URL.

        Without this fix, every ``worthless lock`` run inside a Docker
        workflow would embed ``127.0.0.1`` — which resolves to the container
        itself, not the host machine running the proxy.
        """
        from worthless.cli.commands.lock import _proxy_base_url

        monkeypatch.setenv("WORTHLESS_PROXY_HOST", "host.docker.internal")
        url = _proxy_base_url("openai-abc12345")
        assert "host.docker.internal" in url
        assert "127.0.0.1" not in url

    def test_url_contains_alias_and_v1(self, monkeypatch):
        """URL format is ``http://<host>:<port>/<alias>/v1``."""
        from worthless.cli.commands.lock import _proxy_base_url

        monkeypatch.delenv("WORTHLESS_PROXY_HOST", raising=False)
        url = _proxy_base_url("openai-deadbeef")
        assert url.startswith("http://")
        assert "openai-deadbeef" in url
        assert url.endswith("/v1")

    def test_url_contains_default_port(self, monkeypatch):
        """Default port 8787 appears in the generated URL."""
        from worthless.cli.commands.lock import _proxy_base_url

        monkeypatch.delenv("WORTHLESS_PROXY_HOST", raising=False)
        monkeypatch.delenv("WORTHLESS_PORT", raising=False)
        url = _proxy_base_url("openai-cafebabe")
        assert ":8787/" in url

    def test_worthless_port_env_var_respected(self, monkeypatch):
        """WORTHLESS_PORT overrides the default 8787 in the generated URL."""
        from worthless.cli.commands.lock import _proxy_base_url

        monkeypatch.delenv("WORTHLESS_PROXY_HOST", raising=False)
        monkeypatch.setenv("WORTHLESS_PORT", "9000")
        url = _proxy_base_url("openai-cafebabe")
        assert ":9000/" in url
        assert ":8787" not in url


# ---------------------------------------------------------------------------
# WOR-207 Phase 2: Format-preserving lock + decoy deletion
# ---------------------------------------------------------------------------


class TestLockFormatPreserving:
    """Lock should use split_key_fp, write shard-A to .env, store prefix/charset in DB."""

    def test_lock_writes_shard_a_to_env(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """After lock, .env should contain a format-valid shard-A (not a decoy)."""
        original_key = env_file.read_text().strip().split("=", 1)[1]
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        # Parse the OPENAI_API_KEY line specifically
        from dotenv import dotenv_values

        parsed = dotenv_values(env_file)
        new_value = parsed["OPENAI_API_KEY"]
        # Shard-A must preserve the prefix
        assert new_value.startswith("sk-proj-")
        # Shard-A must differ from original key (it's a random share)
        assert new_value != original_key
        # Shard-A must have the same length as original key
        assert len(new_value) == len(original_key)

    def test_lock_writes_base_url_to_env(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """After lock, .env should contain OPENAI_BASE_URL pointing to proxy."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        content = env_file.read_text()
        assert "OPENAI_BASE_URL=" in content
        # URL must contain the alias in the path
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 1
        alias = aliases[0]
        # Extract the BASE_URL value
        for line in content.splitlines():
            if line.startswith("OPENAI_BASE_URL="):
                url = line.split("=", 1)[1]
                assert alias in url
                assert "/v1" in url
                assert "8787" in url  # default port
                break
        else:
            pytest.fail("OPENAI_BASE_URL not found in .env")

    def test_lock_reads_existing_base_url_from_env(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """If user's .env has OPENROUTER_API_KEY + OPENROUTER_BASE_URL pointing
        at OpenRouter, lock stores that URL in DB and rewrites the var (NAME
        unchanged) to the local proxy URL — not the canonical OPENAI_BASE_URL.

        worthless-8rqs core flow: respect the user's variable names, route
        per-enrollment to the right upstream.
        """
        from worthless.storage.repository import ShardRepository

        env = tmp_path / ".env"
        env.write_text(
            f"OPENROUTER_API_KEY={fake_openai_key()}\n"
            "OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\n"
        )

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        # DB row stores the user's base_url (the upstream — OpenRouter).
        async def _check():
            repo = ShardRepository(str(home_dir.db_path), home_dir.fernet_key)
            await repo.initialize()
            aliases = await repo.list_keys()
            assert len(aliases) == 1
            enc = await repo.fetch_encrypted(aliases[0])
            return enc.base_url, aliases[0]

        base_url_in_db, alias = asyncio.run(_check())
        assert base_url_in_db == "https://openrouter.ai/api/v1"

        # .env rewrite preserves the var NAME (OPENROUTER_BASE_URL, not OPENAI_BASE_URL).
        from dotenv import dotenv_values

        parsed = dotenv_values(env)
        assert "OPENROUTER_BASE_URL" in parsed
        assert "OPENAI_BASE_URL" not in parsed, (
            "lock rewrote to canonical OPENAI_BASE_URL — should preserve OPENROUTER_BASE_URL"
        )
        assert parsed["OPENROUTER_BASE_URL"].startswith("http://127.0.0.1:")
        assert alias in parsed["OPENROUTER_BASE_URL"]

    def test_lock_refuses_unregistered_attacker_base_url(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """M3 (Blocker #1): if the user's .env has a *_BASE_URL pointing at a
        URL not in the provider registry, lock must refuse rather than store
        the attacker-controlled URL in the DB.

        Threat: attacker tampers with .env, sets
        OPENROUTER_BASE_URL=https://attacker.example/v1. Pre-fix, lock pulled
        that URL into the DB unchanged; the proxy then forwarded the
        reconstructed shard-A as Bearer to attacker.example — exfiltration.

        worthless-rzi1 (P1 follow-up) adds per-request re-validation against
        the registry to close the post-lock-tamper variant of the same attack.
        worthless-8fbg adds RFC1918/loopback hardening on the URL shape itself.
        M3 here is the lock-time minimum: refuse unknown URLs with a hint to
        worthless providers register.
        """
        env = tmp_path / ".env"
        env.write_text(
            f"OPENROUTER_API_KEY={fake_openai_key()}\n"
            "OPENROUTER_BASE_URL=https://attacker.example/v1\n"
        )

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

        assert result.exit_code != 0, (
            f"lock should refuse unknown upstream URL, but exit_code={result.exit_code}; "
            f"output={result.output[:300]}"
        )
        # Error message should name the offending URL and point at the fix.
        out = result.output.lower()
        assert "attacker.example" in out, (
            f"error message should name the rejected URL; got: {result.output[:400]}"
        )
        assert "providers register" in out or "register" in out, (
            "error message should hint at 'worthless providers register'; "
            f"got: {result.output[:400]}"
        )

        # DB must not have stored the attacker URL — no enrollment created.
        async def _check_no_enrollment():
            from worthless.storage.repository import ShardRepository

            repo = ShardRepository(str(home_dir.db_path), home_dir.fernet_key)
            await repo.initialize()
            aliases = await repo.list_keys()
            return aliases

        aliases = asyncio.run(_check_no_enrollment())
        assert aliases == [], f"DB should have no enrollments after refused lock, found: {aliases}"

    def test_lock_enrolls_openrouter_key_post_hf1(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Regression: post-HF1 (`detect_provider("sk-or-v1-...") == "openrouter"`),
        an `OPENROUTER_API_KEY` in `.env` must enroll successfully via the
        OpenAI wire protocol — NOT be silently skipped with "provider not
        yet supported."

        Pre-HF1, the OpenRouter `sk-or-v1-` prefix wasn't in
        ``PROVIDER_PREFIXES``, so ``detect_provider`` fell through to
        ``"openai"`` and the lock flow worked. HF1 (commit fcf75f6) added
        the prefix and made detection return ``"openrouter"``. The
        existing ``_SUPPORTED_PROVIDERS = {"openai", "anthropic"}`` gate
        then SKIPPED any OpenRouter key with a warning, leaving the
        plaintext key in ``.env`` — the exact "shard-A on the wire" leak
        8rqs is meant to close.

        Fix (this commit, M8 merge resolution): translate the registry
        name to its wire protocol via ``lookup_by_name`` before the
        supported gate. ``lookup_by_name("openrouter")`` returns the
        bundled registry entry with ``protocol="openai"``, so the gate
        passes, the alias is built with ``protocol`` as the prefix
        (matches pre-HF1 behaviour, namespace stable across re-locks),
        and the proxy dispatches the OpenAI adapter to the OpenRouter
        upstream URL — same flow that the M3 live-smoke validated.
        """
        from tests.helpers import fake_key

        # OpenRouter-shaped key (the "sk-" + "or-v1-" form HF1 added).
        or_key = fake_key("sk-" + "or-v1-")

        env = tmp_path / ".env"
        env.write_text(
            f"OPENROUTER_API_KEY={or_key}\nOPENROUTER_BASE_URL=https://openrouter.ai/api/v1\n"
        )

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

        assert result.exit_code == 0, (
            f"OpenRouter lock failed: exit={result.exit_code}; output={result.output[:400]}"
        )

        # Lock must NOT have emitted "provider 'openrouter' not yet supported".
        out_l = result.output.lower()
        assert "not yet supported" not in out_l, (
            f"OpenRouter key was silently skipped — the M8 fix didn't take. "
            f"output: {result.output[:400]}"
        )

        # DB row exists and stores wire protocol (openai), not registry name.
        async def _check():
            from worthless.storage.repository import ShardRepository

            repo = ShardRepository(str(home_dir.db_path), home_dir.fernet_key)
            await repo.initialize()
            aliases = await repo.list_keys()
            return aliases

        aliases = asyncio.run(_check())
        assert len(aliases) == 1, f"expected 1 enrollment, got: {aliases}"
        # Alias namespace stable: openai-XXXX prefix, not openrouter-XXXX.
        # Pre-merge enrollments used "openai-" prefix because pre-HF1
        # detect_provider returned "openai" for sk-or-v1-* keys.
        # Post-merge with the M8 translation, alias prefix stays "openai-"
        # so existing DB rows still resolve.
        assert aliases[0].startswith("openai-"), (
            f"expected alias to start with 'openai-' (wire protocol), got: {aliases[0]!r}"
        )

        # The .env was rewritten — OpenROUTER_BASE_URL points at local proxy.
        rewritten = env.read_text()
        assert "OPENROUTER_BASE_URL=http://127.0.0.1" in rewritten, (
            f"OPENROUTER_BASE_URL should point at local proxy after lock; got .env: {rewritten!r}"
        )

    def test_lock_captures_original_mode_before_tightening(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """WOR-715 AC-MODE-CAPTURED: lock records the .env's PRE-lock mode.

        ``safe_rewrite`` tightens every locked .env to 0o600. lock must capture
        the original 0o644 in pass-1 BEFORE that tighten, so the enrollment row
        stores 0o644 — not the post-rewrite 0o600. This is the guard against a
        capture placed at the wrong (post-rewrite) point, which would silently
        record 0o600 for everyone and make uninstall restore the wrong mode.
        """
        from tests.helpers import fake_key

        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
        env.chmod(0o644)
        assert (env.stat().st_mode & 0o777) == 0o644  # precondition

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, f"lock failed: {result.output[:400]}"

        # lock DID tighten the file — proves capture-before-tighten matters.
        assert (env.stat().st_mode & 0o777) == 0o600, (
            f"expected lock to tighten .env to 0o600, got {env.stat().st_mode & 0o777:o}"
        )

        # The enrollment row stored the ORIGINAL 0o644, not the tightened 0o600.
        con = sqlite3.connect(str(home_dir.db_path))
        try:
            rows = con.execute(
                "SELECT original_mode FROM enrollments WHERE env_path = ?",
                (str(env.resolve()),),
            ).fetchall()
        finally:
            con.close()
        assert rows, "no enrollment row found for the locked .env"
        assert rows[0][0] == 0o644, (
            f"expected original_mode 0o644 (pre-lock); got "
            f"{oct(rows[0][0]) if rows[0][0] is not None else 'NULL'} — "
            "capture likely happened AFTER the file was tightened to 0o600"
        )

    def test_capture_original_mode_reads_perm_bits(self, tmp_path: Path) -> None:
        """WOR-715: _capture_original_mode returns the file's 0o777 bits."""
        from worthless.cli.commands.lock import _capture_original_mode

        f = tmp_path / ".env"
        f.write_text("OPENAI_API_KEY=x\n")
        f.chmod(0o640)
        assert _capture_original_mode(str(f)) == 0o640

    def test_capture_original_mode_missing_file_returns_none(self, tmp_path: Path) -> None:
        """WOR-715: stat failure (vanished file / bad path) → None, not a crash.

        This is the ``except OSError`` branch — proves lock degrades to
        'mode unknown, leave as-is' instead of blowing up the whole command.
        """
        from worthless.cli.commands.lock import _capture_original_mode

        missing = tmp_path / "nope" / ".env"  # parent dir doesn't exist → OSError
        assert _capture_original_mode(str(missing)) is None

    def test_lock_captures_setgid_bits_stripped_end_to_end(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """WOR-715 / Wave 4: setgid (0o2644) is stripped to 0o644 in original_mode."""
        from tests.helpers import fake_key

        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
        env.chmod(0o2644)  # setgid | rw-r--r--

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output[:400]

        assert (env.stat().st_mode & 0o777) == 0o600, "lock must tighten .env to 0o600"

        con = sqlite3.connect(str(home_dir.db_path))
        try:
            rows = con.execute(
                "SELECT original_mode FROM enrollments WHERE env_path = ?",
                (str(env.resolve()),),
            ).fetchall()
        finally:
            con.close()
        assert rows and rows[0][0] == 0o644, (
            f"setgid must be stripped from captured mode; got {rows[0][0]!r}"
        )

    def test_lock_persists_null_original_mode_when_stat_unavailable(
        self, home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WOR-715 / Wave 4: OSError during capture → NULL original_mode in DB."""
        from tests.helpers import fake_key

        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={fake_key('sk-')}\n")
        env.chmod(0o644)

        monkeypatch.setattr(
            "worthless.cli.commands.lock._capture_original_mode",
            lambda _path: None,
        )

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output[:400]

        con = sqlite3.connect(str(home_dir.db_path))
        try:
            rows = con.execute(
                "SELECT original_mode FROM enrollments WHERE env_path = ?",
                (str(env.resolve()),),
            ).fetchall()
        finally:
            con.close()
        assert rows, "expected enrollment row"
        assert rows[0][0] is None, "stat failure must persist NULL original_mode"

    def test_lock_openrouter_key_without_base_url_routes_to_openrouter(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """An OpenRouter key with NO explicit ``*_BASE_URL`` must store the
        OpenRouter upstream URL in the DB — not fall back to OpenAI's URL.

        Live-container bug (PR #276 thermo-nuclear review): the upstream URL
        for the DB row was resolved from the WIRE PROTOCOL (``openai``, because
        OpenRouter speaks the OpenAI dialect) instead of the REGISTRY NAME
        (``openrouter``). ``_resolve_upstream_base_url`` was called with the
        protocol-collapsed ``provider`` value, so its
        ``lookup_by_name("openai")`` fallback returned
        ``https://api.openai.com/v1``. The proxy then forwarded the
        reconstructed OpenRouter key to OpenAI → HTTP 401, chat dead.

        The two existing OpenRouter tests both set ``OPENROUTER_BASE_URL``
        explicitly, so they take the user-value path and never exercise this
        fallback. This test omits ``*_BASE_URL`` on purpose to hit it.

        Contract: ``provider`` column stays ``openai`` (wire protocol, for
        adapter dispatch) while ``base_url`` is OpenRouter's upstream.
        """
        from worthless.storage.repository import ShardRepository

        or_key = fake_key("sk-" + "or-v1-")

        env = tmp_path / ".env"
        # NOTE: deliberately NO OPENROUTER_BASE_URL — forces the registry fallback.
        env.write_text(f"OPENROUTER_API_KEY={or_key}\n")

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        async def _check():
            repo = ShardRepository(str(home_dir.db_path), home_dir.fernet_key)
            await repo.initialize()
            aliases = await repo.list_keys()
            assert len(aliases) == 1, f"expected 1 enrollment, got: {aliases}"
            enc = await repo.fetch_encrypted(aliases[0])
            return enc.base_url, enc.provider, aliases[0]

        base_url_in_db, provider_in_db, alias = asyncio.run(_check())

        assert base_url_in_db == "https://openrouter.ai/api/v1", (
            f"OpenRouter key routed to the wrong upstream: {base_url_in_db!r}. "
            "Expected openrouter.ai — the proxy would 401 against api.openai.com."
        )
        # Wire protocol stays openai (OpenRouter speaks the OpenAI dialect) so
        # the proxy adapter formats requests correctly and the alias namespace
        # stays stable across re-locks.
        assert provider_in_db == "openai", (
            f"provider column should stay 'openai' (wire protocol), got: {provider_in_db!r}"
        )
        assert alias.startswith("openai-")

    def test_lock_warns_on_non_canonical_var_name(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """M4 (Blocker #2): if the user's API-key var doesn't match the
        canonical ``<PROVIDER>_API_KEY`` convention, lock emits a soft
        warning naming proxy bypass / shard-A leakage as the consequence.

        Threat: app reads the non-canonical var (e.g. ``MY_OPENAI_KEY``)
        directly and constructs an OpenAI client without ``base_url=``.
        SDKs only auto-detect ``OPENAI_BASE_URL`` when no explicit base
        URL is set; with the var read explicitly the SDK falls through
        to ``api.openai.com`` — bypassing the proxy and sending shard-A
        on the wire.

        Per product-manager review the right behavior is a SOFT warning
        (lock proceeds) so users learn about the gotcha without being
        blocked. ``worthless-v5sy`` (P3 follow-up) adds
        ``worthless lock --strict`` for CI/team policy that upgrades the
        warning to a refusal.
        """
        env = tmp_path / ".env"
        env.write_text(f"MY_OPENAI_KEY={fake_openai_key()}\n")

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

        # Soft warning: lock proceeds.
        assert result.exit_code == 0, (
            f"warning is soft, not a refusal; got exit_code={result.exit_code}; "
            f"output={result.output[:400]}"
        )
        out = result.output
        # Warning must name the offending var so the user can find it in .env.
        assert "MY_OPENAI_KEY" in out, (
            f"warning should name the non-canonical var; got: {out[:400]}"
        )
        # Warning must explain the consequence so users know why they care.
        out_l = out.lower()
        assert "shard-a" in out_l or "bypass" in out_l, (
            f"warning should explain shard-A leakage / proxy bypass; got: {out[:400]}"
        )

        # Lock still proceeded — DB has the enrollment.
        async def _check_enrollment():
            from worthless.storage.repository import ShardRepository

            repo = ShardRepository(str(home_dir.db_path), home_dir.fernet_key)
            await repo.initialize()
            return await repo.list_keys()

        aliases = asyncio.run(_check_enrollment())
        assert len(aliases) == 1, (
            f"lock should still create the enrollment despite the warning; got: {aliases}"
        )

    def test_lock_keys_only_skips_base_url(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """--keys-only flag should skip BASE_URL writing."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file), "--keys-only"],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        content = env_file.read_text()
        assert "BASE_URL" not in content

    def test_lock_stores_prefix_charset_in_db(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """After lock, DB shards row should have prefix and charset set."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        # Check DB directly for prefix/charset
        conn = sqlite3.connect(str(home_dir.db_path))
        try:
            row = conn.execute("SELECT prefix, charset FROM shards LIMIT 1").fetchone()
        finally:
            conn.close()
        assert row is not None
        prefix, charset = row
        assert prefix == "sk-proj-"
        assert charset is not None
        assert len(charset) > 0

    def test_lock_writes_no_shard_a_files(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """After lock, shard_a_dir should have ZERO files (SR-09: no file fallback)."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        shard_a_files = [f for f in home_dir.shard_a_dir.iterdir() if f.is_file()]
        assert len(shard_a_files) == 0

    def test_relock_skips_enrolled_via_db(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """Second lock should skip keys that already have an enrollment in DB."""
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        result1 = runner.invoke(app, ["lock", "--env", str(env_file)], env=env_vars)
        assert result1.exit_code == 0

        value_after_first = env_file.read_text().strip().split("\n")[0].split("=", 1)[1]

        result2 = runner.invoke(app, ["lock", "--env", str(env_file)], env=env_vars)
        assert result2.exit_code == 0

        value_after_second = env_file.read_text().strip().split("\n")[0].split("=", 1)[1]
        # Value should NOT change on re-lock (key already enrolled)
        assert value_after_first == value_after_second

    def test_lock_base_url_contains_alias(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """BASE_URL path must include the key alias for proxy routing."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        alias = aliases[0]

        content = env_file.read_text()
        for line in content.splitlines():
            if "BASE_URL" in line:
                assert f"/{alias}/v1" in line
                break


class TestDotenvAddOrRewrite:
    """Tests for the add_or_rewrite_env_key helper."""

    def test_add_or_rewrite_creates_new_var(self, tmp_path: Path) -> None:
        """add_or_rewrite should append a new variable if it doesn't exist."""
        from worthless.cli.dotenv_rewriter import add_or_rewrite_env_key

        env = tmp_path / ".env"
        env.write_text("EXISTING=value\n")

        add_or_rewrite_env_key(env, "NEW_VAR", "new_value")

        content = env.read_text()
        assert "EXISTING=value" in content
        assert "NEW_VAR=new_value" in content

    def test_add_or_rewrite_updates_existing(self, tmp_path: Path) -> None:
        """add_or_rewrite should update an existing variable in place."""
        from worthless.cli.dotenv_rewriter import add_or_rewrite_env_key

        env = tmp_path / ".env"
        env.write_text("MY_VAR=old_value\nOTHER=keep\n")

        add_or_rewrite_env_key(env, "MY_VAR", "new_value")

        content = env.read_text()
        assert "new_value" in content
        assert "old_value" not in content
        assert "OTHER=keep" in content


class TestScanEnvKeysNoDecoy:
    """scan_env_keys should work without is_decoy parameter after decoy removal."""

    def test_scan_env_keys_no_decoy_param(self, tmp_path: Path) -> None:
        """scan_env_keys should not accept is_decoy parameter."""
        from worthless.cli.dotenv_rewriter import scan_env_keys

        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")

        # Should work without is_decoy
        keys = scan_env_keys(env)
        assert len(keys) == 1
        assert keys[0][0] == "OPENAI_API_KEY"


@pytest.fixture()
def env_file(tmp_path: Path) -> Path:
    """Create a .env with a known OpenAI key."""
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    return env


@pytest.fixture()
def multi_env_file(tmp_path: Path) -> Path:
    """Create a .env with multiple API keys."""
    env = tmp_path / ".env"
    env.write_text(
        f"OPENAI_API_KEY={fake_openai_key()}\n"
        f"ANTHROPIC_API_KEY={fake_anthropic_key()}\n"
        "SOME_OTHER=not-a-key\n"
    )
    return env


class TestLockCommand:
    """Tests for `worthless lock`."""

    def test_lock_creates_shards_and_rewrites_env(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """Lock should split key (FP), store shard_b in DB, rewrite .env."""
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env=env_vars,
        )
        assert result.exit_code == 0, result.output

        # .env should be rewritten (different from original)
        from dotenv import dotenv_values

        parsed = dotenv_values(env_file)
        new_value = parsed["OPENAI_API_KEY"]
        assert fake_openai_key()[:24] not in new_value
        # Shard-A should still start with sk-proj-
        assert new_value.startswith("sk-proj-")

        # No shard_a files on disk (SR-09)
        shard_a_files = [f for f in home_dir.shard_a_dir.iterdir() if f.is_file()]
        assert len(shard_a_files) == 0

        # shard_b should be in DB
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 1

    def test_lock_no_env_file_exits_error(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Lock with nonexistent .env should exit with error code."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(tmp_path / "nonexistent.env")],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 1

    def test_lock_no_api_keys_exits_zero(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Lock with .env that has no API keys should print message and exit 0."""
        env = tmp_path / ".env"
        env.write_text("DATABASE_URL=postgres://localhost/db\n")
        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        assert "No unprotected" in result.output or "no unprotected" in result.output.lower()

    def test_lock_idempotent_skips_enrolled(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """Running lock twice should skip already-enrolled keys."""
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        result1 = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env=env_vars,
        )
        assert result1.exit_code == 0

        # Second run -- should skip the already-enrolled key
        result2 = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env=env_vars,
        )
        assert result2.exit_code == 0
        # Still only one alias in DB
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 1

    def test_lock_prefix_preservation(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """Shard-A value should preserve prefix and match original key length."""
        original_key = env_file.read_text().strip().split("=", 1)[1]
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env=env_vars,
        )
        assert result.exit_code == 0

        from dotenv import dotenv_values

        parsed = dotenv_values(env_file)
        shard_a = parsed["OPENAI_API_KEY"]
        assert shard_a.startswith("sk-proj-")
        # Format-preserving: shard-A has same length as original
        assert len(shard_a) == len(original_key)

    def test_lock_multiple_keys(self, home_dir: WorthlessHome, multi_env_file: Path) -> None:
        """Lock should process all API keys in .env."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(multi_env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0

        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 2

    def test_relock_same_key_new_env_rewrites_to_shard_a(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Locking the same real key in a second .env must rewrite the new .env.

        Regression for the silent-no-op bug where the re-lock guard added a DB
        enrollment, printed "1 key(s) protected.", but left the real key in the
        second .env — silently leaking secret material into a file the user
        believed was protected.
        """
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        key = fake_openai_key()

        env_a = tmp_path / "a" / ".env"
        env_b = tmp_path / "b" / ".env"
        env_a.parent.mkdir()
        env_b.parent.mkdir()
        env_a.write_text(f"OPENAI_API_KEY={key}\n")
        env_b.write_text(f"OPENAI_API_KEY={key}\n")

        r1 = runner.invoke(app, ["lock", "--env", str(env_a)], env=env_vars)
        assert r1.exit_code == 0, r1.output

        from dotenv import dotenv_values

        shard_a_first = dotenv_values(env_a)["OPENAI_API_KEY"]
        assert shard_a_first != key, "first lock should already rewrite env_a"

        r2 = runner.invoke(app, ["lock", "--env", str(env_b)], env=env_vars)
        assert r2.exit_code == 0, r2.output

        shard_a_second = dotenv_values(env_b)["OPENAI_API_KEY"]
        assert shard_a_second != key, (
            "re-lock left the real key in the .env — silent secret leak. "
            f"env_b still contains: {shard_a_second[:12]}..."
        )
        # shard-A must still be format-preserving (prefix + length match).
        assert shard_a_second.startswith("sk-proj-")
        assert len(shard_a_second) == len(key)

    def test_relock_same_key_new_env_reconstructs_correctly(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Shard-A written on re-lock must reconstruct the real key via shard-B.

        Derivation correctness check: the re-lock path must produce a shard-A
        that, combined with the already-stored shard-B, yields the original
        real key. Without this, the proxy could not rebuild the real key.
        """
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        key = fake_openai_key()

        env_a = tmp_path / "a" / ".env"
        env_b = tmp_path / "b" / ".env"
        env_a.parent.mkdir()
        env_b.parent.mkdir()
        env_a.write_text(f"OPENAI_API_KEY={key}\n")
        env_b.write_text(f"OPENAI_API_KEY={key}\n")

        assert runner.invoke(app, ["lock", "--env", str(env_a)], env=env_vars).exit_code == 0
        assert runner.invoke(app, ["lock", "--env", str(env_b)], env=env_vars).exit_code == 0

        from dotenv import dotenv_values

        from worthless.crypto.splitter import reconstruct_key_fp

        shard_a_str = dotenv_values(env_b)["OPENAI_API_KEY"]
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 1
        encrypted = asyncio.run(repo.fetch_encrypted(aliases[0]))
        assert encrypted is not None
        stored = asyncio.run(repo.decrypt_shard(encrypted))

        reconstructed = reconstruct_key_fp(
            bytearray(shard_a_str.encode()),
            stored.shard_b,
            stored.commitment,
            stored.nonce,
            encrypted.prefix or "",
            encrypted.charset or "",
        )
        assert reconstructed.decode() == key

    def test_relock_existing_key_deletes_superseded_location_enrollment(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Relocking a location to an already-known key removes the old alias.

        The existing-enrollment branch must keep the one-live-enrollment-per
        ``(var_name, env_path)`` invariant, matching the fresh-enroll path.
        """
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        old_key = fake_key("sk-proj-", seed="existing-location-old")
        new_key = fake_key("sk-proj-", seed="existing-location-new")

        env_a = tmp_path / "a" / ".env"
        env_b = tmp_path / "b" / ".env"
        env_a.parent.mkdir()
        env_b.parent.mkdir()
        env_a.write_text(f"OPENAI_API_KEY={old_key}\n")
        env_b.write_text(f"OPENAI_API_KEY={new_key}\n")

        r1 = runner.invoke(app, ["lock", "--env", str(env_a)], env=env_vars)
        assert r1.exit_code == 0, r1.output
        r2 = runner.invoke(app, ["lock", "--env", str(env_b)], env=env_vars)
        assert r2.exit_code == 0, r2.output

        # User rotates env_a to a key already known from env_b.
        env_a.write_text(f"OPENAI_API_KEY={new_key}\n")
        r3 = runner.invoke(app, ["lock", "--env", str(env_a)], env=env_vars)
        assert r3.exit_code == 0, r3.output

        repo = _repo(home_dir)
        env_a_records = [
            record
            for record in asyncio.run(repo.list_enrollments())
            if record.var_name == "OPENAI_API_KEY" and record.env_path == str(env_a)
        ]
        assert len(env_a_records) == 1
        assert env_a_records[0].key_alias.endswith(
            hashlib.sha256(bytearray(new_key.encode())).hexdigest()[:8]
        )

    def test_relock_compensation_restores_env_on_base_url_failure(
        self, home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Re-lock path must restore real key to .env if BASE_URL write fails.

        Without compensation this recreates WOR-280: the re-lock overwrote .env
        with shard-A, then the BASE_URL write crashed, and the real key was
        gone from the file (destructive) while the user saw an error (not a
        silent leak, but unrecoverable partial state).
        """
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        key = fake_openai_key()

        env_a = tmp_path / "a" / ".env"
        env_b = tmp_path / "b" / ".env"
        env_a.parent.mkdir()
        env_b.parent.mkdir()
        env_a.write_text(f"OPENAI_API_KEY={key}\n")
        env_b.write_text(f"OPENAI_API_KEY={key}\n")

        # Prime: lock env_a cleanly so alias is in DB.
        r1 = runner.invoke(app, ["lock", "--env", str(env_a)], env=env_vars)
        assert r1.exit_code == 0, r1.output

        # Now sabotage BASE_URL writes so the re-lock fails mid-way.
        from worthless.cli.commands import lock as lock_mod

        def _boom_on_base_url(*args, **kwargs):
            raise OSError("disk full on BASE_URL write")

        monkeypatch.setattr(lock_mod, "rewrite_env_keys", _boom_on_base_url)

        r2 = runner.invoke(app, ["lock", "--env", str(env_b)], env=env_vars)
        assert r2.exit_code == 1  # expected failure

        from dotenv import dotenv_values

        parsed = dotenv_values(env_b)
        assert parsed["OPENAI_API_KEY"] == key, (
            "Re-lock failed mid-way and left env_b in a broken state — "
            f"expected real key restored, got: {parsed['OPENAI_API_KEY'][:12]}..."
        )

    def test_relock_rolls_back_base_url_when_enrollment_fails(
        self, home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Re-lock must restore the *whole* .env if enrollment fails after BASE_URL.

        Step 2 (BASE_URL write) succeeds, step 3 (DB enrollment) fails. Partial-
        restore that only rewrites OPENAI_API_KEY would leave a real key
        coexisting with a proxy BASE_URL — inconsistent state the user can't
        reason about. Whole-file snapshot rollback is the correct fix.
        """
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        key = fake_openai_key()

        env_a = tmp_path / "a" / ".env"
        env_b = tmp_path / "b" / ".env"
        env_a.parent.mkdir()
        env_b.parent.mkdir()
        env_a.write_text(f"OPENAI_API_KEY={key}\n")
        env_b.write_text(f"OPENAI_API_KEY={key}\n")

        # Prime: lock env_a cleanly.
        r1 = runner.invoke(app, ["lock", "--env", str(env_a)], env=env_vars)
        assert r1.exit_code == 0, r1.output

        # Capture env_b pre-content (exactly the snapshot we expect restored).
        original_content = env_b.read_text()

        # Sabotage the atomic Pass-1 write (WOR-646 Part 2 folded the shard +
        # enrollment into one transaction): the re-lock fails before `.env` is
        # rewritten, so the compensating unwind must leave env_b byte-identical.
        from worthless.storage import repository as repo_mod

        async def _boom_on_enrollment(self, *args, **kwargs):
            raise RuntimeError("db write failed during atomic Pass-1")

        monkeypatch.setattr(
            repo_mod.ShardRepository, "upsert_locked_shard_and_enroll", _boom_on_enrollment
        )

        r2 = runner.invoke(app, ["lock", "--env", str(env_b)], env=env_vars)
        assert r2.exit_code == 1, r2.output

        # Whole-file restoration: env_b must be byte-identical to pre-run.
        # Partial compensation would leave OPENAI_BASE_URL lingering.
        restored = env_b.read_text()
        assert restored == original_content, (
            "env_b should be restored to its pre-re-lock snapshot — "
            "partial compensation would leak BASE_URL changes."
        )
        assert "OPENAI_BASE_URL" not in restored, (
            "BASE_URL must not persist when re-lock fails mid-way."
        )

    def test_lock_acquires_and_releases_lock_file(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """Lock file should not exist after command completes."""
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env=env_vars,
        )
        assert result.exit_code == 0
        assert not home_dir.lock_file.exists()

    def test_lock_with_provider_override(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """--provider flag should override auto-detection."""
        env = tmp_path / ".env"
        env.write_text(f"MY_KEY={fake_openai_key()}\n")
        result = runner.invoke(
            app,
            ["lock", "--env", str(env), "--provider", "anthropic"],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0

        # Check provider stored as anthropic in DB
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 1
        stored = asyncio.run(repo.retrieve(aliases[0]))
        assert stored is not None
        assert stored.provider == "anthropic"


class TestLockDBAndFiles:
    """Lock stores enrollment in SQLite (no shard_a files per SR-09)."""

    def test_lock_creates_no_shard_a_files(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """After lock, shard_a_dir should have ZERO files (SR-09)."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        all_files = [f for f in home_dir.shard_a_dir.iterdir() if f.is_file()]
        assert len(all_files) == 0

    def test_lock_multiple_keys_no_shard_a_files(
        self, home_dir: WorthlessHome, multi_env_file: Path
    ) -> None:
        """After locking multiple keys, still zero shard_a files (SR-09)."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(multi_env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        all_files = [f for f in home_dir.shard_a_dir.iterdir() if f.is_file()]
        assert len(all_files) == 0

    def test_lock_stores_enrollment_in_db(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """Lock should store var_name and env_path in enrollments table."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert len(aliases) == 1

        enrollment = asyncio.run(repo.get_enrollment(aliases[0]))
        assert enrollment is not None
        assert enrollment.var_name == "OPENAI_API_KEY"
        assert str(env_file.resolve()) in enrollment.env_path

    def test_lock_multiple_keys_stores_enrollments(
        self, home_dir: WorthlessHome, multi_env_file: Path
    ) -> None:
        """Lock should store enrollment records for all keys."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(multi_env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        repo = _repo(home_dir)
        enrollments = asyncio.run(repo.list_enrollments())
        assert len(enrollments) == 2

        var_names = {e.var_name for e in enrollments}
        assert "OPENAI_API_KEY" in var_names
        assert "ANTHROPIC_API_KEY" in var_names


class TestLockErrorBranches:
    """Error branch coverage for lock compensation paths."""

    def test_lock_env_rewrite_failure_compensates(
        self, home_dir: WorthlessHome, env_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """IOError on .env rewrite -> DB enrollment deleted, .env unchanged."""
        original_content = env_file.read_text()

        def _boom(*_args, **_kw):
            raise OSError("disk full")

        monkeypatch.setattr(
            "worthless.cli.commands.lock.rewrite_env_keys",
            _boom,
        )

        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 1

        # DB enrollment cleaned up
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert aliases == []

        # .env unchanged after failed operation
        assert env_file.read_text() == original_content

    def test_lock_symlink_env_refused(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Lock refuses to follow symlinked .env files."""
        real_env = tmp_path / "real.env"
        real_env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
        link_env = tmp_path / "link.env"
        link_env.symlink_to(real_env)

        result = runner.invoke(
            app,
            ["lock", "--env", str(link_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 1
        assert "symlink" in result.output.lower()

    def test_lock_db_write_failure_exits_clean(
        self, home_dir: WorthlessHome, env_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """sqlite3.DatabaseError during the atomic Pass-1 write -> exit_code=1 with WRTLS."""

        async def _boom(self, *args, **kwargs):
            raise sqlite3.DatabaseError("disk I/O error")

        monkeypatch.setattr(
            "worthless.storage.repository.ShardRepository.upsert_locked_shard_and_enroll",
            _boom,
        )

        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 1
        assert "WRTLS" in result.output

    def test_lock_scan_env_keys_oserror_exits_clean(
        self, home_dir: WorthlessHome, env_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """OSError in scan_env_keys -> exit_code=1."""

        def _boom(path):
            raise OSError("permission denied")

        monkeypatch.setattr(
            "worthless.cli.commands.lock.scan_env_keys",
            _boom,
        )

        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 1


class TestLockBaseUrlFailureRestoresEnv:
    """CR-1: If BASE_URL write fails after key rewrite, original key must be restored."""

    def test_base_url_failure_restores_original_key(
        self, home_dir: WorthlessHome, env_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """OSError on add_or_rewrite_env_key -> .env restored to original key."""
        original_content = env_file.read_text()
        original_key = original_content.strip().split("=", 1)[1]

        _call_count = 0

        def _boom_on_base_url(*args, **kwargs):
            nonlocal _call_count
            _call_count += 1
            # Let rewrite_env_key succeed (key replacement), but fail on
            # add_or_rewrite_env_key (BASE_URL write)
            raise OSError("disk full on BASE_URL write")

        monkeypatch.setattr(
            "worthless.cli.commands.lock.rewrite_env_keys",
            _boom_on_base_url,
        )

        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 1

        # The original key MUST be restored — not left as shard-A with no DB
        from dotenv import dotenv_values

        parsed = dotenv_values(env_file)
        assert parsed["OPENAI_API_KEY"] == original_key, (
            "Original key not restored after BASE_URL write failure"
        )

        # DB should be clean
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert aliases == [], "DB shard not cleaned up after failure"


class TestProxyBaseUrl:
    """Unit tests for _proxy_base_url helper."""

    def test_proxy_base_url_format(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from worthless.cli.commands.lock import _proxy_base_url

        monkeypatch.delenv("WORTHLESS_PORT", raising=False)
        url = _proxy_base_url("my-alias")
        assert url == "http://127.0.0.1:8787/my-alias/v1"

    def test_proxy_base_url_custom_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from worthless.cli.commands.lock import _proxy_base_url

        monkeypatch.setenv("WORTHLESS_PORT", "9999")
        url = _proxy_base_url("test-key")
        assert url == "http://127.0.0.1:9999/test-key/v1"


class TestLockChmodEnvFile:
    """Lock tightens .env permissions after writing shard-A."""

    def test_lock_restricts_env_permissions(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """After lock, .env should have no group/other perms."""
        import stat

        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
        env.chmod(0o644)  # world-readable initially

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        mode = env.stat().st_mode
        assert not (mode & stat.S_IRWXG), "Group permissions should be removed"
        assert not (mode & stat.S_IRWXO), "Other permissions should be removed"

    def test_lock_keeps_perms_if_already_strict(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """If .env is already 0o600, lock should not error."""
        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
        env.chmod(0o600)

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output


class TestLockNextStepHint:
    """Tests for post-lock next-step guidance (WOR-178)."""

    def test_lock_prints_next_step_hint(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """After successful lock, output should contain a 'Next:' hint."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output
        assert "Next:" in result.output

    def test_lock_hint_suppressed_in_json_mode(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """In --json mode, the 'Next:' hint should not appear."""
        result = runner.invoke(
            app,
            ["--json", "lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output
        assert "Next:" not in result.output

    def test_lock_hint_suppressed_in_quiet_mode(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """In --quiet mode, the 'Next:' hint should not appear."""
        result = runner.invoke(
            app,
            ["--quiet", "lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output
        assert "Next:" not in result.output

    def test_lock_no_hint_when_no_keys_found(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """When no keys are found, the hint should not appear."""
        env = tmp_path / ".env"
        env.write_text("DATABASE_URL=postgres://localhost/db\n")
        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0
        assert "Next:" not in result.output


class TestPrintHint:
    """Unit tests for WorthlessConsole.print_hint (WOR-178)."""

    def test_print_hint_normal_mode(self, capsys: pytest.CaptureFixture) -> None:
        """print_hint should output the message in normal mode."""
        from worthless.cli.console import WorthlessConsole

        c = WorthlessConsole(quiet=False, json_mode=False)
        c.print_hint("Next: do something")
        captured = capsys.readouterr()
        assert "Next: do something" in captured.err

    def test_print_hint_suppressed_quiet(self, capsys: pytest.CaptureFixture) -> None:
        """print_hint should be suppressed in quiet mode."""
        from worthless.cli.console import WorthlessConsole

        c = WorthlessConsole(quiet=True, json_mode=False)
        c.print_hint("Next: do something")
        captured = capsys.readouterr()
        assert "Next:" not in captured.err
        assert "Next:" not in captured.out

    def test_print_hint_suppressed_json(self, capsys: pytest.CaptureFixture) -> None:
        """print_hint should be suppressed in json_mode."""
        from worthless.cli.console import WorthlessConsole

        c = WorthlessConsole(quiet=False, json_mode=True)
        c.print_hint("Next: do something")
        captured = capsys.readouterr()
        assert "Next:" not in captured.err
        assert "Next:" not in captured.out


class TestEnrollCommand:
    """Tests for `worthless enroll`."""

    def test_enroll_explicit_args(self, home_dir: WorthlessHome) -> None:
        """Enroll with explicit alias, key, and provider."""
        result = runner.invoke(
            app,
            [
                "enroll",
                "--alias",
                "my-test-key",
                "--key",
                fake_openai_key(),
                "--provider",
                "openai",
            ],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        # shard_b should be in DB with prefix/charset
        repo = _repo(home_dir)
        stored = asyncio.run(repo.retrieve("my-test-key"))
        assert stored is not None
        assert stored.provider == "openai"

    def test_enroll_duplicate_alias_errors_without_destroying_first(
        self, home_dir: WorthlessHome
    ) -> None:
        """Re-enrolling the same alias must error cleanly without deleting
        the first enrollment's data."""
        # First enrollment — should succeed
        result1 = runner.invoke(
            app,
            [
                "enroll",
                "--alias",
                "dup-test",
                "--key",
                fake_openai_key(),
                "--provider",
                "openai",
            ],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result1.exit_code == 0, result1.output

        # Verify first enrollment is intact
        repo = _repo(home_dir)
        stored_before = asyncio.run(repo.retrieve("dup-test"))
        assert stored_before is not None

        # Second enrollment — same alias — should fail
        result2 = runner.invoke(
            app,
            [
                "enroll",
                "--alias",
                "dup-test",
                "--key",
                fake_openai_key(),
                "--provider",
                "openai",
            ],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result2.exit_code != 0, (
            "Re-enrolling the same alias should fail, but exit_code was 0"
        )

        # Original enrollment must still be intact
        stored_after = asyncio.run(repo.retrieve("dup-test"))
        assert stored_after is not None, (
            "First enrollment's shard was destroyed by failed re-enrollment"
        )

    def test_enroll_db_failure_exits_clean(
        self, home_dir: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """DB failure during enroll -> clean exit, no partial state."""

        async def _db_boom(self, *args, **kwargs):
            raise sqlite3.DatabaseError("disk I/O error")

        monkeypatch.setattr(
            "worthless.storage.repository.ShardRepository.store_enrolled",
            _db_boom,
        )

        result = runner.invoke(
            app,
            [
                "enroll",
                "--alias",
                "orphan-test",
                "--key",
                fake_openai_key(),
                "--provider",
                "openai",
            ],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        # Command should fail
        assert result.exit_code != 0

        # No DB shard should remain
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert aliases == []


# Child script for TestLockBaseUrlSlotPriority live tests.
# Reads base_url + key from .env, fires a minimal LLM request, prints JSON result.
# Add entries to PROVIDER_PROBES to support additional providers.
_LIVE_PROBE_CHILD = textwrap.dedent("""\
    import os, json, httpx
    from dotenv import dotenv_values

    env = dotenv_values(os.environ["WORTHLESS_TEST_ENV_PATH"])

    PROVIDER_PROBES = {
        "openai": {
            "base_url_var": "OPENAI_BASE_URL",
            "key_var": "OPENAI_API_KEY",
            "auth_header": lambda k: {"Authorization": f"Bearer {k}"},
            "path": "/chat/completions",
            "body": {"model": "gpt-4o-mini", "max_tokens": 1,
                     "messages": [{"role": "user", "content": "hi"}]},
        },
        "anthropic": {
            "base_url_var": "ANTHROPIC_BASE_URL",
            "key_var": "ANTHROPIC_API_KEY",
            "auth_header": lambda k: {"x-api-key": k,
                                      "anthropic-version": "2023-06-01"},
            "path": "/messages",
            "body": {"model": "claude-haiku-4-5-20251001", "max_tokens": 1,
                     "messages": [{"role": "user", "content": "hi"}]},
        },
        "openrouter": {
            "base_url_var": "OPENROUTER_BASE_URL",
            "key_var": "OPENROUTER_API_KEY",
            "auth_header": lambda k: {"Authorization": f"Bearer {k}"},
            "path": "/chat/completions",
            "body": {"model": "openai/gpt-4o-mini", "max_tokens": 1,
                     "messages": [{"role": "user", "content": "hi"}]},
        },
    }

    provider = os.environ.get("WORTHLESS_TEST_PROVIDER", "openai")
    probe = PROVIDER_PROBES[provider]
    base = env.get(probe["base_url_var"], "")
    key  = env.get(probe["key_var"], "")
    r = httpx.post(
        base.rstrip("/") + probe["path"],
        json=probe["body"],
        headers=probe["auth_header"](key),
        timeout=60.0,
    )
    try:
        body = r.json()
    except Exception:
        body = r.text
    print(json.dumps({"status": r.status_code, "body": body}))
""")


class TestLockBaseUrlSlotPriority:
    """worthless-sb8v: canonical <PROVIDER>_API_KEY wins OPENAI_BASE_URL slot."""

    def test_canonical_key_wins_base_url_slot_over_noncanonical(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """When .env has both OPENAI_API_KEY and a non-canonical OpenAI key,
        OPENAI_BASE_URL must point to OPENAI_API_KEY's alias — not API_KEY's.

        Before the fix: file-order determined the winner. API_KEY's alias
        claimed OPENAI_BASE_URL, so sending OPENAI_API_KEY's shard-A to
        that route produced a 401 (commitment mismatch). (worthless-sb8v)
        """
        from dotenv import dotenv_values

        canonical_key = fake_openai_key()
        noncanonical_key = fake_openai_key()
        env = tmp_path / ".env"
        # Non-canonical key appears FIRST — before the fix it would win the slot.
        env.write_text(f"API_KEY={noncanonical_key}\nOPENAI_API_KEY={canonical_key}\n")

        result = runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 0, result.output

        parsed = dotenv_values(env)
        base_url = parsed.get("OPENAI_BASE_URL", "")
        assert base_url, "OPENAI_BASE_URL should have been added by lock"

        # The alias in OPENAI_BASE_URL must belong to OPENAI_API_KEY, not API_KEY.
        alias_in_url = base_url.rstrip("/").rsplit("/", 2)[-2]

        repo = _repo(home_dir)
        enrollments = asyncio.run(repo.list_enrollments())
        canonical_enrollment = next(
            (e for e in enrollments if e.var_name == "OPENAI_API_KEY"), None
        )
        assert canonical_enrollment is not None, "OPENAI_API_KEY should be enrolled"
        assert canonical_enrollment.key_alias == alias_in_url, (
            f"OPENAI_BASE_URL points to alias {alias_in_url!r} but "
            f"OPENAI_API_KEY enrolled as {canonical_enrollment.key_alias!r} — "
            "non-canonical key claimed the slot (worthless-sb8v regression)"
        )

    @pytest.mark.live
    @pytest.mark.timeout(120)
    def test_canonical_key_routes_correctly_live(self, tmp_path: Path) -> None:
        """Live: shard-A authenticates via proxy when non-canonical key appears first in .env."""
        real_key = os.environ.get("OPENAI_API_KEY")
        if not real_key:
            pytest.skip("OPENAI_API_KEY not set")

        worthless_home = tmp_path / ".worthless"
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        env_file = project_dir / ".env"
        # Non-canonical key first — this is the exact bug scenario
        env_file.write_text(f"API_KEY=sk-fake-noncanonical-key\nOPENAI_API_KEY={real_key}\n")

        cli_env = {
            **os.environ,
            "WORTHLESS_HOME": str(worthless_home),
            "WORTHLESS_KEYRING_BACKEND": "null",
        }

        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(worthless_home), "WORTHLESS_KEYRING_BACKEND": "null"},
        )
        assert result.exit_code == 0, f"lock failed: {result.output}"

        proc = subprocess.run(
            [
                str(Path(sys.executable).parent / "worthless"),
                "wrap",
                "--",
                sys.executable,
                "-c",
                _LIVE_PROBE_CHILD,
            ],
            env={
                **cli_env,
                "WORTHLESS_TEST_ENV_PATH": str(env_file),
                "WORTHLESS_TEST_PROVIDER": "openai",
            },
            timeout=90,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, (
            f"wrap failed (rc={proc.returncode}):\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        )

        data = json.loads(proc.stdout.strip())

        # Layer 1 — proxy auth (provider-agnostic).
        # 401 here = proxy rejected shard-A = alias mismatch = bug still present.
        assert data["status"] != 401, (
            f"Proxy returned 401 — shard-A routed to wrong alias (worthless-sb8v). "
            f"body: {data.get('body')}"
        )

        verify_upstream_response_openai(data)


# ---------------------------------------------------------------------------
# worthless-8a5d: lock must refuse when source files bypass the proxy
# ---------------------------------------------------------------------------


@pytest.mark.real_ipc  # asyncio.run() inside lock; xdist threads → event-loop conflict (WOR-582)
class TestLockHardcodedBaseUrlDetection:
    """Lock fails fast when source files contain hardcoded provider URLs.

    If a hardcoded base_url reaches the LLM SDK, the proxy is bypassed even
    though the key is enrolled. The check runs before any enrollment so the
    user never ends up in a "protected but not really" state.
    """

    def _env(self, tmp_path: Path) -> Path:
        env = tmp_path / ".env"
        env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
        return env

    def _run(self, home_dir: WorthlessHome, env: Path) -> object:
        return runner.invoke(
            app,
            ["lock", "--env", str(env)],
            env={
                "WORTHLESS_HOME": str(home_dir.base_dir),
                "WORTHLESS_KEYRING_BACKEND": "null",
            },
        )

    def test_passes_with_no_source_files(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Lock succeeds when project has no source files."""
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code == 0, result.output

    def test_fails_py_file_hardcoded_openai_url(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Lock fails when a Python file has a hardcoded OpenAI base URL."""
        (tmp_path / "app.py").write_text('client = OpenAI(base_url="https://api.openai.com/v1")\n')
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code != 0, "Expected lock to fail with hardcoded base_url"
        assert "OPENAI_BASE_URL" in result.output

    def test_fails_ts_file_hardcoded_anthropic_url(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Lock fails when a TypeScript file has a hardcoded Anthropic base URL."""
        (tmp_path / "client.ts").write_text(
            'const ai = new Anthropic({ baseURL: "https://api.anthropic.com/v1" });\n'
        )
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code != 0
        assert "ANTHROPIC_BASE_URL" in result.output

    def test_fails_openrouter_url(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Lock fails when OpenRouter's base URL is hardcoded."""
        (tmp_path / "llm.py").write_text(
            'client = OpenAI(base_url="https://openrouter.ai/api/v1")\n'
        )
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code != 0
        assert "OPENROUTER_BASE_URL" in result.output

    def test_error_includes_line_number(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Error output includes file:line so the user can find the bypass."""
        (tmp_path / "llm.py").write_text(
            "# LLM client setup\n"
            "import openai\n"
            'client = openai.OpenAI(base_url="https://api.openai.com/v1")\n'
        )
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code != 0
        out = result.output
        # Rich wraps long paths at terminal width — check format components separately
        assert re.search(r":\d", out), "file:line format not in error output"
        assert "OPENAI_BASE_URL" in out

    def test_scans_subdirectory(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Lock scans recursively — catches bypasses in nested source files."""
        nested = tmp_path / "src" / "providers"
        nested.mkdir(parents=True)
        (nested / "openai_client.py").write_text('BASE = "https://api.openai.com/v1"\n')
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code != 0
        assert "OPENAI_BASE_URL" in result.output

    def test_skips_node_modules(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Lock ignores node_modules — provider SDK source isn't user code."""
        nm = tmp_path / "node_modules" / "openai" / "src"
        nm.mkdir(parents=True)
        (nm / "client.js").write_text('const DEFAULT_BASE_URL = "https://api.openai.com/v1";\n')
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code == 0, result.output

    def test_skips_git_dir(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Lock ignores .git — internal git objects aren't user code."""
        git_hooks = tmp_path / ".git" / "hooks"
        git_hooks.mkdir(parents=True)
        (git_hooks / "hook.py").write_text('BASE = "https://api.openai.com/v1"\n')
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code == 0, result.output

    def test_skips_venv(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Lock ignores .venv — installed packages aren't user code."""
        venv = tmp_path / ".venv" / "lib" / "python3.11" / "site-packages" / "openai"
        venv.mkdir(parents=True)
        (venv / "_client.py").write_text('DEFAULT_BASE_URL: str = "https://api.openai.com/v1"\n')
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code == 0, result.output

    def test_skips_pycache(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Lock ignores __pycache__ — compiled bytecode isn't user code."""
        cache = tmp_path / "__pycache__"
        cache.mkdir()
        (cache / "app.py").write_text('BASE = "https://api.openai.com/v1"\n')
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code == 0, result.output

    def test_skips_localhost_provider(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Localhost providers (e.g. Ollama) are not flagged — already local."""
        (tmp_path / "local.py").write_text(
            'client = OpenAI(base_url="http://localhost:11434/v1")\n'
        )
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code == 0, result.output

    def test_js_and_go_files_also_scanned(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Lock scans .js and .go files, not just Python."""
        (tmp_path / "api.js").write_text(
            'const client = new OpenAI({ baseURL: "https://api.openai.com/v1" });\n'
        )
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code != 0
        assert "OPENAI_BASE_URL" in result.output

    # ------------------------------------------------------------------
    # Additional coverage — QA gap fills
    # ------------------------------------------------------------------

    def test_fails_groq_url(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Groq is in the bundled registry — hardcoded Groq URL must block lock."""
        (tmp_path / "chat.py").write_text(
            'client = Groq(base_url="https://api.groq.com/openai/v1")\n'
        )
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code != 0
        assert "GROQ_BASE_URL" in result.output

    def test_fails_together_url(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """Together.ai is in the bundled registry — hardcoded Together URL must block lock."""
        (tmp_path / "infer.py").write_text(
            'llm = Together(base_url="https://api.together.xyz/v1")\n'
        )
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code != 0
        assert "TOGETHER_BASE_URL" in result.output

    def test_no_db_enrollment_when_scan_blocks(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Scan gate fires pre-enrollment — DB must be empty when lock is blocked."""
        import asyncio

        from worthless.storage.repository import ShardRepository

        (tmp_path / "app.py").write_text('client = OpenAI(base_url="https://api.openai.com/v1")\n')
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code != 0

        async def _check():
            repo = ShardRepository(str(home_dir.db_path), home_dir.fernet_key)
            await repo.initialize()
            return await repo.list_keys()

        aliases = asyncio.run(_check())
        assert aliases == [], (
            "DB has enrollments despite scan blocking lock — gate must run pre-enrollment"
        )

    def test_allow_hardcoded_urls_flag_bypasses_block(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """--allow-hardcoded-urls lets lock proceed with a warning, not an error."""
        (tmp_path / "test_llm.py").write_text(
            '    assert resp.url == "https://api.openai.com/v1/chat/completions"\n'
        )
        result = runner.invoke(
            app,
            ["lock", "--env", str(self._env(tmp_path)), "--allow-hardcoded-urls"],
            env={
                "WORTHLESS_HOME": str(home_dir.base_dir),
                "WORTHLESS_KEYRING_BACKEND": "null",
            },
        )
        assert result.exit_code == 0, result.output
        assert "Proceeding with --allow-hardcoded-urls" in result.output

    def test_url_in_python_comment_triggers_block(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """URL in a comment is inside a quoted string — scanner fires on it.

        The scanner is syntax-unaware and treats quoted strings in comments as
        findings. This test pins the current contract so any change is deliberate.
        """
        (tmp_path / "app.py").write_text(
            '# Old default: "https://api.openai.com/v1" — do not use\n'
            "client = OpenAI()  # uses env var\n"
        )
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code != 0, (
            "Scanner fires on quoted URLs inside comments (syntax-unaware). "
            "Use --allow-hardcoded-urls or # worthless: ignore (future) to suppress."
        )

    def test_js_template_literal_not_detected(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Template literals use backticks — _QUOTED_STR_RE does not match them.

        This is a known false-negative gap. Pinned here so any future fix that
        adds backtick support causes this test to fail loudly, prompting the
        assertion to be flipped.
        """
        (tmp_path / "api.js").write_text(
            "const client = new OpenAI({ baseURL: `https://api.openai.com/v1` });\n"
        )
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code == 0, (
            "Template literal backtick support was added — flip this assertion to != 0."
        )

    def test_multiple_findings_in_one_file_all_reported(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """All hardcoded URLs in a single file appear in the error output."""
        (tmp_path / "multi.py").write_text(
            'openai_client = OpenAI(base_url="https://api.openai.com/v1")\n'
            'anthropic_client = Anthropic(base_url="https://api.anthropic.com/v1")\n'
        )
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code != 0
        assert "OPENAI_BASE_URL" in result.output
        assert "ANTHROPIC_BASE_URL" in result.output

    def test_unreadable_source_file_does_not_crash(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """OSError on a source file is silently skipped — lock must not crash."""
        restricted = tmp_path / "private.py"
        restricted.write_text("client = OpenAI()\n")
        restricted.chmod(0o000)
        try:
            result = self._run(home_dir, self._env(tmp_path))
            assert result.exit_code == 0, f"Unreadable source file crashed lock: {result.output}"
        finally:
            restricted.chmod(0o644)

    def test_unreadable_directory_does_not_crash(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """PermissionError on iterdir() is silently skipped — lock must not crash."""
        restricted = tmp_path / "private_dir"
        restricted.mkdir()
        (restricted / "llm.py").write_text(
            'client = OpenAI(base_url="https://api.openai.com/v1")\n'
        )
        restricted.chmod(0o000)
        try:
            result = self._run(home_dir, self._env(tmp_path))
            assert result.exit_code == 0, f"Unreadable directory crashed lock: {result.output}"
        finally:
            restricted.chmod(0o755)

    def test_skips_127_0_0_1_provider(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        """127.0.0.1 is a loopback address — not flagged as a proxy bypass."""
        (tmp_path / "local_model.py").write_text(
            'client = OpenAI(base_url="http://127.0.0.1:8080/v1")\n'
        )
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code == 0, result.output

    def test_non_interactive_error_includes_fix_guidance(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Non-interactive (no TTY) error output tells the user how to fix and re-run."""
        (tmp_path / "app.py").write_text('client = OpenAI(base_url="https://api.openai.com/v1")\n')
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code != 0
        assert "re-run: worthless lock" in result.output

    def test_no_false_positive_on_mismatched_quotes(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Mismatched quote delimiters ('url") do not produce false positives."""
        (tmp_path / "weird.py").write_text("x = 'https://api.openai.com/v1\"\n")
        result = self._run(home_dir, self._env(tmp_path))
        assert result.exit_code == 0, "Mismatched quotes produced a false-positive finding"


class TestScannerProperties:
    """Property-based tests for scan_source_for_hardcoded_provider_urls."""

    def test_every_registered_hostname_is_detected(self, tmp_path: Path) -> None:
        """Every non-local hostname in the bundled registry triggers a finding."""
        from urllib.parse import urlparse

        from worthless.cli.providers import load_bundled
        from worthless.cli.scanner import (
            _LOCAL_HOSTNAMES,
            scan_source_for_hardcoded_provider_urls,
        )

        registry = load_bundled()
        for entry in registry.values():
            hostname = urlparse(entry.url).hostname or ""
            if not hostname or hostname in _LOCAL_HOSTNAMES:
                continue

            src = tmp_path / "probe.py"
            src.write_text(f'url = "https://{hostname}/v1"\n')

            findings = scan_source_for_hardcoded_provider_urls(tmp_path)
            assert len(findings) >= 1, (
                f"No finding for registered hostname {hostname!r} ({entry.name})"
            )
            src.unlink()


# ---------------------------------------------------------------------------
# WOR-504: re-lock surfaces "[OK] N key(s) still protected." instead of
# silently succeeding or falsely claiming a new split occurred.
# ---------------------------------------------------------------------------


class TestLockRerun:
    """Re-locking an already-protected .env surfaces '[OK] N keys still protected.'

    The commitment-verify path already proves the key is intact on re-lock —
    it just doesn't say so. These tests pin the new output contract and guard
    the DB invariants (no dup shards, no re-split).
    """

    def test_lock_prints_still_protected_on_rerun(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """Second lock run on same .env prints '[OK] N keys still protected.'"""
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        first = runner.invoke(app, ["lock", "--env", str(env_file)], env=env_vars)
        assert first.exit_code == 0, first.output

        result = runner.invoke(app, ["lock", "--env", str(env_file)], env=env_vars)

        assert result.exit_code == 0, result.output
        assert "[OK]" in result.output, result.output
        assert "still protected" in result.output.lower(), result.output

    def test_lock_rerun_does_not_create_duplicate_shard_row(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """Second lock run on same .env leaves the DB shard count unchanged."""
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        first = runner.invoke(app, ["lock", "--env", str(env_file)], env=env_vars)
        assert first.exit_code == 0, first.output
        count_before = len(asyncio.run(_repo(home_dir).list_keys()))

        second = runner.invoke(app, ["lock", "--env", str(env_file)], env=env_vars)
        assert second.exit_code == 0, second.output
        count_after = len(asyncio.run(_repo(home_dir).list_keys()))

        assert count_after == count_before

    def test_lock_rerun_does_not_resplit_key(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """Second lock run leaves shard_b byte-identical in the DB — key was not re-split."""
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        first = runner.invoke(app, ["lock", "--env", str(env_file)], env=env_vars)
        assert first.exit_code == 0, first.output

        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        alias = aliases[0]
        enc_before = asyncio.run(_repo(home_dir).fetch_encrypted(alias))
        stored_before = asyncio.run(_repo(home_dir).decrypt_shard(enc_before))
        shard_b_before = bytes(stored_before.shard_b)
        stored_before.zero()

        second = runner.invoke(app, ["lock", "--env", str(env_file)], env=env_vars)
        assert second.exit_code == 0, second.output

        enc_after = asyncio.run(_repo(home_dir).fetch_encrypted(alias))
        stored_after = asyncio.run(_repo(home_dir).decrypt_shard(enc_after))
        shard_b_after = bytes(stored_after.shard_b)
        stored_after.zero()

        assert shard_b_after == shard_b_before

    def test_lock_rerun_fresh_project_same_key_creates_new_enrollment(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Same key in a second project dir creates a new enrollment row, not a new shard."""
        key = fake_openai_key()
        env_a = tmp_path / "proj_a" / ".env"
        env_b = tmp_path / "proj_b" / ".env"
        env_a.parent.mkdir()
        env_b.parent.mkdir()
        env_a.write_text(f"OPENAI_API_KEY={key}\n")
        env_b.write_text(f"OPENAI_API_KEY={key}\n")

        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        r1 = runner.invoke(app, ["lock", "--env", str(env_a)], env=env_vars)
        assert r1.exit_code == 0, r1.output
        r2 = runner.invoke(app, ["lock", "--env", str(env_b)], env=env_vars)
        assert r2.exit_code == 0, r2.output

        # One shard row for the shared key — never duplicated.
        aliases = asyncio.run(_repo(home_dir).list_keys())
        assert len(aliases) == 1

        # Two enrollment rows — one per project path.
        enrollments = asyncio.run(_repo(home_dir).list_enrollments())
        env_paths = {e.env_path for e in enrollments}
        assert len(env_paths) == 2

        # Both .env files must be rewritten — the real key must not remain in either.
        from dotenv import dotenv_values

        shard_a_a = dotenv_values(env_a)["OPENAI_API_KEY"]
        shard_a_b = dotenv_values(env_b)["OPENAI_API_KEY"]
        assert shard_a_a != key, "env_a still contains the real key after lock"
        assert shard_a_b != key, "env_b still contains the real key after second-project lock"
        assert shard_a_a.startswith("sk-proj-"), "env_a shard-A must preserve key prefix"
        assert shard_a_b.startswith("sk-proj-"), "env_b shard-A must preserve key prefix"

    def test_lock_rerun_quiet_suppresses_still_protected(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """-q on re-lock produces no output, consistent with -q on fresh lock."""
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
        first = runner.invoke(app, ["lock", "--env", str(env_file)], env=env_vars)
        assert first.exit_code == 0, first.output

        result = runner.invoke(app, ["-q", "lock", "--env", str(env_file)], env=env_vars)

        assert result.exit_code == 0, result.output
        assert "[OK]" not in result.output
        assert "still protected" not in result.output.lower()

    def test_fresh_lock_does_not_print_still_protected(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """First-time lock must not print 'still protected' — that message is re-lock only."""
        result = runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

        assert result.exit_code == 0, result.output
        assert "still protected" not in result.output.lower(), result.output

    def test_lock_mixed_fresh_and_relock_prints_both_messages(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """1 already-locked key + 1 new key in same run → both messages appear."""
        key_old = fake_openai_key()
        key_new = fake_anthropic_key()
        env_file = tmp_path / ".env"
        env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}

        # Lock just the old key first.
        env_file.write_text(f"OPENAI_API_KEY={key_old}\n")
        first = runner.invoke(app, ["lock", "--env", str(env_file)], env=env_vars)
        assert first.exit_code == 0, first.output

        # Add a fresh key and re-lock — mixed run.
        env_file.write_text(f"OPENAI_API_KEY={key_old}\nANTHROPIC_API_KEY={key_new}\n")
        result = runner.invoke(app, ["lock", "--env", str(env_file)], env=env_vars)

        assert result.exit_code == 0, result.output
        assert "split between" in result.output.lower(), result.output
        assert "still protected" in result.output.lower(), result.output


# ---------------------------------------------------------------------------
# WOR-504: _select_unlocked_keys exception-swallow paths
# ---------------------------------------------------------------------------


class TestSelectUnlockedKeys:
    """Unit tests for the _select_unlocked_keys re-lock guard.

    This function decides which scanned keys need (re-)locking by calling
    ``reconstruct_key_fp`` to verify a shard-A value is still intact.  When
    reconstruction raises ``UnicodeDecodeError`` (corrupt UTF-8 shard bytes)
    or ``IndexError`` (length mismatch), the enrollment is treated as unusable
    and the key is returned as a re-lock candidate.  These tests target those
    error branches directly via mock so the CLI URL-registration check and
    .env rewriter do not interfere with the assertions.
    """

    @staticmethod
    def _enrollment(env_path: str, var_name: str, alias: str):
        e = MagicMock()
        e.env_path = env_path
        e.var_name = var_name
        e.key_alias = alias
        return e

    @staticmethod
    def _repo():
        encrypted = MagicMock()
        encrypted.prefix = "sk-proj-"
        encrypted.charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        stored = MagicMock()
        stored.shard_b = bytearray(32)
        stored.zero = MagicMock()
        repo = MagicMock()
        repo.fetch_encrypted = AsyncMock(return_value=encrypted)
        # decrypt_shard is async in the sidecar-IPC repo (WOR-306): it may
        # round-trip to the crypto sidecar, so production awaits it.
        repo.decrypt_shard = AsyncMock(return_value=stored)
        return repo

    def test_value_error_returns_key_as_candidate(self) -> None:
        """ValueError (including UnicodeDecodeError subclass) → key treated as not-still-protected.

        UnicodeDecodeError IS a ValueError subclass, so testing ValueError directly
        is the minimal mutation-killing form.  Drives the ValueError branch of the
        except clause in ``_select_unlocked_keys``.
        """
        from worthless.cli.commands.lock import _select_unlocked_keys

        env_path = "/project/.env"
        var_name = "OPENAI_API_KEY"
        value = "sk-proj-abc123fakefakefakefakefakefakefakefakefakefake"
        provider = "openai"

        with patch(
            "worthless.cli.commands.lock.reconstruct_key_fp",
            side_effect=ValueError("corrupt shard bytes"),
        ):
            candidates = asyncio.run(
                _select_unlocked_keys(
                    self._repo(),
                    [(var_name, value, provider)],
                    [self._enrollment(env_path, var_name, "openai-deadbeef")],
                    env_path,
                )
            )

        assert candidates == [(var_name, value, provider)]

    def test_index_error_returns_key_as_candidate(self) -> None:
        """IndexError during reconstruction → key treated as not-still-protected.

        Drives the IndexError branch of the same except clause.  A
        length-mismatched shard must not suppress the key from re-locking.
        """
        from worthless.cli.commands.lock import _select_unlocked_keys

        env_path = "/project/.env"
        var_name = "OPENAI_API_KEY"
        value = "sk-proj-abc123fakefakefakefakefakefakefakefakefakefake"
        provider = "openai"

        with patch(
            "worthless.cli.commands.lock.reconstruct_key_fp",
            side_effect=IndexError("shard length mismatch"),
        ):
            candidates = asyncio.run(
                _select_unlocked_keys(
                    self._repo(),
                    [(var_name, value, provider)],
                    [self._enrollment(env_path, var_name, "openai-deadbeef")],
                    env_path,
                )
            )

        assert candidates == [(var_name, value, provider)]

    def test_successful_reconstruct_excludes_key_from_candidates(self) -> None:
        """Successful reconstruction → key is still-protected and NOT returned.

        Happy-path complement: a healthy DB shard means the .env value is
        already shard-A and the key must not be re-locked.
        """
        from worthless.cli.commands.lock import _select_unlocked_keys

        env_path = "/project/.env"
        var_name = "OPENAI_API_KEY"
        value = "sk-proj-abc123fakefakefakefakefakefakefakefakefakefake"
        provider = "openai"

        with patch(
            "worthless.cli.commands.lock.reconstruct_key_fp",
            return_value=bytearray(b"reconstructed-key"),
        ):
            candidates = asyncio.run(
                _select_unlocked_keys(
                    self._repo(),
                    [(var_name, value, provider)],
                    [self._enrollment(env_path, var_name, "openai-deadbeef")],
                    env_path,
                )
            )

        assert candidates == []


class TestOpenClawGateWiredIntoLock:
    """Pin that the OpenClaw audit gate (#210) is actually wired into the
    ``worthless lock`` flow at the right point.

    The gate's unit tests cover the helper functions in isolation and the
    docker tests cover classification of live container output — but NOTHING
    exercises that ``_openclaw_audit_preflight()`` is invoked inside
    ``_lock_async`` BEFORE any write. Without these, a mis-wired graft
    (preflight dropped, or moved after the writes) passes CI silently while
    the gate is dead. These are the merge's composition guard.
    """

    def test_blocking_gate_aborts_lock_before_any_write(
        self, home_dir: WorthlessHome, env_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A blocking pre-flight (Exit 73) must abort lock with ZERO side
        effects: .env is untouched (gate-before-write, SR-03)."""
        original_env = env_file.read_text(encoding="utf-8")

        def _blocking_preflight() -> None:
            raise typer.Exit(code=73)

        monkeypatch.setattr(
            "worthless.cli.commands.lock._openclaw_audit_preflight", _blocking_preflight
        )

        result = runner.invoke(
            app, ["lock", "--env", str(env_file)], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
        )

        assert result.exit_code == 73, (
            f"blocking gate did not abort lock with exit 73:\n{result.stdout}\n{result.exception!r}"
        )
        assert env_file.read_text(encoding="utf-8") == original_env, (
            "gate blocked but .env was still rewritten — preflight is wired AFTER "
            "the writes (or not at all). Must run before any DB/.env mutation."
        )

    def test_postflight_runs_after_successful_lock(
        self, home_dir: WorthlessHome, env_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the pre-flight returns a handle, the post-flight must be
        invoked with it after the lock writes succeed."""
        sentinel = object()
        postflight = MagicMock()
        monkeypatch.setattr(
            "worthless.cli.commands.lock._openclaw_audit_preflight", lambda: sentinel
        )
        monkeypatch.setattr("worthless.cli.commands.lock._openclaw_audit_postflight", postflight)

        result = runner.invoke(
            app, ["lock", "--env", str(env_file)], env={"WORTHLESS_HOME": str(home_dir.base_dir)}
        )

        assert result.exit_code == 0, (
            f"lock failed with gate handle present:\n{result.stdout}\n{result.exception!r}"
        )
        postflight.assert_called_once_with(sentinel)
