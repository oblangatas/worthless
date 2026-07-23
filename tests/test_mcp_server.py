"""Tests for the Worthless MCP server tools."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

pytest.importorskip("mcp", reason="mcp extra not installed")

from worthless.mcp.server import (  # noqa: E402
    worthless_lock,
    worthless_scan,
    worthless_spend,
    worthless_status,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_env_file(tmp_path: Path, content: str) -> Path:
    env_file = tmp_path / ".env"
    env_file.write_text(content)
    return env_file


def _make_home(tmp_path: Path) -> Path:
    """Create a minimal WorthlessHome directory."""
    from cryptography.fernet import Fernet

    home = tmp_path / ".worthless"
    home.mkdir(mode=0o700)
    (home / "shard_a").mkdir(mode=0o700)
    key = Fernet.generate_key()
    (home / "fernet.key").write_bytes(key)
    return home


# ---------------------------------------------------------------------------
# worthless_status
# ---------------------------------------------------------------------------


class TestWorthlessStatus:
    @pytest.mark.asyncio
    async def test_status_no_home(self, tmp_path: Path) -> None:
        """Status returns empty when worthless is not initialized."""
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(tmp_path / "nonexistent")}):
            result = json.loads(await worthless_status())
        assert result["keys"] == []
        assert result["proxy"]["healthy"] is False

    @pytest.mark.asyncio
    async def test_status_with_home(self, tmp_path: Path) -> None:
        """Status returns empty keys list when initialized but no keys enrolled."""
        home = _make_home(tmp_path)
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_status())
        assert result["keys"] == []
        assert result["proxy"]["healthy"] is False

    @staticmethod
    def _stub_status(
        monkeypatch: pytest.MonkeyPatch,
        *,
        keys: list[dict[str, str]],
        healthy: bool,
        sentinel: dict[str, str] | None = None,
        identified: bool = True,
    ) -> None:
        """Pin the four inputs the verdict is derived from.

        ``identified`` (WOR-822) mirrors what ``check_proxy_health`` surfaces:
        ``bind_probe_count`` is the marker a real proxy advertises on
        ``/healthz``. The check is presence-only — a same-host process could
        forge it — so it flags a benign/unidentified responder, it does not
        authenticate the proxy.
        """
        import worthless.cli.commands.status as status_mod
        import worthless.cli.sentinel as sentinel_mod

        health: dict[str, object] = {"healthy": healthy, "port": 8787, "mode": "http"}
        if identified:
            health["bind_probe_count"] = 0

        monkeypatch.setattr(status_mod, "_list_enrolled_keys", lambda _home: keys)
        monkeypatch.setattr(status_mod, "_discover_proxy_port", lambda _home: 8787)
        monkeypatch.setattr(status_mod, "_check_proxy_health", lambda _port: health)
        monkeypatch.setattr(sentinel_mod, "read_sentinel", lambda _dir: sentinel)

    @pytest.mark.asyncio
    async def test_locked_keys_with_proxy_down_is_protected_at_rest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WOR-819: locked keys + proxy down is SAFE, not a security failure.

        A stolen ``.env`` is genuinely worthless in this state — only routing
        is unavailable. Reporting it as "not protected" would read as "your
        secret is exposed", the opposite of the truth, and per WOR-779 trains
        the user to ignore red. This is the anti-inversion guard.
        """
        home = _make_home(tmp_path)
        self._stub_status(
            monkeypatch,
            keys=[{"alias": "openai", "provider": "openai", "status": "PROTECTED"}],
            healthy=False,
        )
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_status())

        assert result["verdict"] == "protected_at_rest"
        # The affirmative security claim must survive to the editor surface.
        assert "stolen" in result["header"]

    @pytest.mark.asyncio
    async def test_at_risk_tier_is_reachable_from_the_editor(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WOR-821: the one 🔴 verdict must not be structurally unreachable here.

        ``degraded`` comes from the lock-status sentinel. If a refactor stubs
        it False, ``at_risk`` can never be emitted from this surface and a
        genuinely broken user is told they are protected — a silent false
        green. This test fails if that wire is ever cut.
        """
        home = _make_home(tmp_path)
        self._stub_status(
            monkeypatch,
            keys=[{"alias": "openai", "provider": "openai", "status": "PROTECTED"}],
            healthy=True,
            # is_partial(): status == "partial" AND openclaw == "failed".
            sentinel={"status": "partial", "openclaw": "failed"},
        )
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_status())

        assert result["degraded"] is True
        assert result["verdict"] == "at_risk"

    @pytest.mark.asyncio
    async def test_locked_keys_with_proxy_up_is_protected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both halves in place → the plain green verdict."""
        home = _make_home(tmp_path)
        self._stub_status(
            monkeypatch,
            keys=[{"alias": "openai", "provider": "openai", "status": "PROTECTED"}],
            healthy=True,
        )
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_status())

        assert result["verdict"] == "protected"
        assert result["degraded"] is False

    @pytest.mark.asyncio
    async def test_unidentified_responder_is_not_green_from_the_editor(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WOR-822: the identity gate must reach this surface too.

        The gate lives in the shared ``_status_verdict``, so an agent asking
        "am I protected?" from the editor gets the same refusal to call an
        unidentified responder "the proxy". If this ever passes ``True``
        unconditionally, an unidentified responder reads green here only — the
        exact CLI/editor divergence WOR-820 was opened to end.
        """
        home = _make_home(tmp_path)
        self._stub_status(
            monkeypatch,
            keys=[{"alias": "openai", "provider": "openai", "status": "PROTECTED"}],
            healthy=True,
            identified=False,
        )
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_status())

        assert result["verdict"] == "proxy_unrecognised"
        assert "isn't worthless" in result["header"]

    @pytest.mark.asyncio
    async def test_editor_verdict_matches_the_cli_for_identical_inputs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WOR-820's whole point: one true answer on every surface.

        Asserts this surface reports exactly what the CLI's rulebook returns
        for the same inputs — so a future change can't quietly reintroduce a
        second, divergent notion of "protected" here.
        """
        from worthless.cli.commands.status import _status_verdict

        home = _make_home(tmp_path)
        keys = [{"alias": "openai", "provider": "openai", "status": "PROTECTED"}]
        self._stub_status(monkeypatch, keys=keys, healthy=False)
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_status())

        expected_verdict, expected_header = _status_verdict(keys, False, False, True)
        assert result["verdict"] == expected_verdict
        assert result["header"] == expected_header

    @pytest.mark.asyncio
    async def test_storage_failure_is_not_reported_as_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A broken store must not read as "nothing enrolled" (WOR-820).

        The general ``resolve_home()`` swallows bootstrap errors and returns
        None, which would render as verdict ``empty`` — telling a user whose
        keys ARE locked that nothing is enrolled, and forcing degraded=False.
        The CLI deliberately lets storage corruption propagate; this surface
        must too, or the two disagree on the only question that matters.
        """
        import worthless.cli.commands.status as status_mod
        from worthless.cli.errors import ErrorCode, WorthlessError

        def _boom() -> None:
            raise WorthlessError(ErrorCode.BOOTSTRAP_FAILED, "keystore unavailable")

        monkeypatch.setattr(status_mod, "_resolve_home_for_status", _boom)

        with pytest.raises(WorthlessError):
            await worthless_status()

    @pytest.mark.asyncio
    async def test_sentinel_is_whitelisted_not_passed_through_raw(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Operational detail must not ride along to a possibly-remote model.

        The raw sentinel carries config paths, usernames inside those paths,
        and a provider inventory in ``events`` — none of it needed to explain
        a verdict. Whitelist, so a field added upstream is withheld by default.
        """
        home = _make_home(tmp_path)
        self._stub_status(
            monkeypatch,
            keys=[{"alias": "openai", "provider": "openai", "status": "PROTECTED"}],
            healthy=True,
            sentinel={
                "status": "ok",
                "openclaw": "applied",
                "ts": "2026-07-19T00:00:00Z",
                "events": [{"path": "/Users/someone/.config/secret.json"}],
                "alias_count": 3,
                "bind_confirmation": {"status": "confirmed", "aliases": ["openai"]},
            },
        )
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_status())

        sentinel = result["sentinel"]
        assert "events" not in sentinel, "operational event detail leaked"
        assert "alias_count" not in sentinel
        assert sentinel["bind_confirmation"] == {"status": "confirmed"}, (
            "per-alias bind detail leaked"
        )
        assert sentinel["status"] == "ok"

    @pytest.mark.asyncio
    async def test_shape_is_a_superset_of_the_cli_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Pin the cross-surface contract so shape drift is caught.

        The CLI's ``status --json`` emits verdict/keys/proxy/sentinel/degraded.
        This surface must carry all of them (plus ``header``) or an agent and
        a human reading the same install stop seeing the same facts.
        """
        home = _make_home(tmp_path)
        self._stub_status(
            monkeypatch,
            keys=[{"alias": "openai", "provider": "openai", "status": "PROTECTED"}],
            healthy=True,
        )
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_status())

        cli_json_fields = {"verdict", "keys", "proxy", "sentinel", "degraded"}
        assert cli_json_fields <= set(result), (
            f"missing CLI fields: {sorted(cli_json_fields - set(result))}"
        )


# ---------------------------------------------------------------------------
# worthless_scan
# ---------------------------------------------------------------------------


class TestWorthlessScan:
    @pytest.mark.asyncio
    async def test_scan_clean_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Scanning a file with no keys returns empty findings."""
        monkeypatch.chdir(tmp_path)
        env_file = _make_env_file(tmp_path, "FOO=bar\nBAZ=123\n")
        result = json.loads(await worthless_scan(paths=[str(env_file)]))
        assert result["findings"] == []
        assert result["summary"]["total"] == 0

    @pytest.mark.asyncio
    async def test_scan_detects_key(self, tmp_path: Path) -> None:
        """Scanning a file with a real-looking key returns findings."""
        # Use a high-entropy string that matches provider patterns
        fake_key = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0" * 2
        env_file = _make_env_file(tmp_path, f"OPENAI_API_KEY={fake_key}\n")
        result = json.loads(await worthless_scan(paths=[str(env_file)]))
        assert result["summary"]["total"] >= 1
        assert result["summary"]["unprotected"] >= 1

    @pytest.mark.asyncio
    async def test_scan_no_paths_defaults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Scanning with no paths scans .env in cwd."""
        monkeypatch.chdir(tmp_path)
        _make_env_file(tmp_path, "FOO=bar\n")
        result = json.loads(await worthless_scan())
        assert result["summary"]["total"] == 0

    @pytest.mark.asyncio
    async def test_scan_envelope_has_skipped_and_scan_incomplete(self, tmp_path: Path) -> None:
        """c5kc: MCP scan envelope always carries ``skipped`` + ``scan_incomplete``
        so the calling agent can tell ``no findings`` (clean) apart from
        ``no findings because I couldn't read everything`` (partial)."""
        env_file = _make_env_file(tmp_path, "FOO=bar\n")
        result = json.loads(await worthless_scan(paths=[str(env_file)]))

        # Additive fields must be present even on a clean scan.
        assert "skipped" in result
        assert "scan_incomplete" in result
        assert result["skipped"] == []
        assert result["scan_incomplete"] is False

    @pytest.mark.asyncio
    async def test_scan_offloaded_to_worker_thread(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """c5kc / CodeRabbit follow-up: scan_files is synchronous and runs for
        up to 30 s; calling it inline would block the FastMCP event loop and
        starve other concurrent MCP tools. This test pins that the MCP tool
        actually offloads to a worker thread.

        If a future refactor accidentally re-inlines the call (drops
        ``await asyncio.to_thread(...)``), this test fails because
        ``scan_files`` would then run on the main event-loop thread.
        """
        import threading

        main_thread_id = threading.get_ident()
        called_from: dict[str, int] = {}

        def tracking_scan_files(*args, **kwargs):
            called_from["thread"] = threading.get_ident()
            return []

        # Patch the symbol where the MCP tool imports it from.
        import worthless.cli.scanner as scanner_mod

        monkeypatch.setattr(scanner_mod, "scan_files", tracking_scan_files)

        env_file = _make_env_file(tmp_path, "FOO=bar\n")
        await worthless_scan(paths=[str(env_file)])

        assert "thread" in called_from, "scan_files was never called"
        assert called_from["thread"] != main_thread_id, (
            "scan_files ran on the event-loop thread — would block other MCP tools. "
            "Wrap the call in `await asyncio.to_thread(scan_files, ...)`."
        )

    @pytest.mark.asyncio
    async def test_scan_truncated_file_marks_scan_incomplete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """c5kc: an oversize file scans its prefix and surfaces ``truncated``
        in the envelope so the agent doesn't read ``0 findings`` as clean."""
        import worthless.cli.scanner as scanner_mod

        # Tiny cap so we don't have to write 5 MB to disk in CI.
        monkeypatch.setattr(scanner_mod, "MAX_SCAN_FILE_BYTES", 256)

        env_file = tmp_path / ".env"
        env_file.write_bytes(b"# placeholder\n" + b"x" * 1024)

        result = json.loads(await worthless_scan(paths=[str(env_file)]))

        assert result["scan_incomplete"] is True
        assert any(s["reason"] == "truncated" for s in result["skipped"])
        # Skip notice path + reason only — never any bytes of file content.
        for s in result["skipped"]:
            assert set(s.keys()) == {"file", "reason"}


# ---------------------------------------------------------------------------
# worthless_lock
# ---------------------------------------------------------------------------


class TestWorthlessLock:
    @pytest.mark.asyncio
    async def test_lock_no_keys(self, tmp_path: Path) -> None:
        """Locking a file with no API keys returns 0 protected."""
        home = _make_home(tmp_path)
        env_file = _make_env_file(tmp_path, "FOO=bar\n")
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_lock(env_path=str(env_file)))
        assert result["protected_count"] == 0
        # WOR-829: a 0-key lock has nothing to route, so the probe is skipped
        # and the routing fields are intentionally absent. Pin that.
        assert "proxy_running" not in result
        assert "next_step" not in result

    @pytest.mark.asyncio
    async def test_lock_protects_key(self, tmp_path: Path) -> None:
        """Locking a file with an API key should protect it."""
        home = _make_home(tmp_path)
        fake_key = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0" * 2
        env_file = _make_env_file(tmp_path, f"OPENAI_API_KEY={fake_key}\n")
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_lock(env_path=str(env_file)))
        assert result["protected_count"] == 1
        # Original key should no longer be in the file
        assert fake_key not in env_file.read_text()
        # dqzj: a clean lock reconciles to a consistent state — no false orphan.
        assert result["state_consistent"] is True
        assert "orphan_shards" not in result

    @pytest.mark.asyncio
    async def test_lock_surfaces_orphan_shard(self, tmp_path: Path) -> None:
        """dqzj: a shards row with no enrollment is surfaced, not silently 'ok'.

        The MCP lock runs off the main thread (no interrupt rollback). If the DB
        carries an orphan shard (a half-written/legacy mixed state), the result
        must flag it and point at `doctor` rather than returning a bare success.
        """
        import aiosqlite

        from worthless.storage.schema import init_db

        home = _make_home(tmp_path)
        db_path = str(home / "worthless.db")
        await init_db(db_path)
        # An orphan: a shard with NO enrollment row (no shard-A, useless, but junk).
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "INSERT INTO shards (key_alias, shard_b_enc, commitment, nonce, provider) "
                "VALUES (?, ?, ?, ?, ?)",
                ("orphan-alias", b"b", b"c", b"n", "openai"),
            )
            await db.commit()

        env_file = _make_env_file(tmp_path, "FOO=bar\n")  # no keys → protected_count 0
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_lock(env_path=str(env_file)))

        assert result["protected_count"] == 0
        assert result["state_consistent"] is False
        assert result["orphan_shards"] == ["orphan-alias"]
        assert "doctor" in result["hint"]

    # -- WOR-829: the lock response tells the editor user whether traffic routes --
    #
    # The victim is the MCP editor user with no OpenClaw: lock succeeds with the
    # proxy down (the WRTLS-109 gate is OpenClaw-only, and the suite-wide HOME
    # sandbox makes ``detect().present`` False — see conftest), so nothing warns
    # them their apps can't reach the keys. These pin that the lock response now
    # carries ``proxy_running`` + a ``next_step``.

    KEY = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0" * 2

    @staticmethod
    def _set_proxy(monkeypatch: pytest.MonkeyPatch, *, healthy: bool, identified: bool) -> None:
        """Pin what the post-lock probe sees. ``identified`` mirrors WOR-822:
        ``bind_probe_count`` is present iff the responder is really our proxy."""
        health: dict[str, object] = {
            "healthy": healthy,
            "port": 8787,
            "mode": "http",
            "requests_proxied": 0,
        }
        if identified:
            health["bind_probe_count"] = 0
        monkeypatch.setattr("worthless.mcp.server.check_proxy_health", lambda _p: health)

    @pytest.mark.asyncio
    async def test_lock_with_proxy_down_tells_the_editor_to_start_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Proxy down at lock → the response names the fix. Proof of fix:
        fails on today's count-only response."""
        home = _make_home(tmp_path)
        env_file = _make_env_file(tmp_path, f"OPENAI_API_KEY={self.KEY}\n")
        self._set_proxy(monkeypatch, healthy=False, identified=False)
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_lock(env_path=str(env_file)))
        assert result["protected_count"] == 1
        assert result["proxy_running"] is False
        assert "worthless up" in result["next_step"]

    @pytest.mark.asyncio
    async def test_lock_with_proxy_up_confirms_without_a_green_claim(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Proxy up + identified → calm confirm pointing at ``status`` — but NOT
        a green "protected" claim, because the marker is forgeable (WOR-822)."""
        home = _make_home(tmp_path)
        env_file = _make_env_file(tmp_path, f"OPENAI_API_KEY={self.KEY}\n")
        self._set_proxy(monkeypatch, healthy=True, identified=True)
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_lock(env_path=str(env_file)))
        assert result["proxy_running"] is True
        assert "worthless status" in result["next_step"]
        assert "protected" not in result["next_step"].lower()

    @pytest.mark.asyncio
    async def test_lock_with_a_squatter_on_the_port_is_not_running(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A 200 on /healthz without ``bind_probe_count`` is a stranger, not our
        proxy (WOR-822). Lock must not report it as routing."""
        home = _make_home(tmp_path)
        env_file = _make_env_file(tmp_path, f"OPENAI_API_KEY={self.KEY}\n")
        self._set_proxy(monkeypatch, healthy=True, identified=False)
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_lock(env_path=str(env_file)))
        assert result["proxy_running"] is False
        assert "worthless up" in result["next_step"]

    @pytest.mark.asyncio
    async def test_probe_failure_never_undoes_the_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Lock success is a confidentiality fact, independent of the
        availability probe. A probe that raises must not change
        ``protected_count`` — it just reads as "not running"."""
        home = _make_home(tmp_path)
        env_file = _make_env_file(tmp_path, f"OPENAI_API_KEY={self.KEY}\n")

        def _boom(_p: int) -> dict[str, object]:
            raise httpx.ConnectError("down")

        monkeypatch.setattr("worthless.mcp.server.check_proxy_health", _boom)
        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_lock(env_path=str(env_file)))
        assert result["protected_count"] == 1
        assert result["proxy_running"] is False


# ---------------------------------------------------------------------------
# worthless_spend
# ---------------------------------------------------------------------------


class TestWorthlessSpend:
    @pytest.mark.asyncio
    async def test_spend_empty(self, tmp_path: Path) -> None:
        """Spend returns empty list when no spend data exists."""
        home = _make_home(tmp_path)
        # Initialize the DB schema
        from worthless.storage.schema import init_db

        await init_db(str(home / "worthless.db"))

        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_spend())
        assert result["spend"] == []

    @pytest.mark.asyncio
    async def test_spend_with_data(self, tmp_path: Path) -> None:
        """Spend aggregates rows from spend_log table."""
        home = _make_home(tmp_path)
        from worthless.storage.schema import init_db

        db_path = str(home / "worthless.db")
        await init_db(db_path)

        # Insert test spend data directly
        import aiosqlite

        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
                ("openai-abc123", 100, "gpt-4", "openai"),
            )
            await db.execute(
                "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
                ("openai-abc123", 200, "gpt-4", "openai"),
            )
            await db.commit()

        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_spend())
        assert len(result["spend"]) == 1
        assert result["spend"][0]["alias"] == "openai-abc123"
        assert result["spend"][0]["total_tokens"] == 300
        assert result["spend"][0]["request_count"] == 2

    @pytest.mark.asyncio
    async def test_spend_filter_by_alias(self, tmp_path: Path) -> None:
        """Spend filters by alias when provided."""
        home = _make_home(tmp_path)
        from worthless.storage.schema import init_db

        db_path = str(home / "worthless.db")
        await init_db(db_path)

        import aiosqlite

        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
                ("openai-abc", 100, "gpt-4", "openai"),
            )
            await db.execute(
                "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
                ("anthropic-xyz", 500, "claude-3", "anthropic"),
            )
            await db.commit()

        with patch.dict(os.environ, {"WORTHLESS_HOME": str(home)}):
            result = json.loads(await worthless_spend(alias="openai-abc"))
        assert len(result["spend"]) == 1
        assert result["spend"][0]["alias"] == "openai-abc"
