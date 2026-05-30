"""Tests for the ``worthless wrap`` command."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from tests.conftest import make_repo as _repo
from worthless.cli.commands.wrap import (
    _cleanup_proxy,
    _list_enrolled_aliases,
    _run_child_and_wait,
)
from worthless.cli.process import create_liveness_pipe

runner = CliRunner()


@pytest.fixture(autouse=True)
def _stub_sidecar_lifecycle(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Stub ``split_to_tmpfs`` + ``spawn_sidecar`` + ``shutdown_sidecar`` so
    wrap tests don't try to launch a real sidecar subprocess.

    After WOR-309, ``wrap`` spawns the sidecar before the proxy. The full
    lifecycle is covered by ``tests/cli/test_sidecar_lifecycle.py`` — here
    we stub to no-op fakes and yield a recorder dict so individual tests can
    assert call ordering (e.g., that shutdown_sidecar fired on cleanup).
    """
    from pathlib import Path
    from unittest.mock import MagicMock as _MagicMock

    fake_run_dir = Path("/tmp/wor-test-run")  # noqa: S108
    fake_socket = fake_run_dir / "sidecar.sock"
    fake_shares = _MagicMock(
        run_dir=fake_run_dir,
        share_a_path=fake_run_dir / "share_a.bin",
        share_b_path=fake_run_dir / "share_b.bin",
        shard_a=bytearray(32),
        shard_b=bytearray(32),
    )
    fake_handle = _MagicMock(
        socket_path=fake_socket,
        shares=fake_shares,
        allowed_uid=os.getuid(),
        proc=_MagicMock(pid=99999, poll=lambda: 0),
    )

    calls: dict = {"shutdown_count": 0, "shutdown_handle": None}

    def _record_shutdown(handle):
        calls["shutdown_count"] += 1
        calls["shutdown_handle"] = handle

    monkeypatch.setattr(
        "worthless.cli.commands.wrap.split_to_tmpfs",
        lambda _key, _home: fake_shares,
    )
    monkeypatch.setattr(
        "worthless.cli.commands.wrap.spawn_sidecar",
        lambda _socket, _shares, **_kw: fake_handle,
    )
    monkeypatch.setattr(
        "worthless.cli.commands.wrap.shutdown_sidecar",
        _record_shutdown,
    )
    return calls


@pytest.fixture(autouse=True)
def _default_port_free(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default ``_port_in_use=False`` for every wrap test in this file.

    v0.3.4 added a pre-spawn port-conflict check; without this fixture
    every existing wrap test that doesn't explicitly mock ``_port_in_use``
    would short-circuit on a busy port (real or simulated) instead of
    exercising the path the test was written for. Tests that need the
    conflict path (``TestWrapPortConflict``) override this via their own
    ``monkeypatch.setattr`` calls — pytest's monkeypatch stacks LIFO,
    so the override wins.
    """
    monkeypatch.setattr(
        "worthless.cli.commands.wrap._port_in_use",
        lambda *_a, **_kw: False,
    )


class TestWrapEnvInjection:
    """wrap injects BASE_URL env vars for enrolled providers."""

    def test_injects_base_url_for_enrolled_provider(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With no *_BASE_URL in the parent env, wrap injects the proxy URL
        for each enrolled provider.

        ``home_with_key`` enrolls alias ``openai-a1b2c3d4`` (protocol
        ``openai``) and the port fixture uses ``WORTHLESS_PORT=8787``.
        Expected injection: ``OPENAI_BASE_URL=http://127.0.0.1:8787/openai-a1b2c3d4/v1``.
        """
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        child_env = TestWrapChildEnvContract._capture_child_env(home_with_key, monkeypatch)
        assert child_env.get("OPENAI_BASE_URL") == "http://127.0.0.1:8787/openai-a1b2c3d4/v1"

    def test_skips_alias_with_unsafe_characters(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Aliases containing characters outside [A-Za-z0-9_-] are silently
        skipped — no BASE_URL injected, no exception raised. Valid aliases
        in the same list are still processed normally."""
        monkeypatch.setattr(
            "worthless.cli.commands.wrap._list_enrolled_aliases",
            lambda _home: [("../evil-alias", "openai"), ("openai-a1b2c3d4", "openai")],
        )
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        child_env = TestWrapChildEnvContract._capture_child_env(home_with_key, monkeypatch)
        # Valid alias is injected; the unsafe one is skipped
        assert child_env.get("OPENAI_BASE_URL") == "http://127.0.0.1:8787/openai-a1b2c3d4/v1"
        assert "../evil-alias" not in str(child_env.get("OPENAI_BASE_URL", ""))

    def test_skips_protocol_with_unsafe_characters(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Protocols containing characters outside [A-Za-z0-9_-] are skipped —
        prevents invalid env var names from reaching subprocess.Popen."""
        monkeypatch.setattr(
            "worthless.cli.commands.wrap._list_enrolled_aliases",
            lambda _home: [("openai-a1b2c3d4", "open ai;evil")],
        )
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        child_env = TestWrapChildEnvContract._capture_child_env(home_with_key, monkeypatch)
        # Unsafe protocol skipped — no BASE_URL injected at all
        assert "OPENAI_BASE_URL" not in child_env
        assert not any("evil" in v for v in child_env.values())

    def test_skips_digit_prefix_protocol(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Protocols starting with a digit (e.g. '0abc') produce POSIX-invalid
        env var names like '0ABC_BASE_URL' that are silently dropped by shells
        and libc. _PROTO_RE rejects them before they reach subprocess.Popen."""
        monkeypatch.setattr(
            "worthless.cli.commands.wrap._list_enrolled_aliases",
            lambda _home: [("openai-a1b2c3d4", "0abc")],
        )
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        child_env = TestWrapChildEnvContract._capture_child_env(home_with_key, monkeypatch)
        assert "0ABC_BASE_URL" not in child_env
        assert "OPENAI_BASE_URL" not in child_env


class TestWrapChildEnvContract:
    """``wrap`` injects ``*_BASE_URL`` for enrolled providers, preserving
    any value already present in the parent env.

    Pre-8rqs, wrap synthesised ``OPENAI_BASE_URL`` / ``ANTHROPIC_BASE_URL``
    into the child env. PR #127 (8rqs Phase 8) removed that injection on the
    assumption that ``lock`` would write the vars into .env. That assumption
    broke users not running direnv. PR #251 restores injection: after the proxy
    starts healthy, wrap sets ``{PROVIDER}_BASE_URL=http://127.0.0.1:{port}/{alias}/v1``
    for each enrolled provider — only when the var is absent from the parent env,
    so direnv users keep their loaded value.

    These tests assert the contract end-to-end against the
    ``subprocess.Popen`` ``env=`` kwarg captured during a wrap run.
    """

    @staticmethod
    def _capture_child_env(home_with_key, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
        """Run wrap with everything mocked except the child-env construction
        path. Capture the env= kwarg passed to subprocess.Popen for the child."""
        captured: dict = {}
        mock_proxy = MagicMock()
        mock_proxy.pid = 33330
        mock_proxy.poll.return_value = None
        mock_proxy.wait.return_value = 0
        mock_child = MagicMock()
        mock_child.pid = 33331
        mock_child.wait.return_value = 0
        mock_child.returncode = 0

        def _capture_popen(*args, **kwargs):
            captured["env"] = kwargs.get("env", {})
            return mock_child

        monkeypatch.setattr(
            "worthless.cli.commands.wrap.spawn_proxy", lambda **kw: (mock_proxy, kw["port"])
        )
        monkeypatch.setattr("worthless.cli.commands.wrap.poll_health", lambda *_a, **_kw: True)
        monkeypatch.setattr("worthless.cli.commands.wrap.forward_signals", lambda **_kw: None)
        monkeypatch.setattr("subprocess.Popen", _capture_popen)

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir), "WORTHLESS_PORT": "8787"},
        )
        assert result.exit_code == 0, result.output
        return captured["env"]

    def test_injects_enrolled_providers_when_absent_from_parent(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PR #251 restores injection: when *_BASE_URL is absent from the
        parent env, wrap injects the proxy URL for each enrolled provider.
        Providers not enrolled (anthropic, openrouter) are NOT synthesised."""
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
        monkeypatch.delenv("OPENROUTER_BASE_URL", raising=False)
        child_env = self._capture_child_env(home_with_key, monkeypatch)
        # openai-a1b2c3d4 is enrolled in home_with_key → must be injected
        assert child_env.get("OPENAI_BASE_URL") == "http://127.0.0.1:8787/openai-a1b2c3d4/v1"
        # not enrolled → must not be synthesised
        assert "ANTHROPIC_BASE_URL" not in child_env
        assert "OPENROUTER_BASE_URL" not in child_env

    def test_parent_baseurl_passes_through(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If the parent has ``OPENROUTER_BASE_URL`` set (because the user's
        .env was sourced or exported), wrap MUST NOT overwrite it — the user's
        value reaches the child unchanged."""
        monkeypatch.setenv("OPENROUTER_BASE_URL", "http://127.0.0.1:8787/openrouter-x/v1")
        child_env = self._capture_child_env(home_with_key, monkeypatch)
        assert child_env.get("OPENROUTER_BASE_URL") == "http://127.0.0.1:8787/openrouter-x/v1"

    def test_enrolled_provider_var_in_parent_is_not_overwritten(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If the parent env already carries the enrolled provider's BASE_URL
        (e.g. direnv loaded it), wrap must not overwrite it with the proxy URL.
        This covers the ``if var not in child_env`` False branch."""
        monkeypatch.setenv("OPENAI_BASE_URL", "http://my-custom-proxy:9999/v1")
        child_env = self._capture_child_env(home_with_key, monkeypatch)
        assert child_env.get("OPENAI_BASE_URL") == "http://my-custom-proxy:9999/v1"

    def test_no_session_token(self, home_with_key, monkeypatch: pytest.MonkeyPatch) -> None:
        """``WORTHLESS_SESSION_TOKEN`` is dead — wrap must never add it back."""
        monkeypatch.delenv("WORTHLESS_SESSION_TOKEN", raising=False)
        child_env = self._capture_child_env(home_with_key, monkeypatch)
        assert "WORTHLESS_SESSION_TOKEN" not in child_env


class TestListEnrolledAliasesWithDB:
    """_list_enrolled_aliases returns aliases when DB has data."""

    def test_returns_aliases_from_db(self, home_with_key) -> None:
        aliases = _list_enrolled_aliases(home_with_key)
        assert len(aliases) >= 1
        assert all(isinstance(a, str) and isinstance(p, str) for a, p in aliases)

    def test_returns_aliases_under_ipc_only_flag_without_sidecar(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Under WORTHLESS_FERNET_IPC_ONLY=1, alias listing must NOT depend on a
        running sidecar. The pre-flight enrollment check is a pure DB read —
        no Fernet key, no IPC socket needed. A missing socket must not cause
        _list_enrolled_aliases to silently return [] and mislead the user."""
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        aliases = _list_enrolled_aliases(home_with_key)
        assert len(aliases) >= 1, (
            "Expected enrolled aliases but got []. "
            "Likely open_repo tried to connect IPC before sidecar started."
        )
        assert all(isinstance(a, str) and isinstance(p, str) for a, p in aliases)

    @pytest.mark.asyncio
    async def test_returns_aliases_from_running_loop(self, home_with_key) -> None:
        """_list_enrolled_aliases is a sync function but is invoked from CLI
        commands that may already be inside an event loop (MCP server,
        pytest-asyncio auto mode). The implementation must route through
        worthless._async.run_sync, not raw asyncio.run, otherwise asyncio.run
        raises RuntimeError("This event loop is already running") and the
        bare-except guard swallows it as []."""
        aliases = _list_enrolled_aliases(home_with_key)
        assert len(aliases) >= 1

    def test_corrupt_db_returns_empty(self, home_with_key, monkeypatch: pytest.MonkeyPatch) -> None:
        """OSError from aiosqlite.connect (e.g. unreadable file, permission
        denied) must be caught by the narrowed handler and produce []."""
        import aiosqlite

        def _raise_oserror(*_args, **_kwargs):
            raise OSError("simulated unreadable DB")

        monkeypatch.setattr(aiosqlite, "connect", _raise_oserror)
        aliases = _list_enrolled_aliases(home_with_key)
        assert aliases == []

    def test_aiosqlite_error_returns_empty(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """aiosqlite.Error (malformed DB, locked file, etc.) must be caught
        by the narrowed handler and produce []."""
        import aiosqlite

        def _raise_aiosqlite_error(*_args, **_kwargs):
            raise aiosqlite.Error("simulated query failure")

        monkeypatch.setattr(aiosqlite, "connect", _raise_aiosqlite_error)
        aliases = _list_enrolled_aliases(home_with_key)
        assert aliases == []

    def test_returned_values_are_str(self, home_with_key) -> None:
        """sqlite3.Row indexes return Any at the type level. The implementation
        must coerce both fields to str() so the declared return type
        list[tuple[str, str]] holds even if a column ever returns a non-text
        value (defensive, pyright-strict compliance)."""
        aliases = _list_enrolled_aliases(home_with_key)
        assert len(aliases) >= 1
        for alias, provider in aliases:
            assert type(alias) is str, f"alias is {type(alias).__name__}, not str"
            assert type(provider) is str, f"provider is {type(provider).__name__}, not str"


class TestListEnrolledAliasesAdversarial:
    """Hostile-input and race-condition probes for _list_enrolled_aliases.

    PR #166 changed this function to read the SQLite DB directly. The
    attack surface is now: anyone who can write to ``home.db_path`` (or
    swap it for a different file) can influence what the pre-flight
    enrollment check returns. These tests pin the failure modes that
    must produce a safe ``[]`` instead of a crash or data leak.
    """

    def test_symlink_to_non_sqlite_file_returns_empty(self, home_dir, tmp_path: Path) -> None:
        """If home.db_path is a symlink pointing at a file that isn't a
        valid SQLite database (e.g. /etc/hostname), aiosqlite must fail
        cleanly and the function must return [] — never the target file's
        content. This is the static analogue of a symlink-swap TOCTOU."""
        decoy = tmp_path / "decoy.txt"
        decoy.write_text("not a sqlite db, definitely not key material\n")
        home_dir.db_path.unlink(missing_ok=True)
        home_dir.db_path.symlink_to(decoy)

        aliases = _list_enrolled_aliases(home_dir)
        assert aliases == [], "non-SQLite symlink target leaked through"

    def test_hostile_alias_round_trips_safely(self, home_with_key, tmp_path: Path) -> None:
        """SQL-special chars / NULL-byte / RTL-unicode in the key_alias
        column must not break the join, must not SQL-inject (queries are
        parameterized), and must surface verbatim so downstream display
        code can sanitise them — never silently swallowed.

        If the schema enforces a CHECK constraint that rejects these
        values, the test still proves the protection exists by failing
        on insert; that's a different (also good) outcome."""
        import sqlite3

        hostile_aliases = [
            "'; DROP TABLE shards; --",
            "evil‮reversed",
            "with spaces and 'quotes'",
        ]

        conn = sqlite3.connect(str(home_with_key.db_path))
        try:
            for alias in hostile_aliases:
                try:
                    conn.execute(
                        "INSERT INTO shards (key_alias, shard_b_enc, commitment, "
                        "nonce, provider, prefix, charset, base_url) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (alias, b"x", b"x", b"x", "openai", "sk-", "abc", None),
                    )
                    conn.execute(
                        "INSERT INTO enrollments (key_alias, var_name, env_path, decoy_hash) "
                        "VALUES (?, ?, ?, ?)",
                        (alias, "OPENAI_API_KEY", str(tmp_path / ".env"), "h"),
                    )
                except sqlite3.IntegrityError:
                    pytest.skip("schema rejects hostile alias — protection lives at write time")
            conn.commit()
        finally:
            conn.close()

        aliases = _list_enrolled_aliases(home_with_key)
        returned_alias_names = {a for a, _ in aliases}
        for hostile in hostile_aliases:
            assert hostile in returned_alias_names, (
                f"hostile alias {hostile!r} was silently dropped — "
                "must round-trip so downstream code can decide to sanitise"
            )
        cursor = sqlite3.connect(str(home_with_key.db_path)).execute("SELECT COUNT(*) FROM shards")
        assert cursor.fetchone()[0] >= 1, "shards table was dropped — SQL injection succeeded"

    def test_missing_shards_table_returns_empty(self, home_dir, tmp_path: Path) -> None:
        """If an attacker swaps home.db_path for a SQLite file with a
        different schema (no shards/enrollments tables), aiosqlite raises
        OperationalError (subclass of aiosqlite.Error). The narrowed
        handler must catch it and return []."""
        import sqlite3

        home_dir.db_path.unlink(missing_ok=True)
        conn = sqlite3.connect(str(home_dir.db_path))
        try:
            conn.execute("CREATE TABLE attacker_owned (junk TEXT)")
            conn.commit()
        finally:
            conn.close()

        aliases = _list_enrolled_aliases(home_dir)
        assert aliases == []

    def test_busy_lock_returns_empty(self, home_with_key, monkeypatch: pytest.MonkeyPatch) -> None:
        """When another process holds an exclusive lock on the DB, SQLite
        raises SQLITE_BUSY which aiosqlite surfaces as OperationalError
        (subclass of aiosqlite.Error). The narrowed handler must catch it
        and return [] — concurrent CLI commands (wrap + doctor) must not
        crash each other."""
        import aiosqlite

        def _busy(*_args, **_kwargs):
            raise aiosqlite.OperationalError("database is locked")

        monkeypatch.setattr(aiosqlite, "connect", _busy)
        aliases = _list_enrolled_aliases(home_with_key)
        assert aliases == []

    def test_permission_denied_returns_empty(self, home_with_key) -> None:
        """DB file readable to the user at exists()-time but unreadable
        at connect()-time (chmod 000, ownership flip, mount remount)
        surfaces as PermissionError (subclass of OSError). Must be caught
        by the narrowed handler."""
        original_mode = home_with_key.db_path.stat().st_mode
        home_with_key.db_path.chmod(0o000)
        try:
            aliases = _list_enrolled_aliases(home_with_key)
            assert aliases == []
        finally:
            home_with_key.db_path.chmod(original_mode)

    def test_large_alias_set_does_not_hang(self, home_with_key, tmp_path: Path) -> None:
        """A DB with 10k enrolled aliases must complete the pre-flight
        check quickly — startup cannot become O(seconds) on legit-shaped
        but oversized data. Cap at 5s; on a healthy machine this runs
        well under 1s."""
        import sqlite3
        import time

        env_path = tmp_path / ".env"
        env_path.write_text("OPENAI_API_KEY=stub\n")
        conn = sqlite3.connect(str(home_with_key.db_path))
        try:
            shard_rows = [
                (f"bulk-{i:05d}", b"x", b"x", b"x", "openai", "sk-", "abc", None)
                for i in range(10_000)
            ]
            conn.executemany(
                "INSERT INTO shards "
                "(key_alias, shard_b_enc, commitment, nonce, provider, prefix, charset, base_url) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                shard_rows,
            )
            enroll_rows = [
                (f"bulk-{i:05d}", "OPENAI_API_KEY", str(env_path), "h") for i in range(10_000)
            ]
            conn.executemany(
                "INSERT INTO enrollments (key_alias, var_name, env_path, decoy_hash) "
                "VALUES (?, ?, ?, ?)",
                enroll_rows,
            )
            conn.commit()
        finally:
            conn.close()

        start = time.monotonic()
        aliases = _list_enrolled_aliases(home_with_key)
        elapsed = time.monotonic() - start
        assert len(aliases) >= 10_000
        assert elapsed < 5.0, f"alias listing took {elapsed:.2f}s — too slow for startup"


class TestWrapExitCode:
    """wrap mirrors child exit code."""

    @pytest.mark.integration
    @pytest.mark.timeout(30)
    def test_mirrors_child_exit_code(self, tmp_path: Path):
        """wrap should exit with the child's exit code."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.exit(42)"],
            start_new_session=True,
        )
        code = _run_child_and_wait(proc)
        assert code == 42

    @pytest.mark.integration
    @pytest.mark.timeout(30)
    def test_mirrors_zero_exit(self, tmp_path: Path):
        """wrap should exit 0 when child exits 0."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "pass"],
            start_new_session=True,
        )
        code = _run_child_and_wait(proc)
        assert code == 0


class TestWrapNoKeys:
    """wrap errors when no keys are enrolled."""

    def test_no_enrolled_keys_raises(self, tmp_path: Path):
        from worthless.cli.bootstrap import ensure_home

        home = ensure_home(tmp_path / ".worthless")
        aliases = _list_enrolled_aliases(home)
        assert aliases == []


class TestWrapLifecycleOrdering:
    """Pin the wrap startup contract: sidecar spawns BEFORE proxy, and the
    proxy is handed the sidecar's socket path via WORTHLESS_SIDECAR_SOCKET.

    Regression target: the wrap command shipped without sidecar spawn at all
    (worthless-r67t — proxy refused to bind because no IPC peer was running).
    The 36 stubbed tests in this file all passed because they don't assert
    ordering or env threading. This class is the canary that fires if anyone
    drops the spawn_sidecar call or forgets to thread the socket path.
    """

    def test_spawn_sidecar_runs_before_spawn_proxy(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """spawn_sidecar must be invoked strictly before spawn_proxy."""
        from pathlib import Path
        from unittest.mock import MagicMock as _MagicMock

        order: list[str] = []

        # Override the autouse fixture's stubs to record call order.
        fake_run_dir = Path("/tmp/wor-test-run-order")  # noqa: S108
        fake_socket = fake_run_dir / "sidecar.sock"
        fake_shares = _MagicMock(
            run_dir=fake_run_dir,
            share_a_path=fake_run_dir / "share_a.bin",
            share_b_path=fake_run_dir / "share_b.bin",
            shard_a=bytearray(32),
            shard_b=bytearray(32),
        )
        fake_handle = _MagicMock(
            socket_path=fake_socket,
            shares=fake_shares,
            allowed_uid=os.getuid(),
            proc=_MagicMock(pid=99999, poll=lambda: 0),
        )

        def _record_split(_key, _home):
            order.append("split_to_tmpfs")
            return fake_shares

        def _record_spawn_sidecar(_socket, _shares, **_kw):
            order.append("spawn_sidecar")
            return fake_handle

        def _record_spawn_proxy(**_kw):
            order.append("spawn_proxy")
            mock_proxy = MagicMock()
            mock_proxy.poll.return_value = None
            mock_proxy.wait.return_value = 0
            return (mock_proxy, 9999)

        monkeypatch.setattr("worthless.cli.commands.wrap.split_to_tmpfs", _record_split)
        monkeypatch.setattr("worthless.cli.commands.wrap.spawn_sidecar", _record_spawn_sidecar)
        monkeypatch.setattr("worthless.cli.commands.wrap.spawn_proxy", _record_spawn_proxy)
        # Health poll fails so we exit cleanly without running the child.
        monkeypatch.setattr("worthless.cli.commands.wrap.poll_health", lambda *_a, **_kw: False)

        runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )

        assert order[:3] == ["split_to_tmpfs", "spawn_sidecar", "spawn_proxy"], (
            f"wrong startup order: {order}. Expected split_to_tmpfs → spawn_sidecar → spawn_proxy."
        )

    def test_proxy_env_contains_sidecar_socket(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """spawn_proxy must receive WORTHLESS_SIDECAR_SOCKET pointing to the
        sidecar's actual socket path. Without this, the proxy can't connect
        to the sidecar's IPC peer and refuses to bind."""
        from pathlib import Path
        from unittest.mock import MagicMock as _MagicMock

        fake_socket = Path("/tmp/wor-test-run-env/sidecar.sock")  # noqa: S108
        fake_shares = _MagicMock(
            run_dir=fake_socket.parent,
            share_a_path=fake_socket.parent / "share_a.bin",
            share_b_path=fake_socket.parent / "share_b.bin",
            shard_a=bytearray(32),
            shard_b=bytearray(32),
        )
        fake_handle = _MagicMock(
            socket_path=fake_socket,
            shares=fake_shares,
            allowed_uid=os.getuid(),
            proc=_MagicMock(pid=99999, poll=lambda: 0),
        )

        captured_proxy_env: dict = {}

        def _capture_spawn_proxy(**kw):
            captured_proxy_env.update(kw.get("env", {}))
            mock_proxy = MagicMock()
            mock_proxy.poll.return_value = None
            mock_proxy.wait.return_value = 0
            return (mock_proxy, 9999)

        monkeypatch.setattr(
            "worthless.cli.commands.wrap.split_to_tmpfs",
            lambda _key, _home: fake_shares,
        )
        monkeypatch.setattr(
            "worthless.cli.commands.wrap.spawn_sidecar",
            lambda _socket, _shares, **_kw: fake_handle,
        )
        monkeypatch.setattr("worthless.cli.commands.wrap.spawn_proxy", _capture_spawn_proxy)
        monkeypatch.setattr("worthless.cli.commands.wrap.poll_health", lambda *_a, **_kw: False)

        runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )

        assert "WORTHLESS_SIDECAR_SOCKET" in captured_proxy_env, (
            f"proxy env must include WORTHLESS_SIDECAR_SOCKET, got keys: "
            f"{sorted(captured_proxy_env)}"
        )
        assert captured_proxy_env["WORTHLESS_SIDECAR_SOCKET"] == str(fake_socket), (
            f"socket path mismatch: env={captured_proxy_env['WORTHLESS_SIDECAR_SOCKET']!r}, "
            f"expected={str(fake_socket)!r}"
        )


class TestWrapLivenessPipe:
    """wrap creates liveness pipe for proxy death detection."""

    def test_liveness_pipe_created(self):
        read_fd, write_fd = create_liveness_pipe()
        try:
            os.fstat(read_fd)
            os.fstat(write_fd)
        finally:
            os.close(read_fd)
            os.close(write_fd)


class TestWrapSpawnProxyFailure:
    """wrap exits 1 and cleans up FDs when spawn_proxy fails."""

    def test_spawn_failure_exit_code(self, home_with_key, monkeypatch: pytest.MonkeyPatch) -> None:
        """When spawn_proxy raises and the port is free, wrap exits 1 with
        the generic 'failed to start proxy' message (branch 3 of
        ``_diagnose_proxy_failure``)."""

        def _fail(**_kw):
            raise RuntimeError("bind failed")

        monkeypatch.setattr(
            "worthless.cli.commands.wrap.spawn_proxy",
            _fail,
        )
        # Force the port-free branch: test machine state shouldn't matter.
        monkeypatch.setattr(
            "worthless.cli.commands.wrap._port_in_use",
            lambda *_a, **_kw: False,
        )
        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1
        assert "proxy" in result.output.lower()


class TestWrapHealthTimeout:
    """wrap cleans up proxy when poll_health times out."""

    def test_health_timeout_cleans_proxy(
        self,
        home_with_key,
        monkeypatch: pytest.MonkeyPatch,
        _stub_sidecar_lifecycle: dict,
    ) -> None:
        """When poll_health returns False, proxy is terminated and exit 1.

        v0.3.4 changed the timeout error message from a fixed
        "Proxy failed to become healthy" string to whatever
        ``_diagnose_proxy_failure`` returns (so the actionable
        ``worthless up`` hint fires when applicable). The semantic
        contract under test is still cleanup + non-zero exit; the
        specific wording is verified in
        ``test_poll_health_timeout_runs_diagnostic`` below.
        """
        mock_proxy = MagicMock()
        mock_proxy.poll.return_value = None
        mock_proxy.wait.return_value = 0

        monkeypatch.setattr(
            "worthless.cli.commands.wrap.spawn_proxy",
            lambda **_kw: (mock_proxy, 9999),
        )
        monkeypatch.setattr(
            "worthless.cli.commands.wrap.poll_health",
            lambda *_a, **_kw: False,
        )

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1
        # Cleanup invariant: terminate is called regardless of which
        # diagnostic message branch fires.
        mock_proxy.terminate.assert_called()
        # _cleanup_lifecycle must shut down the sidecar after the proxy.
        assert _stub_sidecar_lifecycle["shutdown_count"] == 1


class TestWrapChildSpawnFailure:
    """wrap cleans up proxy when child Popen fails."""

    def test_child_spawn_failure_cleans_proxy(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When child Popen raises, proxy is cleaned up and exit 1."""
        mock_proxy = MagicMock()
        mock_proxy.poll.return_value = None
        mock_proxy.wait.return_value = 0

        monkeypatch.setattr(
            "worthless.cli.commands.wrap.spawn_proxy",
            lambda **_kw: (mock_proxy, 9999),
        )
        monkeypatch.setattr(
            "worthless.cli.commands.wrap.poll_health",
            lambda *_a, **_kw: True,
        )

        def _fail_popen(*_a, **_kw):
            raise FileNotFoundError("No such file")

        monkeypatch.setattr("subprocess.Popen", _fail_popen)

        result = runner.invoke(
            app,
            ["wrap", "--", "nonexistent-binary"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1
        assert "child" in result.output.lower() or "start" in result.output.lower()
        mock_proxy.terminate.assert_called()


class TestCleanupProxy:
    """_cleanup_proxy handles already-dead and stuck processes."""

    def test_cleanup_already_dead(self) -> None:
        """No error when proxy is already dead."""
        mock = MagicMock()
        mock.poll.return_value = 0
        _cleanup_proxy(mock)
        mock.terminate.assert_not_called()

    def test_cleanup_timeout_kills(self) -> None:
        """Proxy that doesn't stop gets SIGKILL."""
        mock = MagicMock()
        mock.poll.return_value = None
        # First wait (terminate) times out, second wait (kill) succeeds
        mock.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="proxy", timeout=5),
            None,
        ]
        _cleanup_proxy(mock, timeout=0.01)
        mock.kill.assert_called()


class TestWrapProxyCrashMidSession:
    """wrap warns on stderr when proxy dies while child is still running."""

    def test_proxy_crash_warns_and_child_continues(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When proxy crashes mid-session, warning is emitted and exit code is 0."""
        proxy_waited = threading.Event()
        warning_written = threading.Event()
        captured_messages: list[str] = []

        # -- Mock proxy: .wait() returns immediately (simulating crash)
        mock_proxy = MagicMock()
        mock_proxy.pid = 99999

        def proxy_wait(**_kw):
            proxy_waited.set()
            return 0

        mock_proxy.wait.side_effect = proxy_wait
        mock_proxy.poll.return_value = 0  # already dead after crash
        mock_proxy.returncode = 0

        # -- Mock child: .poll() returns None (alive) then 0 (done)
        mock_child = MagicMock()
        mock_child.pid = 99998
        poll_values = iter([None, None, None, 0, 0, 0])
        mock_child.poll.side_effect = lambda: next(poll_values, 0)

        def child_wait(**_kw):
            # Let the watcher thread detect proxy crash first
            proxy_waited.wait(timeout=5)
            time.sleep(0.15)
            mock_child.returncode = 0
            return 0

        mock_child.wait.side_effect = child_wait
        mock_child.returncode = 0

        # Replace the sys module reference inside wrap so _watch_proxy
        # writes to our capturing stderr, not the real one (which CliRunner
        # may have replaced).
        import worthless.cli.commands.wrap as wrap_mod

        fake_sys = ModuleType("fake_sys")
        # Copy all attributes from real sys
        for attr in dir(sys):
            try:
                setattr(fake_sys, attr, getattr(sys, attr))
            except (AttributeError, TypeError):
                pass

        class _CapturingStderr:
            def write(self, msg: str) -> int:
                captured_messages.append(msg)
                if "proxy crashed" in msg:
                    warning_written.set()
                return len(msg)

            def flush(self) -> None:
                pass

        fake_sys.stderr = _CapturingStderr()
        monkeypatch.setattr(wrap_mod, "sys", fake_sys)

        # Patch spawn_proxy -> returns mock proxy
        monkeypatch.setattr(
            wrap_mod,
            "spawn_proxy",
            lambda **_kw: (mock_proxy, 9999),
        )
        # Patch poll_health -> healthy
        monkeypatch.setattr(
            wrap_mod,
            "poll_health",
            lambda *_a, **_kw: True,
        )
        # Patch forward_signals -> no-op (can't killpg mock PIDs)
        monkeypatch.setattr(
            wrap_mod,
            "forward_signals",
            lambda **_kw: None,
        )
        # Patch subprocess.Popen -> returns mock child
        monkeypatch.setattr("subprocess.Popen", lambda *_a, **_kw: mock_child)

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        # Wait for watcher thread to write the warning
        assert warning_written.wait(timeout=5), "Watcher thread did not emit warning"

        assert result.exit_code == 0
        combined = "".join(captured_messages)
        assert "proxy crashed mid-session" in combined


class TestWrapBootstrapFailure:
    """Error branches for wrap bootstrap failures."""

    def test_wrap_get_home_failure_exits_clean(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """OSError in get_home -> exit_code=1."""

        def _boom():
            raise OSError("permission denied")

        monkeypatch.setattr(
            "worthless.cli.commands.wrap.get_home",
            _boom,
        )

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(tmp_path / "nonexistent")},
        )
        assert result.exit_code == 1

    def test_wrap_liveness_pipe_failure_exits_clean(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """OSError in create_liveness_pipe -> exit_code=1."""

        def _boom():
            raise OSError("too many files")

        monkeypatch.setattr(
            "worthless.cli.commands.wrap.create_liveness_pipe",
            _boom,
        )

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1


class TestWrapNoEnrolledKeysError:
    """wrap exits 1 when no keys are enrolled (empty providers list)."""

    def test_no_keys_enrolled_error_message(
        self, home_dir, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """wrap with no enrolled keys prints KEY_NOT_FOUND error."""
        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code == 1
        assert "WRTLS-102" in result.output


class TestCleanupProxyWithWriteFd:
    """_cleanup_proxy closes write_fd when provided."""

    def test_cleanup_closes_write_fd(self) -> None:
        """_cleanup_proxy closes write_fd before terminating proxy."""
        r_fd, w_fd = os.pipe()
        mock = MagicMock()
        mock.poll.return_value = 0  # already dead

        _cleanup_proxy(mock, write_fd=w_fd)

        # write_fd should be closed
        with pytest.raises(OSError):
            os.fstat(w_fd)

        # read_fd still valid, clean up
        os.close(r_fd)

    def test_cleanup_write_fd_already_closed(self) -> None:
        """_cleanup_proxy doesn't error if write_fd is already closed."""
        r_fd, w_fd = os.pipe()
        os.close(w_fd)

        mock = MagicMock()
        mock.poll.return_value = 0

        # Should not raise
        _cleanup_proxy(mock, write_fd=w_fd)
        os.close(r_fd)

    def test_cleanup_live_proxy_with_write_fd(self) -> None:
        """_cleanup_proxy closes write_fd then terminates live proxy."""
        r_fd, w_fd = os.pipe()

        mock = MagicMock()
        mock.poll.return_value = None  # proxy still alive
        mock.wait.return_value = 0

        _cleanup_proxy(mock, write_fd=w_fd, timeout=0.01)

        # write_fd closed
        with pytest.raises(OSError):
            os.fstat(w_fd)
        # proxy terminated
        mock.terminate.assert_called()
        os.close(r_fd)


class TestListEnrolledAliasesNoDB:
    """_list_enrolled_aliases returns [] when DB doesn't exist."""

    def test_no_db_returns_empty(self, tmp_path: Path) -> None:
        from worthless.cli.bootstrap import WorthlessHome

        home = WorthlessHome(base_dir=tmp_path / ".worthless")
        aliases = _list_enrolled_aliases(home)
        assert aliases == []


class TestWrapExceptionHandlers:
    """Cover WorthlessError and generic Exception handlers in wrap."""

    def test_worthless_error_in_wrap_exits_clean(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """WorthlessError raised inside wrap -> exit_code=1 with WRTLS."""
        from worthless.cli.errors import ErrorCode, WorthlessError

        def _boom():
            raise WorthlessError(ErrorCode.UNKNOWN, "test error")

        monkeypatch.setattr("worthless.cli.commands.wrap.get_home", _boom)

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
        )
        assert result.exit_code == 1
        assert "WRTLS" in result.output

    def test_generic_exception_in_wrap_exits_clean(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Generic Exception raised inside wrap -> exit_code=1 with WRTLS-199."""

        def _boom():
            raise ValueError("unexpected")

        monkeypatch.setattr("worthless.cli.commands.wrap.get_home", _boom)

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
        )
        assert result.exit_code == 1
        # Generic exceptions are wrapped in WRTLS-199 (UNKNOWN)
        assert "WRTLS-199" in result.output


# ------------------------------------------------------------------
# WOR-73: CliRunner tests for `wrap` command
# ------------------------------------------------------------------


class TestWrapSetsEnvAndRunsCommand:
    """WOR-73: wrap sets env vars and runs child command via CliRunner."""

    def test_wrap_sets_env_and_runs_command(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CliRunner invokes `wrap`, confirms env vars set and subprocess called."""
        mock_proxy = MagicMock()
        mock_proxy.pid = 55555
        mock_proxy.poll.return_value = None
        mock_proxy.wait.return_value = 0

        mock_child = MagicMock()
        mock_child.pid = 55556
        mock_child.poll.return_value = 0
        mock_child.returncode = 0
        mock_child.wait.return_value = 0

        captured_env: dict[str, str] = {}

        monkeypatch.setattr(
            "worthless.cli.commands.wrap.spawn_proxy",
            lambda **_kw: (mock_proxy, 9999),
        )
        monkeypatch.setattr(
            "worthless.cli.commands.wrap.poll_health",
            lambda *_a, **_kw: True,
        )
        monkeypatch.setattr(
            "worthless.cli.commands.wrap.forward_signals",
            lambda **_kw: None,
        )

        def _capture_popen(*args, **kwargs):
            env = kwargs.get("env", {})
            captured_env.update(env)
            return mock_child

        monkeypatch.setattr("subprocess.Popen", _capture_popen)

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 0, f"wrap failed: {result.output}"

        # PR #251 restores injection: wrap injects OPENAI_BASE_URL for each
        # enrolled provider when the var is absent from the parent env.
        # home_with_key enrolls alias 'openai-a1b2c3d4' (protocol 'openai');
        # spawn_proxy mock returns port 9999 → expect the alias URL.
        assert captured_env.get("OPENAI_BASE_URL") == "http://127.0.0.1:9999/openai-a1b2c3d4/v1", (
            f"wrap did not inject OPENAI_BASE_URL: {captured_env.get('OPENAI_BASE_URL')!r}"
        )


# ------------------------------------------------------------------
# worthless-j3y: Daemon + wrap port coexistence
# ------------------------------------------------------------------


class TestWrapDaemonCoexistence:
    """v0.3.4 contract: wrap binds the same port lock wrote to .env (not 0).

    Pre-v0.3.4 wrap used port=0 (OS-random) on the theory that wrap should
    co-exist with `worthless up`. But wrap stopped injecting *_BASE_URL
    into the child env (8rqs), so the only port the child can see is the
    one in .env — which is whatever lock wrote (default 8787 or
    WORTHLESS_PORT). Random-port wrap was unreachable. v0.3.4 binds the
    same port; if it's already in use (e.g. up is running), wrap errors
    cleanly instead of silently spawning unreachable proxies.
    """

    def test_wrap_binds_resolved_port_matching_lock(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """wrap passes _resolve_port(None) to spawn_proxy — same value lock
        writes to .env so child .env URL → wrap proxy."""
        captured_kwargs: dict = {}

        def _capture_spawn(**kw):
            captured_kwargs.update(kw)
            mock_proxy = MagicMock()
            mock_proxy.pid = 77777
            mock_proxy.poll.return_value = None
            mock_proxy.wait.return_value = 0
            return (mock_proxy, kw["port"])

        mock_child = MagicMock()
        mock_child.pid = 77778
        mock_child.poll.return_value = 0
        mock_child.returncode = 0
        mock_child.wait.return_value = 0

        monkeypatch.setattr("worthless.cli.commands.wrap.spawn_proxy", _capture_spawn)
        monkeypatch.setattr("worthless.cli.commands.wrap.poll_health", lambda *_a, **_kw: True)
        monkeypatch.setattr("worthless.cli.commands.wrap.forward_signals", lambda **_kw: None)
        monkeypatch.setattr("subprocess.Popen", lambda *_a, **_kw: mock_child)

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir), "WORTHLESS_PORT": "8787"},
        )
        assert result.exit_code == 0, f"wrap failed: {result.output}"
        assert captured_kwargs.get("port") == 8787, (
            f"wrap should bind 8787 (matching lock); got {captured_kwargs.get('port')}"
        )


# ------------------------------------------------------------------
# Lifecycle: wrap after lock/unlock leaves no enrolled keys
# ------------------------------------------------------------------


class TestWrapAfterUnlockExitsWithError:
    """wrap refuses when all keys have been unlocked."""

    def test_lock_unlock_then_wrap_fails(self, home_dir, tmp_path: Path) -> None:
        """lock → unlock → wrap exits 1 with WRTLS-102."""
        from tests.helpers import fake_openai_key

        env_file = tmp_path / ".env"
        env_file.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
        home_env = {"WORTHLESS_HOME": str(home_dir.base_dir)}

        result = runner.invoke(app, ["lock", "--env", str(env_file)], env=home_env)
        assert result.exit_code == 0, result.output

        result = runner.invoke(app, ["unlock", "--env", str(env_file)], env=home_env)
        assert result.exit_code == 0, result.output
        assert _list_enrolled_aliases(home_dir) == []

        result = runner.invoke(app, ["wrap", "--", "echo", "hi"], env=home_env)
        assert result.exit_code == 1
        assert "WRTLS-102" in result.output

    def test_partial_unlock_leaves_wrap_functional(self, home_dir, tmp_path: Path) -> None:
        """Lock two keys, unlock one — wrap still has a provider."""
        from tests.helpers import fake_anthropic_key, fake_openai_key

        env_file = tmp_path / ".env"
        env_file.write_text(
            f"OPENAI_API_KEY={fake_openai_key()}\nANTHROPIC_API_KEY={fake_anthropic_key()}\n"
        )
        home_env = {"WORTHLESS_HOME": str(home_dir.base_dir)}

        result = runner.invoke(app, ["lock", "--env", str(env_file)], env=home_env)
        assert result.exit_code == 0, result.output

        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        alias = aliases[0]
        result = runner.invoke(
            app, ["unlock", "--alias", alias, "--env", str(env_file)], env=home_env
        )
        assert result.exit_code == 0, result.output
        assert len(_list_enrolled_aliases(home_dir)) == 1


# ------------------------------------------------------------------
# Failure-path tests (bead worthless-1k9)
# ------------------------------------------------------------------


class TestProxySpawnFailureFDCleanup:
    """spawn_proxy failure must close both liveness pipe FDs."""

    def test_spawn_failure_closes_both_fds(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        closed_fds: list[int] = []
        real_os_close = os.close
        real_r, real_w = os.pipe()

        monkeypatch.setattr(
            "worthless.cli.commands.wrap.create_liveness_pipe",
            lambda: (real_r, real_w),
        )
        monkeypatch.setattr(
            "worthless.cli.commands.wrap.os.close",
            lambda fd: (closed_fds.append(fd), real_os_close(fd)),
        )

        def _fail(**_kw):
            raise RuntimeError("bind failed")

        monkeypatch.setattr("worthless.cli.commands.wrap.spawn_proxy", _fail)

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1
        assert real_r in closed_fds
        assert real_w in closed_fds


class TestChildExitCodePropagatedViaWrap:
    """Child nonzero exit code flows through wrap → typer.Exit."""

    def test_child_exits_42(self, home_with_key, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_proxy = MagicMock()
        mock_proxy.pid = 77770
        mock_proxy.poll.return_value = None
        mock_proxy.wait.return_value = 0

        mock_child = MagicMock()
        mock_child.pid = 77771
        mock_child.poll.return_value = 42
        mock_child.returncode = 42
        mock_child.wait.return_value = 42

        monkeypatch.setattr(
            "worthless.cli.commands.wrap.spawn_proxy",
            lambda **_kw: (mock_proxy, 9999),
        )
        monkeypatch.setattr("worthless.cli.commands.wrap.poll_health", lambda *_a, **_kw: True)
        monkeypatch.setattr("worthless.cli.commands.wrap.forward_signals", lambda **_kw: None)
        monkeypatch.setattr("subprocess.Popen", lambda *_a, **_kw: mock_child)

        result = runner.invoke(
            app,
            ["wrap", "--", "false"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 42


class TestWrapKeyboardInterruptCleanup:
    """Ctrl+C during child.wait() exits 130 (128 + SIGINT)."""

    def test_keyboard_interrupt_exits_130(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_proxy = MagicMock()
        mock_proxy.pid = 66660
        mock_proxy.poll.return_value = None
        mock_proxy.wait.return_value = 0

        mock_child = MagicMock()
        mock_child.pid = 66661
        mock_child.poll.return_value = None
        mock_child.wait.side_effect = KeyboardInterrupt
        mock_child.returncode = None

        monkeypatch.setattr(
            "worthless.cli.commands.wrap.spawn_proxy",
            lambda **_kw: (mock_proxy, 9999),
        )
        monkeypatch.setattr("worthless.cli.commands.wrap.poll_health", lambda *_a, **_kw: True)
        monkeypatch.setattr("worthless.cli.commands.wrap.forward_signals", lambda **_kw: None)
        monkeypatch.setattr("subprocess.Popen", lambda *_a, **_kw: mock_child)

        result = runner.invoke(
            app,
            ["wrap", "--", "sleep", "999"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 130


class TestWrapPortDiscovery:
    """v0.3.4 (worthless-djoe): wrap must bind the port lock wrote to .env.

    The default-port-8787 invariant lives in
    :class:`TestWrapDaemonCoexistence` above; this class covers the
    distinct cases (env-var override, port-conflict diagnostics).
    """

    def test_wrap_honors_worthless_port_env(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WORTHLESS_PORT env var overrides the 8787 default — same priority
        chain lock and up use, so all three commands agree."""
        captured: dict[str, int] = {}

        mock_proxy = MagicMock()
        mock_proxy.pid = 66672
        mock_proxy.poll.return_value = None
        mock_proxy.wait.return_value = 0

        mock_child = MagicMock()
        mock_child.pid = 66673
        mock_child.wait.return_value = 0
        mock_child.returncode = 0

        def _capture_port(**kw):
            captured["port"] = kw["port"]
            return (mock_proxy, kw["port"])

        monkeypatch.setattr("worthless.cli.commands.wrap.spawn_proxy", _capture_port)
        monkeypatch.setattr("worthless.cli.commands.wrap.poll_health", lambda *_a, **_kw: True)
        monkeypatch.setattr("worthless.cli.commands.wrap.forward_signals", lambda **_kw: None)
        monkeypatch.setattr("subprocess.Popen", lambda *_a, **_kw: mock_child)

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={
                "WORTHLESS_HOME": str(home_with_key.base_dir),
                "WORTHLESS_PORT": "9876",
            },
        )
        assert result.exit_code == 0, result.output
        assert captured["port"] == 9876, (
            f"wrap should honor WORTHLESS_PORT=9876; got {captured.get('port')}"
        )


class TestWrapPortConflict:
    """v0.3.4: clean errors when wrap's target port is occupied."""

    def test_conflict_with_worthless_daemon_names_up(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the target port is already serving a worthless daemon,
        the pre-spawn check short-circuits with a message naming
        `worthless up` so the user knows which process to stop (or that
        they don't need wrap at all). spawn_proxy is never reached."""
        # Isolate from any host WORTHLESS_PORT so we can hard-assert 8787.
        monkeypatch.delenv("WORTHLESS_PORT", raising=False)

        def _spawn_should_not_be_called(**_kw):
            raise AssertionError("pre-check should short-circuit; spawn_proxy must not run")

        monkeypatch.setattr("worthless.cli.commands.wrap.spawn_proxy", _spawn_should_not_be_called)
        monkeypatch.setattr("worthless.cli.commands.wrap._port_in_use", lambda *_a, **_kw: True)
        monkeypatch.setattr(
            "worthless.cli.commands.wrap.check_proxy_health",
            lambda *_a, **_kw: {"healthy": True, "port": 8787, "mode": "up", "requests_proxied": 0},
        )

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code != 0
        assert "worthless up" in result.output, (
            f"error message should name `worthless up`:\n{result.output}"
        )

    def test_conflict_with_random_process_names_port(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the port is busy with a non-worthless process, the
        pre-spawn check short-circuits with a message naming the port
        and pointing at WORTHLESS_PORT as the escape hatch."""
        # Isolate from any host WORTHLESS_PORT so we can hard-assert 8787.
        monkeypatch.delenv("WORTHLESS_PORT", raising=False)

        def _spawn_should_not_be_called(**_kw):
            raise AssertionError("pre-check should short-circuit; spawn_proxy must not run")

        monkeypatch.setattr("worthless.cli.commands.wrap.spawn_proxy", _spawn_should_not_be_called)
        monkeypatch.setattr("worthless.cli.commands.wrap._port_in_use", lambda *_a, **_kw: True)
        monkeypatch.setattr(
            "worthless.cli.commands.wrap.check_proxy_health",
            lambda *_a, **_kw: {
                "healthy": False,
                "port": 8787,
                "mode": None,
                "requests_proxied": 0,
            },
        )

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code != 0
        assert "8787" in result.output and "WORTHLESS_PORT" in result.output, (
            f"error should name port + escape hatch:\n{result.output}"
        )

    def test_poll_health_timeout_runs_diagnostic(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The realistic conflict path (CodeRabbit MAJOR): subprocess.Popen
        succeeds even when uvicorn child can't bind, so spawn_proxy returns
        normally and the failure surfaces only when poll_health times out.
        Pre-fix this raised a generic 'Proxy failed to become healthy';
        post-fix the same diagnostic that names `worthless up` runs again
        on the timeout path."""
        monkeypatch.delenv("WORTHLESS_PORT", raising=False)

        mock_proxy = MagicMock()
        mock_proxy.pid = 88880
        mock_proxy.poll.return_value = None
        mock_proxy.wait.return_value = 0

        # _port_in_use changes between pre-check (False, port free) and
        # post-timeout diagnostic (True, conflict now visible). Models a
        # real TOCTOU race or a daemon that started during wrap startup.
        port_in_use_calls = {"n": 0}

        def _port_in_use_toggling(*_a, **_kw):
            port_in_use_calls["n"] += 1
            # First call = pre-check (must be False so we proceed);
            # subsequent calls = diagnostic (return True so the daemon
            # branch fires).
            return port_in_use_calls["n"] > 1

        monkeypatch.setattr(
            "worthless.cli.commands.wrap._port_in_use",
            _port_in_use_toggling,
        )
        monkeypatch.setattr(
            "worthless.cli.commands.wrap.spawn_proxy",
            lambda **kw: (mock_proxy, kw["port"]),
        )
        monkeypatch.setattr(
            "worthless.cli.commands.wrap.poll_health",
            lambda *_a, **_kw: False,
        )
        monkeypatch.setattr(
            "worthless.cli.commands.wrap.check_proxy_health",
            lambda *_a, **_kw: {
                "healthy": True,
                "port": 8787,
                "mode": "up",
                "requests_proxied": 0,
            },
        )

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )

        assert result.exit_code != 0
        # The whole point of the MAJOR fix: we get the actionable
        # `worthless up`-naming diagnostic, not a generic timeout
        # message that left the user staring at "failed to become
        # healthy" with no fix hint.
        assert "worthless up" in result.output, (
            f"poll_health-timeout path must run the same diagnostic that "
            f"names `worthless up`. Got:\n{result.output}"
        )
        mock_proxy.terminate.assert_called()

    def test_spawn_failure_with_free_port_falls_through(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Branch 3 of _diagnose_proxy_failure: when spawn_proxy fails for
        some reason OTHER than a port conflict (port is genuinely free),
        the error falls through to ``sanitize_exception`` with the generic
        'failed to start proxy' message — not one of the port-conflict
        strings, which would mislead the user."""

        def _fail_for_other_reason(**_kw):
            raise RuntimeError("uvicorn import failed (just an example)")

        monkeypatch.setattr("worthless.cli.commands.wrap.spawn_proxy", _fail_for_other_reason)
        # Port truly free — _port_in_use returns False, the daemon-check
        # branch is skipped, message generation falls through.
        monkeypatch.setattr("worthless.cli.commands.wrap._port_in_use", lambda *_a, **_kw: False)

        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code != 0
        # Must NOT name port-conflict messaging, since the port is free.
        assert "worthless up" not in result.output, (
            f"port is free → error should NOT mention `worthless up`:\n{result.output}"
        )
        assert "another process holds it" not in result.output, (
            f"port is free → error should NOT mention foreign-process conflict:\n{result.output}"
        )
        assert "proxy" in result.output.lower(), (
            f"error should still indicate proxy startup failure:\n{result.output}"
        )
