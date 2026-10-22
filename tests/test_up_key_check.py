"""worthless-saaz: ``worthless up`` won't serve with a key that can't open your locked keys.

Reproduced live: restore ``~/.worthless`` from a backup (or lock with
``WORTHLESS_FERNET_KEY`` set to another key) and the background service reads
a ``fernet.key`` that opens none — or only some — of the locked keys. Before
this, ``/healthz`` said 200 while every request got a silent 401.

Decision (option A): none open → refuse (a service waits quietly instead of
exiting, or launchd/systemd would restart it every 5 s forever); some open →
start and say which can't be used. The databases here are real, sealed with
real Fernet keys, so "stale" and "mixed" are genuine, not mocked.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.fernet import Fernet

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli import key_check
from worthless.cli.commands import up as up_mod
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.storage.repository import ShardRepository, StoredShard
from worthless.storage.shard_reader import ShardReader

K1 = Fernet.generate_key()
K2 = Fernet.generate_key()


def _seal(db: Path, key: bytes, *aliases: str) -> None:
    async def go() -> None:
        repo = ShardRepository(str(db), key)
        try:
            await repo.initialize()
            for alias in aliases:
                shard = StoredShard(
                    shard_b=bytearray(b"b" * 32),
                    commitment=bytearray(b"c" * 32),
                    nonce=bytearray(b"n" * 32),
                    provider="openai",
                )
                await repo.store_enrolled(
                    alias, shard, var_name="OPENAI_API_KEY", prefix="sk-", charset="x"
                )
        finally:
            repo.close()

    asyncio.run(go())


@pytest.fixture
def home(tmp_path: Path) -> WorthlessHome:
    base = tmp_path / ".worthless"
    base.mkdir()
    return WorthlessHome(base_dir=base)


class TestWhichKeysOpen:
    def test_reader_lists_every_enrolled_alias(self, home: WorthlessHome) -> None:
        _seal(home.db_path, K1, "work", "side")
        assert sorted(asyncio.run(ShardReader(home.db_path).list_enrolled_aliases())) == [
            "side",
            "work",
        ]

    def test_an_orphan_row_never_counts(self, home: WorthlessHome) -> None:
        """A crash between the shard and enrollment writes leaves a row nothing
        can use. It must not block `up` or `lock` (doctor reports orphans)."""
        _seal(home.db_path, K1, "work")
        with sqlite3.connect(home.db_path) as db:
            db.execute(
                "INSERT INTO shards (key_alias, shard_b_enc, commitment, nonce, provider) "
                "VALUES ('orphan', x'62', x'63', x'6e', 'openai')"
            )
        assert asyncio.run(key_check.aliases_key_cannot_open(home.db_path, bytearray(K1))) == (
            1,
            [],
        )

    @pytest.mark.parametrize(
        ("key", "dead"), [(K1, []), (K2, ["side", "work"])], ids=["right-key", "stale-key"]
    )
    def test_reports_the_aliases_this_key_cannot_open(
        self, home: WorthlessHome, key: bytes, dead: list[str]
    ) -> None:
        _seal(home.db_path, K1, "work", "side")
        total, cannot = asyncio.run(key_check.aliases_key_cannot_open(home.db_path, bytearray(key)))
        assert (total, sorted(cannot)) == (2, dead)

    def test_a_mixed_database_names_only_the_broken_alias(self, home: WorthlessHome) -> None:
        """`lock` with WORTHLESS_FERNET_KEY=<other> sealed one project with another key."""
        _seal(home.db_path, K1, "work")
        _seal(home.db_path, K2, "side")
        assert asyncio.run(key_check.aliases_key_cannot_open(home.db_path, bytearray(K1))) == (
            2,
            ["side"],
        )


def _check(home: WorthlessHome, key: bytes, *, managed: bool) -> MagicMock:
    console = MagicMock()
    with patch.object(up_mod, "is_service_managed", return_value=managed):
        up_mod._refuse_unless_key_opens_locked_keys(home, bytearray(key), console)
    return console


class TestWhatUpDoes:
    def test_the_right_key_starts_silently(self, home: WorthlessHome) -> None:
        _seal(home.db_path, K1, "work")
        console = _check(home, K1, managed=False)
        console.print_warning.assert_not_called()
        console.print_error.assert_not_called()

    def test_you_running_up_with_a_stale_key_are_stopped_with_the_fix(
        self, home: WorthlessHome
    ) -> None:
        _seal(home.db_path, K1, "work")
        with pytest.raises(WorthlessError) as exc:
            _check(home, K2, managed=False)
        assert exc.value.code == ErrorCode.KEY_REFUSED
        assert "worthless doctor --explain fernet_drift" in str(exc.value)

    def test_the_message_never_contains_key_material(self, home: WorthlessHome) -> None:
        _seal(home.db_path, K1, "work")
        with pytest.raises(WorthlessError) as exc:
            _check(home, K2, managed=False)
        for key in (K1, K2):
            assert key.decode() not in str(exc.value)
            assert key.decode()[:8] not in str(exc.value)

    def test_a_service_logs_once_then_waits_instead_of_restart_looping(
        self, home: WorthlessHome
    ) -> None:
        """launchd KeepAlive / systemd Restart=on-failure would relaunch an exit every 5 s."""
        _seal(home.db_path, K1, "work")

        class _Stopped(Exception):
            pass

        with (
            patch.object(up_mod.time, "sleep", side_effect=[None, None, _Stopped()]) as sleep,
            pytest.raises(_Stopped),
        ):
            console = MagicMock()
            with patch.object(up_mod, "is_service_managed", return_value=True):
                up_mod._refuse_unless_key_opens_locked_keys(home, bytearray(K2), console)
        assert console.print_error.call_count == 1
        assert sleep.call_count == 3

    def test_some_keys_open_starts_and_names_the_broken_one(self, home: WorthlessHome) -> None:
        _seal(home.db_path, K1, "work")
        _seal(home.db_path, K2, "side")
        console = _check(home, K1, managed=True)
        console.print_error.assert_not_called()
        (message,) = console.print_warning.call_args.args
        assert "side" in message and "work" not in message
        assert "worthless doctor --explain fernet_drift" in message

    def test_nothing_locked_yet_starts(self, home: WorthlessHome) -> None:
        console = _check(home, K2, managed=False)
        console.print_error.assert_not_called()

    def test_docker_ipc_mode_never_reads_the_database(
        self, home: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WOR-465: under IPC-only the sidecar owns the key; this process must not check it."""
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        _seal(home.db_path, K1, "work")
        with patch.object(key_check, "ShardReader", side_effect=AssertionError("read the db")):
            _check(home, K2, managed=False)


class TestWiredIntoStart:
    def test_a_refused_key_never_reaches_the_sidecar_and_is_wiped(
        self, home: WorthlessHome
    ) -> None:
        buf = bytearray(K2)
        refusal = WorthlessError(ErrorCode.KEY_REFUSED, "stale")
        with (
            patch.object(WorthlessHome, "fernet_key", property(lambda self: buf)),
            patch.object(up_mod, "_refuse_unless_key_opens_locked_keys", side_effect=refusal),
            patch.object(up_mod, "split_to_tmpfs") as split,
            pytest.raises(WorthlessError),
        ):
            up_mod._start_foreground_locked(
                home=home,
                proxy_env={},
                port=8787,
                pid_file=home.base_dir / "proxy.pid",
                console=MagicMock(),
            )
        split.assert_not_called()
        assert buf == bytearray(len(K2))


class TestHealthProbePicksAKeyThatOpens:
    def test_probe_skips_an_alias_the_key_cannot_open(self, home: WorthlessHome) -> None:
        """Otherwise a mixed DB whose first alias is broken makes a healthy
        sidecar look stale, and `up` keeps reclaiming it."""
        _seal(home.db_path, K2, "aaa-broken")
        _seal(home.db_path, K1, "zzz-works")
        with patch("worthless.cli.keystore.read_fernet_key", return_value=bytearray(K1)):
            probe = asyncio.run(up_mod._sidecar_open_probe_material(home))
        assert probe is not None
        assert probe[1] == b"zzz-works"
