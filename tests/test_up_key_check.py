"""worthless-saaz: ``worthless up`` won't serve with a key that can't open your locked keys.

Reproduced live: restore ``~/.worthless`` from a backup (or lock with
``WORTHLESS_FERNET_KEY`` set to another key) and the background service reads
a ``fernet.key`` that opens none — or only some — of the locked keys. Before
this, ``/healthz`` said 200 while every request got a silent 401.

Decision (option A): none open → refuse; some open → start and say which
can't be used. A refused *service* waits instead of exiting (launchd/systemd
would restart it every 5 s forever), holds no key while it waits, and exits
for a clean restart once ``fernet.key`` is fixed. The databases here are real,
sealed with real Fernet keys, so "stale" and "mixed" are genuine, not mocked.
"""

from __future__ import annotations

import asyncio
import contextlib
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from cryptography.fernet import Fernet

from worthless.cli import key_check
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands import up as up_mod
from worthless.cli.errors import ErrorCode, WorthlessError
from worthless.storage.shard_reader import ShardReader

from tests.helpers import seal_enrolled

K1 = Fernet.generate_key()
K2 = Fernet.generate_key()


@pytest.fixture
def home(tmp_path: Path) -> WorthlessHome:
    """A bare home with no ``fernet.key``: each test seals with the key it means."""
    base = tmp_path / ".worthless"
    base.mkdir()
    return WorthlessHome(base_dir=base)


def _write_key_file(home: WorthlessHome, key: bytes) -> None:
    home.fernet_key_path.write_bytes(key)
    home.fernet_key_path.chmod(0o600)


class TestWhichKeysOpen:
    def test_reader_lists_every_enrolled_alias(self, home: WorthlessHome) -> None:
        seal_enrolled(home.db_path, K1, "work", "side")
        aliases = asyncio.run(ShardReader(home.db_path).list_enrolled_aliases())
        assert sorted(aliases) == ["side", "work"]

    def test_an_orphan_row_never_counts(self, home: WorthlessHome) -> None:
        """A crash between the shard and enrollment writes leaves a row nothing
        can use. It must not block `up` or `lock` (doctor reports orphans)."""
        seal_enrolled(home.db_path, K1, "work")
        with sqlite3.connect(home.db_path) as db:
            db.execute(
                "INSERT INTO shards (key_alias, shard_b_enc, commitment, nonce, provider) "
                "VALUES ('orphan', x'62', x'63', x'6e', 'openai')"
            )
        assert key_check.aliases_key_cannot_open(home, K1) == (1, [])

    @pytest.mark.parametrize(
        ("key", "dead"), [(K1, []), (K2, ["side", "work"])], ids=["right-key", "stale-key"]
    )
    def test_reports_the_aliases_this_key_cannot_open(
        self, home: WorthlessHome, key: bytes, dead: list[str]
    ) -> None:
        seal_enrolled(home.db_path, K1, "work", "side")
        total, cannot = key_check.aliases_key_cannot_open(home, key)
        assert (total, sorted(cannot)) == (2, dead)

    def test_a_mixed_database_names_only_the_broken_alias(self, home: WorthlessHome) -> None:
        """`lock` with WORTHLESS_FERNET_KEY=<other> sealed one project with another key."""
        seal_enrolled(home.db_path, K1, "work")
        seal_enrolled(home.db_path, K2, "side")
        assert key_check.aliases_key_cannot_open(home, K1) == (2, ["side"])

    def test_no_database_and_docker_ipc_mode_check_nothing(
        self, home: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WOR-465: under IPC-only the sidecar owns the key; this process must not check it."""
        assert key_check.aliases_key_cannot_open(home, K2) == (0, [])
        seal_enrolled(home.db_path, K1, "work")
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        with patch.object(key_check, "ShardReader", side_effect=AssertionError("read the db")):
            assert key_check.aliases_key_cannot_open(home, K2) == (0, [])


def _check(home: WorthlessHome, key: bytes, *, managed: bool) -> tuple[bool, MagicMock]:
    console = MagicMock()
    with patch.object(up_mod, "is_service_managed", return_value=managed):
        wait = up_mod._refuse_unless_key_opens_locked_keys(home, bytearray(key), console)
    return wait, console


class TestWhatUpDoes:
    def test_the_right_key_starts_silently(self, home: WorthlessHome) -> None:
        seal_enrolled(home.db_path, K1, "work")
        wait, console = _check(home, K1, managed=True)
        assert wait is False
        console.print_warning.assert_not_called()
        console.print_error.assert_not_called()

    def test_you_running_up_with_a_stale_key_are_stopped_with_the_fix(
        self, home: WorthlessHome
    ) -> None:
        seal_enrolled(home.db_path, K1, "work")
        with pytest.raises(WorthlessError) as exc:
            _check(home, K2, managed=False)
        assert exc.value.code == ErrorCode.KEY_REFUSED
        assert "worthless doctor --explain fernet_drift" in str(exc.value)

    def test_the_message_never_contains_key_material(self, home: WorthlessHome) -> None:
        seal_enrolled(home.db_path, K1, "work")
        with pytest.raises(WorthlessError) as exc:
            _check(home, K2, managed=False)
        for key in (K1, K2):
            assert key.decode() not in str(exc.value)
            assert key.decode()[:8] not in str(exc.value)

    def test_a_refused_service_says_so_once_and_is_told_to_wait(self, home: WorthlessHome) -> None:
        """Exiting would make launchd (KeepAlive) / systemd (Restart=on-failure)
        relaunch it every 5 s and log this forever."""
        seal_enrolled(home.db_path, K1, "work")
        wait, console = _check(home, K2, managed=True)
        assert wait is True
        assert console.print_error.call_count == 1

    def test_some_keys_open_starts_and_names_the_broken_one(self, home: WorthlessHome) -> None:
        seal_enrolled(home.db_path, K1, "work")
        seal_enrolled(home.db_path, K2, "side")
        wait, console = _check(home, K1, managed=True)
        assert wait is False
        console.print_error.assert_not_called()
        (message,) = console.print_warning.call_args.args
        assert "side" in message and "work" not in message
        assert "worthless doctor --explain fernet_drift" in message

    def test_nothing_locked_yet_starts(self, home: WorthlessHome) -> None:
        wait, console = _check(home, K2, managed=False)
        assert wait is False
        console.print_error.assert_not_called()


class TestARefusedServiceWaits:
    """The wait holds no key, and heals: fix fernet.key and it restarts on its own."""

    def _wait(self, home: WorthlessHome, on_sleep: list) -> pytest.ExceptionInfo:
        calls = iter(on_sleep)

        def fake_sleep(_seconds: float) -> None:
            next(calls)()

        with (
            patch.object(up_mod.time, "sleep", side_effect=fake_sleep),
            pytest.raises(typer.Exit) as exc,
        ):
            up_mod._wait_for_a_key_that_opens(home)
        return exc

    def test_still_stale_keeps_waiting_then_a_fixed_key_restarts_it(
        self, home: WorthlessHome
    ) -> None:
        seal_enrolled(home.db_path, K1, "work")
        _write_key_file(home, K2)
        nothing = lambda: None  # noqa: E731
        exc = self._wait(home, [nothing, nothing, lambda: _write_key_file(home, K1)])
        # Non-zero: systemd's Restart=on-failure ignores a clean exit.
        assert exc.value.exit_code == up_mod._RESTART_FOR_NEW_KEY

    def test_a_deleted_key_file_restarts_it_too(self, home: WorthlessHome) -> None:
        """A fresh start takes the normal path (keyring) — the wait never prompts for it."""
        seal_enrolled(home.db_path, K1, "work")
        _write_key_file(home, K2)
        exc = self._wait(home, [lambda: home.fernet_key_path.unlink()])
        assert exc.value.exit_code == up_mod._RESTART_FOR_NEW_KEY

    def test_an_unreadable_key_file_keeps_waiting_not_restart_looping(
        self, home: WorthlessHome
    ) -> None:
        """A loose-mode file would be refused again on restart: exiting would loop."""
        seal_enrolled(home.db_path, K1, "work")
        _write_key_file(home, K1)
        home.fernet_key_path.chmod(0o644)

        class _Stopped(Exception):
            pass

        with (
            patch.object(up_mod.time, "sleep", side_effect=[None, None, _Stopped()]),
            pytest.raises(_Stopped),
        ):
            up_mod._wait_for_a_key_that_opens(home)


class TestWiredIntoStart:
    def _start(self, home: WorthlessHome, buf: bytearray, **patches) -> MagicMock:
        split = MagicMock()
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch.object(WorthlessHome, "fernet_key", property(lambda self: buf))
            )
            stack.enter_context(patch.object(up_mod, "split_to_tmpfs", split))
            for name, value in patches.items():
                stack.enter_context(patch.object(up_mod, name, value))
            up_mod._start_foreground_locked(
                home=home,
                proxy_env={},
                port=8787,
                pid_file=home.base_dir / "proxy.pid",
                console=MagicMock(),
            )
        return split

    def test_a_refused_key_never_reaches_the_sidecar_and_is_wiped(
        self, home: WorthlessHome
    ) -> None:
        buf = bytearray(K2)
        refusal = WorthlessError(ErrorCode.KEY_REFUSED, "stale")
        with pytest.raises(WorthlessError):
            self._start(
                home, buf, _refuse_unless_key_opens_locked_keys=MagicMock(side_effect=refusal)
            )
        assert buf == bytearray(len(K2))

    def test_the_key_is_wiped_before_a_service_starts_waiting(self, home: WorthlessHome) -> None:
        """SR-02: a parked service can wait for days; it must not hold the key."""
        buf = bytearray(K2)
        seen: list[bytes] = []
        split = self._start(
            home,
            buf,
            _refuse_unless_key_opens_locked_keys=MagicMock(return_value=True),
            _wait_for_a_key_that_opens=MagicMock(side_effect=lambda h: seen.append(bytes(buf))),
        )
        assert seen == [bytes(len(K2))]
        split.assert_not_called()


class TestHealthProbePicksAKeyThatOpens:
    def test_probe_skips_an_alias_the_key_cannot_open(self, home: WorthlessHome) -> None:
        """Otherwise a mixed DB whose first alias is broken makes a healthy
        sidecar look stale, and `up` keeps reclaiming it."""
        seal_enrolled(home.db_path, K2, "aaa-broken")
        seal_enrolled(home.db_path, K1, "zzz-works")
        with patch("worthless.cli.keystore.read_fernet_key", return_value=bytearray(K1)):
            probe = asyncio.run(up_mod._sidecar_open_probe_material(home))
        assert probe is not None and probe is not False
        assert probe[1] == b"zzz-works"

    def test_a_key_that_opens_nothing_never_reads_as_healthy(
        self, home: WorthlessHome, tmp_path: Path
    ) -> None:
        """WOR-749: falling back to a HELLO-only probe would call a sidecar
        holding the stale key healthy."""
        seal_enrolled(home.db_path, K1, "work")
        with patch("worthless.cli.keystore.read_fernet_key", return_value=bytearray(K2)):
            assert asyncio.run(up_mod._sidecar_open_probe_material(home)) is False
        with (
            patch.object(up_mod, "list_sidecar_sockets", return_value=[tmp_path / "s.sock"]),
            patch.object(up_mod, "probe_socket", side_effect=AssertionError("HELLO-only")),
            patch("worthless.cli.keystore.read_fernet_key", return_value=bytearray(K2)),
        ):
            assert up_mod._managed_sidecar_healthy(home) is False
