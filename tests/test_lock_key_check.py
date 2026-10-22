"""worthless-saaz: ``lock`` never creates a database the background service can't read.

Reproduced live: ``WORTHLESS_FERNET_KEY=<another key> worthless lock`` sealed a
new project with a key neither ``fernet.key`` nor the keyring holds, printed
[OK], and the service then 401'd that project forever. With no ``fernet.key``
yet, the post-lock sync even wrote the shell's key to disk, killing every
older project instead (Brutus, saaz design review).

Never picks a side (WOR-464): lock refuses, and never writes the service's
key file from a shell variable.
"""

from __future__ import annotations

import hashlib
import sqlite3
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.fernet import Fernet
from typer.testing import CliRunner

from worthless.cli import key_check
from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands import lock as lock_mod
from worthless.cli.errors import ErrorCode, WorthlessError

from tests.helpers import fake_key

runner = CliRunner()


def _project(tmp_path: Path, name: str) -> Path:
    env = tmp_path / name / ".env"
    env.parent.mkdir()
    env.write_text(f"OPENAI_API_KEY={fake_key('sk-' + 'proj-', seed=name)}\n")
    return env


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rows(home: WorthlessHome) -> int:
    with sqlite3.connect(home.db_path) as db:
        return db.execute("SELECT COUNT(*) FROM shards").fetchone()[0]


def _lock(env: Path, home: WorthlessHome, **extra: str):
    return runner.invoke(
        app, ["lock", "--env", str(env)], env={"WORTHLESS_HOME": str(home.base_dir), **extra}
    )


class TestLockRefusesAKeyThatOpensNothing:
    def test_a_shell_key_that_opens_nothing_is_refused_and_nothing_changes(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        first = _lock(_project(tmp_path, "proj1"), home_dir)
        assert first.exit_code == 0, first.output

        second_env = _project(tmp_path, "proj2")
        before = (_sha(second_env), _rows(home_dir), _sha(home_dir.fernet_key_path))
        result = _lock(second_env, home_dir, WORTHLESS_FERNET_KEY=Fernet.generate_key().decode())

        said = " ".join(result.output.split())  # the console wraps long lines
        assert result.exit_code != 0
        assert "WORTHLESS_FERNET_KEY" in said
        assert "worthless doctor --explain fernet_drift" in said
        assert (_sha(second_env), _rows(home_dir), _sha(home_dir.fernet_key_path)) == before

    def test_the_same_key_locks_a_second_project_as_before(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        assert _lock(_project(tmp_path, "proj1"), home_dir).exit_code == 0
        result = _lock(_project(tmp_path, "proj2"), home_dir)
        assert result.exit_code == 0, result.output
        assert _rows(home_dir) == 2

    def test_enroll_is_guarded_too(self, home_dir: WorthlessHome, tmp_path: Path) -> None:
        assert _lock(_project(tmp_path, "proj1"), home_dir).exit_code == 0
        with patch.dict("os.environ", {"WORTHLESS_FERNET_KEY": Fernet.generate_key().decode()}):
            fresh = WorthlessHome(base_dir=home_dir.base_dir)  # as `enroll`'s get_home() would
            with pytest.raises(WorthlessError) as exc:
                lock_mod._enroll_single(
                    "openai-extra", fake_key("sk-" + "proj-", seed="x"), "openai", fresh
                )
        assert exc.value.code == ErrorCode.KEY_REFUSED
        assert _rows(home_dir) == 1


class TestTheGuardItself:
    def test_nothing_locked_yet_is_allowed(self, home_dir: WorthlessHome) -> None:
        key_check.refuse_a_key_that_opens_no_locked_key(home_dir)

    def test_a_key_that_still_opens_some_projects_may_keep_locking(
        self, home_dir: WorthlessHome
    ) -> None:
        """Only "opens none" is refused: a key that opens some is the right one,
        and the others were sealed elsewhere (doctor names them)."""
        with patch.object(key_check, "aliases_key_cannot_open", return_value=(2, ["x"])):
            key_check.refuse_a_key_that_opens_no_locked_key(home_dir)

    def test_docker_ipc_mode_is_skipped(
        self, home_dir: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WOR-465: the proxy uid must never load the key in IPC-only mode."""
        monkeypatch.setenv("WORTHLESS_FERNET_IPC_ONLY", "1")
        home_dir.db_path.write_bytes(b"")
        with patch.object(
            WorthlessHome, "fernet_key", property(lambda s: (_ for _ in ()).throw(AssertionError))
        ):
            key_check.refuse_a_key_that_opens_no_locked_key(home_dir)


class TestPostLockSync:
    def _sync(self, home: WorthlessHome, key: bytes, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.delenv("WORTHLESS_FERNET_IPC_ONLY", raising=False)
        console = MagicMock()
        with (
            patch.object(WorthlessHome, "fernet_key", property(lambda s: bytearray(key))),
            patch.object(lock_mod, "get_console", return_value=console),
        ):
            lock_mod._sync_fernet_after_lock(home)
        return console

    def test_a_shell_key_is_never_written_to_the_service_key_file(
        self, home_dir: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home_dir.fernet_key_path.unlink(missing_ok=True)
        shell_key = Fernet.generate_key()
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", shell_key.decode())
        console = self._sync(home_dir, shell_key, monkeypatch)
        assert not home_dir.fernet_key_path.exists()
        (message,) = console.print_warning.call_args.args
        assert "WORTHLESS_FERNET_KEY" in message

    def test_a_disagreeing_file_is_said_out_loud_not_only_in_a_debug_log(
        self, home_dir: WorthlessHome, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("WORTHLESS_FERNET_KEY", raising=False)
        before = _sha(home_dir.fernet_key_path)
        console = self._sync(home_dir, Fernet.generate_key(), monkeypatch)
        assert _sha(home_dir.fernet_key_path) == before  # WOR-464: never pick a side
        (message,) = console.print_warning.call_args.args
        assert "background service" in message
        assert "worthless doctor --explain fernet_drift" in message
