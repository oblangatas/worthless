"""worthless-e4j4: one `worthless doctor` = one keychain read, in both modes.

HF2 contract (one keychain read per command, so at most one macOS Keychain
prompt). The fernet_drift check read the keychain itself, on top of the read
that loads the key, so every doctor run read it twice.

An in-memory keyring stands in for the OS keychain: the real one is never
touched, and every get_password the CLI makes is counted at the boundary.
"""

from __future__ import annotations

import json
from pathlib import Path

import keyring
import keyring.backend
import pytest
from cryptography.fernet import Fernet
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.keystore import _SERVICE, _keyring_username


class _CountingKeyring(keyring.backend.KeyringBackend):
    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self.store: dict[tuple[str, str], str] = {}
        self.reads: list[tuple[str, str]] = []

    def get_password(self, service: str, username: str) -> str | None:
        self.reads.append((service, username))
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.store.pop((service, username), None)


@pytest.fixture
def counting_keyring(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("WORTHLESS_KEYRING_BACKEND", raising=False)
    previous = keyring.get_keyring()
    backend = _CountingKeyring()
    keyring.set_keyring(backend)
    try:
        yield backend
    finally:
        keyring.set_keyring(previous)


@pytest.mark.parametrize("with_file", [False, True], ids=["keychain-only", "keychain-and-file"])
@pytest.mark.parametrize("args", [["doctor"], ["doctor", "--json"]], ids=["plain", "json"])
def test_doctor_reads_the_keychain_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    counting_keyring: _CountingKeyring,
    args: list[str],
    with_file: bool,
) -> None:
    home = tmp_path / ".worthless"
    env = {"WORTHLESS_HOME": str(home), "HOME": str(tmp_path)}
    for var in ("WORTHLESS_FERNET_KEY", "WORTHLESS_FERNET_KEY_PATH", "WORTHLESS_SERVICE_MANAGED"):
        monkeypatch.delenv(var, raising=False)
    home.mkdir(mode=0o700)
    key = Fernet.generate_key()
    counting_keyring.set_password(_SERVICE, _keyring_username(home), key.decode())
    if with_file:
        (home / "fernet.key").write_bytes(key)
        (home / "fernet.key").chmod(0o600)
    first = CliRunner().invoke(app, ["status"], env=env)
    assert first.exit_code == 0, first.output
    counting_keyring.reads.clear()

    result = CliRunner().invoke(app, args, env=env)

    assert result.exit_code in (0, 1), result.output
    assert len(counting_keyring.reads) == 1, (
        f"`worthless {' '.join(args)}` read the keychain {len(counting_keyring.reads)} "
        "times; each read can be a macOS Keychain prompt (HF2: one per command)"
    )
    # Reading once must not blind the drift check: same key in both places is
    # reported as no drift, not as "only one source".
    if with_file and "--json" in args:
        drift = next(
            c for c in json.loads(result.output)["checks"] if c["check_id"] == "fernet_drift"
        )
        assert "matches file" in drift["summary"], drift
