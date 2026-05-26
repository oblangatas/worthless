"""Tests for keyring integration in proxy config and CLI process transport.

WOR-188: Proxy config delegates to keystore.read_fernet_key() for the
full cascade. CLI process skips pipe transport when keyring is available.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

import pytest

from worthless.cli.process import build_proxy_env, fernet_transport
from worthless.proxy.config import ProxySettings, _read_fernet_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove all WORTHLESS_* env vars so each test starts clean."""
    for key in list(os.environ):
        if key.startswith("WORTHLESS_"):
            monkeypatch.delenv(key, raising=False)


@dataclass
class FakeHome:
    """Minimal stand-in for WorthlessHome used by build_proxy_env."""

    base_dir: Path = field(default_factory=lambda: Path("/fake"))
    db_path: Path = field(default_factory=lambda: Path("/fake/worthless.db"))
    fernet_key: bytes = b"test-fernet-key-value"
    shard_a_dir: Path = field(default_factory=lambda: Path("/fake/shard_a"))


# ===========================================================================
# _read_fernet_key (proxy/config.py) — delegates to keystore
# ===========================================================================


class TestReadFernetKeyCascade:
    """_read_fernet_key delegates to keystore.read_fernet_key.

    These tests use REAL filesystem state instead of patching
    ``worthless.proxy.config.read_fernet_key`` or its keystore counterpart.
    Patching module attributes on py3.10 + xdist + pytest-rerunfailures
    proved deterministically flaky on CI (PR #112): the patch state could
    leak across reruns and produce a Mock that raised ``WorthlessError``
    when the test expected a returned value. Real filesystem state has no
    such cross-test pollution surface — ``HOME=tmp_path`` plus a real
    ``fernet.key`` file is bulletproof.

    The session-wide ``conftest.py`` sets keyring to the null backend
    (rejected by ``keyring_available()``), so the cascade always reaches
    the file fallback in this suite.
    """

    def test_returns_key_from_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "env-key-value")
        result = _read_fernet_key()
        assert result == bytearray(b"env-key-value")

    def test_returns_key_from_keyring(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Cascade reads a real ``$HOME/.worthless/fernet.key`` file.

        Despite the class name (kept for back-compat with WOR-188), the
        keyring backend is disabled session-wide; the cascade therefore
        falls through env -> keyring (skipped) -> file. We exercise the
        FILE branch with a real on-disk key.
        """
        monkeypatch.setenv("HOME", str(tmp_path))
        worthless_dir = tmp_path / ".worthless"
        worthless_dir.mkdir()
        (worthless_dir / "fernet.key").write_bytes(b"keyring-key")
        result = _read_fernet_key()
        assert result == bytearray(b"keyring-key")

    def test_returns_empty_when_nothing_found(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Empty HOME, no env var, null keyring → cascade raises → empty."""
        monkeypatch.setenv("HOME", str(tmp_path))
        # No file, no env, no keyring → keystore raises KEY_NOT_FOUND →
        # ``_read_fernet_key()`` catches and returns ``bytearray()``.
        result = _read_fernet_key()
        assert result == bytearray()


# ===========================================================================
# ProxySettings integration
# ===========================================================================


class TestProxySettingsKeyring:
    """Inject the Fernet reader via the class-level ``_fernet_reader`` hook.

    The previous approach — ``with patch("worthless.proxy.config.read_fernet_key", ...)``
    — was deterministically flaky on py3.10.20 ubuntu under
    ``--dist loadscope`` + ``--reruns 1``: the patch state could leak
    across reruns and produce a Mock that raised ``WorthlessError`` when
    the test expected a returned value (see PR #112 / WOR-309 for the
    investigation trail).

    ``monkeypatch.setattr(ProxySettings, "_fernet_reader", staticmethod(fn))``
    binds against the class object directly. No module-attribute lookup,
    no Mock-state pollution surface — the test holds the function
    reference itself.
    """

    def test_settings_loads_from_keyring(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            ProxySettings,
            "_fernet_reader",
            staticmethod(lambda: bytearray(b"keyring-settings-key")),
        )
        s = ProxySettings()
        assert s.fernet_key == bytearray(b"keyring-settings-key")

    def test_settings_validate_passes_with_keyring(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            ProxySettings,
            "_fernet_reader",
            staticmethod(lambda: bytearray(b"valid-key")),
        )
        s = ProxySettings()
        s.validate()  # should not raise

    def test_settings_validate_does_not_fail_when_no_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WOR-309: missing Fernet key no longer fails ``validate()``.

        The proxy delegates decrypt to the sidecar, so the key is optional
        at proxy boot. Pre-WOR-309 this raised ``ValueError``; post-WOR-309
        the absence of a raise is the regression guard.
        """
        monkeypatch.setattr(
            ProxySettings,
            "_fernet_reader",
            staticmethod(lambda: bytearray()),
        )
        s = ProxySettings()
        assert s.fernet_key == bytearray()  # confirm no-key state
        s.validate()  # MUST NOT raise — the proxy never decrypts


# ===========================================================================
# build_proxy_env (cli/process.py)
# ===========================================================================


class TestBuildProxyEnvKeyring:
    def testkeyring_available_omits_fernet_key(self) -> None:
        home = FakeHome()
        with patch("worthless.cli.process.keyring_available", return_value=True):
            env = build_proxy_env(home)
        assert "WORTHLESS_FERNET_KEY" not in env
        assert env["WORTHLESS_DB_PATH"] == str(home.db_path)
        assert "WORTHLESS_SHARD_A_DIR" not in env
        assert "WORTHLESS_ALLOW_ALIAS_INFERENCE" not in env

    def test_keyring_unavailable_includes_fernet_key(self) -> None:
        home = FakeHome()
        with patch("worthless.cli.process.keyring_available", return_value=False):
            env = build_proxy_env(home)
        assert env["WORTHLESS_FERNET_KEY"] == "test-fernet-key-value"

    def testkeyring_available_still_has_all_other_keys(self) -> None:
        home = FakeHome()
        with patch("worthless.cli.process.keyring_available", return_value=True):
            env = build_proxy_env(home)
        assert "WORTHLESS_DB_PATH" in env
        assert "WORTHLESS_FERNET_KEY" not in env
        assert "WORTHLESS_SHARD_A_DIR" not in env
        assert "WORTHLESS_ALLOW_ALIAS_INFERENCE" not in env


# ===========================================================================
# fernet_transport (cli/process.py)
# ===========================================================================


class TestFernetTransportKeyring:
    def testkeyring_available_yields_none_tuple(self) -> None:
        env = {"WORTHLESS_FERNET_KEY": "some-key", "WORTHLESS_DB_PATH": "/tmp/db"}  # noqa: S108
        with patch("worthless.cli.process.keyring_available", return_value=True):
            with fernet_transport(env) as (fernet_key, fernet_fd, fernet_fds):
                assert fernet_key is None
                assert fernet_fd is None
                assert fernet_fds == []

    def test_keyring_unavailable_unix_creates_pipe(self) -> None:
        env = {"WORTHLESS_FERNET_KEY": "pipe-me"}
        with patch("worthless.cli.process.keyring_available", return_value=False):
            with patch("worthless.cli.process.IS_WINDOWS", False):
                with fernet_transport(env) as (fernet_key, fernet_fd, fernet_fds):
                    assert fernet_key is None
                    assert fernet_fd is not None
                    assert isinstance(fernet_fd, int)
                    assert fernet_fds == [fernet_fd]
                    data = os.read(fernet_fd, 4096)
                    os.close(fernet_fd)
                    assert data == b"pipe-me"

    def test_keyring_unavailable_env_key_popped(self) -> None:
        env = {"WORTHLESS_FERNET_KEY": "pop-me", "OTHER": "keep"}
        with patch("worthless.cli.process.keyring_available", return_value=False):
            with patch("worthless.cli.process.IS_WINDOWS", False):
                with fernet_transport(env) as (fernet_key, fernet_fd, fernet_fds):
                    if fernet_fd is not None:
                        os.read(fernet_fd, 4096)  # drain
        assert "WORTHLESS_FERNET_KEY" not in env
        assert env["OTHER"] == "keep"

    def testkeyring_available_no_fd_created(self) -> None:
        env = {"WORTHLESS_FERNET_KEY": "no-leak"}
        with patch("worthless.cli.process.keyring_available", return_value=True):
            with fernet_transport(env) as (fernet_key, fernet_fd, fernet_fds):
                assert fernet_fd is None
                assert fernet_fds == []
