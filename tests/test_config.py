"""Tests for ProxySettings env loading and fernet fd fallback."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

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


# ---------------------------------------------------------------------------
# Tests: defaults
# ---------------------------------------------------------------------------


class TestDefaults:
    """ProxySettings should have sensible defaults when no env vars set."""

    def test_default_db_path(self) -> None:
        s = ProxySettings()
        assert s.db_path == str(Path.home() / ".worthless" / "worthless.db")

    def test_default_fernet_key_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Class-attr injection is bulletproof against the py3.10 xdist
        # patch-state race that bit PR #112 — see ``ProxySettings`` docstring.
        monkeypatch.setattr(ProxySettings, "_fernet_reader", staticmethod(lambda: bytearray()))
        s = ProxySettings()
        assert s.fernet_key == bytearray()

    def test_default_rate_limit_rps(self) -> None:
        s = ProxySettings()
        assert s.default_rate_limit_rps == 100.0

    def test_default_upstream_timeout(self) -> None:
        s = ProxySettings()
        assert s.upstream_timeout == 120.0

    def test_default_streaming_timeout(self) -> None:
        s = ProxySettings()
        assert s.streaming_timeout == 300.0

    def test_default_allow_insecure_false(self) -> None:
        s = ProxySettings()
        assert s.allow_insecure is False


# ---------------------------------------------------------------------------
# Tests: custom values from env
# ---------------------------------------------------------------------------


class TestCustomValues:
    """Env vars should override defaults."""

    def test_custom_db_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_DB_PATH", "/tmp/custom.db")  # noqa: S108
        s = ProxySettings()
        assert s.db_path == "/tmp/custom.db"  # noqa: S108

    def test_custom_rate_limit_rps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_RATE_LIMIT_RPS", "42.5")
        s = ProxySettings()
        assert s.default_rate_limit_rps == 42.5

    def test_custom_upstream_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_UPSTREAM_TIMEOUT", "60.0")
        s = ProxySettings()
        assert s.upstream_timeout == 60.0

    def test_custom_streaming_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_STREAMING_TIMEOUT", "600.0")
        s = ProxySettings()
        assert s.streaming_timeout == 600.0


# ---------------------------------------------------------------------------
# Tests: ALLOW_INSECURE truthy/falsy
# ---------------------------------------------------------------------------


class TestAllowInsecure:
    """ALLOW_INSECURE should accept 1/true/yes and reject everything else."""

    @pytest.mark.parametrize("val", ["1", "true", "yes", "True", "TRUE", "Yes", "YES"])
    def test_truthy_values(self, monkeypatch: pytest.MonkeyPatch, val: str) -> None:
        monkeypatch.setenv("WORTHLESS_ALLOW_INSECURE", val)
        s = ProxySettings()
        assert s.allow_insecure is True

    @pytest.mark.parametrize("val", ["0", "false", "no", "False", "NO", "", "maybe", "2"])
    def test_falsy_values(self, monkeypatch: pytest.MonkeyPatch, val: str) -> None:
        monkeypatch.setenv("WORTHLESS_ALLOW_INSECURE", val)
        s = ProxySettings()
        assert s.allow_insecure is False


# ---------------------------------------------------------------------------
# Tests: fernet key from env
# ---------------------------------------------------------------------------


class TestFernetKeyEnv:
    """Fernet key loading from WORTHLESS_FERNET_KEY env var."""

    def test_fernet_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "abc123secret")
        s = ProxySettings()
        assert s.fernet_key == bytearray(b"abc123secret")

    def test_fernet_env_empty_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Empty WORTHLESS_FERNET_KEY env behaves like no key set.

        Class-attr injection on ``ProxySettings._fernet_reader`` sidesteps
        the py3.10 xdist patch-state race that bit PR #112.
        """
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "")
        monkeypatch.setattr(ProxySettings, "_fernet_reader", staticmethod(lambda: bytearray()))
        s = ProxySettings()
        assert s.fernet_key == bytearray()


# ---------------------------------------------------------------------------
# Tests: fernet fd fallback
# ---------------------------------------------------------------------------


class TestFernetFdFallback:
    """Fernet key loading from inherited file descriptor."""

    def test_fernet_from_fd(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_FERNET_FD", "99")
        with (
            patch(
                "worthless.proxy.config.os.read",
                return_value=b"  fd-secret-key  \n",
            ) as mock_read,
            patch("worthless.proxy.config.os.close") as mock_close,
        ):
            key = _read_fernet_key()
        assert key == bytearray(b"fd-secret-key")
        mock_read.assert_called_once_with(99, 4096)
        mock_close.assert_called_once_with(99)

    def test_fernet_fd_invalid_number_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Non-integer fd falls back to env var."""
        monkeypatch.setenv("WORTHLESS_FERNET_FD", "not-a-number")
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "env-fallback")
        key = _read_fernet_key()
        assert key == bytearray(b"env-fallback")

    @pytest.mark.parametrize(
        "error",
        [
            OSError("Bad fd"),
            OSError(9, "Bad file descriptor"),
        ],
        ids=["generic-oserror", "closed-fd"],
    )
    def test_fernet_fd_os_error_falls_back(
        self, monkeypatch: pytest.MonkeyPatch, error: OSError
    ) -> None:
        """OSError on read (generic or closed fd) falls back to env var."""
        monkeypatch.setenv("WORTHLESS_FERNET_FD", "99")
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "env-fallback")
        with (
            patch("worthless.proxy.config.os.read", side_effect=error),
            patch("worthless.proxy.config.os.close"),
        ):
            key = _read_fernet_key()
        assert key == bytearray(b"env-fallback")

    def test_fernet_fd_closed_even_when_read_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """If os.read(fd) raises OSError, the fd must still be closed."""
        monkeypatch.setenv("WORTHLESS_FERNET_FD", "99")
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "env-fallback")
        with (
            patch("worthless.proxy.config.os.read", side_effect=OSError("read boom")),
            patch("worthless.proxy.config.os.close") as mock_close,
        ):
            key = _read_fernet_key()
        # Key should fall back to env
        assert key == bytearray(b"env-fallback")
        # fd must have been closed despite the read failure
        mock_close.assert_called_once_with(99)

    def test_fernet_fd_preferred_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When both fd and env are set, fd wins."""
        monkeypatch.setenv("WORTHLESS_FERNET_FD", "7")
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "env-value")
        with (
            patch("worthless.proxy.config.os.read", return_value=b"fd-value"),
            patch("worthless.proxy.config.os.close"),
        ):
            key = _read_fernet_key()
        assert key == bytearray(b"fd-value")


# ---------------------------------------------------------------------------
# Tests: validation
# ---------------------------------------------------------------------------


class TestValidation:
    """ProxySettings.validate() — post-WOR-309 contract.

    The proxy no longer holds the Fernet key; the sidecar does. ``validate()``
    therefore MUST NOT raise when the key is unavailable: the proxy boots
    fine and delegates decrypt over IPC. Asserting the absence of a raise
    is the new regression guard.
    """

    def test_missing_fernet_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """WOR-309: ``validate()`` ignores a missing Fernet key.

        Pre-WOR-309 this raised ``ValueError`` because the proxy needed the
        key to decrypt shard-B. Post-WOR-309 the sidecar holds the key and
        the proxy only reads ciphertext-at-rest, so a missing key is fine.
        """
        monkeypatch.setattr(ProxySettings, "_fernet_reader", staticmethod(lambda: bytearray()))
        s = ProxySettings()
        s.validate()  # MUST NOT raise — the proxy never decrypts

    def test_valid_fernet_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_FERNET_KEY", "valid-key")
        s = ProxySettings()
        s.validate()  # should not raise


# ---------------------------------------------------------------------------
# Tests: invalid / edge-case values
# ---------------------------------------------------------------------------


class TestInvalidValues:
    """Malformed env vars should raise during construction."""

    def test_invalid_float_rate_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_RATE_LIMIT_RPS", "not-a-number")
        with pytest.raises(ValueError):
            ProxySettings()

    def test_invalid_float_upstream_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_UPSTREAM_TIMEOUT", "abc")
        with pytest.raises(ValueError):
            ProxySettings()

    def test_empty_string_for_float(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_RATE_LIMIT_RPS", "")
        with pytest.raises(ValueError):
            ProxySettings()

    def test_negative_timeout_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Negative values are technically valid floats — no runtime guard."""
        monkeypatch.setenv("WORTHLESS_UPSTREAM_TIMEOUT", "-5.0")
        s = ProxySettings()
        assert s.upstream_timeout == -5.0
