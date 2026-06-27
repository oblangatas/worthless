"""Tests for the WORTHLESS_DEPLOY_MODE invariant table."""

from __future__ import annotations

import os

import pytest

from worthless.proxy.config import ConfigError, DeployMode, ProxySettings


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("WORTHLESS_") or key in {
            "RENDER",
            "FLY_APP_NAME",
            "KUBERNETES_SERVICE_HOST",
        }:
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("WORTHLESS_FERNET_KEY", "test-key")


class TestDeployModeParsing:
    def test_default_is_loopback(self) -> None:
        assert ProxySettings().deploy_mode is DeployMode.LOOPBACK

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("loopback", DeployMode.LOOPBACK),
            ("LOOPBACK", DeployMode.LOOPBACK),
            ("lan", DeployMode.LAN),
            ("public", DeployMode.PUBLIC),
            ("  public  ", DeployMode.PUBLIC),
        ],
    )
    def test_explicit_mode_parses(
        self, monkeypatch: pytest.MonkeyPatch, value: str, expected: DeployMode
    ) -> None:
        monkeypatch.setenv("WORTHLESS_DEPLOY_MODE", value)
        assert ProxySettings().deploy_mode is expected

    def test_unknown_mode_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_DEPLOY_MODE", "wide-open")
        with pytest.raises(ConfigError, match="WORTHLESS_DEPLOY_MODE"):
            ProxySettings()


class TestDefaultHost:
    def test_loopback_defaults_127(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_DEPLOY_MODE", "loopback")
        assert ProxySettings().host == "127.0.0.1"

    def test_public_defaults_anyiface(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_DEPLOY_MODE", "public")
        assert ProxySettings().host == "0.0.0.0"  # noqa: S104 — testing public-mode bind contract

    def test_lan_defaults_anyiface(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """LAN mode alone must bind 0.0.0.0 — no WORTHLESS_HOST needed.

        Regression guard: previously only PUBLIC triggered the all-ifaces default.
        Declaring LAN intent and silently binding loopback defeats the whole mode.
        """
        monkeypatch.setenv("WORTHLESS_DEPLOY_MODE", "lan")
        monkeypatch.delenv("WORTHLESS_HOST", raising=False)
        assert ProxySettings().host == "0.0.0.0"  # noqa: S104 — testing lan-mode bind contract

    def test_explicit_host_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WORTHLESS_DEPLOY_MODE", "lan")
        monkeypatch.setenv("WORTHLESS_HOST", "10.0.5.7")
        assert ProxySettings().host == "10.0.5.7"


class TestValidateInvariants:
    @pytest.mark.parametrize(
        "env,match",
        [
            # LOOPBACK: refuses non-127 host
            (
                {"WORTHLESS_DEPLOY_MODE": "loopback", "WORTHLESS_HOST": "0.0.0.0"},  # noqa: S104
                "loopback requires host=127.0.0.1",
            ),
            # LAN: refuses public-internet IP
            (
                {"WORTHLESS_DEPLOY_MODE": "lan", "WORTHLESS_HOST": "8.8.8.8"},
                "lan requires host in a private CIDR",
            ),
            # PUBLIC: refuses allow_insecure=true
            (
                {
                    "WORTHLESS_DEPLOY_MODE": "public",
                    "WORTHLESS_ALLOW_INSECURE": "true",
                    "WORTHLESS_TRUSTED_PROXIES": "10.0.0.0/8",
                },
                "WORTHLESS_ALLOW_INSECURE is FORBIDDEN",
            ),
            # PUBLIC: refuses missing trusted_proxies
            ({"WORTHLESS_DEPLOY_MODE": "public"}, "requires WORTHLESS_TRUSTED_PROXIES"),
            # PUBLIC: refuses unreplaced placeholder (would silently 401 every request)
            (
                {
                    "WORTHLESS_DEPLOY_MODE": "public",
                    "WORTHLESS_TRUSTED_PROXIES": "REPLACE_WITH_EDGE_CIDR",
                },
                "is not a valid CIDR",
            ),
        ],
    )
    def test_refuses(
        self, monkeypatch: pytest.MonkeyPatch, env: dict[str, str], match: str
    ) -> None:
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        s = ProxySettings()
        with pytest.raises(ConfigError, match=match):
            s.validate()

    @pytest.mark.parametrize(
        "env",
        [
            # LOOPBACK happy path
            {"WORTHLESS_DEPLOY_MODE": "loopback"},
            # LAN: 127 ok
            {"WORTHLESS_DEPLOY_MODE": "lan"},
            # LAN: private CIDR ok
            {"WORTHLESS_DEPLOY_MODE": "lan", "WORTHLESS_HOST": "10.5.1.4"},
            # LAN: 0.0.0.0 ok (docker compose)
            {"WORTHLESS_DEPLOY_MODE": "lan", "WORTHLESS_HOST": "0.0.0.0"},  # noqa: S104
            # PUBLIC: trusted_proxies present, allow_insecure unset
            {"WORTHLESS_DEPLOY_MODE": "public", "WORTHLESS_TRUSTED_PROXIES": "10.0.0.0/8"},
        ],
    )
    def test_accepts(self, monkeypatch: pytest.MonkeyPatch, env: dict[str, str]) -> None:
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        ProxySettings().validate()  # must not raise


class TestPaasAutoDetection:
    @pytest.mark.parametrize("paas_var", ["RENDER", "FLY_APP_NAME", "KUBERNETES_SERVICE_HOST"])
    def test_refuses_silent_loopback_on_paas(
        self, monkeypatch: pytest.MonkeyPatch, paas_var: str
    ) -> None:
        monkeypatch.setenv(paas_var, "1")
        s = ProxySettings()
        with pytest.raises(ConfigError, match="Detected PaaS env var"):
            s.validate()

    def test_explicit_loopback_on_paas_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Explicit WORTHLESS_DEPLOY_MODE=loopback overrides PaaS detection."""
        monkeypatch.setenv("RENDER", "1")
        monkeypatch.setenv("WORTHLESS_DEPLOY_MODE", "loopback")
        ProxySettings().validate()  # must not raise

    def test_public_on_paas_passes_with_proxies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RENDER", "1")
        monkeypatch.setenv("WORTHLESS_DEPLOY_MODE", "public")
        monkeypatch.setenv("WORTHLESS_TRUSTED_PROXIES", "10.0.0.0/8")
        ProxySettings().validate()  # must not raise
