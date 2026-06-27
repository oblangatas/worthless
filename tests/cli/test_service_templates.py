"""Tests for service unit/plist templates."""

from __future__ import annotations

from worthless.cli.commands.service import templates


def test_launchd_plist_contains_managed_env_and_up() -> None:
    content = templates.render_launchd_plist(
        binary="/home/u/.local/bin/worthless",
        worthless_home="/home/u/.worthless",
        log_path="/home/u/.worthless/proxy.log",
        port=8787,
    )
    assert "dev.worthless.proxy" in content
    assert "<string>up</string>" in content
    assert "WORTHLESS_SERVICE_MANAGED" in content
    assert "WORTHLESS_HOME" in content
    assert "WORTHLESS_PORT" in content
    assert "<true/>" in content  # KeepAlive / RunAtLoad


def test_systemd_unit_hardening_directives() -> None:
    content = templates.render_systemd_unit(
        binary="/home/u/.local/bin/worthless",
        worthless_home="/home/u/.worthless",
    )
    assert "ExecStart=/home/u/.local/bin/worthless up" in content
    assert "WORTHLESS_SERVICE_MANAGED=1" in content
    assert "NoNewPrivileges=true" in content
    assert "LimitCORE=0" in content
    assert "UMask=0077" in content
    assert "UnsetEnvironment=WORTHLESS_FERNET_KEY" in content
    assert "Restart=on-failure" in content
