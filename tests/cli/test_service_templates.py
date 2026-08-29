"""Tests for service unit/plist templates."""

from __future__ import annotations

import re

import pytest

from worthless.cli.commands.service import templates

# A systemd *user* unit is what `worthless service install` ships on Linux
# (WOR-175). Converting it to a system unit would need root at install time,
# lose keyring access, and make the key material root-readable — see
# "Service supervision boundary" in engineering/architecture.md.
_WANTED_BY_RE = re.compile(r"^WantedBy=(\S+)$", re.MULTILINE)
_OWNING_USER_RE = re.compile(r"^(?:Dynamic)?User=", re.MULTILINE)
_USER_UNIT_DIR = "/.config/systemd/user/"


def _user_unit_violations(unit_text: str, unit_path: str) -> list[str]:
    """Reasons this unit is not a systemd *user* unit; empty means it is one.

    Two states only, never "ambiguous": a drift guard that can shrug is a
    drift guard that never fires. Each check is independent so a single
    regression produces a single violation, naming the thing that broke.
    """
    violations: list[str] = []
    targets = _WANTED_BY_RE.findall(unit_text)
    if targets != ["default.target"]:
        violations.append(
            f"install target is {targets!r}, expected ['default.target'] "
            "(multi-user.target is a system-unit target)"
        )
    if _OWNING_USER_RE.search(unit_text):
        violations.append("unit names an owning User=; user units never do")
    if _USER_UNIT_DIR not in unit_path:
        violations.append(f"unit path {unit_path!r} is not under {_USER_UNIT_DIR}")
    return violations


def test_launchd_plist_contains_managed_env_and_up() -> None:
    content = templates.render_launchd_plist(
        binary="/home/u/.local/bin/worthless",
        worthless_home="/home/u/.worthless",
        log_path="/home/u/.worthless/proxy.log",
        port=8787,
    )
    assert "sh.worthless.proxy" in content
    assert "<string>up</string>" in content
    assert "WORTHLESS_SERVICE_MANAGED" in content
    assert "WORTHLESS_HOME" in content
    assert "WORTHLESS_PORT" in content
    assert "<true/>" in content  # KeepAlive / RunAtLoad
    assert "WORTHLESS_FERNET_KEY" in content
    assert "<key>WORTHLESS_FERNET_KEY</key>" in content
    assert "<string></string>" in content
    assert "poison-env-key" not in content


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
    assert "WantedBy=default.target" in content


def test_systemd_unit_is_a_user_unit() -> None:
    """The shipped Linux unit is user-scoped: user target, no User=, under $HOME.

    Nothing else asserts the unit *path*; the argv tests in
    test_service_backends.py cover `systemctl --user` but not where the file
    lands or what it declares.
    """
    content = templates.render_systemd_unit(
        binary="/home/u/.local/bin/worthless",
        worthless_home="/home/u/.worthless",
    )
    path = templates.systemd_unit_path("/home/u")

    assert path == "/home/u/.config/systemd/user/worthless-proxy.service"
    assert _user_unit_violations(content, path) == []


def _system_unit_text() -> str:
    """The shipped unit, minimally converted to a system-unit target."""
    content = templates.render_systemd_unit(
        binary="/home/u/.local/bin/worthless",
        worthless_home="/home/u/.worthless",
    )
    return content.replace("WantedBy=default.target", "WantedBy=multi-user.target")


def _unit_text_with_owning_user() -> str:
    content = templates.render_systemd_unit(
        binary="/home/u/.local/bin/worthless",
        worthless_home="/home/u/.worthless",
    )
    return content.replace("[Service]\n", "[Service]\nUser=worthless\n")


@pytest.mark.parametrize(
    ("unit_text", "unit_path", "expected_fragment"),
    [
        pytest.param(
            _system_unit_text(),
            "/home/u/.config/systemd/user/worthless-proxy.service",
            "install target is",
            id="system-unit-target-is-rejected",
        ),
        pytest.param(
            _unit_text_with_owning_user(),
            "/home/u/.config/systemd/user/worthless-proxy.service",
            "owning User=",
            id="owning-user-directive-is-rejected",
        ),
        pytest.param(
            templates.render_systemd_unit(
                binary="/home/u/.local/bin/worthless",
                worthless_home="/home/u/.worthless",
            ),
            "/etc/systemd/system/worthless-proxy.service",
            "is not under",
            id="system-wide-unit-path-is-rejected",
        ),
    ],
)
def test_system_unit_conversions_are_rejected(
    unit_text: str, unit_path: str, expected_fragment: str
) -> None:
    """Each check fires alone: one conversion produces exactly one violation.

    This is the committed proof that the user-unit assertions bite. A manual
    edit-and-revert of src/ would prove the same thing once and leave no
    evidence; these cases prove it on every run.
    """
    violations = _user_unit_violations(unit_text, unit_path)
    assert len(violations) == 1, f"expected exactly one violation, got {violations}"
    assert expected_fragment in violations[0]
