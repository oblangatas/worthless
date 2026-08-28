"""Unit tests for service shared helpers."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.service import templates
from worthless.cli.commands.service._common import (
    atomic_write_text,
    current_platform_backend_name,
    preflight_service_install,
    resolve_worthless_binary,
    unit_file_matches_home,
    report_proxy_health,
)
from worthless.cli.errors import ErrorCode, WorthlessError


@pytest.fixture()
def home(tmp_path: Path) -> WorthlessHome:
    base = tmp_path / ".worthless"
    base.mkdir()
    fernet = base / "fernet.key"
    fernet.write_bytes(b"x" * 32)
    fernet.chmod(0o600)
    return WorthlessHome(base_dir=base)


class TestAtomicWriteText:
    def test_writes_content(self, tmp_path: Path) -> None:
        target = tmp_path / "unit.service"
        atomic_write_text(target, "hello", mode=0o600)
        assert target.read_text() == "hello"
        assert oct(target.stat().st_mode & 0o777) == oct(0o600)

    def test_refuses_symlink_target(self, tmp_path: Path) -> None:
        real = tmp_path / "real.service"
        link = tmp_path / "link.service"
        link.symlink_to(real)
        with pytest.raises(WorthlessError) as exc_info:
            atomic_write_text(link, "x")
        assert exc_info.value.code == ErrorCode.UNSAFE_REWRITE_REFUSED


class TestResolveWorthlessBinary:
    def test_uses_shutil_which(self, tmp_path: Path) -> None:
        binary = tmp_path / "worthless"
        binary.write_text("#!/bin/sh\n")
        with patch("worthless.cli.commands.service._common.shutil.which", return_value=str(binary)):
            assert resolve_worthless_binary() == binary.resolve()

    def test_falls_back_to_local_bin(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fallback = tmp_path / ".local" / "bin" / "worthless"
        fallback.parent.mkdir(parents=True)
        fallback.write_text("#!/bin/sh\n")
        fallback.chmod(0o755)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        with patch("worthless.cli.commands.service._common.shutil.which", return_value=None):
            assert resolve_worthless_binary() == fallback.resolve()

    def test_raises_when_missing(self) -> None:
        with (
            patch("worthless.cli.commands.service._common.shutil.which", return_value=None),
            patch.object(Path, "home", return_value=Path("/nonexistent")),
            pytest.raises(WorthlessError) as exc_info,
        ):
            resolve_worthless_binary()
        assert exc_info.value.code == ErrorCode.BOOTSTRAP_FAILED


class TestPreflightAndHealth:
    def test_preflight_zeroes_key(self, home: WorthlessHome) -> None:
        preflight_service_install(home)

    def test_preflight_missing_fernet(self, tmp_path: Path) -> None:
        base = tmp_path / ".worthless"
        base.mkdir()
        home = WorthlessHome(base_dir=base)
        with (
            patch(
                "worthless.cli.bootstrap.read_fernet_key",
                side_effect=WorthlessError(ErrorCode.KEY_NOT_FOUND, "missing"),
            ),
            pytest.raises(WorthlessError) as exc_info,
        ):
            preflight_service_install(home)
        assert exc_info.value.code == ErrorCode.KEY_NOT_FOUND

    def test_health_timeout_is_no_longer_an_error(self) -> None:
        """Replaces test_verify_proxy_health_failure (worthless-rnl8).

        That test pinned `verify_proxy_health` raising PROXY_UNREACHABLE when
        `/healthz` did not answer in time. The contract was wrong, not the test:
        this function runs only after the unit has been written and started, so a
        silent proxy means "not up yet", not "install failed". Live proof on macOS
        v0.3.11 — the aborted install had a healthy service moments later.

        The behaviour is deliberately inverted and now lives in
        TestHealthReportHonesty. Kept as a marker so the removal reads as a
        decision rather than a dropped assertion.
        """
        with patch("worthless.cli.commands.service._common.poll_health", return_value=False):
            report_proxy_health(8787, timeout=0.01)  # no raise: that is the fix


class TestPlatformBackendName:
    def test_darwin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        assert current_platform_backend_name() == "launchd"

    def test_linux(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        assert current_platform_backend_name() == "systemd"

    def test_unsupported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        with pytest.raises(WorthlessError) as exc_info:
            current_platform_backend_name()
        assert exc_info.value.code == ErrorCode.PLATFORM_UNSUPPORTED


class TestUnitFileMatchesHome:
    def test_matches_systemd_environment_line(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = tmp_path / "worthless-proxy.service"
        unit.write_text(
            templates.render_systemd_unit(
                binary="/usr/local/bin/worthless",
                worthless_home=str(home.base_dir.resolve()),
            )
        )
        assert unit_file_matches_home(unit, home)

    def test_rejects_prefix_collision(self, home: WorthlessHome, tmp_path: Path) -> None:
        other = tmp_path / "other-home"
        other.mkdir()
        unit = tmp_path / "worthless-proxy.service"
        unit.write_text(
            templates.render_systemd_unit(
                binary="/usr/local/bin/worthless",
                worthless_home=str(other),
            )
        )
        assert not unit_file_matches_home(unit, home)

    def test_symlink_home_matches_resolved_path(self, tmp_path: Path) -> None:
        target = tmp_path / "worthless-real"
        target.mkdir()
        link = tmp_path / "worthless-link"
        link.symlink_to(target)
        home = WorthlessHome(base_dir=link)
        (target / "fernet.key").write_bytes(b"x" * 32)
        unit = tmp_path / "worthless-proxy.service"
        unit.write_text(
            templates.render_systemd_unit(
                binary="/usr/local/bin/worthless",
                worthless_home=str(target.resolve()),
            )
        )
        assert unit_file_matches_home(unit, home)

    def test_symlink_home_matches_legacy_unresolved_unit_path(self, tmp_path: Path) -> None:
        target = tmp_path / "worthless-real"
        target.mkdir()
        link = tmp_path / "worthless-link"
        link.symlink_to(target)
        home = WorthlessHome(base_dir=link)
        (target / "fernet.key").write_bytes(b"x" * 32)
        unit = tmp_path / "worthless-proxy.service"
        unit.write_text(
            templates.render_systemd_unit(
                binary="/usr/local/bin/worthless",
                worthless_home=str(link),
            )
        )
        assert unit_file_matches_home(unit, home)

    def test_unreadable_unit_raises_clean_error(self, home: WorthlessHome, tmp_path: Path) -> None:
        unit = tmp_path / "worthless-proxy.service"
        unit.write_text(
            templates.render_systemd_unit(
                binary="/usr/local/bin/worthless",
                worthless_home=str(home.base_dir.resolve()),
            )
        )
        unit.chmod(0o000)
        try:
            with pytest.raises(WorthlessError) as exc_info:
                unit_file_matches_home(unit, home)
            assert exc_info.value.code == ErrorCode.INVALID_INPUT
            assert "Cannot read service unit" in exc_info.value.message
        finally:
            unit.chmod(0o600)

    def test_matches_launchd_plist_home_key(self, home: WorthlessHome, tmp_path: Path) -> None:
        plist = tmp_path / "sh.worthless.proxy.plist"
        log_path = home.base_dir / "proxy.log"
        plist.write_text(
            templates.render_launchd_plist(
                binary="/usr/local/bin/worthless",
                worthless_home=str(home.base_dir.resolve()),
                log_path=str(log_path),
            )
        )
        assert unit_file_matches_home(plist, home)


class TestTemplatesPortOverride:
    def test_launchd_explicit_port(self) -> None:
        content = templates.render_launchd_plist(
            binary="/bin/worthless",
            worthless_home="/home/u/.worthless",
            log_path="/home/u/.worthless/proxy.log",
            port=9999,
        )
        assert "9999" in content

    def test_systemd_explicit_port(self) -> None:
        content = templates.render_systemd_unit(
            binary="/bin/worthless",
            worthless_home="/home/u/.worthless",
            port=9090,
        )
        assert "9090" in content


class TestHealthReportHonesty:
    """worthless-rnl8: a health-check timeout is not an install failure.

    Verified live on macOS with released v0.3.11: `worthless service install`
    printed

        WRTLS-104: Service started but /healthz on port 8787 did not respond within 15s.

    and exited non-zero — while the service was, in fact, installed and about to
    become healthy. `launchctl list` showed last exit status 1, so the first spawn
    died and launchd's restart succeeded seconds later, after install had stopped
    watching. The user was told a success was a failure, and a user who believes
    that will uninstall a working service.

    The load-bearing fact: `report_proxy_health` is only ever reached AFTER the
    platform's bootstrap/kickstart (launchd) or enable/start (systemd) calls have
    returned successfully. Reaching this line is itself proof the unit is written
    and started. What has NOT been established is whether the proxy answered yet.
    Those are different claims and must read differently.
    """

    def test_timeout_does_not_raise(self) -> None:
        """An unconfirmed health check must not abort a successful install."""
        with patch("worthless.cli.commands.service._common.poll_health", return_value=False):
            report_proxy_health(8787, timeout=0.01)  # must not raise

    def test_timeout_does_not_call_it_a_failure(self, capsys: pytest.CaptureFixture) -> None:
        """The wording must not assert something failed when nothing did."""
        with patch("worthless.cli.commands.service._common.poll_health", return_value=False):
            report_proxy_health(8787, timeout=0.01)
        out = " ".join((capsys.readouterr().err + capsys.readouterr().out).split()).lower()
        for lie in ("failed", "did not respond within"):
            assert lie not in out, (
                f"still asserts failure ({lie!r}) on a successful install:\n{out}"
            )

    def test_timeout_says_what_did_succeed_and_how_to_check(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Name the established fact, then the open question, then the next step."""
        with patch("worthless.cli.commands.service._common.poll_health", return_value=False):
            report_proxy_health(8787, timeout=0.01)
        out = " ".join((capsys.readouterr().err + capsys.readouterr().out).split()).lower()
        assert "installed" in out or "started" in out, f"must state what succeeded:\n{out}"
        assert "worthless service status" in out, f"must give the next step:\n{out}"

    def test_healthy_proxy_stays_silent(self, capsys: pytest.CaptureFixture) -> None:
        """No warning when the proxy answered — silence is the success signal."""
        with patch("worthless.cli.commands.service._common.poll_health", return_value=True):
            report_proxy_health(8787, timeout=0.01)
        out = (capsys.readouterr().err + capsys.readouterr().out).lower()
        assert "status" not in out, f"clean install should not nag:\n{out}"

    def test_default_wait_exceeds_the_observed_cold_start(self) -> None:
        """15s was shorter than a real launchd cold start — that is what broke."""
        import inspect

        default = inspect.signature(report_proxy_health).parameters["timeout"].default
        assert default > 15.0, (
            f"default wait is still {default}s; the live failure happened at 15s, so "
            "keeping it there reproduces the bug even with better wording"
        )
