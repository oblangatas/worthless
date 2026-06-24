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
    verify_proxy_health,
)
from worthless.cli.errors import ErrorCode, WorthlessError


@pytest.fixture()
def home(tmp_path: Path) -> WorthlessHome:
    base = tmp_path / ".worthless"
    base.mkdir()
    (base / "fernet.key").write_bytes(b"x" * 32)
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

    def test_ignores_non_executable_local_bin(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fallback = tmp_path / ".local" / "bin" / "worthless"
        fallback.parent.mkdir(parents=True)
        fallback.write_text("not executable\n")
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        with (
            patch("worthless.cli.commands.service._common.shutil.which", return_value=None),
            pytest.raises(WorthlessError) as exc_info,
        ):
            resolve_worthless_binary()
        assert exc_info.value.code == ErrorCode.BOOTSTRAP_FAILED

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

    def test_verify_proxy_health_failure(self) -> None:
        with (
            patch("worthless.cli.commands.service._common.poll_health", return_value=False),
            pytest.raises(WorthlessError) as exc_info,
        ):
            verify_proxy_health(8787, timeout=1.0)
        assert exc_info.value.code == ErrorCode.PROXY_UNREACHABLE


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
