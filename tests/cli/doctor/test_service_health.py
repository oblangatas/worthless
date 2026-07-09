"""WOR-726: service_health doctor check.

Catches service-specific breakage the plain status/doctor checks miss,
synthesized from a reliability + security premortem panel:

  A. binary mismatch  — installed unit runs a binary != the resolved one
  B. port mismatch    — installed unit's port != the expected port
  C. legacy label     — pre-rename dev.worthless.proxy plist still present
  D. orphan home      — unit references a WORTHLESS_HOME that no longer exists
  E. linger off        — systemd unit installed but Linger=no (dies at logout)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from worthless.cli.bootstrap import ensure_home
from worthless.cli.commands.doctor.checks import service_health
from worthless.cli.commands.doctor.registry import CheckContext
from worthless.storage.repository import ShardRepository


@pytest.fixture
def fake_home(tmp_path: Path):
    return ensure_home(tmp_path / ".worthless")


@pytest.fixture
def ctx(fake_home):
    repo = ShardRepository(str(fake_home.db_path), bytes(fake_home.fernet_key))
    return CheckContext(home=fake_home, repo=repo, fix=False, dry_run=False)


# --- pure sub-check functions -------------------------------------------------


class TestBinaryMismatch:
    @staticmethod
    def _plist(binary: str) -> str:
        return (
            "<key>ProgramArguments</key>\n<array>\n"
            f"  <string>{binary}</string>\n  <string>up</string>\n</array>"
        )

    def test_none_when_match(self) -> None:
        content = self._plist("/usr/local/bin/worthless")
        assert (
            service_health._binary_mismatch(content, "launchd", Path("/usr/local/bin/worthless"))
            is None
        )

    def test_finding_when_mismatch(self) -> None:
        content = self._plist("/opt/evil/worthless")
        finding = service_health._binary_mismatch(
            content, "launchd", Path("/usr/local/bin/worthless")
        )
        assert finding is not None
        assert finding["kind"] == "binary_mismatch"

    def test_systemd_execstart(self) -> None:
        content = "ExecStart=/opt/evil/worthless up\n"
        finding = service_health._binary_mismatch(
            content, "systemd", Path("/usr/local/bin/worthless")
        )
        assert finding is not None
        assert finding["kind"] == "binary_mismatch"

    def test_none_when_binary_unparseable(self) -> None:
        # No binary in content → can't compare → no false positive.
        assert service_health._binary_mismatch("garbage", "launchd", Path("/x")) is None


class TestPortMismatch:
    def test_none_when_match(self) -> None:
        assert service_health._port_mismatch(8787, 8787) is None

    def test_finding_when_mismatch(self) -> None:
        finding = service_health._port_mismatch(9000, 8787)
        assert finding is not None
        assert finding["kind"] == "port_mismatch"
        assert finding["installed_port"] == 9000
        assert finding["expected_port"] == 8787

    def test_none_when_installed_unknown(self) -> None:
        assert service_health._port_mismatch(None, 8787) is None


class TestOrphanHome:
    def test_none_when_home_exists(self, tmp_path: Path) -> None:
        existing = tmp_path / "home"
        existing.mkdir()
        content = f"Environment=WORTHLESS_HOME={existing}\n"
        assert service_health._orphan_home_findings(content) == []

    def test_finding_when_home_missing(self, tmp_path: Path) -> None:
        missing = tmp_path / "gone"
        content = f"Environment=WORTHLESS_HOME={missing}\n"
        findings = service_health._orphan_home_findings(content)
        assert len(findings) == 1
        assert findings[0]["kind"] == "orphan_home"


class TestLegacyLabel:
    def test_none_when_absent(self, tmp_path: Path) -> None:
        assert service_health._legacy_label_finding(tmp_path / "missing.plist") is None

    def test_finding_when_present(self, tmp_path: Path) -> None:
        legacy = tmp_path / "dev.worthless.proxy.plist"
        legacy.write_text("legacy")
        finding = service_health._legacy_label_finding(legacy)
        assert finding is not None
        assert finding["kind"] == "legacy_label"


class TestLingerFinding:
    def test_none_when_enabled(self) -> None:
        assert service_health._linger_finding(True) is None

    def test_finding_when_disabled(self) -> None:
        finding = service_health._linger_finding(False)
        assert finding is not None
        assert finding["kind"] == "linger_off"


# --- run() integration --------------------------------------------------------


class TestRun:
    def test_skips_when_no_unit_installed(self, ctx, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(service_health, "current_platform_backend_name", lambda: "systemd")
        monkeypatch.setattr(
            service_health, "_installed_unit_path", lambda name: tmp_path / "missing.service"
        )
        result = service_health.run(ctx)
        assert result["status"] == "ok"
        assert result["skipped_reason"] is not None

    def test_ok_when_unit_healthy(self, ctx, tmp_path, monkeypatch) -> None:
        home_dir = ctx.home.base_dir
        binary = tmp_path / "worthless"
        binary.write_text("#!/bin/sh\n")
        unit = tmp_path / "worthless-proxy.service"
        unit.write_text(
            f"ExecStart={binary} up\n"
            f"Environment=WORTHLESS_HOME={home_dir}\n"
            "Environment=WORTHLESS_PORT=8787\n"
        )
        monkeypatch.setattr(service_health, "current_platform_backend_name", lambda: "systemd")
        monkeypatch.setattr(service_health, "_installed_unit_path", lambda name: unit)
        monkeypatch.setattr(service_health, "resolve_worthless_binary", lambda: binary)
        monkeypatch.setattr(service_health, "resolve_port", lambda _: 8787)
        monkeypatch.setattr(service_health, "_installed_port", lambda name: 8787)
        monkeypatch.setattr(service_health, "_linger_ok_if_systemd", lambda name: True)

        result = service_health.run(ctx)
        assert result["status"] == "ok"
        assert result["findings"] == []

    def test_detects_multiple_findings(self, ctx, tmp_path, monkeypatch) -> None:
        binary = tmp_path / "worthless"
        binary.write_text("#!/bin/sh\n")
        missing_home = tmp_path / "gone"
        unit = tmp_path / "worthless-proxy.service"
        unit.write_text(
            f"ExecStart=/opt/evil/worthless up\n"
            f"Environment=WORTHLESS_HOME={missing_home}\n"
            "Environment=WORTHLESS_PORT=9000\n"
        )
        monkeypatch.setattr(service_health, "current_platform_backend_name", lambda: "systemd")
        monkeypatch.setattr(service_health, "_installed_unit_path", lambda name: unit)
        monkeypatch.setattr(service_health, "resolve_worthless_binary", lambda: binary)
        monkeypatch.setattr(service_health, "resolve_port", lambda _: 8787)
        monkeypatch.setattr(service_health, "_installed_port", lambda name: 9000)
        monkeypatch.setattr(service_health, "_linger_ok_if_systemd", lambda name: False)

        result = service_health.run(ctx)
        assert result["status"] == "warn"
        kinds = {f["kind"] for f in result["findings"]}
        assert kinds == {"binary_mismatch", "orphan_home", "port_mismatch", "linger_off"}
