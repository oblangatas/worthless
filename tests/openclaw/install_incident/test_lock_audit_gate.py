"""WOR-515 Phase 1 — audit gate unit/integration tests (no Docker required).

12 AC tests + 10 adversarial tests.  All mocked at the subprocess layer.
Docker-gated tests live in test_lock_audit_gate_docker.py.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from worthless.openclaw.audit import (
    AuditFinding,
    AuditGateError,
    AuditResult,
    BlockingFinding,
    _AUTH_PROFILES_MAX_DEPTH,
    check_auth_profiles_direct,
    classify_findings,
    format_gate_error_message,
    parse_audit_result,
    resolve_openclaw_bin,
    run_and_classify,
    run_audit,
    sanitise_for_message,
    snapshot_hashes,
)

# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


def _make_proc(stdout: str, returncode: int = 0) -> MagicMock:
    m = MagicMock()
    m.stdout = stdout
    m.returncode = returncode
    return m


def _audit_json(findings: list[dict], files_scanned: list[str] | None = None) -> str:
    """Build a minimal valid audit JSON payload."""
    plaintext = sum(1 for f in findings if f.get("code") == "PLAINTEXT_FOUND")
    return json.dumps(
        {
            "version": 1,
            "status": "findings" if findings else "clean",
            "resolution": {"refsChecked": 0, "skippedExecRefs": 0, "resolvabilityComplete": True},
            "filesScanned": files_scanned or ["/home/node/.openclaw/openclaw.json"],
            "summary": {
                "plaintextCount": plaintext,
                "unresolvedRefCount": 0,
                "shadowedRefCount": 0,
                "legacyResidueCount": 0,
            },
            "findings": findings,
        }
    )


def _plaintext_finding(
    json_path: str = "providers.openai.apiKey",
    file: str = "/home/node/.openclaw/openclaw.json",
    provider: str | None = "openai",
) -> dict:
    return {
        "code": "PLAINTEXT_FOUND",
        "severity": "warn",
        "file": file,
        "jsonPath": json_path,
        "message": f"{json_path} is stored as plaintext.",
        **({"provider": provider} if provider else {}),
    }


# --------------------------------------------------------------------------- #
# AC 1 — clean config → proceed                                                #
# --------------------------------------------------------------------------- #


class TestAC1CleanConfig:
    def test_clean_audit_result_is_not_blocking(self) -> None:
        """AC 1: clean audit (no findings) returns empty blocking list."""
        clean = _load_fixture("m0_audit_clean.json")
        result = AuditResult(
            version=clean["version"],
            status=clean["status"],
            files_scanned=tuple(clean["filesScanned"]),
            plaintext_count=clean["summary"]["plaintextCount"],
            findings=tuple(
                AuditFinding(
                    code=f["code"],
                    severity=f["severity"],
                    file=f["file"],
                    json_path=f["jsonPath"],
                    message=f["message"],
                    provider=f.get("provider"),
                )
                for f in clean["findings"]
            ),
        )
        classification = classify_findings(result)
        assert len(classification.blocking) == 0
        assert len(classification.unknown_codes) == 0


# --------------------------------------------------------------------------- #
# AC 2 — openclaw.json plaintext provider apiKey → exit 73                     #
# --------------------------------------------------------------------------- #


class TestAC2PlaintextProviderKey:
    def test_plaintext_provider_key_is_blocking(self) -> None:
        """AC 2: PLAINTEXT_FOUND for non-allowlisted provider blocks."""
        finding = AuditFinding(
            code="PLAINTEXT_FOUND",
            severity="warn",
            file="/home/node/.openclaw/openclaw.json",
            json_path="providers.openai.apiKey",
            message="providers.openai.apiKey is stored as plaintext.",
            provider="openai",
        )
        result = AuditResult(
            version=1,
            status="findings",
            files_scanned=("/home/node/.openclaw/openclaw.json",),
            plaintext_count=1,
            findings=(finding,),
        )
        classification = classify_findings(result)
        assert len(classification.blocking) == 1
        assert classification.blocking[0].json_path == "providers.openai.apiKey"

    def test_error_message_names_configure_remediation(self) -> None:
        """AC 2+5: error message for exit 73 names openclaw secrets configure."""
        blocking = (
            BlockingFinding(
                file="/home/node/.openclaw/openclaw.json",
                json_path="providers.openai.apiKey",
                provider="openai",
                message="openai.apiKey is plaintext",
                source="audit",
            ),
        )
        msg = format_gate_error_message(blocking)
        assert "openclaw secrets configure" in msg
        assert "--apply" not in msg  # no non-interactive flag — requires TTY
        assert "--yes" not in msg

    def test_run_audit_dispatches_subprocess(self, tmp_path: Path) -> None:
        """run_audit calls openclaw with --json and returns parsed result."""
        fake_bin = tmp_path / "openclaw"
        fake_bin.write_text("#!/bin/sh\n")
        fake_bin.chmod(0o755)
        payload = _audit_json([])
        proc = _make_proc(stdout=payload)
        with patch("subprocess.run", return_value=proc) as mock_run:
            result = run_audit(fake_bin)
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert str(fake_bin) in args
        assert "--json" in args
        assert result.plaintext_count == 0


# --------------------------------------------------------------------------- #
# AC 3 — auth-profiles plaintext → exit 73 (direct read, not audit)           #
# --------------------------------------------------------------------------- #


class TestAC3AuthProfilesDirect:
    def test_auth_profiles_plaintext_detected_directly(self, tmp_path: Path) -> None:
        """AC 3: worthless reads auth-profiles.json directly; audit never flags it."""
        auth = tmp_path / "auth-profiles.json"
        auth.write_text(
            json.dumps(
                {
                    "profiles": {
                        "default": {"token": "sk-proj-realcachedkey0000000000000000000000000000000"}
                    }
                }
            )
        )
        findings = check_auth_profiles_direct([str(auth)])
        assert len(findings) == 1
        assert "auth-profiles" in findings[0].file
        assert findings[0].source == "auth-profiles-direct"

    def test_auth_profiles_not_in_files_scanned_is_ignored(self, tmp_path: Path) -> None:
        """AC 3: file not in filesScanned[] is not read — decoy protection."""
        decoy = tmp_path / "auth-profiles.json"
        decoy.write_text(
            json.dumps(
                {"profiles": {"x": {"key": "sk-proj-decoy000000000000000000000000000000000000000"}}}
            )
        )
        # Not passing the decoy path — it's not in filesScanned
        findings = check_auth_profiles_direct([])
        assert len(findings) == 0

    def test_auth_profiles_classified_as_blocking(self, tmp_path: Path) -> None:
        """AC 3: auth-profiles blocking finding → classify_findings returns blocking."""
        auth_finding = BlockingFinding(
            file=str(tmp_path / "auth-profiles.json"),
            json_path="profiles.default.token",
            provider=None,
            message="plaintext key in auth-profiles",
            source="auth-profiles-direct",
        )
        result = AuditResult(
            version=1,
            status="clean",
            files_scanned=(str(tmp_path / "auth-profiles.json"),),
            plaintext_count=0,
            findings=(),
        )
        classification = classify_findings(result, auth_profiles_blocking=[auth_finding])
        assert len(classification.blocking) == 1
        assert classification.blocking[0].source == "auth-profiles-direct"


# --------------------------------------------------------------------------- #
# AC 4 — multi-provider aggregation                                            #
# --------------------------------------------------------------------------- #


class TestAC4MultiProviderAggregation:
    def test_all_blocking_findings_listed(self) -> None:
        """AC 4: classify_findings returns ALL blocking findings, no short-circuit."""
        findings = tuple(
            AuditFinding(
                code="PLAINTEXT_FOUND",
                severity="warn",
                file="/home/node/.openclaw/openclaw.json",
                json_path=f"providers.provider{i}.apiKey",
                message=f"provider{i}.apiKey is plaintext",
                provider=f"provider{i}",
            )
            for i in range(3)
        )
        result = AuditResult(
            version=1,
            status="findings",
            files_scanned=("/home/node/.openclaw/openclaw.json",),
            plaintext_count=3,
            findings=findings,
        )
        classification = classify_findings(result)
        assert len(classification.blocking) == 3

    def test_error_message_lists_all_providers(self) -> None:
        """AC 4: error message lists every blocking finding."""
        blocking = tuple(
            BlockingFinding(
                file="/home/node/.openclaw/openclaw.json",
                json_path=f"providers.provider{i}.apiKey",
                provider=f"provider{i}",
                message=f"provider{i} is plaintext",
                source="audit",
            )
            for i in range(3)
        )
        msg = format_gate_error_message(blocking)
        for i in range(3):
            assert f"provider{i}" in msg


# --------------------------------------------------------------------------- #
# AC 5 — error message names correct remediation                               #
# --------------------------------------------------------------------------- #


class TestAC5RemediationMessage:
    def test_remediation_names_configure_no_interactive_flags(self) -> None:
        """AC 5: remediation command is 'openclaw secrets configure' only."""
        blocking = (
            BlockingFinding(
                file="/f",
                json_path="providers.x.apiKey",
                provider="x",
                message="x is plaintext",
                source="audit",
            ),
        )
        msg = format_gate_error_message(blocking)
        assert "openclaw secrets configure" in msg
        # M0 confirmed: no non-interactive flags exist
        assert "--apply" not in msg
        assert "--yes" not in msg
        assert "--plan-out" not in msg


# --------------------------------------------------------------------------- #
# AC 6 — re-lock works (bootstrap paradox, exact-name allowlist)              #
# --------------------------------------------------------------------------- #


class TestAC6ReLockBootstrapParadox:
    def test_worthless_own_provider_apikey_is_not_blocking(self) -> None:
        """AC 6: worthless-openai.apiKey (shard-A) is NOT blocking — allowlist."""
        finding = AuditFinding(
            code="PLAINTEXT_FOUND",
            severity="warn",
            file="/home/node/.openclaw/openclaw.json",
            json_path="providers.worthless-openai.apiKey",
            message="worthless-openai.apiKey is stored as plaintext.",
            provider="worthless-openai",
        )
        result = AuditResult(
            version=1,
            status="findings",
            files_scanned=("/home/node/.openclaw/openclaw.json",),
            plaintext_count=1,
            findings=(finding,),
        )
        classification = classify_findings(result)
        assert len(classification.blocking) == 0

    def test_bootstrap_fixture_has_zero_blocking_after_allowlist(self) -> None:
        """AC 6: m0_audit_bootstrap_paradox fixture → 0 blocking after allowlist."""
        raw = _load_fixture("m0_audit_bootstrap_paradox.json")
        findings = tuple(
            AuditFinding(
                code=f["code"],
                severity=f["severity"],
                file=f["file"],
                json_path=f["jsonPath"],
                message=f["message"],
                provider=f.get("provider"),
            )
            for f in raw["findings"]
        )
        result = AuditResult(
            version=raw["version"],
            status=raw["status"],
            files_scanned=tuple(raw["filesScanned"]),
            plaintext_count=raw["summary"]["plaintextCount"],
            findings=findings,
        )
        classification = classify_findings(result)
        # Only worthless-openai should be in findings; it's in the allowlist
        blocking_providers = {b.provider for b in classification.blocking}
        assert "worthless-openai" not in blocking_providers


# --------------------------------------------------------------------------- #
# AC 7 — subprocess fail-closed, split exit codes                              #
# --------------------------------------------------------------------------- #


class TestAC7SubprocessFailClosed:
    def test_subprocess_failure_raises_audit_gate_error(self, tmp_path: Path) -> None:
        """AC 7: non-zero subprocess exit → AuditGateError (not silent pass)."""
        fake_bin = tmp_path / "openclaw"
        fake_bin.write_text("#!/bin/sh\n")
        fake_bin.chmod(0o755)
        proc = _make_proc(stdout="", returncode=1)
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(AuditGateError):
                run_audit(fake_bin)

    def test_subprocess_failure_retries_exactly_once(self, tmp_path: Path) -> None:
        """AC 7: transient failure retried exactly once before raising.

        subprocess.run must be called exactly 2 times — first attempt fails,
        second attempt fails, then AuditGateError is raised. Not 1 (no retry),
        not 3+ (over-retry).
        """
        fake_bin = tmp_path / "openclaw"
        fake_bin.write_text("#!/bin/sh\n")
        fake_bin.chmod(0o755)
        proc = _make_proc(stdout="", returncode=1)
        with patch("subprocess.run", return_value=proc) as mock_run:
            with pytest.raises(AuditGateError):
                run_audit(fake_bin)
        assert mock_run.call_count == 2, (
            f"Expected exactly 1 retry (2 total calls), got {mock_run.call_count}"
        )

    def test_timeout_raises_audit_gate_error_without_retry(self, tmp_path: Path) -> None:
        """AC 7: subprocess timeout → AuditGateError with no retry.

        Timeouts are never retried — doubling the wait on a hung binary
        is worse than surfacing the failure immediately.
        subprocess.run must be called exactly once.
        """
        fake_bin = tmp_path / "openclaw"
        fake_bin.write_text("#!/bin/sh\n")
        fake_bin.chmod(0o755)
        expired = subprocess.TimeoutExpired(cmd="openclaw", timeout=5)
        with patch("subprocess.run", side_effect=expired) as mock_run:
            with pytest.raises(AuditGateError):
                run_audit(fake_bin, timeout=0.001)
        assert mock_run.call_count == 1, (
            f"Timeout must not be retried — expected 1 call, got {mock_run.call_count}"
        )

    def test_unparseable_stdout_raises_audit_gate_error(self, tmp_path: Path) -> None:
        """AC 7: garbage stdout → AuditGateError."""
        fake_bin = tmp_path / "openclaw"
        fake_bin.write_text("#!/bin/sh\n")
        fake_bin.chmod(0o755)
        proc = _make_proc(stdout="not json at all", returncode=0)
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(AuditGateError):
                run_audit(fake_bin)


# --------------------------------------------------------------------------- #
# AC 8 — TOCTOU post-flight re-audit                                           #
# --------------------------------------------------------------------------- #


class TestAC8TOCTOUPostFlight:
    def test_snapshot_hashes_returns_sha256_per_file(self, tmp_path: Path) -> None:
        """AC 8: snapshot_hashes computes per-file SHA-256."""
        f = tmp_path / "openclaw.json"
        f.write_text('{"test": 1}')
        hashes = snapshot_hashes([str(f)])
        assert str(f) in hashes
        assert len(hashes[str(f)]) == 64  # hex SHA-256

    def test_snapshot_hashes_records_sentinel_for_unreadable_files(self) -> None:
        """AC 8: snapshot_hashes records UNREADABLE sentinel so TOCTOU guard still fires.

        Silently omitting unreadable files would allow a file that is unreadable
        at pre-flight but readable+modified at post-flight to produce identical
        dicts and bypass the guard.
        """
        hashes = snapshot_hashes(["/nonexistent/file.json"])
        assert hashes["/nonexistent/file.json"] == "UNREADABLE"

    def test_snapshot_hashes_treats_non_regular_file_as_unreadable(self, tmp_path: Path) -> None:
        """AC 8 / CR: snapshot_hashes must not open FIFOs or device files.

        Opening a FIFO without a writer blocks forever. The stat.S_ISREG guard
        must detect non-regular files and record the UNREADABLE sentinel instead
        of calling open(), preventing the audit gate from hanging indefinitely.
        """
        fifo = tmp_path / "openclaw.json"
        os.mkfifo(fifo)
        hashes = snapshot_hashes([str(fifo)])
        assert hashes[str(fifo)] == "UNREADABLE"


# --------------------------------------------------------------------------- #
# AC 9 — explicit binary resolution                                            #
# --------------------------------------------------------------------------- #


class TestAC9ExplicitBinaryResolution:
    def test_resolve_uses_env_var_when_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """AC 9: WORTHLESS_OPENCLAW_BIN env var takes precedence."""
        fake_bin = tmp_path / "openclaw"
        fake_bin.write_text("#!/bin/sh\n")
        fake_bin.chmod(0o755)
        monkeypatch.setenv("WORTHLESS_OPENCLAW_BIN", str(fake_bin))
        resolved = resolve_openclaw_bin()
        assert resolved == fake_bin

    def test_resolve_raises_without_absolute_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """AC 9: no env var, no absolute path → AuditGateError."""
        monkeypatch.delenv("WORTHLESS_OPENCLAW_BIN", raising=False)
        with patch("shutil.which", return_value=None):
            with pytest.raises(AuditGateError, match="openclaw"):
                resolve_openclaw_bin()

    def test_resolve_uses_which_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """AC 9: shutil.which result is used when env var absent."""
        monkeypatch.delenv("WORTHLESS_OPENCLAW_BIN", raising=False)
        fake_bin = tmp_path / "openclaw"
        fake_bin.write_text("#!/bin/sh\n")
        fake_bin.chmod(0o755)
        with patch("shutil.which", return_value=str(fake_bin)):
            resolved = resolve_openclaw_bin()
        assert resolved == fake_bin


# --------------------------------------------------------------------------- #
# AC 10 — doctor surface: worthless doctor reports exit-73 and exit-87 states #
# --------------------------------------------------------------------------- #


class TestAC10DoctorSurface:
    """AC 10: worthless doctor reports audit gate exit-73 and exit-87 states.

    Tests call the actual doctor check function (checks/openclaw._audit_gate_findings)
    with subprocess-layer mocks so no real openclaw binary is required.
    """

    def test_doctor_reports_exit_87_when_binary_unavailable(self) -> None:
        """Doctor surfaces exit-87 state when openclaw binary cannot be resolved."""
        from worthless.cli.commands.doctor.checks.openclaw import _audit_gate_findings

        with patch(
            "worthless.cli.commands.doctor.checks.openclaw._oc_audit.resolve_openclaw_bin",
            side_effect=AuditGateError("openclaw binary not found — set WORTHLESS_OPENCLAW_BIN"),
        ):
            findings = _audit_gate_findings()

        assert len(findings) == 1
        assert findings[0]["exit_code"] == 87
        assert "87" in findings[0]["issue"]
        assert "WORTHLESS_OPENCLAW_BIN" in findings[0]["remediation"]

    def test_doctor_reports_exit_87_when_audit_subprocess_fails(self) -> None:
        """Doctor surfaces exit-87 state when audit subprocess returns non-zero."""
        from worthless.cli.commands.doctor.checks.openclaw import _audit_gate_findings

        with (
            patch(
                "worthless.cli.commands.doctor.checks.openclaw._oc_audit.resolve_openclaw_bin",
                return_value=Path("/usr/local/bin/openclaw"),
            ),
            patch(
                "worthless.cli.commands.doctor.checks.openclaw._oc_audit.run_and_classify",
                side_effect=AuditGateError("openclaw secrets audit exited 1"),
            ),
        ):
            findings = _audit_gate_findings()

        assert len(findings) == 1
        assert findings[0]["exit_code"] == 87
        assert "87" in findings[0]["issue"]

    def test_doctor_reports_exit_73_for_plaintext_provider_key(self) -> None:
        """Doctor surfaces exit-73 state when plaintext API key is detected."""
        from worthless.openclaw.audit import AuditClassification

        from worthless.cli.commands.doctor.checks.openclaw import _audit_gate_findings

        blocking = (
            BlockingFinding(
                file="/home/user/.openclaw/openclaw.json",
                json_path="providers.anthropic.apiKey",
                provider="anthropic",
                message="plaintext key",
                source="audit",
            ),
        )
        mock_classification = AuditClassification(
            blocking=blocking,
            advisory_count=0,
            unknown_codes=(),
        )
        with (
            patch(
                "worthless.cli.commands.doctor.checks.openclaw._oc_audit.resolve_openclaw_bin",
                return_value=Path("/usr/local/bin/openclaw"),
            ),
            patch(
                "worthless.cli.commands.doctor.checks.openclaw._oc_audit.run_and_classify",
                return_value=(MagicMock(), mock_classification),
            ),
        ):
            findings = _audit_gate_findings()

        assert len(findings) == 1
        assert findings[0]["exit_code"] == 73
        assert "73" in findings[0]["issue"]
        assert findings[0]["json_path"] == "providers.anthropic.apiKey"
        assert "openclaw secrets configure" in findings[0]["remediation"]

    def test_doctor_returns_empty_findings_when_audit_clean(self) -> None:
        """Doctor reports no audit findings when gate would pass clean."""
        from worthless.openclaw.audit import AuditClassification

        from worthless.cli.commands.doctor.checks.openclaw import _audit_gate_findings

        mock_classification = AuditClassification(
            blocking=(),
            advisory_count=0,
            unknown_codes=(),
        )
        with (
            patch(
                "worthless.cli.commands.doctor.checks.openclaw._oc_audit.resolve_openclaw_bin",
                return_value=Path("/usr/local/bin/openclaw"),
            ),
            patch(
                "worthless.cli.commands.doctor.checks.openclaw._oc_audit.run_and_classify",
                return_value=(MagicMock(), mock_classification),
            ),
        ):
            findings = _audit_gate_findings()

        assert findings == []


# --------------------------------------------------------------------------- #
# AC 11 — fixture-driven: real audit schema round-trip                        #
# --------------------------------------------------------------------------- #


class TestAC11RealAuditFixture:
    def test_m0_audit_schema_parses_correctly(self) -> None:
        """AC 11: m0_audit_schema.json (real fixture) parses to 3 blocking findings."""
        raw = _load_fixture("m0_audit_schema.json")
        findings = tuple(
            AuditFinding(
                code=f["code"],
                severity=f["severity"],
                file=f["file"],
                json_path=f["jsonPath"],
                message=f["message"],
                provider=f.get("provider"),
            )
            for f in raw["findings"]
        )
        result = AuditResult(
            version=raw["version"],
            status=raw["status"],
            files_scanned=tuple(raw["filesScanned"]),
            plaintext_count=raw["summary"]["plaintextCount"],
            findings=findings,
        )
        classification = classify_findings(result)
        # gateway.auth.token is advisory; exactly the two provider keys are blocking
        blocking_paths = {b.json_path for b in classification.blocking}
        assert blocking_paths == {
            "providers.custom-api-openai-com.apiKey",
            "providers.anthropic.apiKey",
        }

    def test_m0_audit_schema_has_correct_structure(self) -> None:
        """AC 11: m0_audit_schema.json has required top-level keys."""
        raw = _load_fixture("m0_audit_schema.json")
        assert "filesScanned" in raw
        assert "findings" in raw
        assert "summary" in raw
        assert raw["summary"]["plaintextCount"] == 3


# --------------------------------------------------------------------------- #
# AC 12 — WOR-545 xfail test exists and is wired correctly                    #
# --------------------------------------------------------------------------- #


class TestAC12WOR545LoadBearingTestExists:
    def test_load_bearing_test_file_exists(self) -> None:
        """AC 12: test_proxy_load_bearing.py exists in the correct location."""
        test_file = Path(__file__).parent / "test_proxy_load_bearing.py"
        assert test_file.exists(), (
            "WOR-545: test_proxy_load_bearing.py must exist before Phase 1 merges"
        )

    def test_load_bearing_test_no_longer_carries_xfail(self) -> None:
        """AC 12 inversion: Phase 1 originally pinned ``xfail(strict=True)``
        on ``test_proxy_load_bearing.py`` because the proxy was bypassable.
        F1 fixed that (lock now rewrites the original entry to the proxy)
        and the xfail marker was removed when the test went green —
        per WOR-545's success criterion in the PR-1 plan.

        This meta-test inverts the original assertion: the marker must
        STAY removed so a regression that re-introduces it (silently
        accepting the WOR-514 bypass again) fails this gate.
        """
        test_file = Path(__file__).parent / "test_proxy_load_bearing.py"
        content = test_file.read_text()
        assert "xfail" not in content, (
            "WOR-545 regression: xfail marker must stay removed (F1 success "
            "criterion). Re-introducing it means the proxy bypass is back."
        )

    def test_load_bearing_test_wired_in_docker_security_workflow(self) -> None:
        """AC 12b: docker-security.yml runs the behavioral load-bearing test."""
        workflow = Path(__file__).resolve().parents[3] / ".github/workflows/docker-security.yml"
        content = workflow.read_text()
        assert "test_proxy_load_bearing.py" in content, (
            "WOR-621: load-bearing test must run in docker-security workflow"
        )
        assert "openclaw and docker" in content, (
            'load-bearing pytest step must pass -m "openclaw and docker" '
            "(pyproject addopts exclude docker/openclaw by default)"
        )
        assert "tests/openclaw/**" in content, (
            "docker-security paths must include tests/openclaw/**"
        )


# =========================================================================== #
# ADVERSARIAL TESTS                                                             #
# =========================================================================== #


class TestAdversarial:
    def test_adversarial_provider_named_worthless_evil_is_blocked(self) -> None:
        """Adv 1: provider named 'worthless-evil' (starts with 'worthless-')
        but NOT in exact allowlist → blocked. Pins security crit #1."""
        finding = AuditFinding(
            code="PLAINTEXT_FOUND",
            severity="warn",
            file="/home/node/.openclaw/openclaw.json",
            json_path="providers.worthless-evil.apiKey",
            message="worthless-evil.apiKey is stored as plaintext.",
            provider="worthless-evil",
        )
        result = AuditResult(
            version=1,
            status="findings",
            files_scanned=("/home/node/.openclaw/openclaw.json",),
            plaintext_count=1,
            findings=(finding,),
        )
        classification = classify_findings(result)
        # Must be blocking — "worthless-evil" is NOT in the exact allowlist
        blocking_paths = {b.json_path for b in classification.blocking}
        assert "providers.worthless-evil.apiKey" in blocking_paths

    def test_adversarial_path_traversal_in_file_field_exits_87(self) -> None:
        """Adv 2: PLAINTEXT_FOUND for a file not in filesScanned → exit 87 (inconsistent output).

        A rogue binary could suppress a real finding by emitting PLAINTEXT_FOUND but
        omitting the file from filesScanned. Treating this as advisory would let the
        gate pass. It must appear in unknown_codes so the caller raises AuditGateError.
        """
        evil_finding = AuditFinding(
            code="PLAINTEXT_FOUND",
            severity="warn",
            file="../../etc/passwd",
            json_path="providers.openai.apiKey",
            message="plaintext",
            provider="openai",
        )
        result = AuditResult(
            version=1,
            status="findings",
            files_scanned=("/home/node/.openclaw/openclaw.json",),
            plaintext_count=1,
            findings=(evil_finding,),
        )
        classification = classify_findings(result)
        assert len(classification.blocking) == 0
        assert "PLAINTEXT_FOUND[file_not_in_filesScanned]" in classification.unknown_codes, (
            "Out-of-scope PLAINTEXT_FOUND must appear in unknown_codes (→ exit 87), "
            f"got unknown_codes={classification.unknown_codes}"
        )

    def test_adversarial_control_chars_in_jsonpath_sanitised_in_message(self) -> None:
        """Adv 3: jsonPath with control chars → sanitised in error message."""
        evil_path = "providers.x.apiKey\x1b[31mRED\x1b[0m\nnewline"
        blocking = (
            BlockingFinding(
                file="/f",
                json_path=evil_path,
                provider="x",
                message="plaintext",
                source="audit",
            ),
        )
        msg = format_gate_error_message(blocking)
        # Injected terminal escapes, carriage returns, and null bytes must be stripped.
        # Structural \n from the multi-line message format is expected and allowed.
        assert "\x1b" not in msg  # ANSI terminal escape injection
        assert "\r" not in msg  # carriage return injection
        assert "\x00" not in msg  # null byte injection

    def test_adversarial_unknown_finding_code_blocks_default_deny(self) -> None:
        """Adv 4: unknown finding code → classify_findings records it as unknown
        (caller must raise AuditGateError — default-deny posture)."""
        unknown_finding = AuditFinding(
            code="FUTURE_UNKNOWN_CODE",
            severity="warn",
            file="/home/node/.openclaw/openclaw.json",
            json_path="providers.x.apiKey",
            message="unknown",
            provider="x",
        )
        result = AuditResult(
            version=1,
            status="findings",
            files_scanned=("/home/node/.openclaw/openclaw.json",),
            plaintext_count=0,
            findings=(unknown_finding,),
        )
        classification = classify_findings(result)
        assert "FUTURE_UNKNOWN_CODE" in classification.unknown_codes

    def test_adversarial_path_lookup_for_openclaw_binary_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Adv 5: fake 'openclaw' in $PATH (relative) → refused. Security crit #6."""
        monkeypatch.delenv("WORTHLESS_OPENCLAW_BIN", raising=False)
        # which returns a relative-looking path
        with patch("shutil.which", return_value="openclaw"):
            with pytest.raises(AuditGateError):
                resolve_openclaw_bin()

    def test_adversarial_symlink_loop_timeout_distinguishable_from_block(
        self, tmp_path: Path
    ) -> None:
        """Adv 6: subprocess hangs (symlink loop) → AuditGateError, NOT exit 73.
        User must be able to distinguish 'audit failed to run' from 'audit found plaintext'."""
        fake_bin = tmp_path / "openclaw"
        fake_bin.write_text("#!/bin/sh\n")
        fake_bin.chmod(0o755)
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="openclaw", timeout=30),
        ):
            with pytest.raises(AuditGateError) as exc_info:
                run_audit(fake_bin, timeout=0.001)
        # The error must clearly indicate subprocess failure, not plaintext
        assert exc_info.value.reason  # has a reason
        # Must NOT classify as BlockingFinding (exit-73 path)

    def test_adversarial_toctou_post_flight_catches_inserted_plaintext(
        self, tmp_path: Path
    ) -> None:
        """Adv 7: plaintext injected between pre-flight and apply_lock → exit 87.

        Tests the full _openclaw_audit_postflight path:
        1. Pre-flight snapshots file hash (clean)
        2. File is modified after pre-flight (attacker/race condition)
        3. Post-flight detects hash change, re-runs audit
        4. Audit returns blocking finding → postflight raises typer.Exit(87)
        """
        import typer

        from worthless.cli.commands.lock import (  # noqa: PLC2701
            _openclaw_audit_postflight,
        )
        from worthless.openclaw.audit import AuditClassification, AuditGateHandle

        f = tmp_path / "openclaw.json"
        f.write_text('{"version": 1}')

        # Pre-flight snapshot (clean file)
        gate = AuditGateHandle(
            openclaw_bin=Path("/usr/local/bin/openclaw"),
            pre_hashes=snapshot_hashes([str(f)]),
        )

        # Attacker injects plaintext after pre-flight snapshot
        f.write_text('{"version": 1, "injected": "sk-proj-evil000000000000000000000"}')

        # Post-flight runs audit and finds the injected key
        blocking = (
            BlockingFinding(
                file=str(f),
                json_path="providers.evil.apiKey",
                provider="evil",
                message="plaintext key injected",
                source="audit",
            ),
        )
        mock_classification = AuditClassification(
            blocking=blocking, advisory_count=0, unknown_codes=()
        )
        with patch(
            "worthless.cli.commands.lock._oc_audit.run_and_classify",
            return_value=(MagicMock(), mock_classification),
        ):
            with pytest.raises(typer.Exit) as exc_info:
                _openclaw_audit_postflight(gate)

        assert exc_info.value.exit_code == 87

    def test_adversarial_audit_clean_but_nonzero_exit_fails_closed(self, tmp_path: Path) -> None:
        """Adv 8: valid JSON 'no findings' but subprocess exits non-zero → AuditGateError.
        Must NOT silently proceed (qa #6)."""
        fake_bin = tmp_path / "openclaw"
        fake_bin.write_text("#!/bin/sh\n")
        fake_bin.chmod(0o755)
        clean_json = _audit_json([])
        proc = _make_proc(stdout=clean_json, returncode=1)
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(AuditGateError):
                run_audit(fake_bin)

    def test_adversarial_plaintext_in_non_canonical_auth_profile_field_still_blocks(
        self, tmp_path: Path
    ) -> None:
        """Adv 9: auth-profiles.json has plaintext key under accessToken (not .key/.token).
        Worthless must block on the file regardless of field name. Security crit #3."""
        auth = tmp_path / "auth-profiles.json"
        auth.write_text(
            json.dumps(
                {
                    "profiles": {
                        "x": {
                            "accessToken": ("sk-proj-realcachedkey0000000000000000000000000000000")
                        }
                    }
                }
            )
        )
        findings = check_auth_profiles_direct([str(auth)])
        assert len(findings) >= 1, "accessToken field with plaintext API key must be detected"

    def test_adversarial_decoy_openclaw_json_outside_scope_does_not_dos_gate(
        self, tmp_path: Path
    ) -> None:
        """Adv 10: /etc/evil/openclaw.json not in filesScanned[] → ignored.
        Worthless must use filesScanned[] not filename suffix. Security #4."""
        evil = tmp_path / "openclaw.json"
        evil.write_text('{"providers": {"evil": {"apiKey": "sk-proj-decoy000000000"}}}')
        # filesScanned[] does not include this file
        findings = check_auth_profiles_direct([])  # empty filesScanned
        assert len(findings) == 0


# =========================================================================== #
# GAP CLOSURE TESTS (worthless-avcd)                                           #
# Tests covering execution paths identified in post-review gap analysis.       #
# =========================================================================== #


# --------------------------------------------------------------------------- #
# parse_audit_result — schema guard (KeyError / TypeError paths)               #
# --------------------------------------------------------------------------- #


class TestParseAuditResult:
    def test_missing_version_key_raises_audit_gate_error(self) -> None:
        """parse_audit_result raises AuditGateError on missing 'version' key."""
        bad = {"status": "clean", "filesScanned": [], "summary": {}, "findings": []}
        with pytest.raises(AuditGateError, match="unexpected schema"):
            parse_audit_result(bad)

    def test_missing_finding_code_raises_audit_gate_error(self) -> None:
        """parse_audit_result raises AuditGateError when a finding lacks 'code'."""
        bad = {
            "version": 1,
            "status": "findings",
            "filesScanned": [],
            "summary": {"plaintextCount": 1},
            "findings": [
                # 'code' intentionally missing
                {"severity": "warn", "file": "/f", "jsonPath": "x", "message": "m"}
            ],
        }
        with pytest.raises(AuditGateError, match="unexpected schema"):
            parse_audit_result(bad)

    def test_findings_not_iterable_raises_audit_gate_error(self) -> None:
        """parse_audit_result raises AuditGateError when 'findings' is not a list."""
        bad = {
            "version": 1,
            "status": "findings",
            "filesScanned": [],
            "summary": {"plaintextCount": 0},
            "findings": "not-a-list",
        }
        with pytest.raises(AuditGateError, match="unexpected schema"):
            parse_audit_result(bad)

    def test_valid_payload_round_trips_correctly(self) -> None:
        """parse_audit_result maps camelCase wire fields to snake_case."""
        raw = _load_fixture("m0_audit_schema.json")
        result = parse_audit_result(raw)
        assert result.version == 1
        assert len(result.findings) == len(raw["findings"])
        # jsonPath → json_path mapping
        paths = {f.json_path for f in result.findings}
        assert "providers.anthropic.apiKey" in paths


# --------------------------------------------------------------------------- #
# resolve_openclaw_bin — relative WORTHLESS_OPENCLAW_BIN is rejected           #
# --------------------------------------------------------------------------- #


class TestResolveOpenclawBinRelativePath:
    def test_relative_env_var_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """resolve_openclaw_bin raises when WORTHLESS_OPENCLAW_BIN is not absolute.

        'openclaw' (no leading /) looks like a PATH lookup — accepting it would
        let an attacker in $PATH substitute a rogue binary. Must be rejected.
        """
        monkeypatch.setenv("WORTHLESS_OPENCLAW_BIN", "openclaw")
        with pytest.raises(AuditGateError, match="not an absolute path"):
            resolve_openclaw_bin()

    def test_dotslash_relative_env_var_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """./openclaw is relative — also rejected."""
        monkeypatch.setenv("WORTHLESS_OPENCLAW_BIN", "./openclaw")
        with pytest.raises(AuditGateError, match="not an absolute path"):
            resolve_openclaw_bin()


# --------------------------------------------------------------------------- #
# run_and_classify — end-to-end wiring                                         #
# --------------------------------------------------------------------------- #


class TestRunAndClassifyWiring:
    def test_files_scanned_threaded_to_auth_profiles_check(self, tmp_path: Path) -> None:
        """run_and_classify wires files_scanned from AuditResult into
        check_auth_profiles_direct — a wiring bug here would produce silent false-clean.

        Seeds an auth-profiles.json with a plaintext key.  The audit subprocess
        reports that file in filesScanned.  run_and_classify must surface the
        auth-profiles finding.
        """
        auth = tmp_path / "auth-profiles.json"
        auth.write_text(
            json.dumps(
                {
                    "profiles": {
                        "x": {"token": "sk-proj-realcachedkey0000000000000000000000000000000"}
                    }
                }
            )
        )
        # Subprocess returns clean audit result (no PLAINTEXT_FOUND from binary)
        # but filesScanned includes the auth-profiles path so direct-read fires.
        clean_payload = json.dumps(
            {
                "version": 1,
                "status": "clean",
                "resolution": {
                    "refsChecked": 0,
                    "skippedExecRefs": 0,
                    "resolvabilityComplete": True,
                },
                "filesScanned": [str(auth)],
                "summary": {
                    "plaintextCount": 0,
                    "unresolvedRefCount": 0,
                    "shadowedRefCount": 0,
                    "legacyResidueCount": 0,
                },
                "findings": [],
            }
        )
        proc = _make_proc(stdout=clean_payload)
        fake_bin = tmp_path / "openclaw"
        fake_bin.write_text("#!/bin/sh\n")
        fake_bin.chmod(0o755)

        with patch("subprocess.run", return_value=proc):
            _result, classification = run_and_classify(fake_bin)

        assert len(classification.blocking) == 1
        assert classification.blocking[0].source == "auth-profiles-direct"

    def test_clean_audit_and_clean_auth_profiles_returns_empty_classification(
        self, tmp_path: Path
    ) -> None:
        """run_and_classify returns empty blocking when both audit and auth-profiles are clean."""
        clean_payload = json.dumps(
            {
                "version": 1,
                "status": "clean",
                "resolution": {
                    "refsChecked": 0,
                    "skippedExecRefs": 0,
                    "resolvabilityComplete": True,
                },
                "filesScanned": [],
                "summary": {
                    "plaintextCount": 0,
                    "unresolvedRefCount": 0,
                    "shadowedRefCount": 0,
                    "legacyResidueCount": 0,
                },
                "findings": [],
            }
        )
        proc = _make_proc(stdout=clean_payload)
        fake_bin = tmp_path / "openclaw"
        fake_bin.write_text("#!/bin/sh\n")
        fake_bin.chmod(0o755)

        with patch("subprocess.run", return_value=proc):
            _result, classification = run_and_classify(fake_bin)

        assert len(classification.blocking) == 0
        assert len(classification.unknown_codes) == 0


# --------------------------------------------------------------------------- #
# Doctor — unknown_codes branch (default-deny security path)                   #
# --------------------------------------------------------------------------- #


class TestDoctorUnknownCodes:
    def test_doctor_reports_exit_87_for_unknown_finding_code(self) -> None:
        """Doctor surfaces exit-87 when classification contains unknown codes.

        This is the default-deny path: a future OpenClaw finding code that
        worthless doesn't recognise must block lock (exit 87), not silently pass.
        Without this test the doctor branch at openclaw.py:63-73 is unexercised.
        """
        from worthless.openclaw.audit import AuditClassification

        from worthless.cli.commands.doctor.checks.openclaw import _audit_gate_findings

        mock_classification = AuditClassification(
            blocking=(),
            advisory_count=0,
            unknown_codes=("FUTURE_UNKNOWN_CODE",),
        )
        with (
            patch(
                "worthless.cli.commands.doctor.checks.openclaw._oc_audit.resolve_openclaw_bin",
                return_value=Path("/usr/local/bin/openclaw"),
            ),
            patch(
                "worthless.cli.commands.doctor.checks.openclaw._oc_audit.run_and_classify",
                return_value=(MagicMock(), mock_classification),
            ),
        ):
            findings = _audit_gate_findings()

        assert len(findings) == 1
        assert findings[0]["exit_code"] == 87
        assert "FUTURE_UNKNOWN_CODE" in findings[0]["issue"]
        assert "87" in findings[0]["issue"]


# --------------------------------------------------------------------------- #
# _walk depth-limit guard in check_auth_profiles_direct                        #
# --------------------------------------------------------------------------- #


class TestAuthProfilesWalkDepth:
    def test_deeply_nested_dict_does_not_crash_or_leak(self, tmp_path: Path) -> None:
        """_walk stops at _AUTH_PROFILES_MAX_DEPTH — no recursion error, no CPU spin.

        Adversarially deep JSON (depth > limit) must produce zero findings
        (the walk stops before reaching string values), not a RecursionError.
        """
        # Build a dict nested _AUTH_PROFILES_MAX_DEPTH + 3 levels deep,
        # with a plaintext API key at the deepest level.
        nested: dict = {"key": "sk-proj-shouldnotbefound0000000000000000000000000000"}
        for _ in range(_AUTH_PROFILES_MAX_DEPTH + 3):
            nested = {"level": nested}

        auth = tmp_path / "auth-profiles.json"
        auth.write_text(json.dumps(nested))

        findings = check_auth_profiles_direct([str(auth)])
        # The key is buried beyond the max depth — must NOT be found
        assert len(findings) == 0, "Key nested beyond _AUTH_PROFILES_MAX_DEPTH must not be reported"

    def test_key_within_depth_limit_is_still_detected(self, tmp_path: Path) -> None:
        """Keys within _AUTH_PROFILES_MAX_DEPTH are still found (depth guard is a ceiling)."""
        # Nest exactly at max depth (should still be walked)
        nested: dict = {"key": "sk-proj-withinlimitkey0000000000000000000000000000"}
        for _ in range(_AUTH_PROFILES_MAX_DEPTH - 1):
            nested = {"level": nested}

        auth = tmp_path / "auth-profiles.json"
        auth.write_text(json.dumps(nested))

        findings = check_auth_profiles_direct([str(auth)])
        assert len(findings) == 1, "Key at max depth must be detected"


# --------------------------------------------------------------------------- #
# sanitise_for_message — direct assertion on bidi / BOM character classes      #
# --------------------------------------------------------------------------- #


class TestSanitiseForMessage:
    def test_c0_control_chars_stripped(self) -> None:
        """C0 control characters (U+0000–U+001F) and DEL are stripped."""
        assert sanitise_for_message("abc\x00\x01\x1f\x7fdef") == "abcdef"

    def test_c1_control_chars_stripped(self) -> None:
        """C1 control characters (U+0080–U+009F) are stripped."""
        assert sanitise_for_message("x\x80\x9fy") == "xy"

    def test_zero_width_marks_stripped(self) -> None:
        """Zero-width and direction marks (U+200B–U+200F) are stripped."""
        zwsp = "​"  # ZERO WIDTH SPACE
        zwnj = "‌"  # ZERO WIDTH NON-JOINER
        rlm = "‏"  # RIGHT-TO-LEFT MARK
        assert sanitise_for_message(f"a{zwsp}{zwnj}{rlm}b") == "ab"

    def test_bidi_embedding_overrides_stripped(self) -> None:
        """Bidi embedding/override characters (U+202A–U+202E) are stripped."""
        lre = "‪"  # LEFT-TO-RIGHT EMBEDDING
        rlo = "‮"  # RIGHT-TO-LEFT OVERRIDE
        assert sanitise_for_message(f"a{lre}b{rlo}c") == "abc"

    def test_bidi_isolates_stripped(self) -> None:
        """Bidi isolate characters (U+2066–U+2069) are stripped."""
        lri = "⁦"  # LEFT-TO-RIGHT ISOLATE
        pdi = "⁩"  # POP DIRECTIONAL ISOLATE
        assert sanitise_for_message(f"a{lri}b{pdi}c") == "abc"

    def test_bom_stripped(self) -> None:
        """BOM (U+FEFF) is stripped."""
        assert sanitise_for_message("﻿path/to/file") == "path/to/file"

    def test_clean_string_unchanged(self) -> None:
        """Normal ASCII strings pass through unchanged."""
        s = "/home/user/.openclaw/models.json"
        assert sanitise_for_message(s) == s


# --------------------------------------------------------------------------- #
# Non-providers.X.apiKey PLAINTEXT_FOUND scope (intentional advisory)          #
# --------------------------------------------------------------------------- #


class TestNonProviderPlaintextScope:
    def test_plaintext_found_at_non_provider_path_is_advisory(self) -> None:
        """PLAINTEXT_FOUND at a jsonPath that doesn't match providers.<X>.apiKey
        is classified as advisory, not blocking.

        This is intentional scope: worthless only gates on provider API keys in
        models.json. A finding at config.apiKey or settings.key is a future
        OpenClaw schema addition that worthless hasn't been told to handle.
        The comment in classify_findings documents this; this test pins it so
        a refactor can't silently change the behaviour.
        """
        finding = AuditFinding(
            code="PLAINTEXT_FOUND",
            severity="warn",
            file="/home/node/.openclaw/openclaw.json",
            json_path="config.apiKey",  # matches no known schema
            message="config.apiKey is stored as plaintext.",
            provider=None,
        )
        result = AuditResult(
            version=1,
            status="findings",
            files_scanned=("/home/node/.openclaw/openclaw.json",),
            plaintext_count=1,
            findings=(finding,),
        )
        classification = classify_findings(result)
        # Must be advisory, not blocking — intentional scope boundary
        assert len(classification.blocking) == 0
        assert classification.advisory_count == 1
        assert len(classification.unknown_codes) == 0
