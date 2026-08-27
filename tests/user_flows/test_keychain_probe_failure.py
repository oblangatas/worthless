"""WOR-835: a keychain probe that cannot run is disclosed, on a real Mac.

THIS IS the ``user_flow`` half of WOR-835 (its third acceptance criterion).
The unit tests in ``tests/openclaw/test_unshardable_credentials.py`` monkeypatch
``subprocess.run``, so they prove the branching but never execute a real
process. This file executes one: a real binary, spawned by the real
``subprocess`` machinery, driven by the real CLI, asserted on the real rendered
output.

THIS IS NOT a test that touches your keychain. It never adds, reads, or deletes
a keychain item, and it never runs ``lock`` (which writes real keys under this
lane's real-keyring fixture). It points the probe at a stand-in binary that
fails on purpose, and runs the read-only ``doctor --json``. That distinction is
not fussiness — an earlier review of this very change left a stray credential
on a maintainer's login keychain, which is exactly the mess a "live keychain
test" invites if written carelessly.

Deliberately NOT gated behind ``WORTHLESS_TEST_KEYCHAIN_READY`` like
``test_keychain_macos_writes.py``: that guard exists because real-keychain
*writes* hang on headless CI. Nothing here goes near the keychain, so it runs
on every macOS runner.
"""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.openclaw import unshardable_credentials as uc

pytestmark = [
    pytest.mark.user_flow,
    pytest.mark.skipif(
        sys.platform != "darwin",
        reason="the keychain probe only runs on macOS; elsewhere it is ABSENT by design",
    ),
]

runner = CliRunner()


def _failing_security(tmp_path: Path, exit_code: int) -> Path:
    """A real, executable stand-in for /usr/bin/security that always fails.

    Exit 51 is errSecAuthFailed's truncated status — a genuine "could not
    answer", distinct from 44 ("no item visible"), so it must produce a caveat.
    """
    script = tmp_path / "security"
    script.write_text(f"#!/bin/sh\nexit {exit_code}\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def _unshardable_check(payload: dict) -> dict:
    checks = payload.get("checks", [])
    entries = list(checks.values()) if isinstance(checks, dict) else checks
    for entry in entries:
        if "unshardable" in json.dumps(entry):
            return entry
    raise AssertionError(f"no unshardable-credentials check in payload: {list(payload)}")


def test_a_real_failing_security_binary_is_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The headline claim, end to end: a probe that could not answer says so.

    Nothing is mocked below the CLI — ``subprocess.run`` really forks, really
    execs the script above, and really collects its exit status.
    """
    monkeypatch.setattr(uc, "_SECURITY_BIN", str(_failing_security(tmp_path, 51)))

    result = runner.invoke(app, ["doctor", "--json"])

    assert result.exit_code in (0, 1), result.output
    check = _unshardable_check(json.loads(result.stdout))
    caveats = check.get("caveats") or []
    assert caveats, f"a probe that could not run must be disclosed, got: {check}"
    assert any("could not be checked" in c for c in caveats), caveats
    assert any("keychain" in c.lower() for c in caveats), caveats
    assert any("51" in c for c in caveats), (
        "the caveat should carry the actual failure reason, not a generic message"
    )


def test_a_missing_security_binary_is_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other real-world shape: the binary is not there at all.

    A genuine FileNotFoundError out of the OS, not a raised stub.
    """
    monkeypatch.setattr(uc, "_SECURITY_BIN", str(tmp_path / "definitely-not-here"))

    result = runner.invoke(app, ["doctor", "--json"])

    assert result.exit_code in (0, 1), result.output
    caveats = _unshardable_check(json.loads(result.stdout)).get("caveats") or []
    assert any("could not be checked" in c for c in caveats), caveats


def test_the_real_security_binary_stays_quiet_on_a_clean_machine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The false-alarm guard, against the genuine /usr/bin/security.

    Read-only: it looks up a service name that cannot exist. If this ever
    starts emitting a caveat, every real Mac has just been handed noise it
    must learn to ignore — which would destroy the value of the caveat that
    the tests above prove we emit.
    """
    if not Path(uc._SECURITY_BIN).exists():  # pragma: no cover - macOS always has it
        pytest.skip(f"{uc._SECURITY_BIN} is absent on this host")

    absent = "worthless-wor835-service-that-cannot-exist"
    monkeypatch.setattr(uc, "CLAUDE_CLI_KEYCHAIN_SERVICE", absent)
    monkeypatch.setattr(uc, "CODEX_CLI_KEYCHAIN_SERVICE", absent)

    caveats: list[str] = []
    probe = uc._keychain_probe(absent, caveats)

    assert probe is uc.KeychainProbe.ABSENT, (
        "a real lookup of a non-existent service is a definite answer, not a gap"
    )
    assert caveats == [], f"a clean machine must gain no new noise, got: {caveats}"
