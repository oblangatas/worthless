"""Black-box tests: entrypoint.sh exits 78 on unsafe deploy_mode combos."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ENTRYPOINT = Path(__file__).resolve().parents[1] / "deploy" / "entrypoint.sh"
EX_CONFIG = 78


@pytest.fixture
def stubbed_path(tmp_path: Path) -> dict[str, str]:
    """Build a PATH where `python` and `uvicorn` are no-op stubs.

    Lets the script run far enough to reach the case-statement / precheck
    without us caring whether the bootstrap or exec succeed.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # Stub binaries echo their args and exit 0 — `set -e` in the script
    # treats them as success.
    for name in ("python", "uvicorn"):
        stub = bin_dir / name
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Provide /bin tools (sh, install, chmod, etc.) by prepending to system PATH.
    sys_path = os.environ.get("PATH", "/usr/bin:/bin")
    return {"PATH": f"{bin_dir}:{sys_path}"}


def _run(env: dict[str, str], home: Path) -> subprocess.CompletedProcess[str]:
    """Invoke the entrypoint with a clean env + tmp HOME and return result."""
    full_env = {
        **env,
        "WORTHLESS_HOME": str(home),
        # Touch a fake fernet so the script skips bootstrap + chmod.
        "WORTHLESS_FERNET_KEY_PATH": str(home / "fernet.key"),
    }
    (home / "fernet.key").write_bytes(b"fake-key-for-test")
    sh = shutil.which("sh") or "/bin/sh"
    return subprocess.run(  # noqa: S603 — args list is fully checked-in
        [sh, str(ENTRYPOINT)],
        env=full_env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    return h


@pytest.mark.skipif(shutil.which("sh") is None, reason="POSIX sh required")
class TestEntrypointPrecheck:
    def test_public_with_allow_insecure_exits_78(
        self, stubbed_path: dict[str, str], home: Path
    ) -> None:
        result = _run(
            {
                **stubbed_path,
                "WORTHLESS_DEPLOY_MODE": "public",
                "WORTHLESS_ALLOW_INSECURE": "true",
                "WORTHLESS_TRUSTED_PROXIES": "10.0.0.0/8",
            },
            home,
        )
        assert result.returncode == EX_CONFIG, result.stderr
        assert "WORTHLESS_ALLOW_INSECURE is forbidden" in result.stderr

    def test_public_without_trusted_proxies_exits_78(
        self, stubbed_path: dict[str, str], home: Path
    ) -> None:
        result = _run(
            {**stubbed_path, "WORTHLESS_DEPLOY_MODE": "public"},
            home,
        )
        assert result.returncode == EX_CONFIG, result.stderr
        assert "requires WORTHLESS_TRUSTED_PROXIES" in result.stderr

    def test_unknown_mode_exits_78(self, stubbed_path: dict[str, str], home: Path) -> None:
        result = _run(
            {**stubbed_path, "WORTHLESS_DEPLOY_MODE": "wide-open"},
            home,
        )
        assert result.returncode == EX_CONFIG, result.stderr
        assert "unknown WORTHLESS_DEPLOY_MODE" in result.stderr

    def test_public_with_proxies_passes_precheck(
        self, stubbed_path: dict[str, str], home: Path
    ) -> None:
        """Valid public combo runs through to the stubbed uvicorn (rc=0)."""
        result = _run(
            {
                **stubbed_path,
                "WORTHLESS_DEPLOY_MODE": "public",
                "WORTHLESS_TRUSTED_PROXIES": "10.0.0.0/8",
            },
            home,
        )
        assert result.returncode == 0, result.stderr

    def test_loopback_default_passes_precheck(
        self, stubbed_path: dict[str, str], home: Path
    ) -> None:
        result = _run({**stubbed_path}, home)  # no MODE set
        assert result.returncode == 0, result.stderr
