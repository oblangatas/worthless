"""Permanent smoke tests for the worthless revoke lifecycle.

These invoke the real CLI via subprocess with an isolated WORTHLESS_HOME
and file-only keyring (WORTHLESS_KEYRING_BACKEND=null).  They replace
the ad-hoc shell script from worthless-u7hk so this coverage is never lost.

Run with: pytest -m e2e tests/smoke/test_smoke_revoke.py

Scenarios:
  A1 – fernet.key exists after 2 enrollments
  A2 – fernet.key survives a partial revoke (1 of 2 aliases)
  B1 – fernet.key is deleted after the last revoke
  C1 – re-enroll after full revoke recreates fernet.key (no WRTLS-102)
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from tests.helpers import fake_key

_WORKTREE_ROOT = Path(__file__).resolve().parents[2]

# WOR-582: subprocess.run(["uv", "run", "worthless", ...]) with no timeout hangs
# indefinitely under PEP 475 (SIGALRM can't interrupt waitpid). Route to the
# serial pass so a stuck subprocess doesn't wedge an xdist worker.
pytestmark = pytest.mark.real_ipc

# Split to avoid tripping secret scanners on a literal key prefix in source.
_OPENAI_PREFIX = "sk-" + "proj-"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alias(provider: str, value: str) -> str:
    """Compute alias from provider + first 8 hex chars of sha256(value)."""
    digest = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"{provider}-{digest}"


def _run(args: list[str], home: Path) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "WORTHLESS_HOME": str(home),
        "WORTHLESS_KEYRING_BACKEND": "null",
    }
    return subprocess.run(
        ["uv", "run", "worthless", *args],
        env=env,
        capture_output=True,
        text=True,
        cwd=_WORKTREE_ROOT,
        timeout=60,
    )


def _lock(env_file: Path, home: Path) -> subprocess.CompletedProcess[str]:
    return _run(["lock", "--env", str(env_file)], home)


def _revoke(alias: str, home: Path) -> subprocess.CompletedProcess[str]:
    return _run(["revoke", "--alias", alias], home)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def smoke_home(tmp_path: Path) -> Path:
    """Isolated WORTHLESS_HOME directory, unique per test run."""
    return tmp_path / ".worthless"


# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestSmokeRevoke:
    def test_a1_fernet_key_exists_after_two_enrollments(
        self, tmp_path: Path, smoke_home: Path
    ) -> None:
        """A1: bootstrapping two keys in the same home creates fernet.key."""
        key1 = fake_key(_OPENAI_PREFIX, seed="smoke-a1-key1")
        key2 = fake_key(_OPENAI_PREFIX, seed="smoke-a1-key2")

        env1 = tmp_path / "proj1" / ".env"
        env1.parent.mkdir()
        env1.write_text(f"OPENAI_API_KEY={key1}\n")
        r1 = _lock(env1, smoke_home)
        assert r1.returncode == 0, f"first lock failed:\n{r1.stdout}\n{r1.stderr}"

        env2 = tmp_path / "proj2" / ".env"
        env2.parent.mkdir()
        env2.write_text(f"OPENAI_API_KEY={key2}\n")
        r2 = _lock(env2, smoke_home)
        assert r2.returncode == 0, f"second lock failed:\n{r2.stdout}\n{r2.stderr}"

        assert (smoke_home / "fernet.key").exists(), "fernet.key must exist after 2 enrollments"

    def test_a2_fernet_key_survives_partial_revoke(self, tmp_path: Path, smoke_home: Path) -> None:
        """A2: revoking one of two enrolled aliases must not delete fernet.key."""
        key1 = fake_key(_OPENAI_PREFIX, seed="smoke-a2-key1")
        key2 = fake_key(_OPENAI_PREFIX, seed="smoke-a2-key2")
        alias1 = _make_alias("openai", key1)

        env1 = tmp_path / "proj1" / ".env"
        env1.parent.mkdir()
        env1.write_text(f"OPENAI_API_KEY={key1}\n")
        assert _lock(env1, smoke_home).returncode == 0

        env2 = tmp_path / "proj2" / ".env"
        env2.parent.mkdir()
        env2.write_text(f"OPENAI_API_KEY={key2}\n")
        assert _lock(env2, smoke_home).returncode == 0

        r = _revoke(alias1, smoke_home)
        assert r.returncode == 0, f"partial revoke failed:\n{r.stdout}\n{r.stderr}"

        assert (smoke_home / "fernet.key").exists(), (
            "fernet.key must survive when a second enrollment still exists"
        )

    def test_b1_fernet_key_deleted_after_last_revoke(
        self, tmp_path: Path, smoke_home: Path
    ) -> None:
        """B1: revoking the only enrolled alias deletes fernet.key from disk."""
        key1 = fake_key(_OPENAI_PREFIX, seed="smoke-b1-key1")
        alias1 = _make_alias("openai", key1)

        env1 = tmp_path / "proj1" / ".env"
        env1.parent.mkdir()
        env1.write_text(f"OPENAI_API_KEY={key1}\n")
        assert _lock(env1, smoke_home).returncode == 0
        assert (smoke_home / "fernet.key").exists(), "fernet.key should exist post-lock"

        r = _revoke(alias1, smoke_home)
        assert r.returncode == 0, f"last revoke failed:\n{r.stdout}\n{r.stderr}"

        assert not (smoke_home / "fernet.key").exists(), (
            "fernet.key must be deleted after last enrollment is revoked"
        )

    def test_c1_reenroll_after_full_revoke(self, tmp_path: Path, smoke_home: Path) -> None:
        """C1: re-enroll after a full revoke recreates fernet.key (no WRTLS-102)."""
        key1 = fake_key(_OPENAI_PREFIX, seed="smoke-c1-key1")
        alias1 = _make_alias("openai", key1)

        env1 = tmp_path / "proj1" / ".env"
        env1.parent.mkdir()
        env1.write_text(f"OPENAI_API_KEY={key1}\n")
        assert _lock(env1, smoke_home).returncode == 0

        r = _revoke(alias1, smoke_home)
        assert r.returncode == 0
        assert not (smoke_home / "fernet.key").exists()

        # Re-enroll: must succeed without WRTLS-102
        key2 = fake_key(_OPENAI_PREFIX, seed="smoke-c1-key2")
        env2 = tmp_path / "proj2" / ".env"
        env2.parent.mkdir()
        env2.write_text(f"OPENAI_API_KEY={key2}\n")
        r2 = _lock(env2, smoke_home)
        assert r2.returncode == 0, (
            f"re-enroll after full revoke failed (WRTLS-102?):\n{r2.stdout}\n{r2.stderr}"
        )
        assert (smoke_home / "fernet.key").exists(), "fernet.key must be recreated after re-enroll"
