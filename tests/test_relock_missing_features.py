"""TDD red-phase tests for two unimplemented features.

Feature 1 (Tests 1-2): Alias collision warning when ``worthless lock`` is run
    on an API key whose alias already exists in the DB from a DIFFERENT .env path.
    The command should warn the user and still succeed (exit 0).

Feature 2 (Tests 3-5): ``worthless doctor`` detects stale openclaw.json apiKey —
    i.e. openclaw.json's ``apiKey`` for a worthless provider no longer reconstructs
    correctly with shard-B stored in the DB.

All five tests are FAILING by design (RED phase). They define the contract for
the two missing features and will become green once those features are implemented.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from pathlib import Path

from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome, ensure_home
from worthless.crypto.splitter import split_key_fp
from worthless.storage.repository import ShardRepository, StoredShard

from tests.helpers import fake_openai_key

import pytest

pytestmark = pytest.mark.skip(reason="WOR-549: worthless-16x2 ↔ sidecar IPC integration pending")

# mix_stderr=False so CLI output to stderr doesn't bleed into result.output
runner = CliRunner(mix_stderr=False)

_PROVIDER = "openai"
_BASE_URL = "https://api.openai.com/v1"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _home_env(home: WorthlessHome) -> dict[str, str]:
    """Return env dict that pins WORTHLESS_HOME to *home*."""
    return {"WORTHLESS_HOME": str(home.base_dir)}


def _make_env_file(directory: Path, key: str) -> Path:
    """Write a minimal .env file containing one OPENAI_API_KEY line."""
    env_file = directory / ".env"
    env_file.write_text(f"OPENAI_API_KEY={key}\n")
    return env_file


def _lock_env(home: WorthlessHome, env_file: Path) -> object:
    """Run ``worthless lock --env <path>`` and return the CliRunner result."""
    return runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env=_home_env(home),
    )


def _doctor(home: WorthlessHome, extra_env: dict[str, str] | None = None) -> object:
    """Run ``worthless doctor`` and return the CliRunner result."""
    env = {**_home_env(home), **(extra_env or {})}
    return runner.invoke(
        app,
        ["doctor"],
        env=env,
    )


def _make_repo(home: WorthlessHome) -> ShardRepository:
    return ShardRepository(str(home.db_path), home.fernet_key)


# ---------------------------------------------------------------------------
# Feature 1 — Alias collision warning
# ---------------------------------------------------------------------------


class TestAliasCollisionWarning:
    """Tests 1-2: cross-.env-path alias collision warning.

    Feature 1 is NOT implemented: when the same API key is locked from two
    different .env files the second lock silently succeeds without telling
    the user that the alias was already enrolled from a different path.
    """

    def test_lock_warns_when_alias_already_enrolled_different_path(self, tmp_path: Path) -> None:
        """Test 1 — RED: second lock from env_b warns about the original env_a path.

        Contract:
        - Enroll the same API key from env_a (first lock, succeeds silently).
        - Lock the same key again from env_b (different .env, same key → same alias).
        - The second invocation MUST print a warning that:
            a) names the alias (e.g. "openai-XXXX")
            b) names the original .env path (env_a)
        - Exit code MUST be 0 (warning, not error).

        FAILS today: lock re-locks silently with no cross-path collision notice.
        """
        home = ensure_home(tmp_path / ".worthless")

        # Shared key → shared alias
        key = fake_openai_key()

        project_a = tmp_path / "project_a"
        project_b = tmp_path / "project_b"
        project_a.mkdir()
        project_b.mkdir()

        env_a = _make_env_file(project_a, key)
        env_b = _make_env_file(project_b, key)

        # First lock — enrolls from env_a
        result_a = _lock_env(home, env_a)
        assert result_a.exit_code == 0, (  # type: ignore[union-attr]
            f"First lock failed: {result_a.output}\n{result_a.stderr}"  # type: ignore[union-attr]
        )

        # Second lock — same key, different path
        result_b = _lock_env(home, env_b)

        # Must exit 0 (warning, not error)
        assert result_b.exit_code == 0, (  # type: ignore[union-attr]
            "Second lock should succeed (exit 0) even with alias collision.\n"
            f"stdout: {result_b.output}\nstderr: {result_b.stderr}"  # type: ignore[union-attr]
        )

        combined = (result_b.output or "") + (result_b.stderr or "")  # type: ignore[union-attr]

        # Must mention the alias name
        assert "openai-" in combined, (
            "Expected alias name (openai-XXXX) in output.\n"
            f"stdout: {result_b.output}\nstderr: {result_b.stderr}"  # type: ignore[union-attr]
        )

        # Must mention the original enrollment path (env_a).
        # Rich may wrap long paths across lines — remove newlines before the
        # substring check so a wrapped path still matches its full form.
        combined_no_wrap = combined.replace("\n", "")
        assert str(env_a) in combined_no_wrap, (
            f"Expected original .env path '{env_a}' in collision warning.\n"
            f"stdout: {result_b.output}\nstderr: {result_b.stderr}"  # type: ignore[union-attr]
        )

        # Must contain a recognisable warning signal
        combined_lower = combined.lower()
        assert any(
            phrase in combined_lower
            for phrase in ("already enrolled", "collision", "break", "re-lock")
        ), (
            "Expected collision warning phrase not found in output.\n"
            f"stdout: {result_b.output}\nstderr: {result_b.stderr}"  # type: ignore[union-attr]
        )

    def test_lock_no_warning_when_relocking_same_path(self, tmp_path: Path) -> None:
        """Test 2 — GREEN (WOR-504): same-path re-lock must not emit a collision warning.

        Feature 1 is now implemented (WOR-504): same-path re-lock emits
        "[OK] N key(s) still protected." and does NOT produce the cross-path
        "already enrolled from /other/path" warning.
        """
        home = ensure_home(tmp_path / ".worthless")
        key = fake_openai_key()
        env_a = _make_env_file(tmp_path, key)

        # First lock
        result_a = _lock_env(home, env_a)
        assert result_a.exit_code == 0, (  # type: ignore[union-attr]
            f"First lock failed: {result_a.output}\n{result_a.stderr}"  # type: ignore[union-attr]
        )

        # Re-lock same path — must succeed and NOT produce a collision warning
        result_b = _lock_env(home, env_a)

        combined = (result_b.output or "") + (result_b.stderr or "")  # type: ignore[union-attr]
        combined_lower = combined.lower()

        # The cross-path collision warning must NOT appear for same-path re-lock
        assert "already enrolled from" not in combined_lower, (
            "Collision warning must not appear when re-locking the SAME path.\n"
            f"stdout: {result_b.output}\nstderr: {result_b.stderr}"  # type: ignore[union-attr]
        )

        # Feature 1 (WOR-504): must emit a same-path re-lock confirmation line.
        # Delivered as "[OK] N key still protected." / "[OK] N keys still protected."
        assert any(
            phrase in combined_lower
            for phrase in ("re-lock", "same path", "re-enrolled", "updated", "still protected")
        ), (
            "Feature 1 must emit a same-path re-lock confirmation.\n"
            f"stdout: {result_b.output}\nstderr: {result_b.stderr}"  # type: ignore[union-attr]
        )


# ---------------------------------------------------------------------------
# Feature 2 — Doctor openclaw consistency check
# ---------------------------------------------------------------------------


def _inject_openclaw_state(
    openclaw_dir: Path,
    *,
    provider_name: str,
    api_key: str,
    alias: str,
    proxy_port: int = 8787,
) -> Path:
    """Write a minimal openclaw.json with one worthless provider entry.

    Uses the canonical format that ``_read_worthless_providers_from_config``
    accepts (flat ``providers`` key, provider name prefixed ``worthless-``).
    The baseUrl encodes the alias so ``_alias_from_base_url`` can extract it.
    """
    proxy_url = f"http://127.0.0.1:{proxy_port}/{alias}/v1"
    config = {
        "providers": {
            provider_name: {
                "apiKey": api_key,
                "baseUrl": proxy_url,
                "type": "openai",
            }
        }
    }
    config_path = openclaw_dir / "openclaw.json"
    openclaw_dir.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2))
    return config_path


def _get_first_alias(home: WorthlessHome) -> str:
    """Return the first enrolled alias from the DB."""
    repo = _make_repo(home)

    async def _query():
        await repo.initialize()
        enrollments = await repo.list_enrollments()
        assert enrollments, "No enrollments in DB"
        return enrollments[0].key_alias

    return asyncio.run(_query())


class TestDoctorOpenclawConsistency:
    """Tests 3-5: doctor detects stale openclaw.json apiKey.

    These tests bypass the ``detect()`` call by injecting a fake
    IntegrationState pointing at a test-controlled openclaw.json file.
    They call ``_check_openclaw_apikey_consistency`` directly (unit-level)
    so they are not dependent on the host machine having OpenClaw installed.
    """

    def test_doctor_warns_openclaw_apikey_stale_after_relock(self, tmp_path: Path) -> None:
        """Test 3 — RED: _check_openclaw_apikey_consistency returns issues when shard-B changed.

        Setup:
        1. Lock a key → derive the shard-A value (it would be in openclaw.json).
        2. Directly upsert a NEW shard pair (B₂) into the DB using a mutated key,
           leaving openclaw.json with the OLD shard-A₁.
        3. Call _check_openclaw_apikey_consistency with the stale openclaw.json.

        Expected: non-empty issues list containing a stale/out-of-sync message.

        FAILS today IF the consistency check does not exist or does not detect
        shard-B replacement (without corresponding openclaw.json update).
        """
        from worthless.cli.commands.doctor import _check_openclaw_apikey_consistency
        from worthless.openclaw.integration import IntegrationState

        home = ensure_home(tmp_path / ".worthless")
        key = fake_openai_key()
        env_a = _make_env_file(tmp_path, key)

        # Step 1: Lock → DB has shard-B₁; derive shard-A₁ to put in openclaw.json
        result = _lock_env(home, env_a)
        assert result.exit_code == 0, f"Lock failed: {result.output}\n{result.stderr}"  # type: ignore[union-attr]

        alias = _get_first_alias(home)
        repo = _make_repo(home)

        # Step 2: upsert a NEW corrupted shard-B₂ directly, WITHOUT updating openclaw.json
        sr2 = split_key_fp(key, prefix="sk-proj-", provider=_PROVIDER)
        new_b = bytearray(sr2.shard_b)
        new_b[0] ^= 0xFF  # one-byte flip → reconstruction from old shard-A₁ will fail

        async def _replace_shard():
            await repo.initialize()
            stored = StoredShard(
                shard_b=new_b,
                commitment=bytearray(sr2.commitment),
                nonce=bytearray(sr2.nonce),
                provider=_PROVIDER,
            )
            await repo.upsert_locked_shard(
                alias,
                stored,
                prefix=sr2.prefix,
                charset=sr2.charset,
                base_url=_BASE_URL,
            )

        asyncio.run(_replace_shard())

        # Step 3: openclaw.json still carries the original shard-A₁ (old api key value)
        # Re-read the ORIGINAL shard-A from the .env (lock replaces the plaintext with shard-A)
        env_contents = env_a.read_text()
        shard_a_value = env_contents.split("OPENAI_API_KEY=")[1].split("\n")[0].strip()

        openclaw_dir = tmp_path / ".openclaw"
        config_path = _inject_openclaw_state(
            openclaw_dir,
            provider_name="worthless-openai",
            api_key=shard_a_value,  # OLD shard-A₁ — stale after shard-B₂ upsert
            alias=alias,
        )

        state = IntegrationState(
            present=True,
            config_path=config_path,
            workspace_path=None,
            skill_path=None,
            home_dir=openclaw_dir,
            notes=(),
        )

        issues = _check_openclaw_apikey_consistency(state, repo)

        # Must detect the mismatch
        assert len(issues) > 0, (
            "Expected _check_openclaw_apikey_consistency to return at least one issue "
            "when shard-B was replaced without updating openclaw.json.\n"
            f"alias={alias}, issues={issues}"
        )
        issues_text = " ".join(issues).lower()
        assert any(
            phrase in issues_text
            for phrase in ("stale", "out of sync", "mismatch", "re-run", "re-lock")
        ), f"Issue message does not describe the problem clearly: {issues}"

    def test_doctor_passes_openclaw_consistent(self, tmp_path: Path) -> None:
        """Test 4 — RED: _check_openclaw_apikey_consistency returns empty when consistent.

        After a normal lock:
        - openclaw.json has the shard-A value as apiKey
        - DB has shard-B
        - Reconstruction succeeds

        The function must return an empty list (no issues).

        This test is RED because _check_openclaw_apikey_consistency currently
        fails to distinguish a valid shard-A from an arbitrary string — it uses
        a reconstruction attempt, but the shard-A value in the post-lock .env
        is the format-preserved shard, not the original key. The function must
        accept the FP-encoded shard-A as input and verify it correctly.

        FAILS if the consistency check raises or returns spurious issues for a
        healthy enrollment.
        """
        from worthless.cli.commands.doctor import _check_openclaw_apikey_consistency
        from worthless.openclaw.integration import IntegrationState

        home = ensure_home(tmp_path / ".worthless")
        key = fake_openai_key()
        env_a = _make_env_file(tmp_path, key)

        result = _lock_env(home, env_a)
        # 0 = clean, 73 = lock core OK but OpenClaw integration failed (skill dir
        # conflict from parallel test runs).  Both mean the DB has shard-B and .env
        # has shard-A — which is all this test cares about.
        assert result.exit_code in (0, 73), (  # type: ignore[union-attr]
            f"Lock failed: {result.output}\n{result.stderr}"  # type: ignore[union-attr]
        )

        alias = _get_first_alias(home)
        repo = _make_repo(home)

        # Read the shard-A value that lock wrote into .env
        env_contents = env_a.read_text()
        shard_a_value = env_contents.split("OPENAI_API_KEY=")[1].split("\n")[0].strip()

        openclaw_dir = tmp_path / ".openclaw"
        config_path = _inject_openclaw_state(
            openclaw_dir,
            provider_name="worthless-openai",
            api_key=shard_a_value,  # correct shard-A₁
            alias=alias,
        )

        state = IntegrationState(
            present=True,
            config_path=config_path,
            workspace_path=None,
            skill_path=None,
            home_dir=openclaw_dir,
            notes=(),
        )

        issues = _check_openclaw_apikey_consistency(state, repo)

        # Healthy enrollment → zero issues
        assert issues == [], (
            "Expected no consistency issues for a correct openclaw.json apiKey.\n"
            f"alias={alias}, shard_a_in_env={shard_a_value!r}\nissues={issues}"
        )

    def test_doctor_warns_openclaw_apikey_completely_wrong(self, tmp_path: Path) -> None:
        """Test 5 — RED: _check_openclaw_apikey_consistency warns when apiKey is garbage.

        Simulates an external tool (e.g. Crestodian) reverting openclaw.json
        to a placeholder / random value that was never a valid shard-A.

        Expected: issues list is non-empty and the message is actionable.

        FAILS today if the consistency function silently ignores non-parseable
        apiKey values or crashes instead of returning an issue.
        """
        from worthless.cli.commands.doctor import _check_openclaw_apikey_consistency
        from worthless.openclaw.integration import IntegrationState

        home = ensure_home(tmp_path / ".worthless")
        key = fake_openai_key()
        env_a = _make_env_file(tmp_path, key)

        result = _lock_env(home, env_a)
        assert result.exit_code == 0, f"Lock failed: {result.output}\n{result.stderr}"  # type: ignore[union-attr]

        alias = _get_first_alias(home)
        repo = _make_repo(home)

        # Garbage apiKey — not a valid shard-A under any circumstances
        garbage_key = "sk-NOT-A-REAL-SHARD-" + secrets.token_hex(24)

        openclaw_dir = tmp_path / ".openclaw"
        config_path = _inject_openclaw_state(
            openclaw_dir,
            provider_name="worthless-openai",
            api_key=garbage_key,
            alias=alias,
        )

        state = IntegrationState(
            present=True,
            config_path=config_path,
            workspace_path=None,
            skill_path=None,
            home_dir=openclaw_dir,
            notes=(),
        )

        issues = _check_openclaw_apikey_consistency(state, repo)

        # Must detect the garbage apiKey as stale/invalid
        assert len(issues) > 0, (
            "Expected _check_openclaw_apikey_consistency to return issues for "
            "a garbage apiKey value.\n"
            f"alias={alias}, garbage_key={garbage_key!r}, issues={issues}"
        )

        issues_text = " ".join(issues).lower()
        assert any(
            phrase in issues_text
            for phrase in ("stale", "out of sync", "invalid", "mismatch", "re-run", "re-lock")
        ), f"Issue message does not describe the problem clearly: {issues}"


# ---------------------------------------------------------------------------
# worthless-4lsv: _check_openclaw_apikey_consistency hardening (RED tests)
# ---------------------------------------------------------------------------


class TestOpencawConsistencyHardening:
    """worthless-4lsv TDD red phase.

    _check_openclaw_apikey_consistency must:
    1. Refuse to read a symlinked config_path (re-introduces the attack vector
       that health_check() intentionally blocks via F-CFG-15).
    2. Report aliases present in openclaw.json but absent from the DB as an
       explicit issue — not silently skip them.
    """

    def test_consistency_check_refuses_symlinked_config_path(self, tmp_path: Path) -> None:
        """_check_openclaw_apikey_consistency must surface a symlink as an issue.

        health_check() records a note when config_path is a symlink (F-CFG-15)
        rather than following the link.  The consistency check must do the same —
        reading through a symlinked openclaw.json is the exact attack surface
        F-CFG-15 closes.

        Setup:
        - Lock a real key so the DB has a valid enrollment.
        - Create a symlinked openclaw.json pointing at a real file that contains
          a worthless-* provider entry with a GARBAGE apiKey for that alias.
        - Call _check_openclaw_apikey_consistency with config_path = symlink.

        Without the guard the function follows the symlink, reads the garbage
        apiKey, and returns ["stale apiKey"]. With the guard it must instead
        return an issue mentioning "symlink" (or at minimum "refused" / "safe").

        RED: today the function reads through the symlink without any guard.
        """
        import json as _json

        from worthless.cli.commands.doctor import _check_openclaw_apikey_consistency
        from worthless.openclaw.integration import IntegrationState

        home = ensure_home(tmp_path / ".worthless")
        env_file = tmp_path / ".env"
        env_file.write_text("OPENAI_API_KEY=sk-symlink-test-abcdef1234567890\n")
        _lock_env(home, env_file)

        alias = _get_first_alias(home)
        repo = _make_repo(home)

        openclaw_dir = tmp_path / ".openclaw"
        openclaw_dir.mkdir(parents=True, exist_ok=True)

        # Real target file — contains a garbage apiKey for the enrolled alias.
        # Without the symlink guard the function reads this, fails reconstruct,
        # and returns a "stale apiKey" issue (not a symlink issue).
        real_target = openclaw_dir / "real_openclaw.json"
        real_target.write_text(
            _json.dumps(
                {
                    "models": {
                        "providers": {
                            "worthless-openai": {
                                "apiKey": "sk-GARBAGE-NOT-A-REAL-SHARD",
                                "baseUrl": f"http://localhost:8787/{alias}/v1",
                            }
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        # Symlink → target (the attack vector)
        symlink_config = openclaw_dir / "openclaw.json"
        symlink_config.symlink_to(real_target)

        state = IntegrationState(
            present=True,
            config_path=symlink_config,  # symlinked path
            workspace_path=None,
            skill_path=None,
            home_dir=openclaw_dir,
            notes=(),
        )

        issues = _check_openclaw_apikey_consistency(state, repo)

        # Must surface the symlink, not silently read through it
        assert len(issues) > 0, "Expected at least one issue for a symlinked config_path, got none."
        issues_text = " ".join(issues).lower()
        assert "symlink" in issues_text or "refused" in issues_text, (
            f"Issue must mention 'symlink' or 'refused', got: {issues}\n"
            "Returning a 'stale apiKey' issue instead means the function "
            "followed the symlink — the guard is missing."
        )

    def test_consistency_check_reports_missing_db_alias(self, tmp_path: Path) -> None:
        """Alias in openclaw.json but absent from DB → explicit issue, not silent skip.

        The current implementation has:
            except Exception:  # noqa: S112 — fetch failure skipped
                continue

        This silently swallows DB lookup failures, letting doctor report clean
        OpenClaw section even when openclaw.json refers to an alias that was never
        enrolled or was deleted from the DB.  The missing alias must be surfaced.

        RED: today the function silently skips aliases whose fetch_encrypted() returns
        None or raises, and the issues list comes back empty.
        """
        import json as _json

        from worthless.cli.commands.doctor import _check_openclaw_apikey_consistency
        from worthless.openclaw.integration import IntegrationState

        home = ensure_home(tmp_path / ".worthless")
        repo = ShardRepository(str(home.db_path), home.fernet_key)
        asyncio.run(repo.initialize())

        # openclaw.json references an alias that is NOT in the DB
        openclaw_dir = tmp_path / ".openclaw"
        openclaw_dir.mkdir(parents=True, exist_ok=True)
        config_path = openclaw_dir / "openclaw.json"
        config_path.write_text(
            _json.dumps(
                {
                    "models": {
                        "providers": {
                            "worthless-openai": {
                                "apiKey": "sk-some-shard-a",
                                "baseUrl": "http://localhost:8787/worthless-openai/v1",
                            }
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        state = IntegrationState(
            present=True,
            config_path=config_path,
            workspace_path=None,
            skill_path=None,
            home_dir=openclaw_dir,
            notes=(),
        )

        issues = _check_openclaw_apikey_consistency(state, repo)

        assert len(issues) > 0, (
            "Expected _check_openclaw_apikey_consistency to return an issue "
            "for an alias present in openclaw.json but absent from the DB. "
            "Silent skip masks a configuration error and lets doctor pass clean "
            "when keys are actually unresolvable.\n"
            f"issues={issues}"
        )
        issues_text = " ".join(issues).lower()
        assert any(
            phrase in issues_text
            for phrase in ("not found", "missing", "no db", "not enrolled", "re-lock", "re-run")
        ), f"Issue must describe the missing-alias problem clearly: {issues}"
