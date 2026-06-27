"""Shared CLI-test helpers and fixtures.

Consolidates the helper functions and ``env_file`` fixture used by both
``test_state_machine.py`` and ``test_doctor_purge.py``. Prior to HF7's
simplify pass these were duplicated verbatim in both files.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from dotenv import dotenv_values
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

from tests.conftest import make_repo as _repo
from tests.helpers import fake_anthropic_key, fake_openai_key

runner = CliRunner()

# Module-level test keys. Same instance across the suite so tests don't
# regenerate openssl-shaped strings on every collection.
TEST_OPENAI_KEY = fake_openai_key()
TEST_ANTHROPIC_KEY = fake_anthropic_key()


def cli_invoke(args: list[str], home: WorthlessHome, **kwargs: object) -> object:
    """Run a CLI command with WORTHLESS_HOME pointed at the test home."""
    return runner.invoke(
        app,
        args,
        env={"WORTHLESS_HOME": str(home.base_dir)},
        **kwargs,
    )


def lock_env(env_file: Path, home: WorthlessHome) -> None:
    """Lock the env file. Failures here are pre-conditions, not under test."""
    result = cli_invoke(["lock", "--env", str(env_file)], home)
    assert result.exit_code == 0, f"precondition lock failed:\n{result.output}"


def dotenv_value(env_file: Path, var: str) -> str | None:
    """Read a single key from a .env file. Convenience over ``dotenv_values``."""
    return dotenv_values(env_file).get(var)


def looks_like_traceback(text: str) -> bool:
    """Heuristic: did a raw Python stack trace leak into user output?"""
    return "Traceback (most recent call last):" in text


def has_actionable_hint(text: str, *keywords: str) -> bool:
    """Case-insensitive: at least one hint keyword present in user output."""
    lowered = text.lower()
    return any(k.lower() in lowered for k in keywords)


def has_all_tokens(text: str, *required: str) -> bool:
    """Case-insensitive: ALL tokens must appear. Used to bind a hint to a
    specific bug (e.g. "can't restore" + the actual var name) so unrelated
    errors that share one keyword cannot turn the test green spuriously.
    """
    lowered = text.lower()
    return all(k.lower() in lowered for k in required)


def list_enrollments(home: WorthlessHome) -> list:
    """Return DB enrollments. ``initialize`` is idempotent (CREATE … IF NOT
    EXISTS) so calling it twice in a session is safe.
    """
    repo = _repo(home)
    asyncio.run(repo.initialize())
    return asyncio.run(repo.list_enrollments())


@pytest.fixture()
def _cli_user_home(tmp_path: Path) -> Path:
    home = tmp_path / "user-home"
    home.mkdir()
    return home


@pytest.fixture(autouse=True)
def _isolate_cli_process_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _cli_user_home: Path
) -> None:
    """Keep cwd/HOME-sensitive CLI commands hermetic under xdist.

    `worthless doctor` intentionally inspects both the current project's
    `.env` and the user's OpenClaw home. Tests in this package usually pass
    an explicit `WORTHLESS_HOME`, but that alone is not enough: a previous
    test in the same xdist worker can leave cwd or HOME pointing at a project
    with `.env` / OpenClaw state and make unrelated doctor tests flaky.
    """
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("HOME", str(_cli_user_home))
    monkeypatch.setenv("USERPROFILE", str(_cli_user_home))


@pytest.fixture()
def env_file(tmp_path: Path) -> Path:
    """A .env file with a single OpenAI-shaped fake key."""
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={TEST_OPENAI_KEY}\n")
    return env


@pytest.fixture()
def multi_env_file(tmp_path: Path) -> Path:
    """A .env file with both an OpenAI and an Anthropic fake key."""
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={TEST_OPENAI_KEY}\nANTHROPIC_API_KEY={TEST_ANTHROPIC_KEY}\n")
    return env
