"""F7 (WOR-648 / WOR-621 AC5) — proxy health pre-flight before openclaw.json write.

Spec: before ``worthless lock`` writes ANYTHING (the .env rewrite, the DB
enroll, OR ``~/.openclaw/openclaw.json``), it MUST probe the Worthless proxy's
``/healthz`` when OpenClaw is present. If the proxy is down, lock ABORTS with a
legible proxy-down error (``PROXY_NOT_RUNNING``) and .env, the DB, and
openclaw.json are ALL byte-for-byte unchanged — a clean no-op, never a partial
lock.

The probe lives at the start of the command flow (``_lock_async`` in
``worthless.cli.commands.lock``), beside the OpenClaw audit gate, BEFORE
``_pass1_db_writes``/``_batch_rewrite``. The low-level ``integration.apply_lock()``
unit tests run WITHOUT any proxy and stay green because the probe is in the
command flow, not in ``apply_lock`` itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

from tests.helpers import fake_openai_key

runner = CliRunner()


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    """A .env with one fake OpenAI key — enough to drive lock-core."""
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    return env


@pytest.fixture
def sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pin HOME so detect() probes the tmp workspace, not the dev's real ~/.openclaw."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture
def openclaw_present(sandboxed_home: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Pre-stage ~/.openclaw/ with workspace + a valid openclaw.json."""
    openclaw_dir = sandboxed_home / ".openclaw"
    workspace = openclaw_dir / "workspace"
    workspace.mkdir(parents=True)
    config_path = openclaw_dir / "openclaw.json"
    config_path.write_text(
        json.dumps({"models": {"providers": {}}}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(sandboxed_home)
    return {"home": sandboxed_home, "workspace": workspace, "config_path": config_path}


def test_lock_aborts_and_leaves_openclaw_json_unchanged_when_proxy_down(
    home_dir: WorthlessHome,
    env_file: Path,
    openclaw_present: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Proxy down + OpenClaw present → lock aborts with a proxy-down code and
    openclaw.json is byte-for-byte unchanged.
    """
    from worthless.cli.commands import lock as lock_mod

    # Simulate the proxy being unreachable: /healthz never answers healthy.
    monkeypatch.setattr(
        lock_mod,
        "check_proxy_health",
        lambda port: {"healthy": False, "port": port, "mode": None, "requests_proxied": 0},
    )

    config_path = openclaw_present["config_path"]
    before_bytes = config_path.read_bytes()
    env_before = env_file.read_bytes()

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir)},
    )

    # Lock must NOT exit 0 — the proxy-down abort is a hard failure.
    assert result.exit_code != 0, result.output
    # The legible cause must name the proxy being down.
    assert "proxy" in result.output.lower(), result.output
    # openclaw.json byte-for-byte unchanged — nothing was written.
    assert config_path.read_bytes() == before_bytes, (
        "openclaw.json must be byte-identical when the proxy is down"
    )
    # AND .env byte-for-byte unchanged — the probe gates BEFORE the .env
    # rewrite + DB enroll, so proxy-down is a clean no-op (never a partial
    # lock where .env holds shard-A but the DB shard was unwound).
    assert env_file.read_bytes() == env_before, (
        ".env must be byte-identical when the proxy is down (clean no-op)"
    )
