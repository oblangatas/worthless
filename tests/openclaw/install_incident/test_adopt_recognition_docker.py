"""WOR-650 — LIVE: real ``worthless lock --adopt`` produces a config that the
REAL OpenClaw binary accepts, for both providers.

The unit + integration suites assert on a hand-written fixture shape. Only the
real ``openclaw`` binary proves OpenClaw *accepts* what our integration writes
after adopting an unrecognized entry — the exact "passes in mock, fails live"
gap WOR-514 was. This is the trust anchor:

1. Seed ``~/.openclaw/openclaw.json`` with a VALID proxy-shaped entry whose
   alias this machine never created (a synced config / reinstall).
2. Run the REAL ``worthless lock --adopt`` CLI (hermetic subprocess), with a
   fake-healthy proxy so the WRTLS-109 gate lets the integration run.
3. Assert on the host: the foreign alias is gone, our proxy URL is in, and the
   adoption notice surfaced.
4. Copy the rewritten config into a pinned OpenClaw container and run
   ``openclaw config get models`` — assert it does NOT report "Config invalid".

Marks: ``openclaw`` + ``docker``; skipped when Docker / the image is absent.
Lean (one short-lived container, no proxy stack) — ~60s, 300s ceiling.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from tests._docker_helpers import docker_available
from tests.helpers import fake_anthropic_key, fake_openai_key
from tests.openclaw.install_incident.reproduce import fake_proxy_health

REPO = Path(__file__).resolve().parents[3]
OC_IMAGE = "ghcr.io/openclaw/openclaw:2026.5.3-1"


pytestmark = [
    pytest.mark.openclaw,
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
    # No image-present guard: `docker run` below auto-pulls OC_IMAGE, matching
    # test_proxy_load_bearing.py. A local-presence skipif made this silently
    # skip in CI (which never pre-pulls the image) — defeating the CI wiring.
    pytest.mark.timeout(300),
]

_PROVIDERS = {
    "openai": {"var": "OPENAI_API_KEY", "key": fake_openai_key(), "api": "openai-completions"},
    "anthropic": {
        "var": "ANTHROPIC_API_KEY",
        "key": fake_anthropic_key(),
        "api": "anthropic-messages",
    },
}


def _run(args: list[str], *, check: bool = False, timeout: int = 120):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=timeout)


def _lock_adopt(home: Path, whome: Path, env: Path, port: int):
    """Invoke the REAL ``worthless lock --adopt`` with a hermetic env (strip all
    inherited ``WORTHLESS_*`` so a sibling test can't flip the result)."""
    e = {k: v for k, v in os.environ.items() if not k.startswith("WORTHLESS_")}
    e.update(
        HOME=str(home),
        USERPROFILE=str(home),
        WORTHLESS_HOME=str(whome),
        WORTHLESS_KEYRING_BACKEND="null",
        WORTHLESS_PORT=str(port),
    )
    return subprocess.run(
        ["uv", "run", "worthless", "lock", "--adopt", "--env", str(env)],
        cwd=str(REPO),
        env=e,
        capture_output=True,
        text=True,
        timeout=180,
    )


def _validate_in_container(cfg_path: Path) -> tuple[bool, str]:
    """Copy ``cfg_path`` into a fresh OpenClaw container and ask the real binary
    whether it loads. ``openclaw config get models`` prints "Config invalid"
    (+ the schema problems) when the file is rejected."""
    c = f"wor650-{uuid.uuid4().hex[:8]}"
    try:
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                c,
                "--entrypoint",
                "sh",
                OC_IMAGE,
                "-c",
                "sleep infinity",
            ],
            check=True,
        )
        # The image's ~/.openclaw already exists; wait for it to be cp-able.
        for _ in range(10):
            if _run(["docker", "exec", c, "test", "-d", "/home/node/.openclaw"]).returncode == 0:
                break
            time.sleep(1)
        _run(
            ["docker", "cp", str(cfg_path), f"{c}:/home/node/.openclaw/openclaw.json"],
            check=True,
        )
        # docker cp lands the file owned by root with the host mode (lock writes
        # it 0600); OpenClaw runs as uid 1000 and can't read it. Make it readable
        # as root so the validation tests OUR schema, not file ownership.
        _run(
            ["docker", "exec", "-u", "0", c, "chmod", "644", "/home/node/.openclaw/openclaw.json"],
            check=True,
        )
        r = _run(["docker", "exec", c, "openclaw", "config", "get", "models"], timeout=120)
        out = r.stdout + r.stderr
        # Require the command to actually succeed — otherwise a Docker/OpenClaw
        # failure whose output lacks "Config invalid" (container died, exec
        # error) would false-pass the schema guard.
        return (r.returncode == 0 and "Config invalid" not in out), out
    finally:
        _run(["docker", "rm", "-f", c])


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_live_adopt_produces_openclaw_valid_config(tmp_path, provider) -> None:
    spec = _PROVIDERS[provider]
    home = tmp_path / "home"
    (home / ".openclaw").mkdir(parents=True)
    whome = tmp_path / "whome"
    project = tmp_path / "project"
    project.mkdir()
    env = project / ".env"
    env.write_text(f"{spec['var']}={spec['key']}\n", encoding="utf-8")
    cfg = home / ".openclaw" / "openclaw.json"

    with fake_proxy_health() as port:
        foreign_url = f"http://127.0.0.1:{port}/{provider}-foreign/v1"
        cfg.write_text(
            json.dumps(
                {
                    "models": {
                        "providers": {
                            provider: {
                                "baseUrl": foreign_url,
                                "apiKey": "sk-foreign-not-ours",
                                "api": spec["api"],
                                "models": [{"id": "m", "name": "m"}],
                            }
                        }
                    }
                }
            )
            + "\n",
            encoding="utf-8",
        )
        result = _lock_adopt(home, whome, env, port)

    assert result.returncode == 0, f"lock failed:\n{result.stdout}\n{result.stderr}"

    entry = json.loads(cfg.read_text(encoding="utf-8"))["models"]["providers"][provider]
    assert "foreign" not in entry["baseUrl"], f"foreign alias survived: {entry['baseUrl']}"
    assert f"127.0.0.1:{port}" in entry["baseUrl"]
    assert entry["baseUrl"].endswith("/v1")
    assert "records" in (result.stdout + result.stderr), "adoption notice not surfaced"

    ok, out = _validate_in_container(cfg)
    assert ok, f"real OpenClaw rejected our adopted config:\n{out}"
