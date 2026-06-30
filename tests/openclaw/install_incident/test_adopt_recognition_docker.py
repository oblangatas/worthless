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
import pty
import re
import select
import subprocess
import sys
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


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _lock_decline(home: Path, whome: Path, env: Path, port: int) -> tuple[int, str]:
    """Run the REAL ``worthless lock`` (no ``--adopt``) under a PTY and answer
    'n' to every prompt. Returns ``(exit_code, combined_output)``.

    A PTY is REQUIRED: ``_resolve_adoption_policy`` only prompts when
    ``sys.stdin.isatty()`` is true; a plain pipe is the non-interactive (CI)
    path which auto-adopts. To exercise a real human DECLINE we give lock a
    controlling terminal and feed it 'n'.

    Two real prompts surface on this path: the adoption consent AND a
    post-lock "scan for hardcoded provider URLs?" prompt — so we feed several
    'n' lines (extra lines are discarded once the process exits). We invoke the
    venv entrypoint directly (not ``uv run``) for reliable PTY stdin
    passthrough, and bound the read loop with a wall-clock deadline so a missed
    prompt can never hang the suite (the body would otherwise block forever).
    """
    e = {k: v for k, v in os.environ.items() if not k.startswith("WORTHLESS_")}
    e.update(
        HOME=str(home),
        USERPROFILE=str(home),
        WORTHLESS_HOME=str(whome),
        WORTHLESS_KEYRING_BACKEND="null",
        WORTHLESS_PORT=str(port),
    )
    worthless_bin = str(Path(sys.executable).parent / "worthless")
    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(
            [worthless_bin, "lock", "--env", str(env)],
            cwd=str(REPO),
            env=e,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            text=False,
        )
        os.close(slave)
        os.write(master, b"n\n" * 4)  # decline adoption + the URL-scan prompt
        chunks: list[bytes] = []
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 1.0)
            if ready:
                try:
                    data = os.read(master, 4096)
                except OSError:  # slave closed on child exit
                    break
                if not data:
                    break
                chunks.append(data)
            elif proc.poll() is not None:
                break
        if proc.poll() is None:
            proc.kill()
        rc = proc.wait(timeout=30)
        return rc, b"".join(chunks).decode(errors="replace")
    finally:
        os.close(master)


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_live_declined_adoption_warns_and_leaves_openclaw_valid_config(tmp_path, provider) -> None:
    """LIVE decline mirror of the adopt test (WOR-650 follow-up).

    When the user DECLINES adopting an unrecognized proxy-shaped entry, the
    foreign entry is LEFT IN PLACE — OpenClaw will keep routing through it, so
    the .env-only lock is incomplete. This proves, against the REAL CLI and the
    REAL OpenClaw binary, that:

    1. lock does NOT print a clean ``[OK] OpenClaw integration:`` — it prints a
       ``[WARN] ... incomplete`` header (the honesty fix);
    2. the sentinel is DEGRADED (``status=partial`` / ``openclaw=failed``) so
       ``worthless status`` reports it across sessions;
    3. the foreign entry SURVIVES verbatim (the bypass the WARN names); and
    4. that left-in-place config is one the REAL OpenClaw binary still loads —
       i.e. OpenClaw WILL route through the foreign baseUrl. The warning
       describes a real state, not theatre.
    """
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
        rc, out = _lock_decline(home, whome, env, port)

    # Strip ANSI colour so substring checks see the plain text (the real CLI
    # colourises, which splits "[WARN]" with escape codes).
    clean = _ANSI_RE.sub("", out)

    # 0. The interactive decline path actually ran (not some other skip reason).
    assert "not created on this machine" in clean, f"adoption prompt path didn't run:\n{clean}"
    # 1. Declining is a user choice, not a lock error.
    assert rc == 0, f"decline should exit 0; got {rc}\n{clean}"
    # 2. Output must NOT read as a clean success; it must WARN. (The "[OK] N key
    #    split" line is lock-CORE's summary — distinct from the OpenClaw header.)
    assert "[OK] OpenClaw integration:" not in clean, (
        f"declined adoption printed a bare [OK] OpenClaw header:\n{clean}"
    )
    assert "[WARN]" in clean and "incomplete" in clean.lower(), (
        f"expected a [WARN] ... incomplete header on decline:\n{clean}"
    )
    # 3. The foreign entry is LEFT IN PLACE (the bypass the WARN warns about).
    entry = json.loads(cfg.read_text(encoding="utf-8"))["models"]["providers"][provider]
    assert entry["baseUrl"] == foreign_url, (
        f"a declined entry must survive verbatim; got {entry['baseUrl']}"
    )
    # 4. Sentinel is DEGRADED so `worthless status` reports it across sessions.
    sentinel = json.loads((whome / "last-lock-status.json").read_text(encoding="utf-8"))
    assert sentinel["status"] == "partial" and sentinel["openclaw"] == "failed", (
        f"declined adoption must leave a DEGRADED sentinel; got {sentinel}"
    )
    # 5. The left-in-place config is one the REAL OpenClaw binary loads — so
    #    OpenClaw WILL use the foreign baseUrl. The bypass is real, not theory.
    ok, vout = _validate_in_container(cfg)
    assert ok, f"real OpenClaw rejected the left-in-place config:\n{vout}"
