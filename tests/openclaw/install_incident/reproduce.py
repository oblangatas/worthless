#!/usr/bin/env python3
"""Reproduce the OpenClaw install incident (WOR-514).

A real user (host install) ran the documented Worthless flow to protect his
OpenClaw key. Two things failed at once:

  * WOR-515 -- silent bypass. ``worthless lock`` reported success but the
    proxy was never in OpenClaw's request path.
  * WOR-516 -- config breakage. ``worthless lock`` corrupted ``openclaw.json``;
    the user had to restore from his own backup.

This harness reproduces both at the configuration level, on a *realistic*
pre-Worthless OpenClaw config (not the pristine one-provider test fixture).
It runs the real ``worthless lock`` CLI against a seeded ``~/.openclaw`` and
reports exactly what changed.

It is intentionally a plain script (not pytest) -- it is the Phase 0
"reproduce the incident" deliverable. The findings it prints drive the
red regression test that follows.

Run:
    uv run python tests/openclaw/install_incident/reproduce.py
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import http.server
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# A format-valid fake OpenAI key -- deterministic, not a live credential.
# Mirrors tests.helpers.fake_openai_key() so ``worthless lock`` recognises it
# as an unprotected key worth processing. One value, reused across the .env,
# the openclaw.json provider, and the cached auth profile.
REAL_KEY = (
    "sk-proj-"
    + base64.urlsafe_b64encode(hashlib.sha256(b"test-fixture-seed").digest())
    .decode()
    .rstrip("=")[:48]
)

# A realistic openclaw.json as it looks BEFORE the user runs Worthless:
#   * the user already has a working ``openai`` provider with the real key,
#   * the agent's default model points AT that provider,
#   * sibling top-level keys the daemon owns (gateway auth, channels) that
#     Worthless must never touch or destroy.
REALISTIC_OPENCLAW_JSON = {
    "gateway": {"port": 18789, "authToken": "oc-gw-SECRET-must-survive"},
    "channels": {
        "discord": {"enabled": True, "botToken": "discord-bot-token-must-survive"},
    },
    "agents": {"defaults": {"model": {"primary": "openai/gpt-4o"}}},
    "models": {
        "providers": {
            "openai": {
                "baseUrl": "https://api.openai.com/v1",
                "apiKey": REAL_KEY,
                "api": "openai-completions",
                "models": [{"id": "gpt-4o"}],
            },
        },
    },
}

# OpenClaw caches the credential it obtained on first use. Path per the
# incident report: ~/.openclaw/agents/main/agent/auth-profiles.json
AUTH_PROFILES_JSON = {
    "profiles": {
        "openai": {"token": REAL_KEY, "cachedAt": "2026-05-17T10:00:00Z"},
    },
}


def agent_primary_model(cfg: dict) -> str | None:
    """Return OpenClaw's configured primary model from the current schema."""
    return cfg.get("agents", {}).get("defaults", {}).get("model", {}).get("primary")


def seed(root: Path) -> dict[str, Path]:
    """Build a realistic ~/.openclaw under ``root`` and a project .env."""
    home = root / "home"
    oc = home / ".openclaw"
    workspace = oc / "workspace"
    agent_dir = oc / "agents" / "main" / "agent"
    workspace.mkdir(parents=True)
    agent_dir.mkdir(parents=True)

    cfg = oc / "openclaw.json"
    cfg.write_text(json.dumps(REALISTIC_OPENCLAW_JSON, indent=2) + "\n", encoding="utf-8")

    auth_profiles = agent_dir / "auth-profiles.json"
    auth_profiles.write_text(json.dumps(AUTH_PROFILES_JSON, indent=2) + "\n", encoding="utf-8")

    project = root / "project"
    project.mkdir()
    env = project / ".env"
    env.write_text(f"OPENAI_API_KEY={REAL_KEY}\n", encoding="utf-8")

    return {
        "home": home,
        "cfg": cfg,
        "auth_profiles": auth_profiles,
        "env": env,
        "whome": root / "whome",
    }


class _HealthzHandler(http.server.BaseHTTPRequestHandler):
    """Answer ``GET /healthz`` with 200 + minimal JSON; 404 for anything else.

    The minimum ``cli.process.check_proxy_health`` accepts as "healthy": a 200
    with a JSON body (``mode`` / ``requests_proxied`` default if absent).

    WOR-658: surface ``bind_probe_count`` so lock-side bind-confirmation can
    recognise this harness as a worthless-like proxy and observe a delta.
    The probe endpoint is ``/_bind_probe/{alias}`` (GET + HEAD) — we count
    it without forwarding, identical to the real proxy's behaviour.
    """

    # Server-scoped (class attribute) so the count survives per-connection
    # handlers and is visible across the two /healthz reads
    # bind-confirmation makes. Reset by fake_proxy_health on each context-
    # manager entry below.
    bind_probe_count: int = 0

    def _is_probe(self) -> bool:
        return self.path.startswith("/_bind_probe/")

    def do_HEAD(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        if self._is_probe():
            type(self).bind_probe_count += 1
            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        if self.path == "/healthz":
            body = (
                f'{{"mode": "up", "requests_proxied": 0, '
                f'"bind_probe_count": {type(self).bind_probe_count}}}'
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self._is_probe():
            type(self).bind_probe_count += 1
            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_args: object) -> None:  # silence the access log
        pass


@contextlib.contextmanager
def fake_proxy_health() -> Iterator[int]:
    """Serve a healthy ``/healthz`` on an ephemeral 127.0.0.1 port; yield the port.

    ``worthless lock`` aborts with WRTLS-109 (WOR-648 / WOR-621 F7) unless the
    proxy answers ``check_proxy_health`` -- a gate that runs BEFORE the OpenClaw
    integration these tests exercise. Without a healthy proxy ``lock`` no-ops, so
    the invariants below pass/xfail VACUOUSLY (lock never reached the code under
    test). This is the minimum that satisfies the gate so ``lock`` proceeds.

    It does NOT proxy anything: ``lock`` only *probes* health before writing the
    split + config; it never makes an upstream call. Pass the yielded port to
    :func:`run_lock` via ``proxy_port``.
    """
    # Reset the shared counter so prior contexts don't leak through.
    _HealthzHandler.bind_probe_count = 0
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _HealthzHandler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def run_lock(
    paths: dict[str, Path], proxy_port: int | None = None
) -> subprocess.CompletedProcess[str]:
    """Invoke the real ``worthless lock`` CLI, as a user would.

    The child env is built HERMETICALLY: every inherited ``WORTHLESS_*`` var is
    stripped, then only the vars this harness controls are set. Without this the
    subprocess inherits whatever ``WORTHLESS_*`` a sibling test left in
    ``os.environ`` -- e.g. a leaked ``WORTHLESS_OPENCLAW_BIN`` makes the audit gate
    run against the seeded *plaintext* ``openclaw.json`` and exit 73, or a
    ``monkeypatch.delenv("WORTHLESS_KEYRING_BACKEND")`` makes ``lock`` hit a real
    keyring in headless CI. Under ``pytest-randomly`` + xdist that flipped the
    xfail-strict invariants below to XPASS in CI only (never locally on macOS).
    Stripping the namespace makes ``lock``'s exit deterministic regardless of order.

    ``proxy_port`` (from :func:`fake_proxy_health`) points lock's WRTLS-109 health
    probe at a fake-healthy proxy so the OpenClaw integration runs. Omit it only
    when deliberately exercising the proxy-down abort path.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("WORTHLESS_")}
    env["HOME"] = str(paths["home"])
    env["USERPROFILE"] = str(paths["home"])
    env["WORTHLESS_HOME"] = str(paths["whome"])
    env["WORTHLESS_KEYRING_BACKEND"] = "null"
    if proxy_port is not None:
        env["WORTHLESS_PORT"] = str(proxy_port)
    return subprocess.run(
        ["uv", "run", "worthless", "lock", "--env", str(paths["env"])],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )


def read_json_lenient(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
    except PermissionError:
        path.chmod(0o600)
        raw = path.read_text(encoding="utf-8")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"__PARSE_ERROR__": str(exc), "__RAW__": raw}


def _redacted_json(obj: dict) -> str:
    """Serialise ``obj`` with key-shaped values redacted.

    Both ``REAL_KEY`` and the Worthless shard-A written into the
    ``worthless-openai`` provider are deterministic, non-secret fixture
    values -- but they match the ``sk-`` key shape. Redacting them keeps
    committed evidence files from tripping secret scanners. The structure
    -- which providers/keys survive -- is what the evidence is for.
    """
    text = json.dumps(obj, indent=2) + "\n"
    return re.sub(r"sk-[A-Za-z0-9_-]{12,}", "<key-shaped-redacted>", text)


def scenario(name: str, description: str, make_unreadable: bool) -> dict:
    """Run one reproduction scenario and return a findings dict."""
    print(f"\n{'=' * 70}\nSCENARIO {name}: {description}\n{'=' * 70}")
    with tempfile.TemporaryDirectory(prefix="wor514-") as tmp:
        root = Path(tmp)
        paths = seed(root)

        before = read_json_lenient(paths["cfg"])
        before_mode = stat.S_IMODE(paths["cfg"].stat().st_mode)
        before_auth = read_json_lenient(paths["auth_profiles"])

        if make_unreadable:
            paths["cfg"].chmod(0o000)

        with fake_proxy_health() as _proxy_port:
            result = run_lock(paths, proxy_port=_proxy_port)

        # Capture mode BEFORE read_json_lenient -- it chmods unreadable files to read.
        after_mode = stat.S_IMODE(paths["cfg"].stat().st_mode)
        after = read_json_lenient(paths["cfg"])
        after_auth = read_json_lenient(paths["auth_profiles"])

        # Capture before/after states as committed regression evidence.
        FIXTURES.mkdir(exist_ok=True)
        (FIXTURES / "openclaw.before.json").write_text(_redacted_json(before), encoding="utf-8")
        (FIXTURES / "auth-profiles.before.json").write_text(
            _redacted_json(before_auth), encoding="utf-8"
        )
        (FIXTURES / f"openclaw.after-scenario-{name.lower()}.json").write_text(
            _redacted_json(after), encoding="utf-8"
        )

        # --- analysis ---------------------------------------------------
        providers_before = set(before.get("models", {}).get("providers", {}).keys())
        providers_after = set(after.get("models", {}).get("providers", {}).keys())
        sibling_keys_before = {k for k in before if k != "models"}
        sibling_keys_after = {k for k in after if k != "models"}
        lost_siblings = sibling_keys_before - sibling_keys_after
        original_openai_survived = "openai" in providers_after
        worthless_added = any(p.startswith("worthless-") for p in providers_after)
        agent_still_on_real = agent_primary_model(after) == "openai/gpt-4o"
        auth_profiles_untouched = before_auth == after_auth
        real_key_still_reachable = REAL_KEY in json.dumps(after) or REAL_KEY in json.dumps(
            after_auth
        )

        rc = result.returncode
        stdout_lines = result.stdout.strip().splitlines()
        stdout_tail = stdout_lines[-1] if stdout_lines else "(empty)"
        default_model = agent_primary_model(after) or "(GONE)"

        print(f"lock exit code         : {rc}")
        print(f"lock stdout (tail)     : {stdout_tail}")
        if result.stderr.strip():
            print(f"lock stderr (tail)     : {result.stderr.strip().splitlines()[-1]}")
        print(f"openclaw.json mode     : {oct(before_mode)} -> {oct(after_mode)}")
        print(f"providers before/after : {sorted(providers_before)} -> {sorted(providers_after)}")
        print(f"sibling keys lost      : {sorted(lost_siblings) or 'none'}")
        print(f"original 'openai' kept : {original_openai_survived}")
        print(f"worthless provider add : {worthless_added}")
        print(f"agent default model    : {default_model}")
        print(f"auth-profiles touched  : {not auth_profiles_untouched}")
        print(f"real key still on disk : {real_key_still_reachable}")

        config_corrupted = bool(lost_siblings) or "__PARSE_ERROR__" in after
        # Bypass: OpenClaw can still reach upstream with the real key without
        # the proxy -- because the agent still points at a non-proxy provider
        # and/or the cached token is intact.
        bypass = (agent_still_on_real and original_openai_survived) or (
            auth_profiles_untouched and real_key_still_reachable
        )

        print(f"\n  >> WOR-516 config corrupted : {config_corrupted}")
        print(f"  >> WOR-515 proxy bypassable : {bypass}")

        return {
            "name": name,
            "lock_returncode": result.returncode,
            "config_corrupted": config_corrupted,
            "lost_siblings": sorted(lost_siblings),
            "bypass": bypass,
            "mode_change": before_mode != after_mode,
            "before_mode": oct(before_mode),
            "after_mode": oct(after_mode),
        }


def main() -> int:
    print("WOR-514 OpenClaw install incident -- reproduction harness")
    print(f"repo: {REPO}")
    version = subprocess.run(
        ["uv", "run", "worthless", "--version"],
        cwd=REPO,
        capture_output=True,
        text=True,
    ).stdout.strip()
    print(f"worthless: {version}")

    results = [
        scenario(
            "A",
            "readable config -- normal host install",
            make_unreadable=False,
        ),
        scenario(
            "B",
            "unreadable config -- daemon-owned 0600 / foreign uid",
            make_unreadable=True,
        ),
    ]

    print(f"\n{'=' * 70}\nSUMMARY\n{'=' * 70}")
    for r in results:
        print(
            f"  {r['name']}: corrupted={r['config_corrupted']} "
            f"bypass={r['bypass']} lost={r['lost_siblings']} "
            f"mode={r['before_mode']}->{r['after_mode']}"
        )
    incident_reproduced = any(r["config_corrupted"] for r in results) and any(
        r["bypass"] for r in results
    )
    print(f"\nINCIDENT REPRODUCED: {incident_reproduced}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
