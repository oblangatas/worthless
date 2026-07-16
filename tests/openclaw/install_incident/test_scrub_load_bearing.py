"""WOR-796 — the agent-cache scrub actually strips a real, OpenClaw-written key.

Every other WOR-796 test (``tests/openclaw/test_lock_scrubs_agent_auth_stores.py``)
uses synthetic fixtures: a fake ``HOME``, hand-crafted ``models.json`` content the
author of the feature also wrote the assertions against. That can't catch a
mismatch between what the code ASSUMES about OpenClaw's on-disk cache and what
OpenClaw ACTUALLY writes there.

This test closes that gap with a real ``worthless-oc-test:local`` container
(same image as the sibling rotation test):

1. Inject a RAW real key directly into OpenClaw's own config (``openclaw config
   set``) — simulating a user who configured OpenClaw directly, before ever
   adopting Worthless.
2. Force a real chat turn. OpenClaw resolves and caches that raw key into its
   OWN per-agent ``models.json`` on disk — this file is written by OpenClaw's
   real code, not by this test.
3. Confirm the vulnerability precondition is real: read the real file, the raw
   key is genuinely sitting there in plaintext.
4. Run a real ``worthless lock`` (adopting the pre-existing provider).
5. Read the SAME real file again — no additional chat turn, so nothing besides
   the WOR-796 scrub could have touched it — and confirm the raw key is gone.

Marks: openclaw + docker; skipped when Docker or the prebuilt image is
unavailable (see ``test_rotation_load_bearing.py``'s docstring to build it).
"""

from __future__ import annotations

import subprocess
import time
import uuid
from pathlib import Path

import pytest

from tests._docker_helpers import docker_available
from tests.helpers import fake_key

REPO_ROOT = Path(__file__).resolve().parents[3]
OC_WORTHLESS_IMAGE = "worthless-oc-test:local"
MOCK_DOCKERFILE_DIR = str(REPO_ROOT / "tests" / "openclaw" / "mock-upstream")
_MOCK_PORT = 9999
_MODEL = "openai/gpt-4o"


def _image_present(ref: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", ref], capture_output=True).returncode == 0


pytestmark = [
    pytest.mark.openclaw,
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
    pytest.mark.skipif(
        not _image_present(OC_WORTHLESS_IMAGE),
        reason=f"{OC_WORTHLESS_IMAGE} not built (see test_rotation_load_bearing.py docstring)",
    ),
    pytest.mark.timeout(600),
]


def _run(
    args: list[str], *, check: bool = False, timeout: int = 120
) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=timeout)


def _exec(c: str, args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    return _run(["docker", "exec", c, *args], timeout=timeout)


def _sh(c: str, script: str, *, timeout: int = 120) -> subprocess.CompletedProcess:
    return _exec(c, ["sh", "-c", script], timeout=timeout)


def _oc(c: str, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return _exec(c, ["node", "openclaw.mjs", *args], timeout=timeout)


def _wait_oc(c: str, tries: int = 40) -> None:
    for _ in range(tries):
        if _oc(c, "config", "get", "gateway", timeout=30).returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError(f"OpenClaw container {c} did not become ready")


_HEALTHZ = (
    "python3 -c \"import urllib.request as u;u.urlopen('http://127.0.0.1:8787/healthz',timeout=2)\""
)


def _daemon_healthy(c: str) -> bool:
    return _sh(c, _HEALTHZ, timeout=15).returncode == 0


def _wait_daemon(c: str, up: bool, tries: int = 30) -> bool:
    for _ in range(tries):
        if _daemon_healthy(c) is up:
            return True
        time.sleep(1)
    return False


def _start_daemon(c: str) -> None:
    _run(["docker", "exec", "-d", c, "sh", "-c", "worthless up > /tmp/up.log 2>&1"])
    if not _wait_daemon(c, up=True):
        logs = _sh(c, "tail -10 /tmp/up.log").stdout
        raise RuntimeError(f"worthless daemon did not become healthy.\n{logs}")


def _route(c: str) -> subprocess.CompletedProcess:
    sid = f"wor796-{uuid.uuid4().hex[:6]}"
    return _oc(c, "agent", "--session-id", sid, "--message", "hi", "--json", timeout=120)


def _models_json_api_key(c: str) -> str:
    """Read providers.openai.apiKey from the REAL agent models.json on disk."""
    script = (
        'node -e \'const fs=require("fs");'
        'const p="/home/node/.openclaw/agents/main/agent/models.json";'
        'const d=JSON.parse(fs.readFileSync(p,"utf8"));'
        'process.stdout.write(((d.providers||{})["openai"]||{}).apiKey||"(none)")\''
    )
    return _sh(c, script).stdout.strip()


def _agents_files_with_real_key(c: str, real_key: str) -> list[str]:
    """Recursively list EVERY file under the real ``agents/`` tree that still
    holds the raw key — the file/provider-agnostic proof, not just one field of
    one models.json. Catches auth-profiles.json, any provider, any agent dir.

    ``grep -rlF`` prints matching filenames (fixed-string); rc 1 = no matches,
    swallowed to ``true`` so a clean tree returns an empty list, not an error.
    ``real_key`` is a fixed alphanumeric fixture — no shell metacharacters.
    """
    r = _sh(c, f"grep -rlF -- '{real_key}' /home/node/.openclaw/agents/ 2>/dev/null || true")
    return [line for line in r.stdout.splitlines() if line.strip()]


def _hide_openclaw_binary(c: str) -> None:
    """Move the real openclaw binary off PATH — no WORTHLESS_OPENCLAW_BIN override,
    so resolve_openclaw_bin() fails via shutil.which, and the #210 audit
    preflight gate takes its SKIP branch (returns None) rather than blocking.
    This isolates: does WOR-796's scrub still catch a real key when the
    OTHER gate that would normally catch it first is unavailable?
    """
    # The container runs --user node; /usr/local/bin is root-owned, so this
    # one admin action needs a root exec (the running gateway/agent processes
    # stay on the node user — this doesn't change their permission model).
    r = _run(
        [
            "docker",
            "exec",
            "-u",
            "root",
            c,
            "sh",
            "-c",
            "mv /usr/local/bin/openclaw /usr/local/bin/openclaw.hidden",
        ],  # fmt: skip
    )
    assert r.returncode == 0, f"could not hide openclaw binary: {r.stderr}"


@pytest.fixture(scope="module")
def scrub_stack():
    sfx = uuid.uuid4().hex[:8]
    net = f"wor796-net-{sfx}"
    mock = f"wor796-mock-{sfx}"
    oc = f"wor796-oc-{sfx}"
    mock_img = f"wor796-mockimg-{sfx}"
    mock_url = f"http://{mock}:{_MOCK_PORT}/openai/v1"
    real_key = fake_key("sk-proj-", "wor796-scrub-realkey")

    try:
        _run(["docker", "build", "-t", mock_img, MOCK_DOCKERFILE_DIR], check=True, timeout=300)
        _run(["docker", "network", "create", net], check=True)
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                mock,
                "--network",
                net,
                "--network-alias",
                mock,
                "-p",
                "127.0.0.1::9999",
                mock_img,
            ],  # fmt: skip
            check=True,
        )
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                oc,
                "--network",
                net,
                "-e",
                "OPENCLAW_ACCEPT_TERMS=yes",
                "--user",
                "node",
                OC_WORTHLESS_IMAGE,
            ],  # fmt: skip
            check=True,
        )
        _wait_oc(oc)

        # Register the mapping so `worthless lock` (step 3) recognizes this
        # base_url's protocol. "openai" itself is REJECTED here (WRTLS-112:
        # conflicts with a bundled provider name) — this is Worthless's OWN
        # registry bookkeeping, a separate namespace from OpenClaw's config
        # provider id below. Mirrors the sibling rotation test's naming.
        reg = _exec(
            oc,
            [
                "worthless",
                "providers",
                "register",
                "--name",
                "openai-mock",
                "--url",
                mock_url,
                "--protocol",
                "openai",
            ],  # fmt: skip
        )
        assert reg.returncode == 0, f"register failed: {reg.stderr}"

        # --- Step 1: inject the RAW real key directly into OpenClaw's own
        # config — simulating a user who configured OpenClaw BEFORE ever
        # running `worthless lock`. Nothing Worthless-side has touched this key.
        provider_obj = (
            '{"baseUrl":"' + mock_url + '","apiKey":"' + real_key + '",'
            '"models":[{"id":"gpt-4o","name":"GPT-4o","contextWindow":128000,"maxTokens":4096}]}'
        )
        set_key = _oc(oc, "config", "set", "models.providers.openai", provider_obj)
        assert set_key.returncode == 0, f"raw config set failed: {set_key.stderr}\n{set_key.stdout}"
        set_model = _oc(oc, "config", "set", "agents.defaults.model.primary", _MODEL)
        assert set_model.returncode == 0, f"model set failed: {set_model.stderr}"

        _run(["docker", "restart", oc], check=True)
        _wait_oc(oc)
        _start_daemon(oc)

        # --- Step 2: a real chat turn. OpenClaw resolves the raw key from its
        # own config and — this is the load-bearing bit — CACHES it into the
        # real per-agent models.json on disk. Nothing Worthless-side wrote
        # this file; OpenClaw's own code did.
        pre_turn = _route(oc)
        pre_lock_key = _models_json_api_key(oc)
        # WOR-796 (scrub proof #3): capture EVERY file under agents/ holding the
        # raw key before lock, so the post-lock "zero survivors" claim isn't
        # vacuous and covers auth-profiles.json + all agent dirs, not just one
        # field of main/models.json.
        pre_lock_leak_files = _agents_files_with_real_key(oc, real_key)

        # --- Step 2.5: hide the openclaw binary so the #210 audit-preflight
        # gate (lock.py:1635) takes its SKIP branch instead of blocking. That
        # older gate would otherwise abort the lock outright on seeing this
        # exact plaintext finding (confirmed in an earlier run of this test) —
        # which would prove the OLDER gate protects this scenario, not WOR-796.
        # Hiding the binary isolates whether WOR-796's scrub is real
        # defense-in-depth for the case where that gate is unavailable.
        _hide_openclaw_binary(oc)

        # --- Step 3: NOW adopt it via a real `worthless lock`, with the same
        # real key in .env (the realistic path: the user decides to protect a
        # key OpenClaw was already using directly).
        _sh(
            oc,
            "mkdir -p /tmp/p && printf 'OPENAI_API_KEY=%s\\nOPENAI_BASE_URL=%s\\n' "
            f"'{real_key}' '{mock_url}' > /tmp/p/.env",
        )
        lock = _sh(oc, "cd /tmp/p && worthless lock --env .env")

        yield {
            "oc": oc,
            "real_key": real_key,
            "pre_turn_rc": pre_turn.returncode,
            "pre_turn_stderr": pre_turn.stderr,
            "pre_lock_key": pre_lock_key,
            "lock_rc": lock.returncode,
            "lock_stdout": lock.stdout,
            "lock_stderr": lock.stderr,
            "post_lock_key": _models_json_api_key(oc),
            "pre_lock_leak_files": pre_lock_leak_files,
            "post_lock_leak_files": _agents_files_with_real_key(oc, real_key),
        }
    finally:
        _run(["docker", "rm", "-f", oc, mock], timeout=60)
        _run(["docker", "network", "rm", net], timeout=60)
        _run(["docker", "image", "rm", "-f", mock_img], timeout=60)


def test_precondition_openclaw_really_cached_the_raw_key(scrub_stack):
    """Sanity gate: prove the vulnerability precondition is real before
    trusting the fix's assertion. If OpenClaw never actually cached the raw
    key here, the scrub test below would trivially "pass" for the wrong
    reason (nothing to scrub).

    Deliberately does NOT require the chat turn's own HTTP round-trip to the
    mock to succeed (pre_turn_rc == 0) — OpenClaw resolves and CACHES the
    apiKey into models.json as part of preparing the request, independent of
    whether the upstream call itself then succeeds or 404s. The real signal
    is the cache content, checked directly below.
    """
    assert scrub_stack["pre_lock_key"] == scrub_stack["real_key"], (
        "OpenClaw's real models.json does not actually contain the raw key before lock — "
        f"got {scrub_stack['pre_lock_key'][:20]!r}. Test setup does not reproduce the "
        "real vulnerability precondition."
    )


def test_lock_succeeded_via_the_gate_skip_not_some_other_allowlist(scrub_stack):
    """Isolates the causal story: confirm the #210 audit gate was actually
    SKIPPED (binary unresolvable), not silently allowlisted for some other
    reason — otherwise a pass below wouldn't prove what this test claims."""
    combined = scrub_stack["lock_stdout"] + scrub_stack["lock_stderr"]
    assert "plaintext API keys detected" not in combined, (
        "the #210 gate fired anyway — hiding the binary did not actually skip it, "
        "so this test is not isolating what it claims to"
    )


def test_lock_scrubs_the_real_key_from_the_real_models_json(scrub_stack):
    """THE PROOF: with the #210 gate unavailable, does WOR-796's own scrub —
    and nothing else — still strip the real key from a genuine OpenClaw-written
    models.json? After a real `worthless lock` on a real OpenClaw container,
    the real per-agent models.json should no longer hold the raw key anywhere
    OpenClaw itself would look — not a fixture I hand-crafted, an actual file
    OpenClaw wrote that this test never touched directly except to read it."""
    assert scrub_stack["lock_rc"] == 0, (
        f"worthless lock failed:\n{scrub_stack['lock_stdout']}\n{scrub_stack['lock_stderr']}"
    )
    post_key = scrub_stack["post_lock_key"]
    assert post_key != scrub_stack["real_key"], (
        "the real key is STILL sitting in the real models.json after lock — "
        "WOR-796's scrub is NOT real defense-in-depth for the gate-unavailable case"
    )
    assert scrub_stack["real_key"] not in post_key, "the raw key leaked as a substring"


def test_no_real_key_survives_anywhere_under_agents(scrub_stack):
    """THE STRONGER PROOF (scrub proof #3): not just one field of
    main/models.json, but a recursive grep over the ENTIRE real ``agents/**``
    tree — every agent dir, both auth-profiles.json and models.json, any
    provider. After a real `worthless lock`, the raw key must survive in ZERO
    files. This is the file/provider-agnostic form of WOR-796's security claim.
    """
    assert scrub_stack["lock_rc"] == 0, (
        f"worthless lock failed:\n{scrub_stack['lock_stdout']}\n{scrub_stack['lock_stderr']}"
    )
    # Precondition: the key really WAS somewhere under agents/ before lock, else
    # "zero after" would pass for the wrong reason (nothing to scrub).
    assert scrub_stack["pre_lock_leak_files"], (
        "no file under agents/ held the raw key before lock — the recursive proof "
        "would be vacuous; test setup did not reproduce the on-disk leak"
    )
    assert scrub_stack["post_lock_leak_files"] == [], (
        "the raw key STILL survives on disk under agents/ after lock, in: "
        f"{scrub_stack['post_lock_leak_files']} — the scrub did not neutralize every "
        "cached copy (auth-profiles.json / a non-main agent dir / another provider)"
    )
