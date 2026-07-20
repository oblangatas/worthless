"""WOR-797 — ``worthless`` really detects & clears unshardable creds at their
REAL on-disk home paths, inside a real install.

The 13 existing WOR-797 tests (``tests/openclaw/test_unshardable_credentials.py``)
are 100% mocked: they monkeypatch ``HOME``, stub ``_keychain_service_present``,
use ``tmp_path``, and call the check directly. That proves the classification
logic, but it cannot prove the one thing a real user depends on — that the
installed ``worthless`` binary, running as its real OS user, with a real
``Path.home()``, actually finds and removes real files through the real
``worthless doctor --fix`` command. Neither detector parses file contents
(both are ``is_file()`` + ``unlink``), so a mock only ever proves "we can
delete a file we ourselves planted at the path our own constant defines" —
it is blind to path drift and to ``Path.home()`` resolving somewhere the CLI
doesn't expect.

This closes that gap for surfaces **5 (MiniMax)** and **8 (Vertex ADC)** — the
two the ticket itself flags as needing a live guard — against a real OpenClaw
``2026.5.3-1`` container (the ``worthless-oc-test:local`` image, same as the
sibling scrub/rotation tests):

1. Plant a MiniMax OAuth file and a Vertex ADC file at the exact home-relative
   paths a real ``minimax`` CLI / ``gcloud`` login would write (content is
   irrelevant — the detector is ``is_file()`` only, so a placeholder ``{}``
   stands in for a real token without seeding a secret).
2. Confirm the real ``worthless doctor`` DETECTS both at those paths — this is
   the path-drift / ``Path.home()`` assertion a mock can't make.
3. Run the real ``worthless doctor --fix`` and confirm both files are GONE from
   the real filesystem, and that the Vertex entry carries the
   ``gcloud auth application-default login`` re-auth remediation.

What this does NOT prove: that the ``minimax`` CLI / ``gcloud`` themselves write
exactly these paths (they are third-party tools, not OpenClaw — planting is the
faithful stand-in), nor the two macOS-keychain surfaces (1, 3), which cannot
exist on a Linux container.

Marks: openclaw + docker; skipped when Docker or the prebuilt image is
unavailable (see ``test_rotation_load_bearing.py``'s docstring to build it).
"""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from tests._docker_helpers import docker_available

REPO_ROOT = Path(__file__).resolve().parents[3]
OC_WORTHLESS_IMAGE = "worthless-oc-test:local"

# Surfaces 5 and 8 both resolve under the container user's real ``Path.home()``
# (``/home/node`` for the image's ``node`` user) — NOT ``WORTHLESS_HOME``. If
# ``Path.home()`` ever resolved elsewhere, detection would silently miss these
# and this test would fail at the detection assertion — which is the point.
_HOME = "/home/node"
MINIMAX_PATH = f"{_HOME}/.minimax/oauth_creds.json"
VERTEX_PATH = f"{_HOME}/.config/gcloud/application_default_credentials.json"


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


def _sh(c: str, script: str, *, timeout: int = 120) -> subprocess.CompletedProcess:
    return _run(["docker", "exec", c, "sh", "-c", script], timeout=timeout)


def _wait_worthless(c: str, tries: int = 30) -> None:
    for _ in range(tries):
        if _sh(c, "worthless --version", timeout=30).returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError(f"worthless CLI did not become ready in container {c}")


def _file_exists(c: str, path: str) -> bool:
    return _sh(c, f"test -f {path}").returncode == 0


def _unshardable_check(payload: dict) -> dict:
    """Pull the ``unshardable_credentials`` check out of a ``doctor --json`` doc.

    ``doctor --json`` emits exactly one JSON document with a ``checks`` array;
    a short-circuited (broken/uninitialised) install would omit this check, so
    ``next`` raising ``StopIteration`` is itself a meaningful failure signal.
    """
    return next(c for c in payload["checks"] if c["check_id"] == "unshardable_credentials")


def _doctor_json(c: str, *flags: str) -> dict:
    # `worthless doctor` exits non-zero when it finds issues, so don't check rc;
    # --json emits a single JSON document on stdout regardless.
    r = _sh(c, "worthless doctor " + " ".join(flags) + " --json 2>/dev/null")
    return json.loads(r.stdout)


@pytest.fixture(scope="module")
def unshardable_stack():
    oc = f"wor797-uc-{uuid.uuid4().hex[:8]}"
    try:
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                oc,
                "-e",
                "OPENCLAW_ACCEPT_TERMS=yes",
                "--user",
                "node",
                OC_WORTHLESS_IMAGE,
            ],  # fmt: skip
            check=True,
        )
        _wait_worthless(oc)
        home = _sh(oc, "echo $HOME").stdout.strip()

        # Plant surfaces 5 (MiniMax) and 8 (Vertex ADC) at their real home paths.
        # Content is irrelevant — both detectors are is_file() only — so a
        # placeholder object stands in for a real OAuth/ADC token, seeding no
        # actual secret. GOOGLE_APPLICATION_CREDENTIALS is intentionally unset so
        # the Vertex detector resolves its DEFAULT ADC path (the one gcloud writes).
        _sh(
            oc,
            "mkdir -p /home/node/.minimax /home/node/.config/gcloud && "
            f"printf '{{}}' > {MINIMAX_PATH} && "
            f"printf '{{}}' > {VERTEX_PATH}",
        )
        pre_minimax = _file_exists(oc, MINIMAX_PATH)
        pre_vertex = _file_exists(oc, VERTEX_PATH)

        detect = _unshardable_check(_doctor_json(oc))
        fix = _unshardable_check(_doctor_json(oc, "--fix", "--yes"))

        yield {
            "home": home,
            "pre_minimax": pre_minimax,
            "pre_vertex": pre_vertex,
            "detect_ids": [f.get("surface_id") for f in detect["findings"]],
            "fixed": fix["fixed"],
            "fixed_ids": [f.get("surface_id") for f in fix["fixed"]],
            "post_minimax": _file_exists(oc, MINIMAX_PATH),
            "post_vertex": _file_exists(oc, VERTEX_PATH),
        }
    finally:
        _run(["docker", "rm", "-f", oc], timeout=60)


def test_home_resolves_to_container_node_home(unshardable_stack):
    """The detectors resolve surfaces under ``Path.home()``. If that isn't
    ``/home/node`` here, every detection below would be looking in the wrong
    place — pin it explicitly so a home-resolution regression fails loudly."""
    assert unshardable_stack["home"] == _HOME


def test_precondition_both_surfaces_were_planted(unshardable_stack):
    """Sanity gate: both files really existed before ``--fix``, else the
    "cleared" proof below would pass vacuously (nothing to clear)."""
    assert unshardable_stack["pre_minimax"], f"{MINIMAX_PATH} was not planted"
    assert unshardable_stack["pre_vertex"], f"{VERTEX_PATH} was not planted"


def test_doctor_detects_minimax_and_vertex_at_their_real_paths(unshardable_stack):
    """THE PATH-DRIFT PROOF: the real ``worthless doctor`` command, run in a
    real install, actually finds both surfaces at the real home-relative paths —
    not a monkeypatched HOME, an actual on-disk lookup through the CLI."""
    ids = unshardable_stack["detect_ids"]
    assert "minimax_cli_file" in ids, f"MiniMax surface not detected; got {ids}"
    assert "vertex_adc" in ids, f"Vertex ADC surface not detected; got {ids}"


def test_doctor_fix_clears_both_from_the_real_filesystem(unshardable_stack):
    """THE CLEAR PROOF: ``worthless doctor --fix`` reports both surfaces cleared
    AND they are genuinely gone from the real filesystem afterwards."""
    assert "minimax_cli_file" in unshardable_stack["fixed_ids"], unshardable_stack["fixed_ids"]
    assert "vertex_adc" in unshardable_stack["fixed_ids"], unshardable_stack["fixed_ids"]
    assert not unshardable_stack["post_minimax"], f"{MINIMAX_PATH} still on disk after --fix"
    assert not unshardable_stack["post_vertex"], f"{VERTEX_PATH} still on disk after --fix"


def test_vertex_fix_carries_the_gcloud_reauth_remediation(unshardable_stack):
    """Vertex ADC is the one surface with no in-app re-login flow — its cleared
    entry must carry the ``gcloud auth application-default login`` remediation
    so the user knows how to re-authenticate. Proven end-to-end through the real
    CLI, not just the unit that builds the string."""
    entry = next(
        (f for f in unshardable_stack["fixed"] if f.get("surface_id") == "vertex_adc"), None
    )
    assert entry is not None, f"no vertex_adc entry in fixed: {unshardable_stack['fixed']}"
    assert "gcloud auth application-default login" in entry.get("remediation", ""), (
        f"vertex remediation missing the gcloud re-auth command: {entry!r}"
    )


# ---------------------------------------------------------------------------
# WOR-823 — a scan that couldn't LOOK must not report it found nothing.
#
# On the pre-fix binary, an unreadable credential directory raised
# PermissionError straight out of detection; the doctor runner caught it at the
# check boundary and marked the whole check ``status="error"`` with no caveats
# (verified live in this exact image before the fix). A half-written
# auth-profiles.json was worse: swallowed silently, so every OAuth profile
# inside went unreported while the scan still read clean.
#
# The unit suite proves this on tmp_path, but its permission test SKIPS as root
# — and CI's user is not guaranteed. This container runs as the non-root
# ``node`` user, so ``chmod 000`` genuinely blocks and the permission path
# actually executes. This is the load-bearing guard for that path.
# ---------------------------------------------------------------------------

_BLIND_GEMINI_DIR = f"{_HOME}/.gemini"
_BLIND_AUTH_PROFILES = f"{_HOME}/.openclaw/agents/main/agent/auth-profiles.json"


@pytest.fixture(scope="module")
def blind_spot_stack():
    """A real install where two surfaces cannot be inspected: an unreadable
    credential directory (``chmod 000`` as the non-root node user) and a
    truncated ``auth-profiles.json``. Captures what the real ``worthless
    doctor`` reports — the whole point is that it neither crashes nor implies
    clean."""
    oc = f"wor823-blind-{uuid.uuid4().hex[:8]}"
    try:
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                oc,
                "-e",
                "OPENCLAW_ACCEPT_TERMS=yes",
                "--user",
                "node",
                OC_WORTHLESS_IMAGE,
            ],  # fmt: skip
            check=True,
        )
        _wait_worthless(oc)
        # Plant an unreadable Gemini creds dir and a half-written profile store.
        _sh(
            oc,
            "mkdir -p /home/node/.openclaw/agents/main/agent && "
            f'printf \'{{"profiles": {{"leaky": {{"type": "oau\' > {_BLIND_AUTH_PROFILES} && '
            f"mkdir -p {_BLIND_GEMINI_DIR} && "
            f'printf "{{}}" > {_BLIND_GEMINI_DIR}/oauth_creds.json && '
            f"chmod 000 {_BLIND_GEMINI_DIR}",
        )
        doc = _doctor_json(oc)
        yield {
            "doc": doc,
            "check": _unshardable_check(doc),
            "num_checks": len(doc["checks"]),
        }
    finally:
        # Restore perms before removal so docker's cleanup can traverse the dir.
        _sh(oc, f"chmod 700 {_BLIND_GEMINI_DIR} 2>/dev/null || true")
        _run(["docker", "rm", "-f", oc], timeout=60)


def test_doctor_survives_uninspectable_surfaces_without_crashing(blind_spot_stack):
    """THE CRASH GUARD: an unreadable credential dir used to make this check
    ``status="error"`` (a caught crash) in this exact image. The real doctor
    must now complete the whole scan and keep this check out of the error
    state."""
    check = blind_spot_stack["check"]
    assert blind_spot_stack["num_checks"] >= 2, "doctor returned a truncated run — it crashed"
    assert check["status"] != "error", (
        f"unshardable check is still in the crashed error state: {check!r}"
    )


def test_unreadable_dir_and_malformed_profiles_are_caveated_live(blind_spot_stack):
    """THE HONESTY PROOF: both blind spots are named in the real doctor's
    structured output, so a scan that couldn't look is never presented as a
    clean bill of health."""
    caveats = blind_spot_stack["check"].get("caveats") or []
    joined = " || ".join(caveats)
    assert any("could not be checked" in c for c in caveats), (
        f"the unreadable Gemini dir was not surfaced as a caveat: {caveats!r}"
    )
    assert "Gemini" in joined, "the permission caveat must name which surface"
    assert any("could not be read" in c for c in caveats), (
        f"the half-written auth-profiles.json was silently skipped, not caveated: {caveats!r}"
    )
