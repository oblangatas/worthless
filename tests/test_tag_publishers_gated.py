"""Every workflow that publishes on a `v*` tag must verify the signed tag first.

WOR-881. The maintainer-GPG gate is described as the thing that authorises a
release. For the container lane that was simply not true: `publish-docker.yml`
triggers on `push: tags: v*` and never invoked `.github/scripts/verify-tag.sh`.

Measured, not hypothesised — on all three v0.3.12 tag pushes the three gated
publishers failed closed and the container published anyway:

    08-12 19:20   PyPI x  npm x  worker x   docker OK   (tag object unfetchable)
    08-16 20:44   PyPI x  npm x  worker x   docker OK   (SSH-signed, wrong key)
    08-16 20:48   PyPI OK npm OK worker OK  docker OK   (the good tag)

cosign then attests whatever it is handed, so an unverified image ends up
carrying a valid signature — the gap manufactures trust rather than merely
missing it. GHCR also overwrites by tag, so a later push silently replaces the
image behind an existing version.

Three properties are asserted here, and the third is the one that survives:

1. every tag-triggered workflow is CLASSIFIED as publisher or non-publisher, so
   a newly added publisher fails this test until someone declares it;
2. every publisher invokes verify-tag.sh;
3. the verify step comes BEFORE the first step that ships anything.

Matching ignores comments. A whole-file substring check is satisfied by the
marker appearing in a comment left behind by the change that deleted the code —
that exact failure shipped four times in `test-verify-tag-multikey.sh` during
#501 and was only caught by mutation testing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
VERIFY_SCRIPT = "verify-tag.sh"

# Workflows that ship an artifact when a `v*` tag is pushed. Each MUST verify.
TAG_PUBLISHERS = {
    "publish.yml": "uploads the wheel + sdist to PyPI",
    "publish-npm.yml": "publishes the worthless-mcp wrapper to npm",
    "publish-docker.yml": "pushes and cosign-signs the proxy image to GHCR",
    "deploy-worker.yml": "deploys the worthless.sh Cloudflare Worker",
}

# Tag-triggered workflows that ship nothing. Each needs a stated reason, so
# "it doesn't publish" is a claim someone made on purpose rather than an
# omission nobody noticed.
TAG_NON_PUBLISHERS = {
    "tests.yml": "runs the test suite; produces no external artifact",
    "pre-release.yml": "pre-release qualifiers only (v*rc*, v*a*, v*b*)",
}
# docker-security.yml is deliberately absent: #507 rescoped it to
# workflow_dispatch + push-to-main + schedule, so it is no longer tag-triggered.
# The stale-entry half of the classification test is what caught that.


def _workflow_files() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml"))


def _triggers_on_version_tag(data: object) -> bool:
    """True when the workflow fires on a pushed tag.

    YAML 1.1 parses a bare `on:` key as the boolean True, so the trigger block
    is looked up under both spellings. Reading only the string key silently
    finds nothing and would make this whole file vacuous.
    """
    if not isinstance(data, dict):
        return False
    triggers = data.get("on", data.get(True))
    if not isinstance(triggers, dict):
        return False
    push = triggers.get("push")
    return isinstance(push, dict) and "tags" in push


def _code_of(path: Path) -> str:
    """Workflow text with comment-only lines removed."""
    return "\n".join(
        line for line in path.read_text().splitlines() if not line.lstrip().startswith("#")
    )


def _tag_triggered() -> dict[str, Path]:
    found = {}
    for path in _workflow_files():
        try:
            data = yaml.safe_load(path.read_text())
        except yaml.YAMLError:  # pragma: no cover - a malformed workflow fails elsewhere
            continue
        if _triggers_on_version_tag(data):
            found[path.name] = path
    return found


def test_every_tag_triggered_workflow_is_classified() -> None:
    """A new tag-triggered workflow must be declared publisher or not.

    This is the property that makes the other two durable. Without it, adding a
    fifth publisher silently inherits no gate — which is exactly how the
    container lane went unnoticed from v0.3.4 to v0.3.12.
    """
    classified = set(TAG_PUBLISHERS) | set(TAG_NON_PUBLISHERS)
    actual = set(_tag_triggered())

    unclassified = actual - classified
    assert not unclassified, (
        f"these workflows trigger on a pushed tag but are not classified: {sorted(unclassified)}.\n"
        "Add each to TAG_PUBLISHERS (and give it the verify-tag step) or to "
        "TAG_NON_PUBLISHERS with a reason it ships nothing."
    )

    stale = classified - actual
    assert not stale, (
        f"classified but no longer tag-triggered: {sorted(stale)}. Drop them from the tables."
    )


@pytest.mark.parametrize("name", sorted(TAG_PUBLISHERS), ids=sorted(TAG_PUBLISHERS))
def test_tag_publisher_verifies_the_signed_tag(name: str) -> None:
    """Every publisher runs verify-tag.sh. WOR-881: the container one did not."""
    path = WORKFLOWS / name
    assert path.exists(), f"{name} is listed as a publisher but does not exist"

    assert VERIFY_SCRIPT in _code_of(path), (
        f"{name} publishes on a v* tag ({TAG_PUBLISHERS[name]}) but never runs "
        f"{VERIFY_SCRIPT}.\n"
        "An unsigned or wrongly-signed tag would ship through it while the other "
        "publishers fail closed — measured three times out of three on v0.3.12."
    )


# Steps that put an artifact somewhere the outside world can reach it. The
# verify must precede all of them; verifying after publishing proves nothing.
PUBLISH_MARKERS = (
    "docker/build-push-action",
    "pypa/gh-action-pypi-publish",
    "npm publish",
    "cosign sign",
    "wrangler",
    "gh release create",
)


@pytest.mark.parametrize("name", sorted(TAG_PUBLISHERS), ids=sorted(TAG_PUBLISHERS))
def test_verify_precedes_anything_that_ships(name: str) -> None:
    """The gate must run before the first shipping step, not merely somewhere."""
    code = _code_of(WORKFLOWS / name)

    verify_at = code.find(VERIFY_SCRIPT)
    if verify_at == -1:
        pytest.skip("covered by test_tag_publisher_verifies_the_signed_tag")

    for marker in PUBLISH_MARKERS:
        ships_at = code.find(marker)
        if ships_at == -1:
            continue
        assert verify_at < ships_at, (
            f"{name} reaches {marker!r} before running {VERIFY_SCRIPT}. "
            "A gate that runs after the artifact is out is decoration."
        )


def test_the_gate_script_itself_exists() -> None:
    """Guard against the tables above pointing at a script someone deleted."""
    assert (REPO_ROOT / ".github" / "scripts" / VERIFY_SCRIPT).exists()
