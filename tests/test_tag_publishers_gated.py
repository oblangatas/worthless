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


# --------------------------------------------------------------------------
# The tests above prove the gate is PRESENT and correctly PLACED. They do not
# prove it RUNS. Four independent reviews demonstrated the gap with mutations
# that each disable the gate while leaving this suite green:
#
#     if: false                     on the verify step
#     run: ... || true              swallows the failure
#     continue-on-error: true       job continues, image ships, workflow green
#     add workflow_dispatch:        event_name guard turns fail-closed into skip
#
# The last one is not hypothetical: publish-docker.yml's own header records that
# workflow_dispatch was added in WOR-871 and removed only after review. publish.yml
# is already guarded against it by test_deploy_static.py::test_no_skip_path_triggers;
# these extend the same idea to every publisher.
# --------------------------------------------------------------------------

PUSH_GUARD = "github.event_name == 'push'"


def _verify_step(name: str) -> dict:
    """The parsed verify-tag step, located through the job/step structure.

    Text position cannot answer this: `str.find` measures characters, while GitHub
    executes steps by index within a job and jobs by `needs:`. Two of the four
    publishers are multi-job.
    """
    data = yaml.safe_load((WORKFLOWS / name).read_text())
    for job in (data.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            run = step.get("run") or ""
            if VERIFY_SCRIPT in run:
                return step
    raise AssertionError(f"{name}: no step whose `run` invokes {VERIFY_SCRIPT}")


@pytest.mark.parametrize("name", sorted(TAG_PUBLISHERS), ids=sorted(TAG_PUBLISHERS))
def test_the_gate_is_not_defanged(name: str) -> None:
    """The verify step must be able to fail the job."""
    step = _verify_step(name)

    assert not step.get("continue-on-error"), (
        f"{name}: the verify step has continue-on-error, so a failed signature "
        "check no longer stops the publish."
    )

    run = step.get("run", "")
    for swallow in ("||", "| true", "set +e"):
        assert swallow not in run, (
            f"{name}: the verify step's run contains {swallow!r}, which can swallow "
            f"a non-zero exit.\n  run: {run.strip()}"
        )

    condition = step.get("if")
    assert condition is None or PUSH_GUARD in str(condition), (
        f"{name}: the verify step's `if:` is {condition!r}. Only the push guard "
        f"({PUSH_GUARD}) is allowed — anything else can silently skip the gate "
        "and a skipped gate does not fail a job."
    )


# A publisher may carry a non-push trigger ONLY when that trigger provably
# cannot reach production. Each entry says why, and the test below verifies the
# claim rather than trusting it.
EXTRA_TRIGGERS_ALLOWED = {
    "deploy-worker.yml": (
        "workflow_dispatch is restricted to target=preview; production is tag-only"
    ),
}


@pytest.mark.parametrize("name", sorted(TAG_PUBLISHERS), ids=sorted(TAG_PUBLISHERS))
def test_publisher_has_no_trigger_that_skips_the_gate(name: str) -> None:
    """A publisher fires only on a pushed tag, unless a declared exception holds.

    The verify step is guarded on `event_name == 'push'`, so any additional
    trigger converts the gate from fail-closed to SKIPPED while the build, the
    push and cosign still run — a signed artifact nobody checked. WOR-871 added
    exactly such a trigger to publish-docker.yml once already.

    deploy-worker.yml is the one legitimate exception: its dispatch input is a
    `choice` offering only "preview". That is asserted here, not assumed — add
    "production" to the options and this test fails.
    """
    data = yaml.safe_load((WORKFLOWS / name).read_text())
    triggers = data.get("on", data.get(True))
    assert isinstance(triggers, dict), f"{name}: could not read the trigger block"

    assert "tags" in (triggers.get("push") or {}), (
        f"{name}: push trigger has no `tags:` filter, so it would fire on branches "
        "where GITHUB_REF_NAME is not a tag."
    )

    extra = set(triggers) - {"push"}
    if not extra:
        return

    assert name in EXTRA_TRIGGERS_ALLOWED, (
        f"{name} triggers on {sorted(extra)} besides push. The gate is guarded on "
        "github.event_name == 'push', so any other trigger skips it while everything "
        "downstream still ships. Remove the trigger, or add an entry to "
        "EXTRA_TRIGGERS_ALLOWED explaining why it cannot reach production."
    )

    if name == "deploy-worker.yml":
        options = (
            ((triggers.get("workflow_dispatch") or {}).get("inputs") or {})
            .get("target", {})
            .get("options")
        )
        assert options == ["preview"], (
            "deploy-worker.yml's dispatch is allowed only because it can reach "
            f"nothing but preview. Its target options are now {options!r}. If a "
            "production target is reachable by dispatch, the signature gate is "
            "skippable — remove it or gate the deploy on event_name."
        )


@pytest.mark.parametrize("name", sorted(TAG_NON_PUBLISHERS), ids=sorted(TAG_NON_PUBLISHERS))
def test_a_declared_non_publisher_really_ships_nothing(name: str) -> None:
    """The classification cannot be a lie told to silence the other tests.

    Without this, the cheapest way to make a failing publisher green is to move
    it into TAG_NON_PUBLISHERS and delete its gate — the table is self-declared
    and nothing checked it against what the workflow actually does. Verified as
    a real survivor: that mutation left the suite green.
    """
    code = _code_of(WORKFLOWS / name)
    found = [marker for marker in PUBLISH_MARKERS if marker in code]
    assert not found, (
        f"{name} is declared a non-publisher ({TAG_NON_PUBLISHERS[name]}) but "
        f"contains {found}, which ship artifacts. Either it belongs in "
        "TAG_PUBLISHERS with a verify-tag step, or the claim is wrong."
    )
