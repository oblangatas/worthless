"""The .grype.yaml expiry contract is enforced by us, not by grype.

Grype's IgnoreRule schema has no `expiry` field and silently drops unknown
keys, so a suppression dated 2020 still suppresses today (measured against
grype 0.114.0). scripts/hooks/check_grype_ignore_expiry.py is the only thing
making the file's "time-boxed" promise real — these tests keep it honest.
"""

from __future__ import annotations

import datetime as dt
import re
import importlib.util
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
HOOK = REPO / "scripts" / "hooks" / "check_grype_ignore_expiry.py"
WORKFLOW = REPO / ".github" / "workflows" / "docker-security.yml"
PUBLISH_WORKFLOW = REPO / ".github" / "workflows" / "publish-docker.yml"
INFORMATIONAL_CONFIG = REPO / ".grype-informational.yaml"
# arm64 runs on the weekly cron AND on manual dispatch. Dispatch matters: it is
# the only way to answer "is arm64 red right now?" between Mondays, and without
# it the workflow's break-glass trigger silently covered amd64 only.
ARM64_WHEN = 'contains(fromJSON(\'["schedule", "workflow_dispatch"]\'), github.event_name)'


def _load():
    spec = importlib.util.spec_from_file_location("grype_expiry_hook", HOOK)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / ".grype.yaml"
    p.write_text(body)
    return p


TODAY = dt.date(2026, 8, 1)


def test_current_ignore_passes(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path,
        'ignore:\n  - vulnerability: CVE-2026-11940\n    expiry: "2026-08-31"\n',
    )
    assert _load().check(cfg, TODAY) == []


def test_expired_ignore_is_reported(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path,
        'ignore:\n  - vulnerability: CVE-2026-11940\n    expiry: "2020-01-01"\n',
    )
    problems = _load().check(cfg, TODAY)
    assert len(problems) == 1
    assert "CVE-2026-11940" in problems[0]
    assert "expired" in problems[0]


def test_undated_ignore_is_reported(tmp_path: Path) -> None:
    """An ignore with no expiry never gets revisited — that is the failure mode."""
    cfg = _write(tmp_path, "ignore:\n  - vulnerability: CVE-2026-11940\n")
    problems = _load().check(cfg, TODAY)
    assert len(problems) == 1
    assert "no `expiry`" in problems[0]


def test_malformed_expiry_is_reported(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path,
        'ignore:\n  - vulnerability: CVE-2026-11940\n    expiry: "next tuesday"\n',
    )
    problems = _load().check(cfg, TODAY)
    assert len(problems) == 1
    assert "not an ISO date" in problems[0]


def test_expiry_boundary_is_inclusive(tmp_path: Path) -> None:
    """Expiring today is still valid; it lapses tomorrow."""
    cfg = _write(
        tmp_path,
        'ignore:\n  - vulnerability: CVE-2026-11940\n    expiry: "2026-08-01"\n',
    )
    mod = _load()
    assert mod.check(cfg, TODAY) == []
    assert len(mod.check(cfg, TODAY + dt.timedelta(days=1))) == 1


def test_no_ignores_is_fine(tmp_path: Path) -> None:
    assert _load().check(_write(tmp_path, "ignore: []\n"), TODAY) == []


@pytest.mark.parametrize("stamp", ["2026-08-31", '"2026-08-31"'])
def test_yaml_date_and_string_forms_both_parse(tmp_path: Path, stamp: str) -> None:
    """Unquoted YAML dates arrive as datetime.date, quoted ones as str."""
    cfg = _write(tmp_path, f"ignore:\n  - vulnerability: CVE-2026-11940\n    expiry: {stamp}\n")
    assert _load().check(cfg, TODAY) == []


def test_configs_covers_every_location_grype_reads() -> None:
    """Pin the WIRING, not just the logic.

    `grype config locations` (0.114.0) reports .grype.yaml and
    .grype/config.yaml as the two repo-root configs it auto-discovers, and
    anchore/scan-action passes no explicit --config. The blind-spot test below
    hands check_all() its own tuple, so without this assertion someone could
    delete the second entry from CONFIGS and no test would notice — which is
    exactly the hole this suite was written to close.
    """
    mod = _load()
    names = {str(c.relative_to(REPO)) for c in mod.CONFIGS}
    assert names == {".grype.yaml", ".grype/config.yaml"}, names


def test_missing_file_is_not_check_s_job(tmp_path: Path) -> None:
    """check() assumes the file exists; check_all() owns that invariant."""
    mod = _load()
    problems = mod.check_all((tmp_path / ".grype.yaml", tmp_path / "config.yaml"), TODAY)
    assert len(problems) == 1
    assert "no ignore policy" in problems[0]


# --- the .grype/config.yaml blind spot -------------------------------------
# grype reads BOTH .grype.yaml and .grype/config.yaml from the repo root
# (`grype config locations`, grype 0.114.0), and anchore/scan-action passes no
# explicit --config. Checking only the first left the second as a silent place
# to park undated suppressions.


def test_secondary_config_location_is_checked(tmp_path: Path) -> None:
    """An undated ignore in .grype/config.yaml must NOT slip through."""
    mod = _load()
    primary = _write(tmp_path, 'ignore:\n  - vulnerability: CVE-1\n    expiry: "2026-08-31"\n')
    nested = tmp_path / ".grype"
    nested.mkdir()
    secondary = nested / "config.yaml"
    secondary.write_text("ignore:\n  - vulnerability: CVE-2026-11940\n")

    problems = mod.check_all((primary, secondary), TODAY)
    assert len(problems) == 1
    assert "no `expiry`" in problems[0]
    assert "CVE-2026-11940" in problems[0]


def test_check_all_errors_when_no_config_exists(tmp_path: Path) -> None:
    mod = _load()
    problems = mod.check_all((tmp_path / ".grype.yaml", tmp_path / "config.yaml"), TODAY)
    assert len(problems) == 1
    assert "no ignore policy" in problems[0]


def test_rule_without_cve_id_is_rejected(tmp_path: Path) -> None:
    """A dated rule matching on package alone silences a whole class."""
    cfg = _write(
        tmp_path,
        'ignore:\n  - package:\n      type: binary\n    expiry: "2099-01-01"\n',
    )
    problems = _load().check(cfg, TODAY)
    assert len(problems) == 1
    assert "no `vulnerability` id" in problems[0]


def test_malformed_entry_does_not_crash(tmp_path: Path) -> None:
    """A non-mapping list item is reported, not an AttributeError traceback."""
    cfg = _write(tmp_path, "ignore:\n  - just-a-string\n")
    problems = _load().check(cfg, TODAY)
    assert len(problems) == 1
    assert "not a mapping" in problems[0]


def test_the_shipped_config_is_structurally_sound() -> None:
    """Every shipped ignore is named and dated — deliberately NOT a freshness check.

    Asserting the live config against `today` would red the whole unit suite
    the morning an expiry lapses, for every developer, on unrelated work.
    Freshness is the hook's job: it runs at commit time and again in
    docker-security.yml right before the scan. This guards the shape only, so
    the epoch date is used — nothing can be "expired" relative to 1970.
    """
    mod = _load()
    problems = mod.check_all(mod.CONFIGS, dt.date(1970, 1, 1))
    assert problems == [], "\n".join(problems)


# --- the scan policy itself (WOR-852) --------------------------------------
# A suppression is only half the contract. The other half lives in the
# workflow: which severities gate, and which config each scan reads. Both were
# wrong before WOR-852 and both failed silently, so they are pinned here.


def _scan_steps() -> list[dict]:
    """The two anchore/scan-action steps, in file order: gated, then informational."""
    # PyYAML resolves the bare `on:` key to True (YAML 1.1 booleans), so the
    # trigger block is looked up separately where it is needed.
    wf = yaml.safe_load(WORKFLOW.read_text())
    steps = wf["jobs"]["scan"]["steps"]
    return [s for s in steps if "anchore/scan-action" in str(s.get("uses", ""))]


def test_the_gate_fails_on_medium_not_just_high() -> None:
    """The gated scan must stop a fixable Medium, not wave it through.

    `severity-cutoff` becomes grype's `--fail-on`, an exit-code threshold that
    does NOT filter the report — so at `high` a fixable Medium was neither
    gated nor surfaced, and a new one arrived in silence. Reverting this to
    `high` re-opens that hole with a one-word edit and no other symptom.
    """
    gated = [s for s in _scan_steps() if s["with"].get("fail-build") is True]
    assert gated, "no build-failing scan step at all"
    # EVERY gated step, not just the first. WOR-873 added an arm64 gate beside
    # the amd64 one; a second gate at a looser cutoff would be a hole no
    # single-step assertion could see.
    for step in gated:
        assert step["with"]["severity-cutoff"] == "medium", (
            f"{step.get('name')} gates at {step['with'].get('severity-cutoff')}, not medium"
        )
        assert step["with"]["only-fixed"] is True, (
            f"{step.get('name')} gates on unfixable findings too"
        )


def test_the_informational_scan_does_not_inherit_the_gate_s_ignores() -> None:
    """Pointed at .grype.yaml, this scan hides what the gate already skips.

    A suppressed CVE would then appear in NO output anywhere: skipped by the
    gate AND omitted from the report. That regression shipped once during
    WOR-852 and was caught only by reading the CI log by hand.
    """
    informational = [s for s in _scan_steps() if s["with"].get("fail-build") is False]
    assert informational, "no informational scan step at all"
    for step in informational:
        assert step.get("env", {}).get("GRYPE_CONFIG") == INFORMATIONAL_CONFIG.name, (
            f"{step.get('name')} inherits the gate's suppressions"
        )
        # table is what puts findings in the job log; sarif (the action
        # default) is written to a file nothing uploads, so the report
        # reaches no human.
        assert step["with"]["output-format"] == "table", (
            f"{step.get('name')} writes a report nobody can read"
        )


def test_the_informational_config_suppresses_nothing() -> None:
    """An ignore here would re-create the very blind spot the file exists to close."""
    assert INFORMATIONAL_CONFIG.exists(), f"{INFORMATIONAL_CONFIG.name} is missing"
    assert not yaml.safe_load(INFORMATIONAL_CONFIG.read_text()).get("ignore")


def test_the_scan_reruns_when_its_own_config_changes() -> None:
    """A gate that cannot observe edits to itself will eventually ship one that disables it.

    This originally enumerated the globs the `paths:` filter had to contain.
    WOR-874 deleted that filter, so the property now holds for every path —
    but the property is what matters, not the mechanism, and re-adding a
    filter that omits these would silently restore the hole. The assertion
    therefore covers both worlds: no filter, or a filter that self-covers.

    The four paths matter for specific, already-observed reasons:
      - the workflow itself, or an edit disabling the gate ships unscanned
      - both grype config locations, since Actions globs do not cross `/`
      - publish-docker.yml, which triggers only on `v*` tags and is otherwise
        exercised by nothing; WOR-871 shipped its entire release-gate change
        with 36 green checks and no scan among them
    """
    must_cover = {
        ".github/workflows/docker-security.yml",
        ".github/workflows/publish-docker.yml",
        ".grype*.yaml",
        ".grype/config.yaml",
    }
    triggers = yaml.safe_load(WORKFLOW.read_text())[True]  # bare `on:` — see _scan_steps
    for event in ("push", "pull_request"):
        config = triggers.get(event)
        if not isinstance(config, dict) or "paths" not in config:
            continue  # unfiltered: every path re-triggers it, including these
        missing = must_cover - set(config["paths"])
        assert not missing, (
            f"{event}: a paths filter was re-added without {sorted(missing)}. "
            f"Edits to those files would then ship without ever running the gate "
            f"they modify. Prefer no filter at all — see WOR-874."
        )


# --- the RELEASE gate (WOR-871) --------------------------------------------
# Everything above guards the PR path. The artifact users actually `docker
# pull` is gated by a different workflow, and nothing kept the two in step.


# Grype severities, loosest gate first. A cutoff further right blocks more.
_STRICTNESS = ("negligible", "low", "medium", "high", "critical")


def _scan_step_images(workflow: Path) -> list[str]:
    """The `image:` each build-failing scan points at, in file order."""
    wf = yaml.safe_load(workflow.read_text())
    return [
        str(s.get("with", {}).get("image", ""))
        for j in wf["jobs"].values()
        for s in j.get("steps", [])
        if "anchore/scan-action" in str(s.get("uses", ""))
        and s.get("with", {}).get("fail-build") is True
    ]


def _gate_cutoffs(workflow: Path) -> list[str]:
    """Every build-failing anchore/scan-action cutoff in a workflow, lowercased.

    grype's --fail-on is case-insensitive, so `Medium` is valid config; compare
    normalised or a legal value blows up with a ValueError instead of a verdict.
    """
    wf = yaml.safe_load(workflow.read_text())
    cutoffs = []
    for job in wf["jobs"].values():
        for step in job.get("steps", []):
            with_ = step.get("with", {})
            if "anchore/scan-action" not in str(step.get("uses", "")):
                continue
            if with_.get("fail-build") is not True:
                continue
            cutoff = with_.get("severity-cutoff")
            assert cutoff, f"{workflow.name}: build-failing scan step has no severity-cutoff"
            cutoffs.append(str(cutoff).lower())
    return cutoffs


def test_the_release_gate_is_never_looser_than_the_pr_gate() -> None:
    """The published image must not be held to a weaker standard than a branch.

    A PR is a proposal; the GHCR image is what users run against real keys.
    Gating the proposal harder than the artifact is backwards, and it drifted
    that way silently — WOR-852 tightened the PR gate and nothing flagged that
    the release gate had been left two tiers behind.
    """
    pr = _gate_cutoffs(WORKFLOW)
    release = _gate_cutoffs(PUBLISH_WORKFLOW)
    assert pr, "no build-failing scan step in the PR workflow"
    # Arity, not just presence: the release path scans amd64 AND arm64, and
    # deleting one of those steps would otherwise leave this test green while
    # an entire architecture ships unscanned — the exact class of silent drift
    # this suite exists to catch.
    assert len(release) == 2, f"expected 2 release-gate scans (amd64, arm64), found {len(release)}"
    # Arity alone is gameable: duplicate the amd64 step, delete arm64, and a
    # count-only assertion stays green while an architecture ships unscanned.
    # The two scans must point at DIFFERENT images.
    images = _scan_step_images(PUBLISH_WORKFLOW)
    assert len(set(images)) == 2, f"both release scans point at the same image: {images}"
    archives = [i for i in images if i.startswith("docker-archive:")]
    assert archives, "no release scan reads a tarball — arm64 is unscanned"
    # A `docker-archive:` input proves a tarball, NOT an architecture. Two
    # amd64 builds with one exported to a tarball would satisfy everything
    # above while the arm64 image users pull has no gate at all. Trace the
    # tarball back to the step that produced it and check what it built.
    wf = yaml.safe_load(PUBLISH_WORKFLOW.read_text())
    steps = [s for j in wf["jobs"].values() for s in j.get("steps", [])]
    producers = [
        s
        for s in steps
        if "build-push-action" in str(s.get("uses", ""))
        and "ARM64_TAR" in str(s.get("with", {}).get("outputs", ""))
    ]
    assert producers, "nothing produces the scanned tarball"
    for step in producers:
        assert step["with"]["platforms"] == "linux/arm64", (
            f"the scanned tarball is built for {step['with']['platforms']}, not arm64"
        )
    weakest_pr = min(_STRICTNESS.index(c) for c in pr)
    for cutoff in release:
        assert _STRICTNESS.index(cutoff) <= weakest_pr, (
            f"release gate `{cutoff}` is looser than the PR gate `{_STRICTNESS[weakest_pr]}`"
        )


def test_the_release_gate_enforces_ignore_expiry() -> None:
    """Suppressions are time-boxed only where something checks the date.

    Grype drops the unknown `expiry` key silently, so the hook is the sole
    enforcement. The PR gate runs it; without this the release path honours
    every suppression in .grype.yaml with nothing policing whether they have
    lapsed — on the one path that reaches users.
    """
    # Structural, not a substring grep on the file text: `if: false`,
    # `continue-on-error: true`, or commenting the step out must all fail this.
    wf = yaml.safe_load(PUBLISH_WORKFLOW.read_text())
    steps = [s for j in wf["jobs"].values() for s in j.get("steps", [])]
    hook = [
        i
        for i, s in enumerate(steps)
        if "check_grype_ignore_expiry.py" in str(s.get("run", ""))
        and s.get("if") is None
        and s.get("continue-on-error") is not True
    ]
    assert hook, "release workflow never enforces .grype.yaml expiry dates"
    # Existing is not enough — it has to run BEFORE the scans it protects.
    # Placed after them, a lapsed suppression is still honoured by every scan
    # and the hook only reports it once the gate has already passed.
    scans = [i for i, s in enumerate(steps) if "anchore/scan-action" in str(s.get("uses", ""))]
    assert hook[0] < min(scans), "expiry check runs after the scans it is supposed to guard"


def test_arm64_is_scanned_before_a_release_not_only_during_one() -> None:
    """arm64 must meet the Medium bar somewhere other than the release tag.

    The PR scan builds whatever the runner is — amd64. Before WOR-873 the only
    place arm64 met a gate was the release job, which fires on a `v*` tag: one
    arm64-only fixable Medium turned every PR green and then failed a release
    with the tag already pushed and no image behind it.

    Scheduled-only by design, so PRs are not taxed ~8-12min of QEMU. This pins
    BOTH halves — that arm64 is gated at all, and that it stays off the PR path.
    """
    wf = yaml.safe_load(WORKFLOW.read_text())
    steps = [s for j in wf["jobs"].values() for s in j.get("steps", [])]
    arm64_gates = [
        s
        for s in steps
        if "anchore/scan-action" in str(s.get("uses", ""))
        and "ARM64_TAR" in str(s.get("with", {}).get("image", ""))
        and s.get("with", {}).get("fail-build") is True
    ]
    assert arm64_gates, "arm64 is gated only at the release tag"
    for gate in arm64_gates:
        assert gate.get("if") == ARM64_WHEN, (
            "arm64 gate is not schedule-scoped — this taxes every PR with QEMU"
        )
    # And the tarball it reads must actually have been built for arm64.
    producers = [
        s
        for s in steps
        if "build-push-action" in str(s.get("uses", ""))
        and "ARM64_TAR" in str(s.get("with", {}).get("outputs", ""))
    ]
    assert producers, "nothing produces the arm64 tarball"
    for p in producers:
        assert p["with"]["platforms"] == "linux/arm64", (
            f"the scanned tarball is built for {p['with']['platforms']}"
        )
    # The EXPENSIVE steps must be schedule-scoped too, not just the scan.
    # Scoping only the scan would still run QEMU and an emulated arm64 build
    # on every PR — the ~8-12min tax this design exists to avoid — while
    # leaving the assertion above perfectly green.
    emulation = [
        s
        for s in steps
        if "setup-qemu-action" in str(s.get("uses", ""))
        or "setup-buildx-action" in str(s.get("uses", ""))
    ]
    for s in emulation + producers:
        assert s.get("if") == ARM64_WHEN, (
            f"{s.get('name') or s.get('uses')} runs on every PR — arm64 emulation is not free"
        )


def test_the_weekly_cron_still_exists() -> None:
    """Delete the cron and arm64 is scanned nowhere but a release tag.

    The arm64 steps are scoped to `schedule` / `workflow_dispatch`, so the cron
    IS the coverage. Every other test here passed with `schedule:` removed —
    the guards were green, and the thing they guarded never ran.
    """
    triggers = yaml.safe_load(WORKFLOW.read_text())[True]
    assert "schedule" in triggers, "the weekly cron is gone — arm64 is scanned only at a tag"
    assert triggers["schedule"], "schedule block is empty"
    # Both halves of ARM64_WHEN must survive, not just the cron. Drop
    # `workflow_dispatch` and every ARM64_WHEN assertion still passes while the
    # only way to check arm64 between Mondays quietly disappears — which is the
    # hole WOR-873 found in the first place, one trigger over.
    assert "workflow_dispatch" in triggers, (
        "no manual trigger — arm64 can only be checked by waiting for the cron"
    )


def test_a_routine_push_cannot_cancel_the_weekly_scan() -> None:
    """`github.event_name` must be in the concurrency key.

    Without it a scheduled run and a push to main both key on `refs/heads/main`,
    and `cancel-in-progress: true` lets any Monday-morning push kill the cron
    partway through the emulated arm64 build. Cancelled runs render grey, not
    red, so coverage could sit at zero for weeks with nothing looking wrong.
    """
    wf = yaml.safe_load(WORKFLOW.read_text())
    group = str(wf["concurrency"]["group"])
    if wf["concurrency"].get("cancel-in-progress"):
        assert "github.event_name" in group, f"cron shares a cancellation lane with pushes: {group}"


def test_the_scan_job_cannot_run_away() -> None:
    """A hung emulated build must not burn the 6h default before anyone hears."""
    wf = yaml.safe_load(WORKFLOW.read_text())
    timeout = wf["jobs"]["scan"].get("timeout-minutes")
    assert timeout, "scan job has no timeout-minutes — it now builds twice"
    assert timeout <= 60, f"timeout-minutes={timeout} is not a meaningful bound"


def test_a_cve_does_not_swallow_the_dockle_signal() -> None:
    """One arm64 CVE must not silently skip an unrelated best-practice check."""
    wf = yaml.safe_load(WORKFLOW.read_text())
    dockle = [
        s
        for j in wf["jobs"].values()
        for s in j.get("steps", [])
        if "dockle-action" in str(s.get("uses", ""))
    ]
    assert dockle, "no Dockle step"
    for step in dockle:
        assert step.get("if") == "always()", (
            "a failing scan above skips Dockle — two independent problems, one report"
        )


def test_the_ignore_file_says_which_architecture_it_measured() -> None:
    """Reachability arguments are evidence, and evidence has a platform.

    All 7 were measured on amd64 and applied to both architectures. That is
    defensible, but only while it is stated — WOR-873 AC 3.
    """
    header = (REPO / ".grype.yaml").read_text()
    assert "amd64" in header, ".grype.yaml does not say which arch its arguments cover"


def test_the_release_workflow_cannot_be_triggered_by_hand() -> None:
    """`workflow_dispatch` here is a publishing hole, not a break-glass.

    GitHub runs the workflow FROM the dispatched ref, so a branch dispatch
    supplies both the Dockerfile and this workflow — a branch could delete the
    release gate and still publish under the repo's OIDC identity. And because
    `type=semver` yields no tags on a non-tag ref, the build, the push by
    digest and `cosign sign` all SUCCEED; only promotion fails, leaving a
    signed orphan digest whose Fulcio SAN is `@refs/heads/...` rather than the
    `@refs/tags/v.*` our documented verify command pins.

    Added and removed inside WOR-871; this keeps it from coming back.

    An ALLOWLIST, not a `workflow_dispatch not in ...` denylist. `workflow_call`
    (a callee inherits the caller's ref), `repository_dispatch`, `schedule`, or
    `push: branches:` each reopen the same hole while leaving that one string
    absent. Tag-push is the only way this workflow may ever start.
    """
    triggers = yaml.safe_load(PUBLISH_WORKFLOW.read_text())[True]
    assert set(triggers) == {"push"}, (
        f"release workflow must trigger ONLY on push; found {sorted(triggers)}"
    )
    assert set(triggers["push"]) == {"tags"}, (
        f"release workflow must trigger only on TAG push; found {sorted(triggers['push'])}"
    )


# --- scheduled checks must be honest (WOR-877) -----------------------------
# scheduled.yml failed every run it has ever had — 45 of 46, the 46th being
# the dispatch that proved this fix. But the three jobs failed for DIFFERENT
# reasons, and conflating them was an error worth not repeating:
#
#   Mutation testing (crypto)   45/45 failure — never worked, dead mutmut flags
#   Contract tests              45/45 failure — never worked, marker on 0 tests
#   Secret scan (full history)  43/46 SUCCESS — worked fine, regressed 2026-08-07
#
# The scanner is a RECENT regression, not a control that was always broken.
# Repo content did not change (matching identifier count stable across the
# window), so the cause is upstream in TruffleHog's Lob detector and is
# undiagnosed. That matters for the exclusion below: it may be pinning around
# an upstream bug that gets fixed, in which case the exclusion should be
# removed rather than inherited forever.
#
# What the two dead jobs cost was attention: the workflow was red every run
# regardless, so the scanner's genuine regression on 08-07 arrived in a channel
# nobody was reading. These guards pin each failure mode closed.

SCHEDULED_WORKFLOW = REPO / ".github" / "workflows" / "scheduled.yml"
PRERELEASE_WORKFLOW = REPO / ".github" / "workflows" / "pre-release.yml"


def _all_run_steps(workflow: Path) -> list[str]:
    wf = yaml.safe_load(workflow.read_text())
    return [
        str(s.get("run", ""))
        for j in wf["jobs"].values()
        for s in j.get("steps", [])
        if s.get("run")
    ]


def test_no_workflow_invokes_mutmut_with_flags_it_removed() -> None:
    """mutmut 3.x deleted `--paths-to-mutate` and `--runner`.

    The lockfile pins mutmut==3.6.0, whose `run` accepts only `--max-children`.
    Both workflows carried the 2.x invocation and crashed on startup — 45/45
    scheduled runs and 4/4 pre-release runs, every one a failure, for four
    months. Nobody noticed, because nobody reads a job that is always red.
    """
    dead = ("--paths-to-mutate", "--runner")
    # EVERY workflow, not two by name — a new mutation.yml must be covered too.
    for wf in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        for cmd in _all_run_steps(wf):
            if "mutmut" not in cmd:
                continue
            for flag in dead:
                assert flag not in cmd, (
                    f"{wf.name} calls mutmut with {flag}, removed in mutmut 3.x — "
                    "the job cannot start"
                )


def test_no_job_selects_a_pytest_marker_no_test_carries() -> None:
    """`pytest -m <marker>` with zero matching tests exits 5 and looks like failure.

    The `contract` marker was declared in pyproject.toml and documented in the
    CI marker map, and applied to zero tests. The job never tested anything.
    """
    import re

    for wf in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        for cmd in _all_run_steps(wf):
            if "pytest" not in cmd:
                continue
            # Handles `-m contract`, `-m "contract"`, `-m 'not slow'`. A bare
            # \\w+ pattern silently skipped every QUOTED form, so the guard was
            # satisfiable while a dead marker sat in a quoted selector.
            for raw in re.findall(r"-m\s+('[^']*'|\"[^\"]*\"|\S+)", cmd):
                expr = raw.strip("'\"")
                if any(op in expr.split() for op in ("not", "and", "or")):
                    continue  # compound selectors exclude, they don't demand a marker
                marker = expr
                hits = list(REPO.glob("tests/**/*.py"))
                carried = any(f"pytest.mark.{marker}" in f.read_text(errors="ignore") for f in hits)
                assert carried, (
                    f"{wf.name} runs `pytest -m {marker}` but no test carries that "
                    "marker — the job exits 5 and reports red forever"
                )


def test_the_secret_scan_excludes_the_detector_that_matches_test_names() -> None:
    """TruffleHog's Lob detector fires on pytest function names.

    Its regex is `\b(live|test)_[a-zA-Z0-9_]{35}\b` — no keyword proximity, and
    `_` is a body character. Every pytest function named `test_` plus exactly 35
    more characters matches. Measured 149 "verified" findings, each one a test
    function name with a file and line (e.g. tests/test_confusables.py:93 ->
    test_clean_and_legit_names_get_no_marker). "Verified" carries no weight
    here: Lob's verify() treats HTTP 403/422 as success.

    Excluding ONE detector, not the scan — proven narrow: with this flag a
    planted non-Lob token is still caught.
    """
    wf = yaml.safe_load(SCHEDULED_WORKFLOW.read_text())
    steps = [
        s
        for j in wf["jobs"].values()
        for s in j.get("steps", [])
        if "trufflehog" in str(s.get("uses", "")).lower()
    ]
    assert steps, "no TruffleHog step at all"
    for step in steps:
        args = str(step.get("with", {}).get("extra_args", ""))
        # Parse the VALUE and assert the exact set. A substring check passes
        # for `--exclude-detectors=lob,aws,github`, which would silence real
        # detectors — failing open in exactly the direction this comment
        # forbids. Also tolerates `--exclude-detectors lob` (space form).
        found = re.findall(r"--exclude-detectors[= ]([^\\s]+)", args)
        assert found, (
            "TruffleHog step does not exclude the Lob detector — 149 pytest "
            "function names will be reported as verified secrets"
        )
        excluded = {d.strip().lower() for f in found for d in f.split(",") if d.strip()}
        assert excluded == {"lob"}, (
            f"TruffleHog excludes {sorted(excluded)} — only `lob` is argued for. "
            "Every other detector must stay live; see the step's comment."
        )
        assert "--only-verified" in args, (
            "dropping --only-verified would flood the scan with unverified noise"
        )


def test_trufflehog_pins_an_exact_scanner_version() -> None:
    """The action SHA pins the wrapper; `version` pins the scanner itself.

    trufflesecurity/trufflehog is a thin wrapper that runs
    `docker run ghcr.io/trufflesecurity/trufflehog:${VERSION}`, and its
    `version` input defaults to `latest` — a mutable tag upstream can repoint
    at will. Without an explicit pin the SHA is decorative: the code that
    actually scans this repo is whatever `latest` resolved to that morning.

    A version TAG rather than a digest is deliberate and forced: the action
    interpolates "${IMAGE}:${VERSION}" with a colon, so a digest yields the
    invalid ref `trufflehog:sha256:...`. A release tag is the strongest form
    this action accepts. WOR-876.
    """
    for wf in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        doc = yaml.safe_load(wf.read_text())
        for job in (doc.get("jobs") or {}).values():
            for step in job.get("steps") or []:
                if "trufflesecurity/trufflehog" not in str(step.get("uses", "")):
                    continue
                version = str((step.get("with") or {}).get("version", "")).strip()
                assert version, (
                    f"{wf.name}: the TruffleHog step pins no `version`, so it runs "
                    f"whatever `latest` resolves to. The action SHA alone does not "
                    f'pin the scanner. Set an exact release, e.g. version: "3.96.0".'
                )
                assert re.fullmatch(r"\d+\.\d+\.\d+", version), (
                    f"{wf.name}: TruffleHog version {version!r} is not an exact "
                    f"release. `latest` and floating majors are mutable — upstream "
                    f"can repoint them, which is what pinning exists to prevent."
                )


# Jobs that carry the container security gates. A `paths:` filter on their
# workflow makes them unusable as required checks: GitHub only creates a check
# run when the workflow triggers, so on a PR that matches no glob the required
# context never reports and the PR waits forever. Nine PRs went BLOCKED with
# zero failing checks the day `scan` was made required. WOR-874.
GATE_WORKFLOW = REPO / ".github" / "workflows" / "docker-security.yml"


def test_gate_workflow_has_no_paths_filter() -> None:
    """A gate that reports on only some PRs cannot be a required check.

    `severity-cutoff` and the ignore rules decide whether the gate is right.
    This decides whether it is present at all — the failure mode is silence,
    not a wrong answer, and silence is invisible in a PR's check list.
    """
    doc = yaml.safe_load(GATE_WORKFLOW.read_text())
    triggers = doc.get(True) or doc.get("on") or {}
    for event in ("push", "pull_request"):
        config = triggers.get(event)
        if not isinstance(config, dict):
            continue
        for key in ("paths", "paths-ignore"):
            assert key not in config, (
                f"docker-security.yml `{event}` has a `{key}` filter. These jobs "
                f"gate container CVEs and the end-to-end credential tests; a "
                f"filtered gate does not report on non-matching PRs, so making it "
                f"required leaves those PRs permanently BLOCKED with no failing "
                f"check. Runners are free on a public repo — let it always run."
            )


def test_gate_jobs_are_unconditional_and_time_limited() -> None:
    """No job-level `if:`, and every job bounded.

    A skipped job reports SUCCESS to branch protection, so gating these with
    an `if:` converts the gate into a bypass — worse than the deadlock it
    would be working around. And an untimed required job that hangs blocks
    merges until GitHub's 6-hour default expires.
    """
    doc = yaml.safe_load(GATE_WORKFLOW.read_text())
    for name, job in (doc.get("jobs") or {}).items():
        assert "if" not in job, (
            f"job {name!r} has a job-level `if:`. A skipped job counts as SUCCESS "
            f"to branch protection, which turns this gate into a bypass."
        )
        assert isinstance(job.get("timeout-minutes"), int), (
            f"job {name!r} has no `timeout-minutes`, so it inherits GitHub's "
            f"6-hour default. A required job that hangs blocks every merge."
        )
