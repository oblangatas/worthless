"""The .grype.yaml expiry contract is enforced by us, not by grype.

Grype's IgnoreRule schema has no `expiry` field and silently drops unknown
keys, so a suppression dated 2020 still suppresses today (measured against
grype 0.114.0). scripts/hooks/check_grype_ignore_expiry.py is the only thing
making the file's "time-boxed" promise real — these tests keep it honest.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
HOOK = REPO / "scripts" / "hooks" / "check_grype_ignore_expiry.py"
WORKFLOW = REPO / ".github" / "workflows" / "docker-security.yml"
PUBLISH_WORKFLOW = REPO / ".github" / "workflows" / "publish-docker.yml"
INFORMATIONAL_CONFIG = REPO / ".grype-informational.yaml"


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
    assert len(gated) == 1, "expected exactly one build-failing scan step"
    assert gated[0]["with"]["severity-cutoff"] == "medium"
    assert gated[0]["with"]["only-fixed"] is True


def test_the_informational_scan_does_not_inherit_the_gate_s_ignores() -> None:
    """Pointed at .grype.yaml, this scan hides what the gate already skips.

    A suppressed CVE would then appear in NO output anywhere: skipped by the
    gate AND omitted from the report. That regression shipped once during
    WOR-852 and was caught only by reading the CI log by hand.
    """
    informational = [s for s in _scan_steps() if s["with"].get("fail-build") is False]
    assert len(informational) == 1, "expected exactly one informational scan step"
    step = informational[0]
    assert step.get("env", {}).get("GRYPE_CONFIG") == INFORMATIONAL_CONFIG.name
    # table is what puts findings in the job log; sarif (the action default)
    # is written to a file nothing uploads, so the report reaches no human.
    assert step["with"]["output-format"] == "table"


def test_the_informational_config_suppresses_nothing() -> None:
    """An ignore here would re-create the very blind spot the file exists to close."""
    assert INFORMATIONAL_CONFIG.exists(), f"{INFORMATIONAL_CONFIG.name} is missing"
    assert not yaml.safe_load(INFORMATIONAL_CONFIG.read_text()).get("ignore")


def test_the_scan_reruns_when_its_own_config_changes() -> None:
    """A gate that cannot observe edits to itself will eventually ship one that disables it."""
    wf = yaml.safe_load(WORKFLOW.read_text())
    triggers = wf[True]  # bare `on:` — see _scan_steps
    for event in ("push", "pull_request"):
        paths = set(triggers[event]["paths"])
        assert ".grype*.yaml" in paths, f"{event}: grype configs not in paths filter"
        assert ".github/workflows/docker-security.yml" in paths, (
            f"{event}: workflow not self-covering"
        )
        # Actions path globs do not cross `/`, so `.grype*.yaml` does NOT match
        # the nested location — the same blind spot CONFIGS covers above. An
        # ignore parked there would otherwise never re-trigger the scan.
        assert ".grype/config.yaml" in paths, f"{event}: nested grype config not in paths filter"


# --- the RELEASE gate (WOR-871) --------------------------------------------
# Everything above guards the PR path. The artifact users actually `docker
# pull` is gated by a different workflow, and nothing kept the two in step.


# Grype severities, loosest gate first. A cutoff further right blocks more.
_STRICTNESS = ("negligible", "low", "medium", "high", "critical")


def _gate_cutoffs(workflow: Path) -> list[str]:
    """Every build-failing anchore/scan-action cutoff in a workflow."""
    wf = yaml.safe_load(workflow.read_text())
    return [
        step["with"]["severity-cutoff"]
        for job in wf["jobs"].values()
        for step in job.get("steps", [])
        if "anchore/scan-action" in str(step.get("uses", ""))
        and step.get("with", {}).get("fail-build") is True
    ]


def test_the_release_gate_is_never_looser_than_the_pr_gate() -> None:
    """The published image must not be held to a weaker standard than a branch.

    A PR is a proposal; the GHCR image is what users run against real keys.
    Gating the proposal harder than the artifact is backwards, and it drifted
    that way silently — WOR-852 tightened the PR gate and nothing flagged that
    the release gate had been left two tiers behind.
    """
    pr = _gate_cutoffs(WORKFLOW)
    release = _gate_cutoffs(PUBLISH_WORKFLOW)
    assert pr and release, "expected build-failing scan steps in both workflows"
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
    assert "check_grype_ignore_expiry.py" in PUBLISH_WORKFLOW.read_text(), (
        "release workflow never validates .grype.yaml expiry dates"
    )


def test_the_release_gate_can_be_rerun_by_hand() -> None:
    """A hardened gate must not be able to strand a release.

    Publish fires on `v*` tag push only. If the scan blocks mid-release the tag
    already exists while the image does not, and the documented pull command
    404s. A manual trigger is the difference between re-running a release and
    deleting a tag under pressure.
    """
    triggers = yaml.safe_load(PUBLISH_WORKFLOW.read_text())[True]
    assert "workflow_dispatch" in triggers, "release workflow has no break-glass trigger"
