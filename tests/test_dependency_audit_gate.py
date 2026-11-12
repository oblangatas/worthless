"""Pin the CI dependency gate to the pre-commit hook it mirrors (worthless-jymn).

`uv-audit` in .pre-commit-config.yaml is `stages: [pre-push]`, so it never runs
for a Dependabot PR, a GitHub web edit, `git push --no-verify`, or a clone that
never ran `pre-commit install`. dependency-audit.yml mirrors it into CI — the
same move docker-security.yml already made for the grype-expiry hook (WOR-852).

The mirror is only worth anything while both sides run the SAME command. If
they drift, one reports clean and the other reports vulnerable, and there is no
way to tell which is right without reading both. These tests pin:

  - the workflow command is byte-identical to the hook entry
  - the audit step can still FAIL (no continue-on-error) — a gate that cannot
    go red is the exact failure worthless-tidv was opened for
  - the trigger keeps its shape: pull_request present and unfiltered, and no
    job-level `if:` — a paths filter left nine PRs BLOCKED when `scan` became
    required (WOR-874), and a skipped job reports SUCCESS to branch protection,
    which turns a gate into a bypass

Hermetic: parses the two YAML files on disk. No network, no runner, no audit.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "dependency-audit.yml"
PRE_COMMIT = REPO / ".pre-commit-config.yaml"


def _audit_step() -> dict:
    """The step in dependency-audit.yml that actually runs pip-audit."""
    wf = yaml.safe_load(WORKFLOW.read_text())
    steps = wf["jobs"]["audit"]["steps"]
    matches = [s for s in steps if "pip-audit" in str(s.get("run", ""))]
    assert len(matches) == 1, f"expected exactly one pip-audit step, got {len(matches)}"
    return matches[0]


def _hook_entry() -> str:
    """The `uv-audit` hook's command, unwrapped from its `<shell> -c '...'`."""
    cfg = yaml.safe_load(PRE_COMMIT.read_text())
    hooks = [h for repo in cfg["repos"] for h in repo.get("hooks", []) if h.get("id") == "uv-audit"]
    assert len(hooks) == 1, "uv-audit hook not found (renamed? then update this test)"
    entry = hooks[0]["entry"]
    m = re.fullmatch(r"(?:sh|bash) -c '(.*)'", entry.strip(), re.DOTALL)
    assert m, f"uv-audit entry is no longer a `<shell> -c '...'` wrapper: {entry!r}"
    return m.group(1).strip()


def _hook_pipeline() -> str:
    """The audit pipeline itself, with any shell-option prefix removed.

    The hook needs `set -o pipefail` and the CI step gets the same behaviour from
    `shell: bash`, so the two commands can no longer be byte-identical. Comparing
    the pipeline is the invariant that actually matters: both sides must audit the
    same thing. Byte-identity was the wrong invariant — it passed while the two
    ran under different shells, and it twice forced a fix into a more awkward
    shape purely to keep the strings equal.
    """
    entry = _hook_entry()
    return re.sub(r"^set -o pipefail\s*;\s*", "", entry).strip()


# ── Python 3.10 (WOR-1006) ─────────────────────────────────────────────────
# pip-audit skips lines whose markers don't match the Python running it. On 3.10
# that adds dev tools stuck on old pins (filelock's fixes need 3.11+), which
# blocked every push; on 3.13 it hides runtime packages real 3.10 users install.
# So: the full tree on a fixed new Python, the runtime tree on the oldest one.

PY310_JOB = "audit-py310"


def _py310_step() -> dict:
    wf = yaml.safe_load(WORKFLOW.read_text())
    steps = wf["jobs"][PY310_JOB]["steps"]
    matches = [s for s in steps if "pip-audit" in str(s.get("run", ""))]
    assert len(matches) == 1, f"expected exactly one pip-audit step, got {len(matches)}"
    return matches[0]


def test_hook_does_not_follow_the_contributors_python() -> None:
    """Plain `uv run` uses .venv's Python, so a 3.10 clone audits 3.10-only dev pins."""
    pipeline = _hook_pipeline()
    assert "--python 3.13" in pipeline, "the hook's verdict must not depend on the local Python"
    assert "--isolated" in pipeline, "without it, uv deletes and rebuilds the 3.10 .venv"


def test_py310_job_audits_what_oldest_python_users_install() -> None:
    run = _py310_step()["run"]
    floor = re.search(
        r'^requires-python = ">=(\d+\.\d+)"', (REPO / "pyproject.toml").read_text(), re.M
    )
    assert floor, "requires-python no longer has a plain floor; revisit this job"
    assert f"--python {floor.group(1)}" in run, "this job must follow the oldest supported Python"
    assert "--no-dev" in run, "the full tree on 3.10 stays red on dev-only filelock"
    assert "--frozen" in run


def test_py310_job_name_is_stable() -> None:
    """The name is the required context in the `main` ruleset; a rename blocks every PR."""
    wf = yaml.safe_load(WORKFLOW.read_text())
    assert wf["jobs"][PY310_JOB]["name"] == "uv-audit (oldest Python runtime)"


def test_py310_job_can_fail() -> None:
    wf = yaml.safe_load(WORKFLOW.read_text())
    job, step = wf["jobs"][PY310_JOB], _py310_step()
    assert "continue-on-error" not in job and "continue-on-error" not in step
    assert "if" not in job, "a skipped job reports SUCCESS to branch protection"
    assert step.get("shell") == "bash", "a pipeline needs `shell: bash` for pipefail"
    assert "|| true" not in step["run"] and "set +e" not in step["run"]


def test_no_audit_ignores_anything() -> None:
    """Advisories went from 3 to 9 in ten days; a list like that is never finished."""
    for name, command in (
        ("hook", _hook_entry()),
        ("audit job", _audit_step()["run"]),
        ("3.10 job", _py310_step()["run"]),
    ):
        assert "--ignore-vuln" not in command, f"{name} ignores an advisory"


def test_hook_runs_with_pipefail() -> None:
    """The hook's pipeline can otherwise report clean over a partial export.

    `uv export | pip-audit` under a shell without pipefail reports only
    pip-audit's exit code. A `uv export` that dies partway hands over a
    truncated-but-valid stream, which audits what arrived and exits 0. CI got
    this fix via `shell: bash`; the hook was left carrying the defect, so a
    developer's pre-push check could still pass over a fragment.
    """
    cfg = yaml.safe_load(PRE_COMMIT.read_text())
    hooks = [h for repo in cfg["repos"] for h in repo.get("hooks", []) if h.get("id") == "uv-audit"]
    entry = hooks[0]["entry"]
    assert "pipefail" in entry, (
        "the uv-audit hook pipes uv export into pip-audit; without pipefail a "
        "failed export is masked by pip-audit's exit code"
    )
    assert entry.strip().startswith("bash -c"), (
        "`set -o pipefail` is not POSIX — dash, which /bin/sh often is, does not "
        "support it, so the hook must invoke bash explicitly"
    )


def test_ci_command_matches_hook() -> None:
    """CI and the hook must audit the same thing, or they can disagree."""
    assert _audit_step()["run"].strip() == _hook_pipeline()


def test_audit_step_can_fail() -> None:
    """A gate that cannot go red is decoration. See worthless-tidv."""
    step = _audit_step()
    assert "continue-on-error" not in step, (
        "continue-on-error makes this gate report green when it fails"
    )
    assert "set +e" not in step["run"], "`set +e` swallows the exit code the gate depends on"


def test_audit_job_has_no_continue_on_error() -> None:
    wf = yaml.safe_load(WORKFLOW.read_text())
    assert "continue-on-error" not in wf["jobs"]["audit"]


def test_audit_step_runs_with_pipefail() -> None:
    """The run is a PIPELINE, and GitHub's default shell has no pipefail.

    `bash -e -c 'false | true'` exits 0. So without this, a `uv export` that
    died partway would hand pip-audit a truncated stream, which audits the
    packages that arrived and exits 0 — a green gate over a fragment. That is
    the failure mode worthless-tidv was opened for. `shell: bash` is the
    documented opt-in to `-eo pipefail`.
    """
    step = _audit_step()
    assert "|" in step["run"], "if this stops being a pipeline, revisit this test"
    assert step.get("shell") == "bash", (
        "a pipeline step without `shell: bash` runs under `bash -e` with no pipefail, "
        "so a failing `uv export` would be masked by pip-audit's exit code"
    )


def test_lock_freshness_is_checked() -> None:
    """`--frozen` audits uv.lock as-is; a desynced lock exports a stale tree."""
    wf = yaml.safe_load(WORKFLOW.read_text())
    runs = " ".join(str(s.get("run", "")) for s in wf["jobs"]["audit"]["steps"])
    assert "uv lock --check" in runs, (
        "without a freshness check, `--frozen` happily audits a lock that no longer "
        "matches pyproject.toml, while a different tree actually ships"
    )


@pytest.mark.parametrize("forbidden", ["paths", "paths-ignore"])
def test_pull_request_trigger_is_unfiltered(forbidden: str) -> None:
    """A path filter turns a required check into a deadlock. WOR-874."""
    wf = yaml.safe_load(WORKFLOW.read_text())
    # `on:` parses as the boolean True in YAML 1.1 unless quoted.
    triggers = wf.get("on") or wf.get(True)
    assert "pull_request" in triggers, "the gate must report on every PR"
    pr = triggers["pull_request"] or {}
    assert forbidden not in pr, (
        f"`{forbidden}` on pull_request can leave a required check never reporting"
    )


def test_audit_job_is_unconditional() -> None:
    """A skipped job reports SUCCESS to branch protection — a bypass, not a gate."""
    wf = yaml.safe_load(WORKFLOW.read_text())
    assert "if" not in wf["jobs"]["audit"]


# ── npm side (worthless-yhcc) ──────────────────────────────────────────────
# The Worker subproject has its own lockfile and was audited by nothing.


def _npm_step() -> dict:
    wf = yaml.safe_load(WORKFLOW.read_text())
    steps = wf["jobs"]["npm-audit"]["steps"]
    matches = [s for s in steps if "npm audit" in str(s.get("run", ""))]
    assert len(matches) == 1, f"expected exactly one npm audit step, got {len(matches)}"
    return matches[0]


def test_npm_audit_covers_the_full_tree() -> None:
    """Dev tooling stays in scope — it runs in CI with deploy credentials.

    An earlier version of this job used `--omit=dev`, justified by 5 devDependency
    advisories that would have made a full gate red on arrival. That was false:
    `npm audit fix --package-lock-only` cleared all 5 with package.json unchanged.
    Narrowing a security gate to dodge findings that a one-command refresh fixes
    is looking away, not scoping.
    """
    step = _npm_step()
    assert "--omit=dev" not in step["run"], (
        "wrangler and miniflare execute in CI and on dev machines with deploy "
        "credentials; excluding them from a credential-protection product's "
        "supply-chain gate needs a real cost, and the measured cost is zero"
    )
    # The step now wraps npm audit to allow argued, dated exceptions. The tree
    # it audits must still be named explicitly, whether by working-directory
    # or as an argument.
    targets_worker = step.get("working-directory") == "workers/worthless-sh" or (
        "workers/worthless-sh" in step["run"]
    )
    assert targets_worker, "the audited tree must be named, not inferred"


def test_npm_lockfile_freshness_is_checked() -> None:
    """`npm audit` reads the lockfile and never checks it matches package.json.

    Add a runtime dependency without relocking and the audit reports 0
    vulnerabilities and exits 0 — green over a tree that is not the tree, which
    is exactly the failure worthless-tidv was opened for.
    """
    wf = yaml.safe_load(WORKFLOW.read_text())
    runs = " ".join(str(s.get("run", "")) for s in wf["jobs"]["npm-audit"]["steps"])
    assert "npm ci" in runs, (
        "without a sync check, a stale package-lock.json passes the audit while a "
        "different dependency tree actually installs"
    )


def test_npm_audit_can_fail() -> None:
    """Same rule as the Python gate: it must be able to go red."""
    step = _npm_step()
    assert "continue-on-error" not in step
    assert "|| true" not in step["run"], "swallowing the exit code makes this decorative"
    wf = yaml.safe_load(WORKFLOW.read_text())
    assert "continue-on-error" not in wf["jobs"]["npm-audit"]
    assert "if" not in wf["jobs"]["npm-audit"], (
        "a skipped job reports SUCCESS to branch protection — a bypass, not a gate"
    )


def test_dependabot_covers_the_worker() -> None:
    """Advisories with no update PR never clear — main sat on 5 of them."""
    cfg = yaml.safe_load((REPO / ".github" / "dependabot.yml").read_text())
    npm = [u for u in cfg["updates"] if u["package-ecosystem"] == "npm"]
    assert npm, "no npm ecosystem entry: Dependabot raises Worker advisories but never fixes them"
    assert any(u["directory"].rstrip("/").endswith("workers/worthless-sh") for u in npm)


# ── sharp override (worthless-kzfq) ────────────────────────────────────────
#
# TWO advisories now, and the floor is the later one:
#   GHSA-rgj7-g3m4-5g8c  libheif heap overflow, CWE-122   sharp < 0.35.4
#   GHSA-wq5f-xc86-pv6w  librsvg CVE-2026-96889           sharp < 0.35.5
# The second landed 2026-10-07 and made the then-current 0.35.4 pin vulnerable,
# so the floor moved to 0.35.5. Leaving it at 0.35.4 would have let this guard
# bless a pin inside a live advisory — exactly what it exists to prevent.
#
# miniflare pins `"sharp": "0.35.2"` EXACTLY, so npm's resolver can only walk
# backwards: its offered fix was @cloudflare/vitest-pool-workers 0.22.0 ->
# 0.8.30, isSemVerMajor, and on the second wave a wrangler downgrade to 4.15.2.
# An `overrides` entry reaches the patch instead, and takes the audit to 0
# vulnerabilities with every other version unchanged. miniflare, wrangler and
# vitest-pool-workers appear in the audit only BECAUSE they depend on sharp;
# one bump clears all three.
#
# Why these tests exist when `npm audit` already gates this in CI: that job
# resolves advisories from the registry at run time. It is exactly as available
# as the registry is, and it says nothing at all offline. These two read the
# committed lockfile, so the guarantee survives a registry outage and fails in
# under a second locally instead of after a CI round trip.

WORKER = REPO / "workers" / "worthless-sh"
# The docs site owns the ROOT manifest and lockfile. It is a SEPARATE npm
# tree from the Worker, resolves independently, and declared a sharp floor
# inside the advisory while the Worker was being guarded.
DOCS = REPO

# The first version outside BOTH advisories; the binding one is `<0.35.5`.
SHARP_FIXED = (0, 35, 5)


def _version_tuple(raw: str) -> tuple[int, ...]:
    """Numeric release part of a semver string, for ordering comparisons."""
    return tuple(int(p) for p in re.split(r"[-+]", raw, maxsplit=1)[0].split("."))


def test_worker_sharp_is_not_vulnerable() -> None:
    """Every resolved sharp in the Worker lockfile is >= 0.35.4.

    Deliberately walks the whole `packages` map rather than checking one known
    key: a future tree could resolve sharp at a nested path, and a check keyed
    to today's single location would pass over it.
    """
    lock = json.loads((WORKER / "package-lock.json").read_text())

    found = {
        path: meta["version"]
        for path, meta in lock["packages"].items()
        if path.split("node_modules/")[-1] == "sharp" and "version" in meta
    }
    assert found, (
        "no sharp in the Worker lockfile — if miniflare genuinely dropped it, "
        "delete the override in package.json and this test together"
    )

    stale = {p: v for p, v in found.items() if _version_tuple(v) < SHARP_FIXED}
    assert not stale, (
        f"sharp back inside GHSA-wq5f-xc86-pv6w's `<0.35.5` range: {stale}. "
        "The override in workers/worthless-sh/package.json is the thing that "
        "holds this; check it survived the last relock."
    )


def test_sharp_override_is_declared() -> None:
    """package.json carries the override that produces that resolution.

    The lockfile assertion above can be satisfied transiently by a relock that
    happens to hoist a newer sharp. This pins the *cause*, so dropping the
    override fails here loudly rather than waiting for the next resolve to
    quietly reinstate miniflare's exact 0.35.2 pin.
    """
    pkg = json.loads((WORKER / "package.json").read_text())
    override = pkg.get("overrides", {}).get("sharp")

    assert override, (
        "overrides.sharp is gone from workers/worthless-sh/package.json. "
        "miniflare pins sharp exactly, so without it the next `npm install` "
        "resolves back to 0.35.2 and re-opens GHSA-rgj7-g3m4-5g8c and "
        "GHSA-wq5f-xc86-pv6w."
    )
    assert _version_tuple(override.lstrip("^~>=")) >= SHARP_FIXED, (
        f"overrides.sharp is {override!r}, which still allows a version inside "
        "the advisory's `<0.35.4` range"
    )


def test_the_docs_site_sharp_floor_is_also_outside_the_advisory() -> None:
    """The root tree is a separate npm tree and was the unguarded one.

    Both sharp guards above read only `workers/worthless-sh`. Meanwhile the docs
    site declared `^0.35.3` — a floor admitting 0.35.3 and 0.35.4, both inside
    GHSA-wq5f-xc86-pv6w's `<0.35.5`. Its lockfile happened to resolve 0.35.5, so
    the audit was green and nothing was watching the declaration that would
    decide the NEXT resolve. Same reasoning that moved SHARP_FIXED: a guard that
    blesses a pin inside a live advisory is the thing it exists to prevent.
    """
    declared = json.loads((DOCS / "package.json").read_text())
    floor = (declared.get("dependencies") or {}).get("sharp") or (
        declared.get("devDependencies") or {}
    ).get("sharp")
    assert floor, "sharp is no longer a docs-site dependency — delete this test with it"
    assert _version_tuple(floor.lstrip("^~>=")) >= SHARP_FIXED, (
        f"docs site declares sharp {floor!r}, whose floor is inside the advisory. "
        f"A relock could legally resolve a vulnerable version."
    )

    lock = json.loads((DOCS / "package-lock.json").read_text())
    stale = {
        path: meta["version"]
        for path, meta in lock["packages"].items()
        if path.split("node_modules/")[-1] == "sharp"
        and "version" in meta
        and _version_tuple(meta["version"]) < SHARP_FIXED
    }
    assert not stale, f"docs lockfile resolves a vulnerable sharp: {stale}"


# ── undici and zod overrides (WOR-1007) ────────────────────────────────────
#
# Same shape as sharp: miniflare pins undici exactly and
# @cloudflare/vitest-pool-workers pins zod to exactly 4.4.3, so only an
# `overrides` entry reaches the fix.
#   undici  GHSA-4qv8-2p9j-2685, GHSA-f72v-6w45-q472, GHSA-xjj6-f33q-929c  < 7.30.1
#   zod     GHSA-mrhx-c7xc-m3w5                                            < 4.6.6
# Unlike sharp these are pinned EXACTLY. A caret lets the next relock float a
# newer release, compromised or not, into a toolchain that deploys with
# Cloudflare credentials; on main zod could not move at all.

EXACT_OVERRIDES = {"undici": (7, 30, 1), "zod": (4, 6, 6)}


@pytest.mark.parametrize(("name", "fixed"), EXACT_OVERRIDES.items(), ids=list(EXACT_OVERRIDES))
def test_worker_override_resolves_outside_the_advisory(name: str, fixed: tuple[int, ...]) -> None:
    """Every resolved copy in the Worker lockfile is at or above the fix."""
    lock = json.loads((WORKER / "package-lock.json").read_text())
    found = {
        path: meta["version"]
        for path, meta in lock["packages"].items()
        if path.split("node_modules/")[-1] == name and "version" in meta
    }
    assert found, (
        f"no {name} in the Worker lockfile — if nothing pins it any more, "
        "delete the override in package.json and this test's entry together"
    )
    stale = {p: v for p, v in found.items() if _version_tuple(v) < fixed}
    assert not stale, f"{name} back inside its advisory range: {stale}"


@pytest.mark.parametrize(("name", "fixed"), EXACT_OVERRIDES.items(), ids=list(EXACT_OVERRIDES))
def test_worker_override_is_declared_exactly(name: str, fixed: tuple[int, ...]) -> None:
    """package.json pins the fixed version exactly, not a range."""
    override = json.loads((WORKER / "package.json").read_text()).get("overrides", {}).get(name)
    assert override, (
        f"overrides.{name} is gone from workers/worthless-sh/package.json; the "
        "next `npm install` resolves back to the exact pin upstream ships"
    )
    assert re.fullmatch(r"\d+\.\d+\.\d+", override), (
        f"overrides.{name} is {override!r}; pin an exact version so a relock "
        "can't float a newer release in"
    )
    assert _version_tuple(override) >= fixed, (
        f"overrides.{name} {override!r} is inside the advisory"
    )


# ── runtime floors in pyproject.toml ───────────────────────────────────────
#
# install.sh (`uv tool install`), pip and uvx resolve pyproject's
# `dependencies`, never uv.lock, and pip keeps an existing env's copy of a
# dependency unless a floor forces the upgrade. So an advisory
# against a runtime dependency is closed by its floor, not by the lock.
#   certifi       GHSA-6q48-6c7w-9gw2   < 2026.10.18
#   cryptography  PYSEC-2026-3552       < 50.0.0
#   msgpack       GHSA-j8c6-9vc5-hj6x   < 1.2.4
#   pydantic      GHSA-3r8g-cqwr-jr29, GHSA-qpmf-fgh3-ff25   < 2.14.2
#   websockets    GHSA-6m5v-9gmr-5665   < 17.4  (3.11+ only: 17.x needs 3.11)
# certifi is held at 2026.10.23, above its advisory's fix: the CHANGELOG
# promises that release, which also drops emSign Root CA - C1 and ECC C3.
# The `mcp` extra carries its own floor for what only the MCP server runs:
#   opentelemetry-api  GHSA-mf5v-w3w3-f6cg  <= 1.45.1 (mcp parses every
#                      request's traceparent; the proxy has tracing off)

PYPROJECT = REPO / "pyproject.toml"
_RUNTIME_BLOCK = r"^dependencies = \[(.*?)^\]"
_MCP_EXTRA_BLOCK = r"^mcp = \[(.*?)^\]"
MCP_EXTRA_FLOORS = {"opentelemetry-api": (1, 45, 2)}
RUNTIME_FLOORS = {
    "certifi": (2026, 10, 23),
    "cryptography": (50, 0, 0),
    "msgpack": (1, 2, 4),
    "pydantic": (2, 14, 2),
    "websockets": (17, 4),
}
# The only marker a floor may carry. A marker anywhere else would quietly turn
# the floor off for every install it doesn't match.
RUNTIME_FLOOR_MARKERS = {"websockets": "python_version >= '3.11'"}


def _declared_floor(name: str, block_re: str = _RUNTIME_BLOCK) -> tuple[str, str | None] | None:
    """The `>=` version and marker a pyproject dependency list gives *name*.

    *block_re* picks the list: [project] dependencies by default. Regex over
    the raw text, not a TOML parse: tomllib is 3.11+ and this suite runs on
    3.10 too.
    """
    block = re.search(block_re, PYPROJECT.read_text(), re.S | re.M)
    assert block, f"no list matching {block_re!r} in pyproject.toml"
    pattern = rf'^\s*"{re.escape(name)}>=([0-9.]+)(?:\s*;\s*([^"]*))?"'
    match = re.search(pattern, block.group(1), re.M)
    return (match.group(1), match.group(2)) if match else None


@pytest.mark.parametrize(("name", "required"), RUNTIME_FLOORS.items(), ids=list(RUNTIME_FLOORS))
def test_runtime_floor_is_outside_the_advisory(name: str, required: tuple[int, ...]) -> None:
    """pyproject requires at least the listed version of each advised runtime dep."""
    declared = _declared_floor(name)
    assert declared, (
        f"{name} has no `>=` floor in pyproject.toml's dependencies. pip keeps an "
        f"existing env's {name}, so upgrading worthless can leave a vulnerable copy."
    )
    floor, marker = declared
    assert _version_tuple(floor) >= required, (
        f"{name}>={floor} is below the required {'.'.join(map(str, required))}"
    )
    assert marker == RUNTIME_FLOOR_MARKERS.get(name), (
        f"{name}'s floor carries the marker {marker!r}, expected "
        f"{RUNTIME_FLOOR_MARKERS.get(name)!r}: the floor doesn't apply where the marker is false"
    )


@pytest.mark.parametrize(("name", "required"), MCP_EXTRA_FLOORS.items(), ids=list(MCP_EXTRA_FLOORS))
def test_mcp_extra_floor_is_outside_the_advisory(name: str, required: tuple[int, ...]) -> None:
    """The `mcp` extra requires at least the listed version, with no marker."""
    declared = _declared_floor(name, _MCP_EXTRA_BLOCK)
    assert declared, (
        f"{name} has no `>=` floor in pyproject.toml's `mcp` extra. pip keeps an "
        f"existing env's {name}, so upgrading worthless[mcp] can leave a vulnerable copy."
    )
    floor, marker = declared
    assert _version_tuple(floor) >= required, (
        f"{name}>={floor} is below the required {'.'.join(map(str, required))}"
    )
    assert marker is None, f"{name}'s floor carries the marker {marker!r}; it must apply everywhere"
