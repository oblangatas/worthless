"""The npm audit gate lets through only argued, dated, still-unfixable advisories.

Both npm audit jobs were bare `npm audit` until GHSA-fc5q-39xc-vjpf (picomatch
ReDoS) was widened on 2026-11-17 to every published version, with no fix to
take. scripts/hooks/check_npm_audit_waivers.py lets a waiver in
.npm-audit-waivers.json cover one advisory, and these tests pin the ways it
must still go red: a second advisory, a fixed version appearing, a
non-breaking fix path (the worthless-kzfq lesson), the date passing, or the
waiver outliving the finding. WOR-1156.

Fixtures are trimmed from real `npm audit --json` output (npm 11.19.1,
2026-11-17) of workers/worthless-sh.
"""

from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HOOK = REPO / "scripts" / "hooks" / "check_npm_audit_waivers.py"
WAIVERS = REPO / ".npm-audit-waivers.json"

TODAY = dt.date(2026, 11, 17)
ADVISORY_URL = "https://github.com/advisories/GHSA-fc5q-39xc-vjpf"


def _load():
    spec = importlib.util.spec_from_file_location("npm_audit_waivers_hook", HOOK)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # The hook defines a dataclass, which looks its module up in sys.modules.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


hook = _load()


def _advisory(url: str = ADVISORY_URL, name: str = "picomatch", rng: str = "<=4.0.7") -> dict:
    return {
        "source": 1247710,
        "name": name,
        "dependency": name,
        "title": "picomatch vulnerable to ReDoS through single-branch repeated extglobs",
        "url": url,
        "severity": "high",
        "range": rng,
    }


REPORT = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        "picomatch": {
            "name": "picomatch",
            "severity": "high",
            "isDirect": False,
            "via": [_advisory()],
            "effects": ["fdir", "tinyglobby", "vite", "vitest"],
            "range": "*",
            "nodes": ["node_modules/picomatch"],
            "fixAvailable": {"name": "vitest", "version": "3.1.4", "isSemVerMajor": True},
        },
        "fdir": {
            "name": "fdir",
            "severity": "high",
            "isDirect": False,
            "via": ["picomatch"],
            "effects": ["tinyglobby"],
            "range": ">=5.2.1",
            "nodes": ["node_modules/fdir"],
            "fixAvailable": {"name": "vitest", "version": "3.1.4", "isSemVerMajor": True},
        },
        "tinyglobby": {
            "name": "tinyglobby",
            "severity": "high",
            "isDirect": False,
            "via": ["fdir", "picomatch"],
            "effects": ["vite", "vitest"],
            "range": "*",
            "nodes": ["node_modules/tinyglobby"],
            "fixAvailable": {"name": "vitest", "version": "3.1.4", "isSemVerMajor": True},
        },
        # Real npm output: an effect can claim `fixAvailable: true` although its
        # only cause is picomatch. Effects' fix hints are not the advisory's.
        "vite": {
            "name": "vite",
            "severity": "high",
            "isDirect": False,
            "via": ["picomatch", "tinyglobby"],
            "effects": [],
            "range": ">=6.3.0-beta.0",
            "nodes": ["node_modules/vite"],
            "fixAvailable": True,
        },
    },
    "metadata": {
        "vulnerabilities": {
            "info": 0,
            "low": 0,
            "moderate": 0,
            "high": 4,
            "critical": 0,
            "total": 4,
        }
    },
}


def _waiver(**over) -> dict:
    w = {
        "advisory": "GHSA-fc5q-39xc-vjpf",
        "package": "picomatch",
        "range": "<=4.0.7",
        "severity": "high",
        "scopes": ["worker", "docs"],
        "expires": "2026-12-15",
        "last_release_seen": "2026-08-24T14:36:23.690Z",
        "ticket": "WOR-1156",
        "reason": "ReDoS needs an attacker-supplied glob; only our own build patterns reach it.",
    }
    w.update(over)
    return w


# `npm view picomatch time --json`, trimmed: 4.0.7 is the newest release.
RELEASES = {
    "picomatch": {
        "created": "2015-01-01T00:00:00.000Z",
        "modified": "2026-08-24T14:36:23.879Z",
        "4.0.6": "2026-08-24T14:29:55.167Z",
        "4.0.7": "2026-08-24T14:36:23.690Z",
    }
}


def _check(report=None, waivers=None, scope="worker", today=TODAY, releases=None):
    report = copy.deepcopy(REPORT if report is None else report)
    waivers = [_waiver()] if waivers is None else waivers
    releases = RELEASES if releases is None else releases
    return hook.evaluate(report, waivers, scope=scope, today=today, releases=releases)


def _report_with(mutate) -> dict:
    r = copy.deepcopy(REPORT)
    mutate(r)
    return r


# ── the case it exists for ─────────────────────────────────────────────────


def test_the_covered_advisory_and_its_effects_pass() -> None:
    result = _check()
    assert result.problems == []
    assert [w["advisory"] for w in result.waived] == ["GHSA-fc5q-39xc-vjpf"]


def test_a_clean_tree_with_no_waivers_passes() -> None:
    clean = {
        "auditReportVersion": 2,
        "vulnerabilities": {},
        "metadata": {"vulnerabilities": {"total": 0}},
    }
    assert _check(clean, waivers=[]).problems == []


# ── it must still go red ───────────────────────────────────────────────────


def test_a_second_advisory_fails() -> None:
    def add(r):
        r["vulnerabilities"]["picomatch"]["via"].append(
            _advisory(url="https://github.com/advisories/GHSA-xxxx-yyyy-zzzz")
        )

    problems = _check(_report_with(add)).problems
    assert any("GHSA-xxxx-yyyy-zzzz" in p for p in problems)


def test_an_advisory_on_another_package_fails() -> None:
    def add(r):
        r["vulnerabilities"]["vite"]["via"].append(
            _advisory(
                url="https://github.com/advisories/GHSA-aaaa-bbbb-cccc", name="vite", rng="<8.3.6"
            )
        )

    problems = _check(_report_with(add)).problems
    assert any("GHSA-aaaa-bbbb-cccc" in p for p in problems)


def test_the_same_advisory_id_on_a_different_package_is_not_covered() -> None:
    def swap(r):
        r["vulnerabilities"]["picomatch"]["via"] = [_advisory(name="micromatch")]

    assert _check(_report_with(swap)).problems


def test_a_fixed_version_appearing_ends_the_waiver() -> None:
    """GitHub narrows the range when it records a patched release."""

    def narrow(r):
        r["vulnerabilities"]["picomatch"]["via"] = [_advisory(rng="<4.0.8")]

    problems = _check(_report_with(narrow)).problems
    assert any("<4.0.8" in p for p in problems)


@pytest.mark.parametrize(
    "fix",
    [True, {"name": "picomatch", "version": "4.0.8", "isSemVerMajor": False}],
)
def test_a_non_breaking_fix_path_ends_the_waiver(fix) -> None:
    """worthless-kzfq: an allowlist once hid a fix that existed. Never again."""

    def offer(r):
        r["vulnerabilities"]["picomatch"]["fixAvailable"] = fix

    problems = _check(_report_with(offer)).problems
    assert any("fix" in p.lower() for p in problems)


def test_a_breaking_downgrade_is_not_a_fix() -> None:
    """npm's only offer today is vitest 4 -> 3.1.4, a major downgrade."""
    assert _check().problems == []


def test_any_new_release_ends_the_waiver() -> None:
    """The direct test for "a fix shipped". The advisory range and npm's
    fixAvailable can both stay unchanged after a fix lands: GitHub may keep
    `<=4.0.7`, and the docs tree's picomatch 2.x keeps fixAvailable on a
    breaking downgrade. A backport (2.3.3) counts as much as 4.0.8 does."""
    for version in ("4.0.8", "2.3.3"):
        releases = copy.deepcopy(RELEASES)
        releases["picomatch"][version] = "2026-11-20T09:00:00.000Z"
        problems = _check(releases=releases).problems
        assert any(version in p and "published" in p for p in problems), version


def test_unreadable_release_history_fails() -> None:
    assert _check(releases={}).problems
    assert _check(releases={"picomatch": {"4.0.8": "not a date"}}).problems


@pytest.mark.parametrize("rng", ["<4.0.8", "<= 4.0.7", "*", ">=0.0.0"])
def test_only_a_no_fix_range_is_waivable(rng) -> None:
    """`<X` already names a fix (the kzfq shape). The spaced form is GitHub's
    web page, not npm's JSON; copying it would never match, so refuse it."""
    assert _check(waivers=[_waiver(range=rng)]).problems


def test_a_waiver_written_against_a_fixed_range_fails() -> None:
    """The kzfq shape exactly: the advisory says `<0.35.4`, a fix is out, and
    a waiver copied from it would match forever."""

    def fixed(r):
        r["vulnerabilities"]["picomatch"]["via"] = [_advisory(rng="<4.0.8")]

    problems = _check(_report_with(fixed), waivers=[_waiver(range="<4.0.8")]).problems
    assert any("'<=X.Y.Z'" in p for p in problems)


def test_a_severity_change_ends_the_waiver() -> None:
    def escalate(r):
        r["vulnerabilities"]["picomatch"]["via"][0]["severity"] = "critical"

    assert _check(_report_with(escalate)).problems


def test_an_unknown_waiver_field_fails() -> None:
    assert _check(waivers=[_waiver(note="extra")]).problems


def test_duplicate_keys_in_the_waiver_file_fail(tmp_path) -> None:
    f = tmp_path / "w.json"
    f.write_text(
        '{"waivers": [{"advisory": "GHSA-fc5q-39xc-vjpf", "advisory": "GHSA-aaaa-bbbb-cccc"}]}'
    )
    with pytest.raises(ValueError, match="duplicate"):
        hook.load_waivers(f)


def test_totals_that_disagree_fail() -> None:
    def miscount(r):
        r["metadata"]["vulnerabilities"]["total"] = 9

    assert _check(_report_with(miscount)).problems


def test_an_entry_without_causes_fails() -> None:
    def empty(r):
        r["vulnerabilities"]["fdir"]["via"] = []

    assert _check(_report_with(empty)).problems


def test_effects_that_only_cite_each_other_fail() -> None:
    """A loop of effects with no advisory at its root explains nothing."""

    def loop(r):
        r["vulnerabilities"]["a"] = {"name": "a", "via": ["b"], "fixAvailable": False}
        r["vulnerabilities"]["b"] = {"name": "b", "via": ["a"], "fixAvailable": False}
        r["metadata"]["vulnerabilities"]["total"] = 6

    problems = _check(_report_with(loop)).problems
    assert any(p.startswith("a:") for p in problems) and any(p.startswith("b:") for p in problems)


def test_an_effects_own_fix_hint_is_ignored() -> None:
    """Real npm output marks vite `fixAvailable: true` although picomatch is
    its only cause; `npm audit fix` in a scratch copy left all 6 findings."""
    assert REPORT["vulnerabilities"]["vite"]["fixAvailable"] is True
    assert _check().problems == []


def test_an_expired_waiver_fails() -> None:
    problems = _check(today=dt.date(2026, 12, 16)).problems
    assert any("expired" in p for p in problems)


def test_the_expiry_day_itself_still_passes() -> None:
    assert _check(today=dt.date(2026, 12, 15)).problems == []


def test_a_waiver_dated_too_far_out_fails() -> None:
    far = (TODAY + dt.timedelta(days=hook.MAX_DAYS + 1)).isoformat()
    problems = _check(waivers=[_waiver(expires=far)]).problems
    assert any("days" in p for p in problems)


@pytest.mark.parametrize(
    "field",
    [
        "advisory",
        "package",
        "range",
        "severity",
        "scopes",
        "expires",
        "last_release_seen",
        "ticket",
        "reason",
    ],
)
def test_a_waiver_missing_a_field_fails(field) -> None:
    w = _waiver()
    del w[field]
    assert _check(waivers=[w]).problems


@pytest.mark.parametrize("field", ["reason", "ticket"])
def test_a_blank_justification_fails(field) -> None:
    assert _check(waivers=[_waiver(**{field: "  "})]).problems


def test_an_unknown_scope_fails() -> None:
    assert _check(waivers=[_waiver(scopes=["worker", "workers"])]).problems


def test_a_waiver_for_another_scope_does_not_cover() -> None:
    assert _check(waivers=[_waiver(scopes=["docs"])]).problems


def test_a_waiver_that_matches_nothing_fails() -> None:
    """Taking the fix must remove the waiver in the same PR."""
    clean = {
        "auditReportVersion": 2,
        "vulnerabilities": {},
        "metadata": {"vulnerabilities": {"total": 0}},
    }
    problems = _check(clean).problems
    assert any("matches nothing" in p for p in problems)


def test_an_effect_pointing_at_an_unreported_package_fails() -> None:
    """An effect is excused only by a root cause the report actually carries."""

    def dangle(r):
        r["vulnerabilities"]["vite"]["via"] = ["rollup"]

    problems = _check(_report_with(dangle)).problems
    assert any("rollup" in p for p in problems)


@pytest.mark.parametrize(
    "report",
    [
        {"error": {"summary": "", "detail": ""}},
        {"auditReportVersion": 2},
        {"auditReportVersion": 1, "advisories": {}, "metadata": {}},
        [],
    ],
)
def test_an_unreadable_report_fails(report) -> None:
    assert _check(report).problems


def test_parse_rejects_non_json() -> None:
    with pytest.raises(hook.AuditError):
        hook.parse_report("npm error audit endpoint returned an error")


def test_an_advisory_without_a_github_id_fails() -> None:
    def odd(r):
        r["vulnerabilities"]["picomatch"]["via"] = [_advisory(url="https://npmjs.com/advisories/1")]

    assert _check(_report_with(odd)).problems


def test_a_warning_is_printed_inside_the_last_14_days() -> None:
    result = _check(today=dt.date(2026, 12, 5))
    assert result.problems == []
    assert any("expires" in w for w in result.warnings)


# ── the committed waiver file ──────────────────────────────────────────────


def test_the_committed_waivers_are_valid_today_shape() -> None:
    """Every committed waiver has every field; dates are checked in CI."""
    waivers = hook.load_waivers(WAIVERS)
    assert waivers, "the file exists to hold the picomatch waiver"
    for w in waivers:
        assert hook.waiver_shape_problems(w) == []


# ── last_release_seen must be the truth, not a knob ────────────────────────


@pytest.mark.parametrize("seen", ["2099-01-01T00:00:00Z", "2026-08-24T14:29:55.167Z"])
def test_last_release_seen_must_equal_the_newest_release(seen) -> None:
    """A far-future value would switch the "a fix shipped" check off; a stale
    one claims a history that isn't npm's. Only the real newest release fits."""
    problems = _check(waivers=[_waiver(last_release_seen=seen)]).problems
    assert any("newest" in p for p in problems)


def test_a_non_date_in_the_release_history_fails() -> None:
    releases = copy.deepcopy(RELEASES)
    releases["picomatch"]["unpublished"] = {"time": "2026-01-01T00:00:00.000Z"}
    assert _check(releases=releases).problems


# ── the parts that talk to npm ─────────────────────────────────────────────


class _Proc:
    def __init__(self, returncode: int, stdout: str, stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_run(monkeypatch, *procs: _Proc) -> list[dict]:
    calls: list[dict] = []
    queue = list(procs)

    def run(cmd, **kwargs):
        calls.append({"cmd": cmd, **kwargs})
        return queue.pop(0)

    monkeypatch.setattr(hook.subprocess, "run", run)
    return calls


def _json(obj) -> str:
    import json

    return json.dumps(obj)


def test_npm_audit_is_run_over_the_whole_tree(monkeypatch, tmp_path) -> None:
    calls = _fake_run(monkeypatch, _Proc(1, _json(REPORT)))
    hook.run_npm_audit(tmp_path)
    assert calls[0]["cmd"] == [
        "npm",
        "audit",
        "--json",
        "--include=dev",
        "--include=optional",
        "--include=peer",
    ]
    assert calls[0]["cwd"] == tmp_path


@pytest.mark.parametrize("name", ["NPM_CONFIG_OMIT", "npm_config_omit", "Npm_Config_Audit_Level"])
def test_inherited_npm_settings_are_stripped(monkeypatch, tmp_path, name) -> None:
    monkeypatch.setenv(name, "dev")
    monkeypatch.setenv("PATH", "/usr/bin")
    calls = _fake_run(monkeypatch, _Proc(1, _json(REPORT)), _Proc(0, _json(RELEASES["picomatch"])))
    hook.run_npm_audit(tmp_path)
    hook.npm_release_times("picomatch")
    for call in calls:
        assert not any(k.upper().startswith("NPM_CONFIG_") for k in call["env"]), call["env"]
        assert call["env"]["PATH"] == "/usr/bin"


@pytest.mark.parametrize(
    ("code", "report"),
    [
        (0, REPORT),  # findings, but npm said all clear
        (1, {"auditReportVersion": 2, "vulnerabilities": {}, "metadata": {}}),  # red, no findings
        (2, REPORT),  # neither 0 nor 1
        (2, {"auditReportVersion": 2, "vulnerabilities": {}, "metadata": {}}),  # crash, "clean"
    ],
)
def test_npm_exit_code_and_findings_must_agree(monkeypatch, tmp_path, code, report) -> None:
    _fake_run(monkeypatch, _Proc(code, _json(report)))
    with pytest.raises(hook.AuditError):
        hook.run_npm_audit(tmp_path)


def test_npm_missing_fails(monkeypatch, tmp_path) -> None:
    def run(cmd, **kwargs):
        raise FileNotFoundError("npm")

    monkeypatch.setattr(hook.subprocess, "run", run)
    with pytest.raises(hook.AuditError):
        hook.run_npm_audit(tmp_path)
    with pytest.raises(hook.AuditError):
        hook.npm_release_times("picomatch")


@pytest.mark.parametrize(
    "proc",
    [
        _Proc(1, "", "E404"),
        _Proc(1, '{"4.0.7": "2026-08-24T14:36:23.690Z"}', "E500"),  # failed, plausible output
        _Proc(0, "[]"),
        _Proc(0, "not json"),
    ],
)
def test_unreadable_release_history_from_npm_fails(monkeypatch, proc) -> None:
    _fake_run(monkeypatch, proc)
    with pytest.raises((hook.AuditError, ValueError)):
        hook.npm_release_times("picomatch")


def _main(monkeypatch, tmp_path, *procs: _Proc, today=TODAY) -> int:
    waivers = tmp_path / "w.json"
    waivers.write_text(_json({"waivers": [_waiver()]}))
    monkeypatch.setattr(hook, "WAIVERS", waivers)
    monkeypatch.setattr(hook, "_today", lambda: today)
    _fake_run(monkeypatch, *procs)
    return hook.main(["--scope", "worker", "--dir", "workers/worthless-sh"])


def test_main_passes_the_covered_tree(monkeypatch, tmp_path) -> None:
    code = _main(
        monkeypatch, tmp_path, _Proc(0, _json(RELEASES["picomatch"])), _Proc(1, _json(REPORT))
    )
    assert code == 0


def test_main_fails_on_a_new_release(monkeypatch, tmp_path) -> None:
    times = dict(RELEASES["picomatch"], **{"4.0.8": "2026-11-20T09:00:00.000Z"})
    assert _main(monkeypatch, tmp_path, _Proc(0, _json(times)), _Proc(1, _json(REPORT))) == 1


def test_main_fails_when_npm_view_fails(monkeypatch, tmp_path) -> None:
    assert _main(monkeypatch, tmp_path, _Proc(1, "", "E404")) == 1


def test_main_fails_on_an_npm_error_report(monkeypatch, tmp_path) -> None:
    error = {"error": {"summary": "", "detail": ""}}
    code = _main(
        monkeypatch, tmp_path, _Proc(0, _json(RELEASES["picomatch"])), _Proc(1, _json(error))
    )
    assert code == 1


def test_main_warns_in_the_github_summary(monkeypatch, tmp_path, capsys) -> None:
    """A warning in a green job's log is unread; `::warning::` reaches the PR."""
    code = _main(
        monkeypatch,
        tmp_path,
        _Proc(0, _json(RELEASES["picomatch"])),
        _Proc(1, _json(REPORT)),
        today=dt.date(2026, 12, 5),
    )
    assert code == 0
    assert "::warning::" in capsys.readouterr().out
