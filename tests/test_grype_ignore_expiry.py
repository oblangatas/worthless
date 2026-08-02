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

REPO = Path(__file__).resolve().parents[1]
HOOK = REPO / "scripts" / "hooks" / "check_grype_ignore_expiry.py"


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


def test_the_real_repo_config_is_structurally_sound() -> None:
    """Every shipped ignore is named and dated — deliberately NOT a freshness check.

    Asserting the live config against `today` would red the whole unit suite
    the morning an expiry lapses, for every developer, on unrelated work.
    Freshness is the hook's job: it runs at commit time and again in
    docker-security.yml right before the scan. This test guards the shape.
    """
    mod = _load()
    # A date far in the past would make every entry "expired"; a far-future
    # date makes none expire, so anything reported here is structural.
    problems = mod.check(REPO / ".grype.yaml", dt.date(1970, 1, 1))
    assert problems == [], "\n".join(problems)


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


def test_every_real_grype_config_location_is_structurally_sound() -> None:
    """Same for the secondary location, if it exists. Shape, not freshness."""
    mod = _load()
    problems = mod.check_all(mod.CONFIGS, dt.date(1970, 1, 1))
    assert problems == [], "\n".join(problems)


def test_hook_would_fail_the_repo_config_once_an_expiry_lapses() -> None:
    """The forcing function still exists — it just fires in the hook, not here.

    Proves the shipped config WOULD be rejected the day after its earliest
    expiry, without tying this suite to the calendar.
    """
    import yaml

    mod = _load()
    raw = yaml.safe_load((REPO / ".grype.yaml").read_text())
    stamps = []
    for rule in raw["ignore"]:
        e = rule["expiry"]
        stamps.append(e if isinstance(e, dt.date) else dt.date.fromisoformat(str(e)))
    earliest = min(stamps)

    assert mod.check(REPO / ".grype.yaml", earliest) == []
    lapsed = mod.check(REPO / ".grype.yaml", earliest + dt.timedelta(days=1))
    assert lapsed, "an expiry lapsing must be caught by the hook"
    assert "expired" in lapsed[0]
