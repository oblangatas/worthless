"""Phase 2.a — ``skill.install/uninstall/current_version`` tests.

Spec: graceful-dreaming-reef.md §"Public API contracts" / skill module.
Covers F30 (mkdir parents), F31 (overwrite stale), F33 (stage-then-rename
+ tempdir cleanup), F34 (refuse symlinks), F35 (Path.resolve canonical
compare). F32 (foreign owner) is exercised in 2.b functional tests once
we have stat-based ownership fixtures.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# current_version
# ---------------------------------------------------------------------------


def test_skill_md_has_minimum_yaml_frontmatter_for_openclaw_discovery() -> None:
    """worthless-rxi2 regression: OpenClaw silently ignores SKILL.md
    files without YAML frontmatter. Without ``name`` + ``description`` +
    ``metadata.openclaw.requires.bins``, ``openclaw skills check`` does
    not register the skill — install() succeeds but Pi can never find it.

    This regression caught the Phase 2.a placeholder shipped without
    frontmatter; verified live against ghcr.io/openclaw/openclaw:latest.
    Future edits to SKILL.md must keep the minimum keys.
    """
    from worthless.openclaw.skill import _SKILL_ASSETS_DIR, _SKILL_FILE

    body = (_SKILL_ASSETS_DIR / _SKILL_FILE).read_text(encoding="utf-8")
    assert body.startswith("---\n"), "SKILL.md must open with YAML frontmatter delimiter"
    fm_end = body.index("\n---\n", 4)
    frontmatter = body[4:fm_end]
    assert re.search(r"^name:\s*\S", frontmatter, re.MULTILINE), (
        "SKILL.md frontmatter missing 'name:'"
    )
    assert re.search(r"^description:\s*\S", frontmatter, re.MULTILINE), (
        "SKILL.md frontmatter missing 'description:' — OpenClaw won't display the skill"
    )
    assert re.search(r"^\s*bins:\s*$", frontmatter, re.MULTILINE), (
        "SKILL.md frontmatter missing 'metadata.openclaw.requires.bins:' — "
        "OpenClaw won't gate availability on the worthless binary"
    )
    assert "- worthless" in frontmatter, "bins must include 'worthless'"


def test_skill_md_is_real_not_placeholder_stub() -> None:
    """WOR-664 (F13a): the installed skill must be the REAL OpenClaw skill,
    never the Phase-2.a v0.0.0 placeholder. Regression guard so the stub bug
    — a do-nothing skill shipping to users — can never recur.
    """
    from worthless.openclaw import skill
    from worthless.openclaw.skill import _SKILL_ASSETS_DIR, _SKILL_FILE

    body = (_SKILL_ASSETS_DIR / _SKILL_FILE).read_text(encoding="utf-8")

    # Not a stub. (Note: the body legitimately uses the word "placeholder"
    # in the testing-recipe section when discussing low-entropy fake keys,
    # so we anchor the regression check to the stub-specific phrasing.)
    assert "Phase 2.a placeholder" not in body, (
        "installed skill is still the v0.0.0 'Phase 2.a placeholder' stub"
    )
    assert "0.0.0" not in skill.current_version(), "installed skill still carries the stub version"

    # Teaches the agent the core commands (the whole point of the real body).
    for cmd in ("worthless lock", "worthless wrap", "worthless up", "worthless status"):
        assert cmd in body, f"skill must teach `{cmd}`"

    # States the honest LLM-key-only scope (not a general secret scanner).
    assert "sk-ant-" in body and "AIza" in body, "skill must state the LLM-key scope"


def test_skill_md_teaches_non_interactive_lock_flags() -> None:
    """WOR-666 (F13f): every agent driving `worthless lock` from a chat
    surface has no stdin. The skill MUST tell them to pass `--keys-only`
    (skip the source-scan noise) AND `--allow-hardcoded-urls` (accept any
    URL warnings non-interactively). Surfaced by the F13c live drive: every
    agent stalled on the interactive prompt without these.
    """
    from worthless.openclaw.skill import _SKILL_ASSETS_DIR, _SKILL_FILE

    body = (_SKILL_ASSETS_DIR / _SKILL_FILE).read_text(encoding="utf-8")
    assert "--keys-only" in body, (
        "skill must teach `--keys-only` (skip source-code URL scan from agents)"
    )
    assert "--allow-hardcoded-urls" in body, (
        "skill must teach `--allow-hardcoded-urls` (non-interactive lock)"
    )


def test_skill_md_has_lock_test_recipe_against_temp_env() -> None:
    """WOR-667 (F13g): the F13c drive showed agents have no recipe for
    'test lock against a temp .env' — they scan the working dir and
    produce noisy warnings. The skill MUST include a self-contained
    recipe using /tmp/t.env so agents have a deterministic test path,
    AND the recipe MUST use a high-entropy fake key (`secrets.token_hex`)
    since Worthless skips low-entropy placeholders like `faketestkey`.
    """
    from worthless.openclaw.skill import _SKILL_ASSETS_DIR, _SKILL_FILE

    body = (_SKILL_ASSETS_DIR / _SKILL_FILE).read_text(encoding="utf-8")
    assert "/tmp/t.env" in body, "skill must provide a temp-.env test recipe"  # noqa: S108
    assert "worthless lock --env" in body, "skill recipe must show `lock --env`"
    assert "secrets.token_hex" in body, (
        "skill recipe must generate a HIGH-ENTROPY fake key — "
        "low-entropy placeholders trip Worthless's entropy gate and lock skips them"
    )


def test_current_version_returns_nonempty_string() -> None:
    """current_version() reads the embedded SKILL.md placeholder and
    returns its declared version. Phase 3 will replace the body; the
    parser API stays.
    """
    from worthless.openclaw import skill

    version = skill.current_version()
    assert isinstance(version, str)
    assert version.strip(), "current_version() must not be blank"


def test_current_version_is_stable_across_calls() -> None:
    """Two consecutive calls return the exact same string.

    Guards against accidental cache invalidation in the lru_cache wrapper
    backing _read_skill_asset (R5 risk register).
    """
    from worthless.openclaw import skill

    assert skill.current_version() == skill.current_version()


def test_current_version_matches_skill_md_header() -> None:
    """current_version() must be derived from SKILL.md's ``Version:`` line.

    The placeholder ships ``Version: 0.0.0-stub``; Phase 3 owners replace
    the value but the parsing contract stays.
    """
    from worthless.openclaw import skill

    version = skill.current_version()
    # Loose pattern — semver-ish or a stub tag, but never blank.
    assert re.match(r"^[0-9A-Za-z][0-9A-Za-z._\-+]*$", version), version


def test_current_version_raises_on_missing_version_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defensive: a future SKILL.md without a Version line is a bug.

    We catch it loudly with SKILL_INSTALL_FAILED rather than silently
    returning a blank string and letting doctor lie about it.
    """
    from worthless.openclaw import skill
    from worthless.openclaw.errors import (
        OpenclawErrorCode,
        OpenclawIntegrationError,
    )

    monkeypatch.setattr(
        "worthless.openclaw.skill._read_skill_asset",
        lambda: "# no version here\n",
    )

    with pytest.raises(OpenclawIntegrationError) as excinfo:
        skill.current_version()
    assert excinfo.value.code == OpenclawErrorCode.SKILL_INSTALL_FAILED


# ---------------------------------------------------------------------------
# install — happy paths and failure modes
# ---------------------------------------------------------------------------


def test_install_creates_target_dir_and_copies_skill(tmp_path: Path) -> None:
    """U-SKL-30 / F30: install() into a non-existent target makes parents
    and writes target_dir/worthless/SKILL.md.
    """
    from worthless.openclaw import skill

    target = tmp_path / "deep" / "nested" / "skills"
    assert not target.exists()

    final = skill.install(target)
    assert final == (target / "worthless").resolve()
    assert (target / "worthless" / "SKILL.md").is_file()


def test_install_writes_skill_md_matching_embedded_asset(
    tmp_path: Path,
) -> None:
    """U-SKL-30: written SKILL.md content matches the embedded asset.

    Verifies the version reported by current_version() came from the same
    bytes we just placed on disk.
    """
    from worthless.openclaw import skill

    target = tmp_path / "skills"
    skill.install(target)

    written = (target / "worthless" / "SKILL.md").read_text(encoding="utf-8")
    assert skill.current_version() in written


def test_install_is_idempotent(tmp_path: Path) -> None:
    """install() twice with identical content is a no-op.

    Folder must remain present after the second call; no temp directories
    left behind. Idempotency underwrites IDEM-24/IDEM-42.
    """
    from worthless.openclaw import skill

    target = tmp_path / "skills"
    first = skill.install(target)
    second = skill.install(target)

    assert first == second
    assert (target / "worthless" / "SKILL.md").is_file()
    leftovers = [p.name for p in target.iterdir() if p.name != "worthless"]
    assert leftovers == [], f"stray staging dirs: {leftovers}"


def test_install_overwrites_stale_content(tmp_path: Path) -> None:
    """F31: pre-existing skill folder with stale content is replaced.

    L3: we own ``~/.openclaw/workspace/skills/worthless/``; stale files
    from older worthless versions must be overwritten on lock.
    """
    from worthless.openclaw import skill

    target = tmp_path / "skills"
    stale = target / "worthless"
    stale.mkdir(parents=True)
    (stale / "SKILL.md").write_text("STALE CONTENT", encoding="utf-8")

    skill.install(target)

    written = (target / "worthless" / "SKILL.md").read_text(encoding="utf-8")
    assert "STALE CONTENT" not in written
    assert skill.current_version() in written


def test_install_refuses_symlink_target(tmp_path: Path) -> None:
    """F34: target_dir/worthless/ is a symlink → refuse with
    SKILL_SYMLINK_REFUSED. We never follow links; an attacker who can
    plant a symlink could redirect a privileged install elsewhere.
    """
    from worthless.openclaw import skill
    from worthless.openclaw.errors import (
        OpenclawErrorCode,
        OpenclawIntegrationError,
    )

    target = tmp_path / "skills"
    target.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (target / "worthless").symlink_to(elsewhere)

    with pytest.raises(OpenclawIntegrationError) as excinfo:
        skill.install(target)
    assert excinfo.value.code == OpenclawErrorCode.SYMLINK_REFUSED


def test_install_cleans_tempdir_on_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """F33: if rename fails mid-install, the staging tempdir is cleaned.

    The user must end with EITHER the previous folder intact or no folder
    at all — never a half-written .worthless.tmp.<pid>/ artifact.
    """
    from worthless.openclaw import skill
    from worthless.openclaw.errors import OpenclawIntegrationError

    target = tmp_path / "skills"
    target.mkdir()

    real_replace = os.replace

    def boom(src: object, dst: object) -> None:
        # Allow the inner shutil.copytree -> mkdir cascade but blow up the
        # final atomic rename. Match against the expected ``worthless``
        # destination so nested helpers (mkstemp etc.) don't trip the trap.
        if Path(str(dst)).name == "worthless":
            raise OSError("simulated rename failure")
        real_replace(src, dst)

    monkeypatch.setattr("worthless.openclaw.skill.os.replace", boom)

    with pytest.raises(OpenclawIntegrationError):
        skill.install(target)

    # No half-state: no `worthless` folder, no leftover staging dirs.
    assert not (target / "worthless").exists()
    leftovers = [p.name for p in target.iterdir() if p.name.startswith(".worthless.tmp")]
    assert leftovers == [], f"staging tempdir not cleaned: {leftovers}"


# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------


def test_uninstall_removes_installed_folder(tmp_path: Path) -> None:
    """install() then uninstall() leaves the target empty of worthless/.

    Round-trip primitive — RT-01 round-trip test in 2.c builds on this.
    """
    from worthless.openclaw import skill

    target = tmp_path / "skills"
    skill.install(target)
    assert (target / "worthless").is_dir()

    removed = skill.uninstall(target)
    assert removed is True
    assert not (target / "worthless").exists()


def test_uninstall_missing_is_noop(tmp_path: Path) -> None:
    """uninstall() on a target without worthless/ returns False, no error.

    Tolerant of pre-existing user state — supports F-XS-44 "config orphan"
    flows where doctor/unlock can be re-run safely.
    """
    from worthless.openclaw import skill

    target = tmp_path / "skills"
    target.mkdir()

    assert skill.uninstall(target) is False


def test_uninstall_target_dir_missing_is_noop(tmp_path: Path) -> None:
    """uninstall() with a target_dir that doesn't exist returns False.

    Defensive: doctor may probe paths that haven't been created yet.
    """
    from worthless.openclaw import skill

    assert skill.uninstall(tmp_path / "never-created") is False


def test_uninstall_refuses_symlink(tmp_path: Path) -> None:
    """F34: target_dir/worthless/ is a symlink on uninstall → refuse.

    Symmetric with install: never follow the link. An attacker who plants
    a symlink at unlock time would otherwise get our rm to traverse it.
    """
    from worthless.openclaw import skill
    from worthless.openclaw.errors import (
        OpenclawErrorCode,
        OpenclawIntegrationError,
    )

    target = tmp_path / "skills"
    target.mkdir()
    decoy = tmp_path / "victim"
    decoy.mkdir()
    (decoy / "important.txt").write_text("do not delete")
    (target / "worthless").symlink_to(decoy)

    with pytest.raises(OpenclawIntegrationError) as excinfo:
        skill.uninstall(target)
    assert excinfo.value.code == OpenclawErrorCode.SYMLINK_REFUSED
    # Decoy must be intact — we refused before touching anything.
    assert (decoy / "important.txt").read_text() == "do not delete"


# ---------------------------------------------------------------------------
# Path canonicalization (F35)
# ---------------------------------------------------------------------------


def test_install_returns_resolved_path(tmp_path: Path) -> None:
    """F35: returned path is Path.resolve()'d so case-insensitive macOS
    APFS comparisons line up with subsequent doctor checks.
    """
    from worthless.openclaw import skill

    target = tmp_path / "skills"
    final = skill.install(target)
    assert final == final.resolve()
    assert final.name == "worthless"
