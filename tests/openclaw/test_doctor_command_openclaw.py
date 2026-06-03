"""U-DOC-* tests for the OpenClaw section of ``worthless doctor``.

Tests target ``_check_openclaw_section`` and ``_skill_installed_version``
from ``worthless.cli.commands.doctor`` directly — no CLI harness needed.
This keeps each test tight to one behaviour without setting up a full
WorthlessHome + keychain.

Spec: ``.claude/plans/graceful-dreaming-reef.md`` §"Phase 2.d" /
test matrix rows U-DOC-01..07.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


from worthless.cli.commands.doctor import _check_openclaw_section, _skill_installed_version
from worthless.openclaw.integration import IntegrationState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_state(
    *,
    present: bool = True,
    config_path: Path | None = None,
    workspace_path: Path | None = None,
    skill_path: Path | None = None,
    home_dir: Path | None = None,
    notes: tuple[str, ...] = (),
) -> IntegrationState:
    return IntegrationState(
        present=present,
        config_path=config_path,
        workspace_path=workspace_path,
        skill_path=skill_path,
        home_dir=home_dir,
        notes=notes,
    )


def _make_enrollment(
    *,
    key_alias: str = "my-key",
    provider: str = "openai",
    env_path: str = "/fake/.env",
    var_name: str = "OPENAI_API_KEY",
) -> MagicMock:
    """Return a mock EnrollmentRecord with the fields doctor needs."""
    e = MagicMock()
    e.key_alias = key_alias
    e.provider = provider
    e.env_path = env_path
    e.var_name = var_name
    return e


# ---------------------------------------------------------------------------
# U-DOC-01: OpenClaw not detected
# ---------------------------------------------------------------------------


class TestUDoc01OpenclawAbsent:
    """U-DOC-01: detect() returns present=False → returns False, no output."""

    def test_absent_returns_false(self, capsys) -> None:
        """U-DOC-01: absent host produces no OpenClaw section."""
        state = _make_state(present=False)

        with patch("worthless.openclaw.integration.detect", return_value=state):
            result = _check_openclaw_section([], fix=False, dry_run=False)

        assert result is False
        assert capsys.readouterr().out == ""

    def test_absent_fix_still_returns_false(self, capsys) -> None:
        """U-DOC-01 variant: --fix on an absent host is also a no-op."""
        state = _make_state(present=False)

        with patch("worthless.openclaw.integration.detect", return_value=state):
            result = _check_openclaw_section([], fix=True, dry_run=False)

        assert result is False
        assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# U-DOC-02: Skill ok + providers ok → silent pass
# ---------------------------------------------------------------------------


class TestUDoc02AllHealthy:
    """U-DOC-02: Skill installed + version match + providers wired → no issues."""

    def test_all_ok_returns_false_silently(self, tmp_path, capsys) -> None:
        """U-DOC-02: clean state → returns False, prints nothing."""
        workspace = tmp_path / "workspace"
        skill_dir = workspace / "skills" / "worthless"
        skill_dir.mkdir(parents=True)
        skill_dir.joinpath("SKILL.md").write_text(
            "Version: 0.1.0\n\nFake skill content.\n", encoding="utf-8"
        )
        config = tmp_path / "openclaw.json"

        state = _make_state(
            present=True,
            config_path=config,
            workspace_path=workspace,
        )
        enrollment = _make_enrollment(key_alias="my-key", provider="openai")

        with (
            patch("worthless.openclaw.integration.detect", return_value=state),
            patch("worthless.openclaw.skill.current_version", return_value="0.1.0"),
            patch("worthless.cli.commands.doctor.is_orphan", return_value=False),
            patch(
                "worthless.openclaw.config.get_provider",
                return_value={"baseUrl": "http://127.0.0.1:8787/my-key/v1"},
            ),
            # Pin Docker detection to localhost so the expected URL matches the
            # mocked baseUrl on any runner (macOS Docker, Linux CI, etc.)
            patch(
                "worthless.openclaw.integration._resolve_proxy_base_url",
                return_value="http://127.0.0.1:8787",
            ),
        ):
            result = _check_openclaw_section([enrollment], fix=False, dry_run=False)

        assert result is False
        assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# U-DOC-03: Skill missing
# ---------------------------------------------------------------------------


class TestUDoc03SkillMissing:
    """U-DOC-03: Skill directory absent → issue surfaced, returns True."""

    def test_skill_not_installed(self, tmp_path, capsys) -> None:
        """U-DOC-03: no skill dir → ✗ line printed, returns True."""
        workspace = tmp_path / "workspace"
        workspace.mkdir(parents=True)
        # No skills/worthless/ subdir

        state = _make_state(present=True, workspace_path=workspace)

        with (
            patch("worthless.openclaw.integration.detect", return_value=state),
            patch("worthless.openclaw.skill.current_version", return_value="0.1.0"),
        ):
            result = _check_openclaw_section([], fix=False, dry_run=False)

        assert result is True
        out = capsys.readouterr().out
        assert "OpenClaw:" in out
        assert "skill not installed" in out

    def test_skill_missing_fix_installs(self, tmp_path, capsys) -> None:
        """U-DOC-03 + fix: --fix reinstalls the missing skill."""
        workspace = tmp_path / "workspace"
        workspace.mkdir(parents=True)

        state = _make_state(present=True, workspace_path=workspace)

        with (
            patch("worthless.openclaw.integration.detect", return_value=state),
            patch("worthless.openclaw.skill.current_version", return_value="0.1.0"),
            patch("worthless.openclaw.skill.install") as mock_install,
        ):
            result = _check_openclaw_section([], fix=True, dry_run=False)

        assert result is True
        mock_install.assert_called_once()
        out = capsys.readouterr().out
        assert "skill reinstalled" in out

    def test_skill_missing_fix_dry_run(self, tmp_path, capsys) -> None:
        """U-DOC-03 + dry-run: --fix --dry-run prints intent without installing."""
        workspace = tmp_path / "workspace"
        workspace.mkdir(parents=True)

        state = _make_state(present=True, workspace_path=workspace)

        with (
            patch("worthless.openclaw.integration.detect", return_value=state),
            patch("worthless.openclaw.skill.current_version", return_value="0.1.0"),
            patch("worthless.openclaw.skill.install") as mock_install,
        ):
            result = _check_openclaw_section([], fix=True, dry_run=True)

        assert result is True
        mock_install.assert_not_called()
        out = capsys.readouterr().out
        assert "[dry-run]" in out


# ---------------------------------------------------------------------------
# U-DOC-04: Provider not wired
# ---------------------------------------------------------------------------


class TestUDoc04ProviderMissing:
    """U-DOC-04: worthless-* provider absent in openclaw.json → issue surfaced."""

    def test_provider_not_wired(self, tmp_path, capsys) -> None:
        """U-DOC-04: get_provider returns None → ✗ line printed, returns True."""
        workspace = tmp_path / "workspace"
        skill_dir = workspace / "skills" / "worthless"
        skill_dir.mkdir(parents=True)
        skill_dir.joinpath("SKILL.md").write_text("Version: 0.1.0\n", encoding="utf-8")
        config = tmp_path / "openclaw.json"

        state = _make_state(present=True, config_path=config, workspace_path=workspace)
        enrollment = _make_enrollment(key_alias="my-key", provider="openai")

        with (
            patch("worthless.openclaw.integration.detect", return_value=state),
            patch("worthless.openclaw.skill.current_version", return_value="0.1.0"),
            patch("worthless.cli.commands.doctor.is_orphan", return_value=False),
            patch("worthless.openclaw.config.get_provider", return_value=None),
        ):
            result = _check_openclaw_section([enrollment], fix=False, dry_run=False)

        assert result is True
        out = capsys.readouterr().out
        assert "worthless-openai" in out
        assert "not wired" in out

    def test_provider_wrong_base_url(self, tmp_path, capsys) -> None:
        """U-DOC-07 variant: entry exists but baseUrl is wrong → issue surfaced."""
        workspace = tmp_path / "workspace"
        skill_dir = workspace / "skills" / "worthless"
        skill_dir.mkdir(parents=True)
        skill_dir.joinpath("SKILL.md").write_text("Version: 0.1.0\n", encoding="utf-8")
        config = tmp_path / "openclaw.json"

        state = _make_state(present=True, config_path=config, workspace_path=workspace)
        enrollment = _make_enrollment(key_alias="my-key", provider="openai")

        with (
            patch("worthless.openclaw.integration.detect", return_value=state),
            patch("worthless.openclaw.skill.current_version", return_value="0.1.0"),
            patch("worthless.cli.commands.doctor.is_orphan", return_value=False),
            patch(
                "worthless.openclaw.config.get_provider",
                return_value={"baseUrl": "http://127.0.0.1:9999/different/v1"},
            ),
        ):
            result = _check_openclaw_section([enrollment], fix=False, dry_run=False)

        assert result is True
        out = capsys.readouterr().out
        assert "baseUrl mismatch" in out


# ---------------------------------------------------------------------------
# U-DOC-05: Stale skill
# ---------------------------------------------------------------------------


class TestUDoc05StaleSkill:
    """U-DOC-05: Skill version mismatch → reported; --fix updates it."""

    def test_stale_skill_reported(self, tmp_path, capsys) -> None:
        """U-DOC-05a: installed version older than bundled → issue surfaced."""
        workspace = tmp_path / "workspace"
        skill_dir = workspace / "skills" / "worthless"
        skill_dir.mkdir(parents=True)
        skill_dir.joinpath("SKILL.md").write_text("Version: 0.0.1\n", encoding="utf-8")

        state = _make_state(present=True, workspace_path=workspace)

        with (
            patch("worthless.openclaw.integration.detect", return_value=state),
            patch("worthless.openclaw.skill.current_version", return_value="0.1.0"),
        ):
            result = _check_openclaw_section([], fix=False, dry_run=False)

        assert result is True
        out = capsys.readouterr().out
        assert "stale" in out
        assert "0.0.1" in out
        assert "0.1.0" in out

    def test_stale_skill_fix_updates(self, tmp_path, capsys) -> None:
        """U-DOC-05b: --fix on stale skill calls install and reports it."""
        workspace = tmp_path / "workspace"
        skill_dir = workspace / "skills" / "worthless"
        skill_dir.mkdir(parents=True)
        skill_dir.joinpath("SKILL.md").write_text("Version: 0.0.1\n", encoding="utf-8")

        state = _make_state(present=True, workspace_path=workspace)

        with (
            patch("worthless.openclaw.integration.detect", return_value=state),
            patch("worthless.openclaw.skill.current_version", return_value="0.1.0"),
            patch("worthless.openclaw.skill.install") as mock_install,
        ):
            result = _check_openclaw_section([], fix=True, dry_run=False)

        assert result is True
        mock_install.assert_called_once()
        out = capsys.readouterr().out
        assert "skill reinstalled" in out


# ---------------------------------------------------------------------------
# U-DOC-06: Workspace absent
# ---------------------------------------------------------------------------


class TestUDoc06WorkspaceMissing:
    """U-DOC-06: detect() present=True but workspace=None → workspace issue."""

    def test_workspace_none(self, tmp_path, capsys) -> None:
        """U-DOC-06: present but workspace=None → 'workspace not found' issue."""
        state = _make_state(present=True, workspace_path=None)

        with patch("worthless.openclaw.integration.detect", return_value=state):
            result = _check_openclaw_section([], fix=False, dry_run=False)

        assert result is True
        out = capsys.readouterr().out
        assert "workspace not found" in out


# ---------------------------------------------------------------------------
# U-DOC-07: Config absent (workspace present)
# ---------------------------------------------------------------------------


class TestUDoc07ConfigMissing:
    """U-DOC-07: present=True, workspace ok, config=None → provider issue."""

    def test_config_none_with_enrollment(self, tmp_path, capsys) -> None:
        """U-DOC-07: workspace present, config missing → 'not wired' per alias."""
        workspace = tmp_path / "workspace"
        skill_dir = workspace / "skills" / "worthless"
        skill_dir.mkdir(parents=True)
        skill_dir.joinpath("SKILL.md").write_text("Version: 0.1.0\n", encoding="utf-8")

        state = _make_state(
            present=True,
            workspace_path=workspace,
            config_path=None,  # no openclaw.json
        )
        enrollment = _make_enrollment(key_alias="my-key", provider="openai")

        with (
            patch("worthless.openclaw.integration.detect", return_value=state),
            patch("worthless.openclaw.skill.current_version", return_value="0.1.0"),
            patch("worthless.cli.commands.doctor.is_orphan", return_value=False),
        ):
            result = _check_openclaw_section([enrollment], fix=False, dry_run=False)

        assert result is True
        out = capsys.readouterr().out
        assert "worthless-openai" in out
        assert "not wired" in out


# ---------------------------------------------------------------------------
# _skill_installed_version unit tests
# ---------------------------------------------------------------------------


class TestSkillInstalledVersion:
    """Unit tests for the ``_skill_installed_version`` helper."""

    def test_returns_version_from_file(self, tmp_path) -> None:
        skill_dir = tmp_path / "worthless"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("Version: 1.2.3\n\nBody.", encoding="utf-8")
        assert _skill_installed_version(skill_dir) == "1.2.3"

    def test_returns_none_when_no_file(self, tmp_path) -> None:
        skill_dir = tmp_path / "worthless"
        skill_dir.mkdir()
        assert _skill_installed_version(skill_dir) is None

    def test_returns_none_when_dir_missing(self, tmp_path) -> None:
        assert _skill_installed_version(tmp_path / "missing") is None

    def test_returns_none_when_no_version_line(self, tmp_path) -> None:
        skill_dir = tmp_path / "worthless"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("No version here.\n", encoding="utf-8")
        assert _skill_installed_version(skill_dir) is None


# ---------------------------------------------------------------------------
# SP6 — recovery_note schema: every findings entry must have a str "issue"
# ---------------------------------------------------------------------------


class TestRecoveryNoteSchema:
    """SP6: the recovery_note appended to every doctor findings list must have
    ``"issue"`` as a non-None string so any consumer doing ``f["issue"].lower()``
    doesn't crash on the last entry.
    """

    def test_recovery_note_appended_after_real_findings_has_string_issue(self, tmp_path) -> None:
        """recovery_note is the final entry in findings[] and must have ``"issue"``
        as a str (possibly empty), never None.

        Mocks one real skill issue so findings[] contains at least one entry before
        the recovery_note.  With zero real findings the loop was trivially vacuous
        — it ran on an empty list and passed even if recovery_note was never
        appended or carried ``"issue": None``.

        Catches the bug where recovery_note was appended with ``"issue": None``
        while all other findings have ``"issue": str``.
        """
        from unittest.mock import MagicMock  # noqa: PLC0415

        from worthless.cli.commands.doctor.checks.openclaw import run  # noqa: PLC0415

        ctx = MagicMock()
        ctx.dry_run = False
        ctx.fix = False

        # run() imports _check_skill, _check_providers, is_orphan from the
        # parent doctor package at call-time, so patches must target that module.
        # One real skill issue ensures findings[] is non-empty before recovery_note
        # is appended — the test is not vacuous.
        with (
            patch(
                "worthless.cli.commands.doctor.checks.openclaw._audit_gate_findings",
                return_value=[],
            ),
            patch(
                "worthless.cli.commands.doctor.checks.openclaw._oc_integration.detect",
                return_value=_make_state(present=True, workspace_path=tmp_path),
            ),
            patch(
                "worthless.cli.commands.doctor._check_skill",
                return_value=(["skill not installed"], []),
            ),
            patch(
                "worthless.cli.commands.doctor._check_providers",
                return_value=[],
            ),
            patch(
                "worthless.cli.commands.doctor.is_orphan",
                return_value=False,
            ),
        ):
            result = run(ctx)

        findings = result["findings"]  # CheckResult is a TypedDict

        # At minimum: the real skill issue + the recovery_note
        assert len(findings) >= 2, (
            f"Expected at least 2 findings (skill issue + recovery_note), got {findings}"
        )

        # The recovery_note is always the last entry — assert it has a str "issue"
        last = findings[-1]
        assert "issue" in last, f"last finding missing 'issue' key: {last}"
        assert isinstance(last["issue"], str), (
            f"last finding['issue'] must be str (recovery_note), "
            f"got {type(last['issue'])!r}: {last}"
        )

        # Belt-and-suspenders: every entry in the list must have a str "issue"
        for i, finding in enumerate(findings):
            assert "issue" in finding, f"finding[{i}] missing 'issue' key: {finding}"
            assert isinstance(finding["issue"], str), (
                f"finding[{i}]['issue'] must be str, got {type(finding['issue'])!r}: {finding}"
            )

    def test_recovery_note_issue_is_nonempty(self, tmp_path) -> None:
        """Fix 2 (WOR-516): recovery_note had 'issue': '' — renders blank in JSON consumers.

        The real text was in a non-standard 'note' key no consumer reads.
        This test fails on the old code (empty string is falsy) and passes
        once 'issue' carries the actual recovery message.
        """
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        from worthless.cli.commands.doctor.checks.openclaw import run  # noqa: PLC0415

        ctx = MagicMock()
        ctx.dry_run = False
        ctx.fix = False

        with (
            patch(
                "worthless.cli.commands.doctor.checks.openclaw._audit_gate_findings",
                return_value=[],
            ),
            patch(
                "worthless.cli.commands.doctor.checks.openclaw._oc_integration.detect",
                return_value=_make_state(present=True, workspace_path=tmp_path),
            ),
            patch(
                "worthless.cli.commands.doctor._check_skill",
                return_value=([], []),
            ),
            patch(
                "worthless.cli.commands.doctor._check_providers",
                return_value=[],
            ),
            patch(
                "worthless.cli.commands.doctor.is_orphan",
                return_value=False,
            ),
        ):
            result = run(ctx)

        findings = result["findings"]
        assert findings, "findings must be non-empty (recovery_note is always appended)"
        last = findings[-1]
        assert last.get("issue"), (
            f"recovery_note 'issue' must be a non-empty string so consumers can display it; "
            f"got: {last.get('issue')!r}"
        )
