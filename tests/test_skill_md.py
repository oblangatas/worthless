"""SKILL.md drift detection — verify agent discovery file matches actual CLI.

Layer 1: Automated CI test. Parses SKILL.md, extracts every CLI command and
flag it claims exists, and verifies they're registered in the real Typer app.
Catches stale docs before agents hit them.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import click.testing
import pytest
import typer.testing

from worthless.cli.app import app

ROOT = Path(__file__).resolve().parent.parent
SKILL_MD = ROOT / "SKILL.md"


@pytest.fixture(scope="module")
def skill_content() -> str:
    """Load SKILL.md content once per module."""
    assert SKILL_MD.exists(), f"SKILL.md not found at {SKILL_MD}"
    return SKILL_MD.read_text()


@pytest.fixture(scope="module")
def registered_commands() -> dict[str, click.Command]:
    """Get all commands registered on the Typer app."""
    # Typer wraps Click internally; get the Click group
    cli = typer.main.get_command(app)
    assert isinstance(cli, click.Group)
    return {name: cmd for name, cmd in cli.commands.items()}


@pytest.fixture(scope="module")
def skill_commands(skill_content: str) -> list[str]:
    """Extract all `worthless <cmd>` references from SKILL.md.

    YAML frontmatter (content between the opening ``---`` and closing ``---``)
    is stripped first so YAML keys that follow ``worthless`` (e.g.
    ``name: worthless\\ndescription:`` or ``install worthless\\n  bins:``)
    are not misidentified as CLI commands.
    """
    # Strip YAML frontmatter (lines between leading --- delimiters)
    body = skill_content
    if skill_content.startswith("---"):
        end = skill_content.find("\n---", 3)
        if end != -1:
            body = skill_content[end + 4 :]

    # Match patterns like `worthless lock`, `worthless up`, etc.
    # Exclude things inside URLs, code comments, or variable names
    pattern = r"(?:^|\s)`?worthless\s+([a-z][\w-]*)`?"
    matches = re.findall(pattern, body)
    # Deduplicate preserving order
    seen: set[str] = set()
    cmds: list[str] = []
    for m in matches:
        if m not in seen and m not in ("v1", "v2", "v1.0", "v2.0"):
            seen.add(m)
            cmds.append(m)
    return cmds


@pytest.fixture(scope="module")
def skill_flags(skill_content: str) -> dict[str, list[str]]:
    """Extract flags claimed per command in SKILL.md.

    Looks for patterns like:
      #### `worthless lock [OPTIONS]`
      ...
      - `--env, -e PATH`: ...
      - `--provider, -p NAME`: ...
    """
    result: dict[str, list[str]] = {}
    current_cmd: str | None = None

    for line in skill_content.splitlines():
        # Detect command headers: #### `worthless lock [OPTIONS]`
        cmd_match = re.match(r"^####\s+`worthless\s+(\w+)", line)
        if cmd_match:
            current_cmd = cmd_match.group(1)
            result[current_cmd] = []
            continue

        # Detect flags under current command: - `--flag-name`
        if current_cmd:
            flag_match = re.match(r"^-\s+`(--[\w-]+)", line)
            if flag_match:
                result[current_cmd].append(flag_match.group(1))
            # End of flags section (next header or blank line after flags)
            elif line.startswith("#"):
                current_cmd = None

    return result


class TestSkillMdExists:
    """SKILL.md must exist and have minimum content."""

    def test_file_exists(self) -> None:
        assert SKILL_MD.exists()

    def test_minimum_size(self, skill_content: str) -> None:
        # Should be at least 5KB — a real discovery file, not a stub
        assert len(skill_content) > 5000, "SKILL.md seems too small to be useful"

    def test_has_required_sections(self, skill_content: str) -> None:
        required = [
            "## CLI Commands",
            "## Proxy Rules Engine",
            "## Installation",
        ]
        for section in required:
            assert section in skill_content, f"Missing required section: {section}"


class TestCliCommandsDrift:
    """Every CLI command mentioned in SKILL.md must actually exist."""

    def test_all_skill_commands_exist(
        self, skill_commands: list[str], registered_commands: dict[str, click.Command]
    ) -> None:
        missing = [cmd for cmd in skill_commands if cmd not in registered_commands]
        assert not missing, (
            f"SKILL.md references commands that don't exist: {missing}. "
            f"Registered commands: {sorted(registered_commands.keys())}"
        )

    def test_all_registered_commands_documented(
        self, skill_commands: list[str], registered_commands: dict[str, click.Command]
    ) -> None:
        """Every registered command should appear in SKILL.md."""
        undocumented = [cmd for cmd in registered_commands if cmd not in skill_commands]
        assert not undocumented, f"Commands exist but aren't documented in SKILL.md: {undocumented}"


class TestCliFlagsDrift:
    """Flags claimed in SKILL.md must match actual Typer definitions."""

    def test_documented_flags_exist(
        self,
        skill_flags: dict[str, list[str]],
        registered_commands: dict[str, click.Command],
    ) -> None:
        """Every flag documented in SKILL.md must exist on the real command."""
        errors: list[str] = []
        for cmd_name, flags in skill_flags.items():
            cmd = registered_commands.get(cmd_name)
            if cmd is None:
                continue  # Caught by TestCliCommandsDrift
            # Get all option names from the Click command
            real_opts: set[str] = set()
            for param in cmd.params:
                if isinstance(param, click.Option):
                    real_opts.update(param.opts)
                    real_opts.update(param.secondary_opts)
            for flag in flags:
                if flag not in real_opts:
                    errors.append(
                        f"{cmd_name}: --{flag.lstrip('-')} not found (have: {sorted(real_opts)})"
                    )
        assert not errors, "SKILL.md documents flags that don't exist:\n" + "\n".join(errors)


class TestRulesEngineDrift:
    """Rule classes mentioned in SKILL.md must exist in the codebase."""

    def test_documented_rules_importable(self, skill_content: str) -> None:
        """Every rule class referenced in SKILL.md should be importable."""
        from worthless.proxy.rules import (
            RateLimitRule,
            SpendCapRule,
            TimeWindowRule,
            TokenBudgetRule,
        )

        rule_classes = {
            "SpendCapRule": SpendCapRule,
            "RateLimitRule": RateLimitRule,
            "TokenBudgetRule": TokenBudgetRule,
            "TimeWindowRule": TimeWindowRule,
        }

        for name, cls in rule_classes.items():
            assert name in skill_content, f"SKILL.md should document {name}"
            assert callable(cls), f"{name} should be a class"

    def test_rule_protocol_signature_matches(self, skill_content: str) -> None:
        """The Rule protocol shown in SKILL.md should match the real one."""
        from worthless.proxy.rules import Rule

        import inspect

        sig = inspect.signature(Rule.evaluate)
        params = list(sig.parameters.keys())
        # SKILL.md shows: self, alias, request, *, provider, body
        assert "alias" in params
        assert "provider" in params
        assert "body" in params


class TestVersionDrift:
    """Version in SKILL.md should match pyproject.toml."""

    def test_version_matches(self, skill_content: str) -> None:
        pyproject = ROOT / "pyproject.toml"
        assert pyproject.exists()
        toml_content = pyproject.read_text()
        # Extract version from pyproject.toml
        match = re.search(r'^version\s*=\s*"([^"]+)"', toml_content, re.MULTILINE)
        assert match, "Could not find version in pyproject.toml"
        real_version = match.group(1)

        # Extract version from SKILL.md
        skill_match = re.search(r"\*\*Version\*\*:\s*(\S+)", skill_content)
        assert skill_match, "Could not find version in SKILL.md"
        skill_version = skill_match.group(1)

        assert skill_version == real_version, (
            f"SKILL.md says version {skill_version} but pyproject.toml says {real_version}"
        )

    def test_docs_image_tags_match_pyproject(self) -> None:
        """Every pinned ``worthless-proxy:X.Y.Z`` image tag in ``docs/`` must
        match pyproject's version.

        Runs the real release-time guard (``scripts/check_docs_versions.py``)
        as a subprocess, so this test and the ``tag-release.sh`` gate share ONE
        source of truth — same scan, same ``ALLOWLIST`` — with nothing to drift
        (WOR-743 / worthless-zij5). v0.3.8 shipped docs stuck at 0.3.7; this
        pins the contract in the baseline test lane on every PR.
        """
        pyproject = ROOT / "pyproject.toml"
        match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(), re.MULTILINE)
        assert match, "Could not find version in pyproject.toml"
        real_version = match.group(1)

        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_docs_versions.py"), real_version],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"docs/ pins worthless-proxy image tags that don't match pyproject {real_version}:\n"
            f"{result.stdout}{result.stderr}"
        )
