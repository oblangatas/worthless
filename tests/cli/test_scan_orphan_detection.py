"""HF5 / worthless-gmky: ``worthless scan`` lists broken DB enrollments.

The 2026-04-30 dogfood bug: ``scan`` used the DB only as a filter ("is
this .env line enrolled?") not as a join — DB rows with no matching
``.env`` row were silently dropped, contradicting ``status``.

Post-HF5 contract:
  * a "Can't be restored" section appears when any orphan exists
  * each broken row names the alias + the deleted ``.env`` location
  * the trailing total gains a `, N broken` segment
  * JSON output gains an additive ``"orphans": []`` array
  * exit code unchanged (1 if findings, 0 otherwise) — additive only
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from worthless.cli.bootstrap import WorthlessHome

from tests.cli.conftest import (
    cli_invoke,
    has_all_tokens,
    list_enrollments,
    lock_env,
    looks_like_traceback,
)


class TestScanFlagsBrokenEnrollments:
    """``scan`` surfaces orphan DB rows in a dedicated section + JSON field."""

    def _orphan(self, env_file: Path, home: WorthlessHome) -> None:
        lock_env(env_file, home)
        env_file.write_text("")

    def test_scan_lists_broken_section_when_orphans_exist(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """A `Can't be restored:` section names the broken alias + recovery command."""
        self._orphan(env_file, home_dir)
        before = list_enrollments(home_dir)
        assert len(before) == 1, "precondition: 1 orphan row"
        orphan_alias = before[0].key_alias

        result = cli_invoke(["scan", str(env_file.parent)], home_dir)

        assert not looks_like_traceback(result.output)
        # Canonical PROBLEM_PHRASE = "can't restore" (cli/orphans.py — reword
        # in one place). Per CodeRabbit PR #131.
        assert has_all_tokens(
            result.output, "can't restore", orphan_alias, "worthless doctor --fix"
        ), f"scan must surface the broken alias with the canonical wording:\n{result.output}"

    def test_scan_total_includes_broken_count(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """Trailing total reads e.g. `Found N keys ..., 1 broken`."""
        self._orphan(env_file, home_dir)

        result = cli_invoke(["scan", str(env_file.parent)], home_dir)

        assert not looks_like_traceback(result.output)
        assert "1 broken" in result.output.lower(), (
            f"scan total must call out the orphan count:\n{result.output}"
        )

    def test_scan_json_includes_orphans_array(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """JSON output gains additive `"orphans": [...]` (empty when none)."""
        self._orphan(env_file, home_dir)
        before = list_enrollments(home_dir)
        orphan_alias = before[0].key_alias

        result = cli_invoke(["scan", str(env_file.parent), "--json"], home_dir)

        assert not looks_like_traceback(result.output)
        # The JSON shape can change over time — assert the additive `orphans`
        # key is present and contains our orphan, not a specific outer
        # schema. JSON consumers can iterate this directly.
        try:
            parsed = json.loads(result.output)
        except json.JSONDecodeError:
            pytest.fail(f"scan --json did not emit valid JSON:\n{result.output}")
        assert isinstance(parsed, dict) and "orphans" in parsed, (
            f"scan --json must include an `orphans` array:\n{parsed}"
        )
        aliases = [o.get("alias") for o in parsed["orphans"]]
        assert orphan_alias in aliases, (
            f"orphans array must contain the orphan alias {orphan_alias!r}:\n{parsed}"
        )

    def test_scan_json_orphans_empty_when_clean(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """Healthy state: scan --json emits `"orphans": []`."""
        lock_env(env_file, home_dir)  # locked, NOT broken
        # Re-lock keeps env_file healthy. No orphan present.

        result = cli_invoke(["scan", str(env_file.parent), "--json"], home_dir)
        assert not looks_like_traceback(result.output)
        try:
            parsed = json.loads(result.output)
        except json.JSONDecodeError:
            pytest.fail(f"scan --json did not emit valid JSON:\n{result.output}")
        assert "orphans" in parsed, (
            f"scan --json must always include `orphans` (additive shape):\n{parsed}"
        )
        assert parsed["orphans"] == [], f'healthy state must yield `"orphans": []`:\n{parsed}'
