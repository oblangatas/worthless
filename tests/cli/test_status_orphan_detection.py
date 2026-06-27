"""HF5 / worthless-gmky: ``worthless status`` flags broken DB enrollments.

The 2026-04-30 dogfood bug: ``status`` queried the ``shards`` table only,
ignored ``enrollments``, ignored ``.env`` content. Result was
``PROTECTED`` for an alias whose ``.env`` line had been deleted —
contradicting ``scan`` and ``unlock``, leaving the user confused.

Post-HF5 contract:
  * single enrollment, ``.env`` line deleted → status row reads ``BROKEN``
  * multi-enrollment alias, ANY healthy ``.env`` line → still ``PROTECTED``
    (you can still unlock from that one)
  * multi-enrollment alias, ALL ``.env`` lines deleted → ``BROKEN``
  * any broken row in output → a single ``worthless doctor --fix`` hint

Phrase tokens (shared with HF7's ``cli/orphans.py``):
  ``BROKEN``                — the row marker
  ``can't restore``         — appears in the hint line, not the row
  ``worthless doctor --fix`` — names the recovery command

Both required-via-AND, not OR-of-variants.
"""

from __future__ import annotations

from pathlib import Path


from worthless.cli.bootstrap import WorthlessHome

from tests.cli.conftest import (
    TEST_OPENAI_KEY,
    cli_invoke,
    has_all_tokens,
    list_enrollments,
    lock_env,
    looks_like_traceback,
)


class TestStatusFlagsBrokenAliases:
    """``status`` marks aliases whose ``.env`` line is gone as BROKEN."""

    def _orphan(self, env_file: Path, home: WorthlessHome) -> None:
        lock_env(env_file, home)
        env_file.write_text("")

    def test_status_marks_broken_alias_as_broken(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """Single enrollment whose .env line was deleted → status row reads BROKEN."""
        self._orphan(env_file, home_dir)

        result = cli_invoke(["status"], home_dir)

        assert result.exit_code == 0, f"status failed:\n{result.output}"
        assert not looks_like_traceback(result.output)
        assert "BROKEN" in result.output, (
            f"status must mark the orphan alias BROKEN (not PROTECTED):\n{result.output}"
        )
        # Hint must direct the user to the recovery command.
        assert has_all_tokens(result.output, "can't restore", "worthless doctor --fix"), (
            f"status must include the canonical recovery hint:\n{result.output}"
        )

    # NOT xfail: this is a regression-prevention test, not a RED contract.
    # Pre-HF5 status shows everything PROTECTED unconditionally so this test
    # passes today. Post-HF5 must continue to pass — the alias-aggregation
    # logic must keep PROTECTED when ANY enrollment is healthy.
    def test_status_keeps_alias_protected_if_any_enrollment_healthy(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """Multi-enrollment alias: ONE orphan, ONE healthy → still PROTECTED.

        Recovery semantics: the user can still ``unlock`` from the healthy
        ``.env``, so the alias is not broken. Only the row that maps to the
        deleted .env line is broken — and `status`'s default per-alias
        granularity hides that.
        """
        env_a = tmp_path / "project_a" / ".env"
        env_b = tmp_path / "project_b" / ".env"
        env_a.parent.mkdir()
        env_b.parent.mkdir()
        env_a.write_text(f"OPENAI_API_KEY={TEST_OPENAI_KEY}\n")
        env_b.write_text(f"OPENAI_API_KEY={TEST_OPENAI_KEY}\n")
        lock_env(env_a, home_dir)
        lock_env(env_b, home_dir)
        assert len(list_enrollments(home_dir)) == 2, "precondition: 2 enrollments per alias"

        # env_a's line deleted; env_b intact → at least one healthy enrollment.
        env_a.write_text("")

        result = cli_invoke(["status"], home_dir)
        assert result.exit_code == 0
        assert "PROTECTED" in result.output, (
            f"alias with one healthy enrollment must stay PROTECTED:\n{result.output}"
        )
        assert "BROKEN" not in result.output, (
            f"alias with one healthy enrollment must NOT be marked BROKEN:\n{result.output}"
        )

    def test_status_emits_doctor_fix_hint_only_when_broken(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """The doctor-fix hint appears IFF there's a broken row to fix."""
        # Healthy state: no hint.
        lock_env(env_file, home_dir)
        clean = cli_invoke(["status"], home_dir)
        assert clean.exit_code == 0
        assert "worthless doctor --fix" not in clean.output, (
            f"healthy status must NOT show the recovery hint (no orphan to fix):\n{clean.output}"
        )

        # Break it.
        env_file.write_text("")
        broken = cli_invoke(["status"], home_dir)
        assert broken.exit_code == 0
        assert "worthless doctor --fix" in broken.output, (
            f"broken status must show the recovery hint:\n{broken.output}"
        )
