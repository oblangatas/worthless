"""HF7 / worthless-3907: ``worthless doctor --fix`` purges orphan DB rows.

Five tests that pin the HF7 contract. Phrase-token contract (plain English,
not engineer jargon — the user does NOT think "I have an orphan"):

  ``can't restore``           — the problem (replaces engineer-speak "orphan")
  ``worthless doctor --fix``  — the solution (the command name)

Both required-via-AND, not OR-of-variants. The OR-of-five-variants form
was the false-positive class HF4/PR #123 caught: pytest's ``tmp_path``
embeds the test name and ``"orphan"`` matched any path-echoing error.
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

# ``env_file`` fixture is auto-discovered from conftest.py — no import needed.


# ---------------------------------------------------------------------------
# The 5 RED contract tests
# ---------------------------------------------------------------------------


class TestDoctorOrphanPurge:
    """``worthless doctor`` diagnose + ``--fix`` purges orphan DB rows.

    Setup helper: ``_orphan`` locks a key (creating a DB row) and then
    deletes the .env line, leaving the DB row referencing an alias that
    no longer has a matching .env entry — the "orphan" state.
    """

    def _orphan(self, env_file: Path, home: WorthlessHome) -> None:
        lock_env(env_file, home)
        env_file.write_text("")  # user manually deleted the locked line

    # ---- 1. Empty / no-orphans path -----------------------------------------

    def test_doctor_no_orphans_exits_clean(self, home_dir: WorthlessHome) -> None:
        """Fresh home, no enrollments — doctor reports a clean state and exits 0.

        Wording revised from "nothing to fix" to "no issues found" in WOR-456
        per UX review (drop exclamation, flat house-style tone). Tests AND-bind
        on the new phrase so engineer-speak drift is caught.
        """
        result = cli_invoke(["doctor"], home_dir)

        assert result.exit_code == 0, f"doctor exited non-zero:\n{result.output}"
        assert not looks_like_traceback(result.output)
        # Bind to a positive-state phrase so a Typer "no such command" error
        # (which ALSO exits non-zero with no traceback) cannot pass this.
        assert has_all_tokens(result.output, "no issues found"), (
            f"doctor on empty DB must announce a clean state:\n{result.output}"
        )

    # ---- 2. Diagnose mode (no --fix) is read-only ---------------------------

    def test_doctor_detects_orphan_in_diagnose_mode(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """Diagnose-only mode: lists orphan, exit 0, DB unchanged."""
        self._orphan(env_file, home_dir)
        before = list_enrollments(home_dir)
        assert len(before) == 1, "precondition: orphan row exists in DB"

        result = cli_invoke(["doctor"], home_dir)

        assert result.exit_code == 0, (
            "diagnose-only must NOT exit non-zero — it's a read.\n" + result.output
        )
        assert not looks_like_traceback(result.output)
        # Plain-English phrase-token contract: "can't restore" + fix command name.
        assert has_all_tokens(result.output, "can't restore", "worthless doctor --fix"), (
            "doctor must use plain-English wording AND name the fix command:\n" + result.output
        )
        # Read-only invariant: no DB rows deleted.
        after = list_enrollments(home_dir)
        assert len(after) == 1, "diagnose-only mode must NOT mutate state — DB row was deleted."

    # ---- 3. --fix --yes actually purges the orphan --------------------------

    def test_doctor_fix_yes_purges_orphan(self, home_dir: WorthlessHome, env_file: Path) -> None:
        """`doctor --fix --yes`: skip prompt, purge orphan, DB empty after."""
        self._orphan(env_file, home_dir)
        assert len(list_enrollments(home_dir)) == 1, "precondition: orphan row exists"

        result = cli_invoke(["doctor", "--fix", "--yes"], home_dir)

        assert result.exit_code == 0, f"doctor --fix --yes failed:\n{result.output}"
        assert not looks_like_traceback(result.output)
        # DB row gone.
        after = list_enrollments(home_dir)
        assert len(after) == 0, f"orphan DB row was NOT purged. Remaining: {after}\n{result.output}"

    # ---- 4. --fix --dry-run lists planned deletions, writes nothing ---------

    def test_doctor_fix_dry_run_does_not_write(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """`doctor --fix --dry-run`: shows planned action, leaves DB intact."""
        self._orphan(env_file, home_dir)
        before = list_enrollments(home_dir)
        assert len(before) == 1, "precondition: orphan row exists"
        orphan_alias = before[0].key_alias

        result = cli_invoke(["doctor", "--fix", "--dry-run"], home_dir)

        assert result.exit_code == 0, f"dry-run exited non-zero:\n{result.output}"
        assert not looks_like_traceback(result.output)
        # Bind the dry-run preview to an actual orphan, not just the banner —
        # CodeRabbit PR #128: a banner-only check passes even if the preview
        # silently lost the row it was supposed to enumerate.
        assert has_all_tokens(result.output, "dry-run", orphan_alias), (
            f"dry-run output must mark itself as a preview AND name the orphan "
            f"({orphan_alias}):\n{result.output}"
        )
        # DB unchanged.
        after = list_enrollments(home_dir)
        assert len(after) == 1, f"--dry-run wrote to DB (it MUST NOT). Remaining: {after}"

    # ---- 5. --fix without --yes prompts; declining aborts -------------------

    def test_doctor_fix_without_yes_prompts_then_aborts(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """`doctor --fix` (no --yes): prompts, "n" answer aborts, DB unchanged."""
        self._orphan(env_file, home_dir)

        # Feed "n" to the confirmation prompt.
        result = cli_invoke(["doctor", "--fix"], home_dir, input="n\n")

        # Aborted user-decline is not an error; exit 0 with a "cancelled" message.
        assert result.exit_code == 0, (
            f"declining the prompt should be exit 0, not an error:\n{result.output}"
        )
        assert not looks_like_traceback(result.output)
        # CodeRabbit PR #128: assert the prompt was actually exercised, not
        # just the postcondition — otherwise a silent abort path that never
        # reached the prompt would also pass.
        assert has_all_tokens(result.output, "delete", "?"), (
            f"the confirmation prompt must appear in user output "
            f"(text containing 'delete' + '?'):\n{result.output}"
        )
        assert has_all_tokens(result.output, "cancelled"), (
            f"declining must produce a 'cancelled' acknowledgement:\n{result.output}"
        )
        # DB still has the orphan — abort means nothing got deleted.
        after = list_enrollments(home_dir)
        assert len(after) == 1, f"declining the prompt must NOT delete anything. Remaining: {after}"

    # ---- 6. Regression: multi-enrollment alias — surgical purge --------------

    def test_doctor_fix_yes_keeps_other_envs_intact_for_same_alias(
        self, home_dir: WorthlessHome, tmp_path: Path
    ) -> None:
        """CodeRabbit PR #128 MAJOR: an alias may have enrollments in multiple
        ``.env`` files. If only one is orphaned, doctor must purge ONLY that
        row — not wipe the alias from the other ``.env`` too.
        """
        env_a = tmp_path / "project_a" / ".env"
        env_b = tmp_path / "project_b" / ".env"
        env_a.parent.mkdir()
        env_b.parent.mkdir()
        env_a.write_text(f"OPENAI_API_KEY={TEST_OPENAI_KEY}\n")
        env_b.write_text(f"OPENAI_API_KEY={TEST_OPENAI_KEY}\n")
        lock_env(env_a, home_dir)
        lock_env(env_b, home_dir)
        before = list_enrollments(home_dir)
        assert len(before) == 2, f"precondition: 2 enrollments for the shared alias\n{before}"

        # Delete env_a's line — env_a is now orphan, env_b is intact.
        env_a.write_text("")

        result = cli_invoke(["doctor", "--fix", "--yes"], home_dir)
        assert result.exit_code == 0, f"doctor --fix --yes failed:\n{result.output}"

        # The orphan row (env_a) should be gone; env_b's enrollment must survive.
        after = list_enrollments(home_dir)
        env_a_str = str(env_a.resolve())
        env_b_str = str(env_b.resolve())
        remaining_paths = sorted(e.env_path for e in after)
        assert env_a_str not in remaining_paths, (
            f"orphan row for {env_a_str} was not purged:\n{remaining_paths}"
        )
        assert env_b_str in remaining_paths, (
            f"healthy row for {env_b_str} was deleted (alias-wide bug):\n{remaining_paths}"
        )
        assert len(after) == 1, (
            f"expected exactly 1 row remaining (env_b's), got {len(after)}:\n{after}"
        )
