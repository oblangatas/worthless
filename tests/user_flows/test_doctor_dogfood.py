"""HF7 dogfood scenario as a single chained user-flow test.

Closes the test gap surfaced during HF7 review: ``test_doctor_purge.py``
verifies isolated commands (lock alone, doctor alone, unlock alone), but
the bug from 2026-04-30 was an INTEGRATION shape across four commands.
This test runs the full chain and asserts each step, so a regression in
ANY of (status, unlock, doctor, post-fix consistency) gets caught.

The chain:

  1. lock      — enroll a key in the DB + rewrite .env to shard-A
  2. status    — confirms 1 PROTECTED enrollment
  3. (user manually deletes the .env line — the dogfood trigger)
  4. unlock    — must surface canonical wording with the fix command
  5. status    — STILL lists PROTECTED (the surprising part the user reported)
  6. doctor    — diagnose-mode: lists the broken row, exit 0, DB unchanged
  7. doctor --fix --yes — purges; success message
  8. status    — finally consistent: 0 enrolled keys

This file uses ``WORTHLESS_HOME=tmp_path/...`` so it does NOT touch the
developer's actual ``~/.worthless/``. It DOES exercise the real keyring
backend (or real file fallback if no keyring), real SQLite, real Typer
command dispatch — the same way the user-flow seed test
``test_keychain_call_count.py`` does for HF2.

Marked ``user_flow`` so the default test sweep skips it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.helpers import fake_openai_key
from tests.user_flows.helpers import scrubbed_cli_env
from worthless.cli.app import app


@pytest.mark.user_flow
def test_full_dogfood_lock_break_doctor_recover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 2026-04-30 v0.3.2 dogfood scenario, end-to-end.

    Pre-HF7: this scenario left the user stuck — ``unlock`` and ``status``
    gave opposite answers and there was no recovery command. This test
    pins the post-HF7 contract: each of the four commands behaves
    correctly across the chain.
    """
    home = tmp_path / ".worthless"
    env_file = tmp_path / ".env"
    env_file.write_text(f"OPENAI_API_KEY={fake_openai_key()}\n")
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    cli_env = scrubbed_cli_env(home)

    # Step 1 — lock
    lock = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
    assert lock.exit_code == 0, f"lock failed:\n{lock.output}"

    # Step 2 — status: 1 enrolled key, PROTECTED
    status1 = runner.invoke(app, ["status"], env=cli_env)
    assert status1.exit_code == 0, f"status failed:\n{status1.output}"
    assert "OPENAI_API_KEY" in status1.output or "openai-" in status1.output, (
        f"status must show the locked key:\n{status1.output}"
    )

    # Step 3 — user manually deletes the .env line (the dogfood trigger)
    env_file.write_text("")

    # Step 4 — unlock: must surface canonical "can't restore" + fix hint,
    # NOT silently succeed and NOT leak a traceback
    unlock = runner.invoke(app, ["unlock", "--env", str(env_file)], env=cli_env)
    assert unlock.exit_code != 0, (
        f"unlock on broken state must fail loudly, not silently succeed:\n{unlock.output}"
    )
    assert "Traceback" not in unlock.output, (
        f"unlock leaked a traceback to the user:\n{unlock.output}"
    )
    out_lower = unlock.output.lower()
    assert "can't restore" in out_lower, (
        f"unlock must use plain-English problem phrase:\n{unlock.output}"
    )
    assert "worthless doctor --fix" in out_lower, (
        f"unlock must name the recovery command:\n{unlock.output}"
    )

    # Step 5 — status STILL lists the key (DB row exists), but HF5 now
    # marks it BROKEN. Pre-HF5 status said PROTECTED here (the user-confusing
    # dual answer the dogfood reported). HF5 contract: row appears AND is
    # flagged BROKEN AND the doctor-fix hint accompanies it.
    status2 = runner.invoke(app, ["status"], env=cli_env)
    assert status2.exit_code == 0, f"status after break failed:\n{status2.output}"
    assert "OPENAI_API_KEY" in status2.output or "openai-" in status2.output, (
        f"status must STILL list the key after the .env line is deleted:\n{status2.output}"
    )
    # HF5 contract: row reads BROKEN, hint names the recovery command.
    assert "BROKEN" in status2.output, (
        f"HF5: status must mark the broken row BROKEN (not PROTECTED):\n{status2.output}"
    )
    assert "worthless doctor --fix" in status2.output.lower(), (
        f"HF5: status must point at the recovery command:\n{status2.output}"
    )

    # Step 6 — doctor: diagnose-only, lists the row, exit 0, DB unchanged
    doctor_diag = runner.invoke(app, ["doctor"], env=cli_env)
    assert doctor_diag.exit_code == 0, f"doctor diagnose-only must exit 0:\n{doctor_diag.output}"
    diag_lower = doctor_diag.output.lower()
    assert "can't restore" in diag_lower, (
        f"doctor must use plain-English problem phrase:\n{doctor_diag.output}"
    )
    assert "worthless doctor --fix" in diag_lower, (
        f"doctor must name the recovery command in its own output:\n{doctor_diag.output}"
    )

    # Step 7 — doctor --fix --yes: purge
    doctor_fix = runner.invoke(app, ["doctor", "--fix", "--yes"], env=cli_env)
    assert doctor_fix.exit_code == 0, f"doctor --fix --yes failed:\n{doctor_fix.output}"
    assert "cleaned up" in doctor_fix.output.lower(), (
        f"doctor --fix --yes must announce successful cleanup:\n{doctor_fix.output}"
    )

    # Step 8 — status: now consistent. The broken row is gone — and the
    # symmetric assertion to step 5: the key must NOT be listed any more.
    status3 = runner.invoke(app, ["status"], env=cli_env)
    assert status3.exit_code == 0, f"status after fix failed:\n{status3.output}"
    assert "OPENAI_API_KEY" not in status3.output and "openai-" not in status3.output, (
        f"status must NOT list the key after doctor --fix --yes — system is "
        f"now consistent:\n{status3.output}"
    )
    assert "no keys" in status3.output.lower(), (
        f"status must announce the empty state in plain English:\n{status3.output}"
    )
    # The previously-orphaned alias is gone — a second `doctor` call has
    # nothing to report. This double-checks step 7 closed the loop.
    doctor_done = runner.invoke(app, ["doctor"], env=cli_env)
    assert doctor_done.exit_code == 0, f"doctor on clean state must exit 0:\n{doctor_done.output}"
    assert "no issues found" in doctor_done.output.lower(), (
        f"doctor must announce a clean state once the orphan is gone:\n{doctor_done.output}"
    )
