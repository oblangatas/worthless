"""Doctor must disclose what OpenClaw's config backups can contain (WOR-599).

OpenClaw natively writes two kinds of backup beside ``openclaw.json``:

* ``openclaw.json.bak`` (+ ``.bak.1`` … ``.bak.4``) — a 5-slot rotating ring,
  written pre-edit on every config write (``backup-rotation.ts``).
* ``openclaw.json.last-good`` — written at gateway startup and, unlike the ring,
  **never rotated out** (``io.observe-recovery.ts``).

Both are verbatim copies of the config. If the config held a plaintext
``models.providers.*.apiKey`` when they were written — the normal case for anyone
who used OpenClaw before installing Worthless — that key is still in them after
``worthless lock``.

We deliberately do not delete these files: they are daemon-owned, ``.bak`` is our
own documented recovery path, and deleting one can leave OpenClaw unable to
restart. Disclosure is therefore the only control we have, which makes these
assertions the deliverable rather than a nicety.
"""

from __future__ import annotations

from worthless.cli.commands.doctor.checks.openclaw import _RECOVERY_NOTE_TEXT


class TestRecoveryNoteDisclosesResidue:
    """The recovery note sells `.bak` as a rollback path — it must also say what
    that file can still contain, and must not stay silent about `.last-good`."""

    def test_recovery_note_still_offers_the_rollback_path(self) -> None:
        """The affordance comes first. We are adding a caveat, not removing help."""
        text = _RECOVERY_NOTE_TEXT.lower()
        assert "openclaw.json.bak" in text
        assert "restore" in text or "recover" in text

    def test_recovery_note_caveats_the_pre_lock_key(self) -> None:
        """Telling a user to restore from a file that may hold their old plaintext
        key, without saying so, is the contradiction this ticket exists to fix."""
        text = _RECOVERY_NOTE_TEXT.lower()
        assert "key" in text, "must mention the file can contain a key"
        assert any(phrase in text for phrase in ("before you locked", "pre-lock", "original")), (
            "must say the copy predates the lock"
        )

    def test_recovery_note_names_both_backup_kinds(self) -> None:
        """Both kinds must be named, because which one retains the pre-lock key
        depends on daemon state.

        Measured against ghcr.io/openclaw/openclaw:2026.5.3-1 — seed a plaintext
        key, boot the gateway, then rewrite the config the way lock does:

        * ``.bak`` and ``.bak.1`` STILL held the pre-lock key afterwards.
        * ``.last-good`` had been re-promoted to the post-lock contents, because
          the daemon was running and observed the change. With the daemon down at
          lock time it keeps the old copy until it next starts.

        An earlier draft of this note claimed ``.last-good`` "never rotates away"
        and treated the ring as self-healing. The probe showed the opposite
        emphasis, so the wording must not lean on either file alone.
        """
        assert "last-good" in _RECOVERY_NOTE_TEXT
        assert "openclaw.json.bak" in _RECOVERY_NOTE_TEXT

    def test_recovery_note_does_not_claim_last_good_is_permanent(self) -> None:
        """Guard against the specific false claim the probe disproved."""
        text = _RECOVERY_NOTE_TEXT.lower()
        assert "never rotates" not in text
        assert "persists indefinitely" not in text

    def test_recovery_note_contains_no_key_material(self) -> None:
        """SR-04: the note names paths, never bytes."""
        for marker in ("sk-ant-", "sk-proj-", "sk-or-"):
            assert marker not in _RECOVERY_NOTE_TEXT
