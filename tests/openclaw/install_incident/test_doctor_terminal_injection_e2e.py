"""End-to-end terminal-EFFECT test for the audit-gate error message.

``doctor`` (and ``lock``'s exit-73 path) print blocking audit findings via
``format_gate_error_message``, which scrubs both attacker-controlled fields —
``b.file`` and ``b.json_path`` — before rendering the ``- file: json_path``
line. This proves, at the rendered screen level, that escapes in either field
can't clear or forge the terminal. Mirrors the scan proof (PR #376) on the
shared VT100 model.

Caveat: doctor's ``_audit_gate_findings`` wrapper (checks/openclaw.py) isn't a
pure string-builder (it runs the audit subprocess), so it's not exercised here;
it emits its lines through this same ``format_gate_error_message`` / scrubber,
so its scrubbing is covered by transitivity.
"""

from __future__ import annotations

from tests._util.vt100 import ESC, render, warning_survived
from worthless.openclaw.audit import BlockingFinding, format_gate_error_message


def test_gate_error_screen_attack_neutralised() -> None:
    """Escapes in a blocking finding's file (ESC[2J) and json_path (cursor-forge)
    can't hijack the screen when the gate error message is rendered."""
    attack_file = f"models.json{ESC}[2J{ESC}[H>> AUDIT CLEAN <<"
    attack_path = f"providers.openai.apiKey{ESC}[1A{ESC}[2K"  # cursor-up + erase-line
    finding = BlockingFinding(
        file=attack_file,
        json_path=attack_path,
        provider="openai",
        message="plaintext provider key",
        source="audit",
    )

    # Precondition — the attack is REAL: the raw gate line hijacks the screen.
    raw_rows = render(f"  - {attack_file}: {attack_path}")
    assert not warning_survived(raw_rows), "raw escapes in the gate line should hijack the screen"

    # Guard — the real formatter scrubs both fields: warning survives (screen
    # effect) AND no ESC in the output string (byte-level, checked on the real
    # formatter output — not the rendered rows, where ESC can never appear).
    out = format_gate_error_message([finding])
    assert warning_survived(render(out)), "sanitised gate message must not touch the screen"
    assert ESC not in out, "no raw ESC may reach the terminal"
