"""End-to-end terminal-EFFECT test for ``worthless lock``'s blocking output.

``lock`` prints hardcoded-provider-URL findings — whose file paths come from the
scanned (possibly hostile) repo — through ``_format_lock_block_human``, which
scrubs each path via the injected ``sanitize=``. This proves, at the rendered
screen level (not just "bytes stripped"), that a crafted path can't clear the
screen or forge output when lock prints its blocking report. Mirrors the scan
proof (PR #376) on the shared VT100 model.

Caveat: lock's inline skipped-files block is not a standalone function, so it is
not exercised here; it calls the same ``sanitise_for_message``, so its scrubbing
is covered by transitivity (that call + the scrubber's own unit and full-plane
tests in test_lock_audit_gate.py).
"""

from __future__ import annotations

from tests._util.vt100 import ESC, render, warning_survived
from worthless.cli.commands.scan import _format_lock_block_human
from worthless.cli.scanner import HardcodedUrlFinding
from worthless.openclaw.audit import sanitise_for_message


def test_lock_block_clear_screen_attack_neutralised() -> None:
    """A finding whose file path carries ESC[2J can't wipe the screen when
    ``lock`` renders its blocking report."""
    # ESC[2J erases the screen, ESC[H homes the cursor, then a forged clean line.
    attack_file = f"src/config.py{ESC}[2J{ESC}[H>> LOCKED: all clean <<"
    finding = HardcodedUrlFinding(
        file=attack_file, line=12, url="https://api.openai.com", provider="openai"
    )

    # Precondition — the attack is REAL: the raw path, as it would appear in the
    # collapsed file list, wipes the prior warning off the screen.
    raw_rows = render(f"  • {attack_file} — OPENAI_BASE_URL (line 12)")
    assert not warning_survived(raw_rows), "ESC[2J in the path should wipe the screen when raw"

    # Guard — lock's real formatter scrubs the path: warning survives (screen
    # effect) AND no ESC in the output string (byte-level, checked on the real
    # formatter output — not the rendered rows, where ESC can never appear).
    out = _format_lock_block_human([finding], sanitize=sanitise_for_message)
    assert warning_survived(render(out)), "sanitised lock output must not clear the screen"
    assert ESC not in out, "no raw ESC may reach the terminal"
