"""End-to-end terminal-EFFECT tests for ``worthless scan`` output hardening.

The byte-level tests in ``test_lock_audit_gate.py`` assert injection bytes are
removed from the output string. These prove the user-visible promise one level
up — the terminal isn't hijacked — by rendering output through a tiny VT100
screen model. Each test first asserts the attack DOES mutate the screen when raw
(precondition), so a broken model or a dropped sanitiser fails loudly instead of
passing vacuously.

Two hijack classes, two proof styles: screen-mutation attacks (CSI clear/cursor)
get the screen-effect proof here; out-of-band attacks (OSC 52 clipboard, OSC 8,
title-set, bidi) leave no grid change, so ``test_out_of_band_attacks_stripped``
proves them at the byte level (no ESC/BEL/bidi-override reaches the terminal).
Self-contained — no third-party emulator dependency.
"""

from __future__ import annotations

from tests._util.vt100 import BEL, ESC, RLO, render, warning_survived
from worthless.cli.code_scanner import CodeFinding
from worthless.cli.commands.scan import _format_code_findings_human, _format_skipped_human
from worthless.cli.scanner import SkippedFile


def test_source_snippet_clear_screen_attack_neutralised() -> None:
    """A scanned source line with ESC[2J (clear screen) can't wipe the terminal."""
    # ESC[2J clears the screen, ESC[H homes the cursor, then a forged "clean" msg.
    attack = f'KEY="sk-x"{ESC}[2J{ESC}[H>> SCAN CLEAN: 0 issues <<'

    # Precondition — the attack is REAL: raw, it wipes the prior warning.
    raw_rows = render(f"       -> {attack}")
    assert not warning_survived(raw_rows), "ESC[2J should wipe the screen when raw"

    # The fix — fed through the real formatter, the warning survives intact.
    finding = CodeFinding(
        file="config.py",
        line=1,
        column=1,
        matched_url="https://api.openai.com",
        provider_name="openai",
        suggested_env_var="OPENAI_BASE_URL",
        line_text=attack,
    )
    out = _format_code_findings_human([finding])
    assert warning_survived(render(out)), "sanitised output must not clear the screen"
    assert ESC not in out, "no raw ESC may reach the terminal (checked on the formatter output)"


def test_skipped_filename_cursor_forge_attack_neutralised() -> None:
    """A skipped file whose name moves the cursor up can't overwrite real output."""
    # ESC[1A moves cursor up one line, ESC[2K clears it — overwriting the warning
    # with a forged reassuring line.
    attack_name = f"big{ESC}[1A{ESC}[2KFORGED_no_issues.env"

    raw_rows = render(f"  {attack_name}  [timeout]")
    assert not warning_survived(raw_rows), "cursor-move + clear-line should overwrite when raw"

    out = _format_skipped_human([SkippedFile(file=attack_name, reason="timeout")])
    assert warning_survived(render(out)), "sanitised skipped path must not move the cursor"
    assert ESC not in out, "no raw ESC may reach the terminal (checked on the formatter output)"


def test_out_of_band_attacks_stripped() -> None:
    """OSC 52 (clipboard), OSC 8 (hyperlink), title-set, and bidi reorder leave
    NO grid change — a screen model can't express them. Prove neutralisation at
    the byte level instead: the bytes these attacks require (ESC, BEL, the bidi
    override) must never reach the terminal in the real formatter's output.

    Each payload is embedded in attacker-controlled scanned content (the source
    line) and in a skipped-file name, so both real sinks are covered.
    """
    osc52_clipboard = f"{ESC}]52;c;ZXZpbA=={BEL}"  # write attacker data to clipboard
    osc8_hyperlink = f"{ESC}]8;;http://evil{ESC}\\click{ESC}]8;;{ESC}\\"  # spoofed link
    title_set = f"{ESC}]0;PWNED{BEL}"  # rewrite the window title
    payload = f'url = "x"  # {osc52_clipboard}{osc8_hyperlink}{title_set}{RLO}evil'

    code_out = _format_code_findings_human(
        [
            CodeFinding(
                file="config.py",
                line=1,
                column=1,
                matched_url="https://api.openai.com",
                provider_name="openai",
                suggested_env_var="OPENAI_BASE_URL",
                line_text=payload,
            )
        ]
    )
    skipped_out = _format_skipped_human(
        [SkippedFile(file=f"big{title_set}{RLO}.env", reason="timeout")]
    )

    for label, out in (("code finding", code_out), ("skipped", skipped_out)):
        for name, ch in (("ESC", ESC), ("BEL", BEL), ("bidi-override", RLO)):
            assert ch not in out, f"{name} reached terminal via {label} output"
