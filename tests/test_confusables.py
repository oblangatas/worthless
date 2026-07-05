"""WOR-800: detect look-alike (confusable) filename tokens for a display warning.

Signal = a single token whose *letters* mix ≥2 confusable-with-Latin scripts
(Latin+Cyrillic, Latin+Greek, Cyrillic+Greek). Legitimate single-script names
(Hebrew, CJK, accented Latin) must stay silent — no alarm fatigue.

Confusable code points are built with chr() so the intent is explicit; the
legitimate non-Latin names are literal (they are printable letters, not the
invisible chars the #376 scrubber removes).
"""

from __future__ import annotations

from worthless.cli.code_scanner import CodeFinding
from worthless.cli.commands.scan import _code_findings_to_json, _format_code_findings_human
from worthless.cli.confusables import confusable_hits

CYRILLIC_O = chr(0x043E)  # 'о' — look-alike of Latin 'o'
GREEK_OMICRON = chr(0x03BF)  # 'ο' — look-alike of Latin 'o'


def test_latin_cyrillic_token_flagged() -> None:
    hits = confusable_hits(f"c{CYRILLIC_O}nfig.py")
    assert hits, "Latin+Cyrillic token must be flagged"
    h = hits[0]
    assert h.char == CYRILLIC_O
    assert h.codepoint == "U+043E"
    assert h.script == "Cyrillic"


def test_latin_greek_token_flagged() -> None:
    hits = confusable_hits(f"p{GREEK_OMICRON}six.txt")
    assert hits and hits[0].script == "Greek"


def test_pure_latin_not_flagged() -> None:
    assert confusable_hits("config.py") == []


def test_hebrew_name_not_flagged() -> None:
    # single-script Hebrew token — legitimate, must stay silent
    assert confusable_hits("סוד.env") == []


def test_cjk_name_not_flagged() -> None:
    assert confusable_hits("日本語.py") == []


def test_accented_latin_not_flagged() -> None:
    # é is LATIN SMALL LETTER E WITH ACUTE — still Latin script, not confusable
    assert confusable_hits("café.js") == []


def test_all_cyrillic_token_not_flagged_documented_gap() -> None:
    # honest residual (WOR-800): an all-Cyrillic token is single-script, so the
    # mixed-script heuristic does not catch it. Only TR39 would. Documented.
    all_cyrillic = chr(0x0441) + chr(0x043E) + chr(0x0440)  # 'сор' — every letter Cyrillic
    assert confusable_hits(f"{all_cyrillic}.py") == []


def test_separators_scope_the_token() -> None:
    # a lone Cyrillic letter as its own token, Latin in another token — neither
    # token is itself mixed, so it must not fire.
    assert confusable_hits(f"{CYRILLIC_O}/config.py") == []


# --- integration: the marker + footnote in real scan output --------------- #


def _cf(file: str) -> CodeFinding:
    return CodeFinding(
        file=file,
        line=1,
        column=1,
        matched_url="https://api.openai.com",
        provider_name="openai",
        suggested_env_var="OPENAI_BASE_URL",
        line_text='url = "https://api.openai.com"',
    )


def test_confusable_filename_marked_in_human_output() -> None:
    out = _format_code_findings_human([_cf(f"c{CYRILLIC_O}nfig.py")])
    assert "[!]" in out
    assert "WARN_CONFUSABLE_NAME" in out
    assert "U+043E" in out and "Cyrillic" in out  # footnote names the culprit


def test_clean_and_legit_names_get_no_marker() -> None:
    for name in ("config.py", "סוד.env", "日本語.py", "café.js"):
        out = _format_code_findings_human([_cf(name)])
        assert "[!]" not in out, f"{name} falsely flagged"
        assert "WARN_CONFUSABLE_NAME" not in out


def test_footnote_prints_once_per_codepoint() -> None:
    out = _format_code_findings_human([_cf(f"c{CYRILLIC_O}nfig.py"), _cf(f"pr{CYRILLIC_O}d.env")])
    assert out.count("[!] WARN_CONFUSABLE_NAME") == 1  # legend deduped by codepoint


def test_json_warning_structured_and_path_raw() -> None:
    name = f"c{CYRILLIC_O}nfig.py"
    js = _code_findings_to_json([_cf(name)])
    assert js[0]["file"] == name  # raw path preserved (display-only invariant)
    warn = js[0]["warnings"][0]
    assert warn["code"] == "WARN_CONFUSABLE_NAME"
    assert warn["confusable_chars"][0] == {"codepoint": "U+043E", "script": "Cyrillic"}


def test_json_clean_name_no_warning() -> None:
    assert _code_findings_to_json([_cf("config.py")])[0]["warnings"] == []
