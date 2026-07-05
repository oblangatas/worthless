"""Confusable (look-alike) filename detection for scan display warnings (WOR-800).

Flags a filename *token* whose letters mix two or more scripts that are visually
confusable with Latin (Latin / Cyrillic / Greek) — e.g. ``cοnfig.py`` where the
'о' is Cyrillic (U+043E). Display-only: the raw path is never modified.

Deliberately NOT a Unicode TR39 skeleton/confusables-table match — that answers a
pairwise "does X impersonate Y?" question and needs a reference set ``scan`` does
not have. A per-token mixed-script signal catches the realistic attack (a
Latin-looking identifier carrying a homoglyph) with the standard library alone.

Known gap: an *all*-Cyrillic (single-script) token that resembles Latin is not
caught here; only a full TR39 skeleton would. Tracked as the WOR-800 residual.
"""

from __future__ import annotations

import re
import unicodedata
from typing import NamedTuple

# Scripts that carry Latin look-alikes. Names come from unicodedata.name()'s
# first word ("LATIN SMALL LETTER O" -> "LATIN").
_CONFUSABLE_SCRIPTS = frozenset({"LATIN", "CYRILLIC", "GREEK"})

# Split a filename into tokens on the usual path/name separators.
_SEPARATORS = re.compile(r"[/\\._\- ]+")

#: Stable machine code for the warning (paired with the human footnote below).
WARN_CODE = "WARN_CONFUSABLE_NAME"

#: ASCII marker appended to a finding line (never inside the scrubbed path).
MARKER = "[!]"


class ConfusableHit(NamedTuple):
    char: str
    codepoint: str  # e.g. "U+043E"
    script: str  # e.g. "Cyrillic"


def _script(ch: str) -> str | None:
    """First word of a code point's Unicode name (its script family), or None."""
    try:
        return unicodedata.name(ch).split(" ", 1)[0]
    except ValueError:
        return None


def confusable_hits(name: str) -> list[ConfusableHit]:
    """Return the look-alike letters in any mixed-script token of ``name``.

    Empty list = the name is not confusable. A token is confusable when its
    letters span >= 2 of the Latin-confusable scripts; the reported hits are the
    minority-script letters (the ones most likely to be the impersonating glyph).
    """
    hits: list[ConfusableHit] = []
    for token in _SEPARATORS.split(name):
        scripts: dict[str, list[str]] = {}
        for ch in token:
            if not ch.isalpha():
                continue
            sc = _script(ch)
            if sc in _CONFUSABLE_SCRIPTS:
                scripts.setdefault(sc, []).append(ch)
        if len(scripts) < 2:
            continue  # single-script (or scriptless) token — not confusable
        dominant = max(scripts, key=lambda s: len(scripts[s]))
        for ch in token:
            if not ch.isalpha():
                continue
            sc = _script(ch)
            if sc in _CONFUSABLE_SCRIPTS and sc != dominant:
                hits.append(ConfusableHit(ch, f"U+{ord(ch):04X}", sc.capitalize()))
    return hits


def footnote(hit: ConfusableHit) -> str:
    """One-line human legend for a confusable hit. ASCII except the letter itself
    (a printable non-control glyph), which is the evidence a human adjudicates."""
    return (
        f"{MARKER} {WARN_CODE}: {hit.script} '{hit.char}' ({hit.codepoint}) mixed "
        "with Latin in a filename - may impersonate a look-alike name."
    )
