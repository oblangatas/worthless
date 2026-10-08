"""Docs drift detection: every `worthless ...` in docs/ names a real command and flag.

test_skill_md.py guards SKILL.md the same way. Nothing guarded the public docs
site (docs/, served at docs.wless.io): its CI only builds, checks image tags and
links. A renamed command or dropped flag would ship a page users copy-paste into
an error. worthless-86dk.

Only code is checked (fenced blocks and inline backticks) — prose like "worthless
makes keys worthless" is not a command.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import typer

from worthless.cli.app import app

DOCS = Path(__file__).resolve().parent.parent / "docs"

_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_INLINE = re.compile(r"`([^`\n]+)`")
# An invocation starts a command: at line start (after an optional `$ ` prompt,
# list dash or quote), after a shell separator, or as a YAML value. That rules
# out `worthless` used as a name — `pip install worthless`, `docker exec -i
# worthless`, `secret-tool clear service worthless`.
# Also accepted before `worthless`: env assignments (`WORTHLESS_X=1 worthless up`)
# and `uvx` with a package spec (`uvx worthless[mcp]==1.2 mcp`). `worthless` must
# be a whole word, so `worthless-data:` or a YAML `worthless:` key never match.
_INVOCATION = re.compile(
    r"(?:^\s*(?:\$\s+|-\s+)?[\"']?|(?:&&|\|\||[|;(]|\$\()\s*|:\s+[\"']?)"
    r"(?:[A-Z_][A-Z0-9_]*=\S*\s+)*"
    r"(?:uvx\s+)?worthless(?:\[[\w,]+\])?(?:==\S+)?(?![\w.:\[=-])"
    r"((?:\s+[^\s|;&`\"'<>#()]+)*)"
)
_COMMENT = re.compile(r"\s#.*$")
_VERSION = re.compile(r"^v?\d")  # `worthless 0.3.8` is --version output, not input


def _code_snippets(text: str) -> list[str]:
    fenced = _FENCE.findall(text)
    rest = _FENCE.sub("", text)
    # Backticked commands inside fenced blocks too: YAML schemas in the install
    # guides quote commands mid-line (`command: "run `worthless up` first"`).
    inline_in_fences = [m for block in fenced for m in _INLINE.findall(block)]
    return fenced + inline_in_fences + _INLINE.findall(rest)


def _invocations() -> list[tuple[str, list[str]]]:
    found = []
    for page in sorted(DOCS.rglob("*.md*")):
        for snippet in _code_snippets(page.read_text(encoding="utf-8")):
            for raw in snippet.splitlines():
                line = _COMMENT.sub("", raw)
                for m in _INVOCATION.finditer(line):
                    tokens = m.group(1).split()
                    if tokens and _VERSION.match(tokens[0]):
                        continue
                    found.append((f"{page.relative_to(DOCS)}: {raw.strip()}", tokens))
    return found


def _options(cmd: object) -> set[str]:
    # Typer vendors its own Click since 0.26, so match on shape, not on
    # click.Option / click.Group (see test_skill_md.py).
    opts = {"--help", "-h"}
    for p in getattr(cmd, "params", []):
        if getattr(p, "param_type_name", "") == "option":
            opts.update(p.opts)
            opts.update(p.secondary_opts)
    return opts


def _resolve(tokens: list[str]) -> str | None:
    """Walk tokens through the real CLI; return an error string or None."""
    cmd = typer.main.get_command(app)
    path = "worthless"
    for tok in tokens:
        if tok == "--":  # everything after belongs to the wrapped program
            return None
        if tok.startswith("-"):
            flag = tok.split("=", 1)[0]
            if flag not in _options(cmd):
                return f"`{path}` has no option {flag} (has: {sorted(_options(cmd))})"
            continue
        if hasattr(cmd, "commands"):
            if tok not in cmd.commands:
                return f"`{path}` has no subcommand {tok!r} (has: {sorted(cmd.commands)})"
            cmd = cmd.commands[tok]
            path += f" {tok}"
            continue
        # A positional argument (env path, alias, ...) — nothing more to resolve
        # for this token; keep checking any later flags against this command.
    return None


INVOCATIONS = _invocations()


def test_docs_have_command_examples() -> None:
    """Guard the guard: if parsing breaks, the parametrised test would vacuously pass.

    Counts distinct commands that carry arguments — bare `worthless` matches
    trivially and would hide a parser that finds nothing else.
    """
    distinct = {tuple(t) for _, t in INVOCATIONS if t}
    assert len(distinct) >= 30, f"only {len(distinct)} distinct `worthless ...` commands in docs/"


@pytest.mark.parametrize(("where", "tokens"), INVOCATIONS, ids=[w for w, _ in INVOCATIONS])
def test_documented_command_exists(where: str, tokens: list[str]) -> None:
    error = _resolve(tokens)
    assert error is None, f"{where}\n  {error}"
