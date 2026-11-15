"""worthless-qvvs: every command the tool tells you to run must exist.

Error paths printed `worthless unlock --all` (unlock has no --all) and
`worthless relock` (no such command) — exactly when the user is already in
trouble and least able to improvise. This walks every string the program can
print (string literals, not comments or docstrings), finds each
`` `worthless <command> --flag` ``, and checks it against the real CLI's help.
SKILL.md's command lines are checked too: agents run them verbatim.
"""

from __future__ import annotations

import ast
import re
from functools import cache
from pathlib import Path

from typer.testing import CliRunner

from worthless.cli.app import app

_SRC = Path(__file__).resolve().parents[1] / "src" / "worthless"
_COMMAND = re.compile(r"`worthless ((?:[a-z][a-z-]*)(?: [a-z][a-z-]*)?)((?: --?[a-z][a-z-]*)*)")
_runner = CliRunner()


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """ids of the string constants that are docstrings (never printed)."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


def _printed_strings() -> list[tuple[str, int, str]]:
    found = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        skip = _docstring_nodes(tree)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in skip
            ):
                found.append((str(path.relative_to(_SRC.parent)), node.lineno, node.value))
    return found


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


@cache
def _help(words: tuple[str, ...]) -> str | None:
    # CI forces colour (GitHub Actions), and Rich then wraps each option name
    # in colour codes; a narrow terminal can also truncate the options table.
    # Ask for a wide terminal and strip colour so only the real text is read.
    result = _runner.invoke(app, [*words, "--help"], env={"COLUMNS": "200"})
    return _ANSI.sub("", result.output) if result.exit_code == 0 else None


_SKILL_FILES = (_SRC.parents[1] / "SKILL.md", _SRC / "openclaw" / "skill_assets" / "SKILL.md")


def _skill_md_commands() -> list[tuple[str, int, str]]:
    """SKILL files tell agents what to run; code lines start with the command."""
    found = []
    for path in _SKILL_FILES:
        for n, s in enumerate(path.read_text().splitlines(), 1):
            found.append(
                (
                    str(path.relative_to(_SRC.parents[1])),
                    n,
                    f"`{s}" if s.startswith("worthless ") else s,
                )
            )
    return found


def test_every_printed_worthless_command_exists() -> None:
    bad = []
    for where, line, text in _printed_strings() + _skill_md_commands():
        for match in _COMMAND.finditer(text):
            words = tuple(match.group(1).split())
            flags = match.group(2).split()
            out = _help(words)
            if out is None and len(words) > 1:  # second word was an argument
                words, out = words[:1], _help(words[:1])
                if out is not None and "Commands" in out:  # a group: it was a typo'd subcommand
                    bad.append(f"{where}:{line}: no command `{match.group(1)}`")
                    continue
                flags = []  # after a positional (`wrap python -c`) flags may not be ours
            if out is None:
                bad.append(f"{where}:{line}: no command `worthless {words[0]}`")
                continue
            for flag in flags:
                if not re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", out):
                    bad.append(f"{where}:{line}: `worthless {' '.join(words)}` has no {flag}")
    assert not bad, "\n".join(bad)
