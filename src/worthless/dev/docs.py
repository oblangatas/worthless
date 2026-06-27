"""Repo-local entrypoints for engineering docs generation."""

from __future__ import annotations

from collections.abc import Sequence
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _codewiki_wrapper(root: Path) -> Path:
    return root / "scripts" / "codewiki.sh"


def _generate_command(args: Sequence[str]) -> list[str]:
    root = _repo_root()
    return [
        str(_codewiki_wrapper(root)),
        "generate",
        "--output",
        str(root / "engineering/generated/codewiki-pilot"),
        *args,
    ]


def generate_docs() -> None:
    root = _repo_root()
    subprocess.run(_generate_command(sys.argv[1:]), cwd=root, check=True)
