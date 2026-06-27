"""Verify package version is exposed via importlib.metadata."""

import re
from importlib.metadata import version
from pathlib import Path


def _pyproject_version() -> str:
    text = Path(__file__).resolve().parent.parent.joinpath("pyproject.toml").read_text()
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
    assert match, "Could not find version in pyproject.toml"
    return match.group(1)


def test_version_matches_pyproject():
    assert version("worthless") == _pyproject_version()
