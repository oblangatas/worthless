"""Shared fixtures and platform guard for ``tests/e2e/``.

E2E tests invoke the real ``worthless`` CLI as a subprocess. They are
POSIX-only because the product supports macOS + Linux only (same policy
as the backup and safe_rewrite suites).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


@pytest.fixture
def worthless_cli() -> list[str]:
    """Return the argv prefix that invokes the real CLI via the test venv.

    Resolves the ``worthless`` console script from the same interpreter as
    the test runner so tests exercise the installed entry point declared
    in ``pyproject.toml`` (``[project.scripts] worthless = ...``).
    """

    venv_bin = Path(sys.executable).parent
    return [str(venv_bin / "worthless")]


def pytest_collection_modifyitems(config, items) -> None:  # noqa: ANN001, D401
    """Skip the E2E suite on Windows — product is macOS + Linux only.

    Scoped to ``tests/e2e/`` via conftest location; every collected item
    here belongs to the E2E suite, so no path-substring filter is needed.
    """

    if sys.platform == "win32":
        skip = pytest.mark.skip(reason="E2E suite is macOS + Linux only")
        for item in items:
            item.add_marker(skip)
