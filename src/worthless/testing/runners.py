"""Test runner entrypoints for uv run test-* commands."""

from __future__ import annotations

import sys

import pytest  # noqa: DEP004 — test runner, pytest is a dev/test dependency


def unit() -> None:
    sys.exit(pytest.main(["-x", "-q"]))


def docker() -> None:
    sys.exit(
        pytest.main(["-x", "-v", "-m", "docker", "-o", "addopts=--strict-markers --timeout=300"])
    )


def live() -> None:
    sys.exit(
        pytest.main(
            ["-x", "-v", "-s", "-m", "live", "-o", "addopts=--strict-markers --timeout=120"]
        )
    )


def openclaw() -> None:
    sys.exit(
        pytest.main(["-x", "-v", "-m", "openclaw", "-o", "addopts=--strict-markers --timeout=300"])
    )


def all_tests() -> None:
    sys.exit(pytest.main(["-v", "-o", "addopts=--strict-markers --timeout=300"]))
