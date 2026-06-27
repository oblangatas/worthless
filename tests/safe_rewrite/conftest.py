"""Shared fixtures for the ``safe_rewrite`` invariants engine test suite.

Fixtures intentionally avoid any imports from the module under test so that
collection never fails on a broken implementation — they only build real
files/dirs and compute sha256 baselines.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path
from collections.abc import Callable

import pytest


# ---------------------------------------------------------------------------
# File-building helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def make_env_file() -> Callable[..., Path]:
    """Factory: create a file with given content (bytes) and mode.

    Usage::

        p = make_env_file(tmp_path / ".env", b"KEY=value\\n")
    """

    def _make(path: Path, content: bytes = b"KEY=value\n", mode: int = 0o600) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
        path.chmod(mode)
        return path

    return _make


@pytest.fixture
def sha256_of() -> Callable[[Path], str]:
    """Return a function that computes sha256 of a file's bytes."""

    def _sha(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    return _sha


@pytest.fixture
def assert_byte_identical(sha256_of) -> Callable[[Path, str], None]:
    """Assert a file's current sha256 matches the expected hex digest."""

    def _assert(path: Path, expected_sha256: str) -> None:
        actual = sha256_of(path)
        assert actual == expected_sha256, (
            f"byte-identity violated: expected {expected_sha256}, got {actual}"
        )

    return _assert


# ---------------------------------------------------------------------------
# Platform fakes
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_windows(monkeypatch) -> None:
    """Pretend we are running on Windows."""
    monkeypatch.setattr(sys, "platform", "win32", raising=False)


@pytest.fixture
def fake_darwin(monkeypatch) -> None:
    """Pretend we are running on macOS."""
    monkeypatch.setattr(sys, "platform", "darwin", raising=False)


# ---------------------------------------------------------------------------
# Repo scaffolding
# ---------------------------------------------------------------------------


@pytest.fixture
def in_fake_repo(tmp_path) -> Path:
    """Create a ``tmp_path/.git`` marker and return ``tmp_path`` as repo_root."""
    (tmp_path / ".git").mkdir()
    return tmp_path


# ---------------------------------------------------------------------------
# Chaos hooks (used by later red-first tests; kept here so the fixture set
# stays consistent with the plan from the first test onward).
# ---------------------------------------------------------------------------


@pytest.fixture
def chaos_signal_at(tmp_path) -> Callable[[str, int], Callable[[], None]]:
    """Build a ``_hook_before_replace`` callback that sends ``signum`` to self.

    ``hook_name`` is advisory (the public hook currently fires only
    before-replace); kept for forward-compat with sub-PR 2 hook points.
    """

    def _builder(hook_name: str, signum: int) -> Callable[[], None]:
        def _cb() -> None:
            os.kill(os.getpid(), signum)

        return _cb

    return _builder


@pytest.fixture
def chaos_errno_at(monkeypatch) -> Callable[[str, int], None]:
    """Monkeypatch an ``os`` syscall to raise ``OSError(errno_val)`` on first call."""

    def _apply(syscall_name: str, errno_val: int) -> None:
        real = getattr(os, syscall_name)
        state = {"fired": False}

        def _wrapped(*args, **kwargs):  # type: ignore[no-untyped-def]
            if not state["fired"]:
                state["fired"] = True
                raise OSError(errno_val, os.strerror(errno_val))
            return real(*args, **kwargs)

        monkeypatch.setattr(os, syscall_name, _wrapped)

    return _apply


@pytest.fixture
def barrier_file(tmp_path) -> Path:
    """A scratch path used by two-process tests for ordering handshakes."""
    return tmp_path / "_barrier"


@pytest.fixture
def spawn_chaos_child(tmp_path) -> Callable[..., subprocess.Popen]:
    """Spawn a child process that exercises ``safe_rewrite`` for chaos tests.

    The child interface is finalised when the chaos-harness tests land;
    exposing the fixture here means later tests can be added without
    re-plumbing conftest.
    """

    def _spawn(
        target: Path,
        content: bytes,
        signal_at: int | None = None,
    ) -> subprocess.Popen:
        raise NotImplementedError("chaos harness lands with test_chaos.py")

    return _spawn


# ---------------------------------------------------------------------------
# Guard: refuse to run the real chaos harness on Windows.
# ---------------------------------------------------------------------------


def pytest_collection_modifyitems(config, items) -> None:  # noqa: D401, ANN001
    """Skip the entire safe_rewrite suite on Windows — product is mac/Linux only."""
    if sys.platform == "win32":
        skip = pytest.mark.skip(reason="safe_rewrite suite is macOS + Linux only")
        for item in items:
            if "tests/safe_rewrite" in str(item.fspath):
                item.add_marker(skip)
