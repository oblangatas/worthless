"""Shared fixtures for the ``dotenv_rewriter`` safety-wiring test suite.

These fixtures intentionally avoid importing the module under test at
collection time so that a broken implementation never breaks pytest
collection — they only build real files and compute sha256 baselines.

The ``safe_rewrite_spy`` fixture monkeypatches the ``safe_rewrite``
binding inside ``worthless.cli.dotenv_rewriter`` to record every call
while still delegating to the real implementation. Tests assert call
counts and call arguments to prove the gate is wired through every
public entry point.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Callable

import pytest


# ---------------------------------------------------------------------------
# File-building helpers (mirrored from tests/safe_rewrite/conftest.py).
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
# safe_rewrite spy.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SafeRewriteCall:
    """One observed invocation of ``safe_rewrite`` from the rewriter module."""

    target: Path
    new_content: bytes
    original_user_arg: Path


@dataclass
class SafeRewriteSpy:
    """Records every call to ``safe_rewrite`` made by ``dotenv_rewriter``."""

    calls: list[SafeRewriteCall]

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def last(self) -> SafeRewriteCall:
        assert self.calls, "safe_rewrite was never called"
        return self.calls[-1]


@pytest.fixture
def safe_rewrite_spy(monkeypatch) -> SafeRewriteSpy:
    """Wrap the ``safe_rewrite`` binding inside ``dotenv_rewriter`` and record calls.

    The wrapped function still delegates to the real implementation, so
    every invariant fires exactly as in production. Tests can both assert
    call counts/contents AND let real refusals propagate through
    ``UnsafeRewriteRefused``.
    """
    from worthless.cli import dotenv_rewriter as rewriter_mod
    from worthless.cli.safe_rewrite import safe_rewrite as real_safe_rewrite

    spy = SafeRewriteSpy(calls=[])

    def _wrapped(target, new_content, *, original_user_arg, **kwargs):  # type: ignore[no-untyped-def]
        spy.calls.append(
            SafeRewriteCall(
                target=target,
                new_content=new_content,
                original_user_arg=original_user_arg,
            )
        )
        return real_safe_rewrite(
            target,
            new_content,
            original_user_arg=original_user_arg,
            **kwargs,
        )

    # Bind the wrapper into the rewriter module's namespace. If the
    # module hasn't yet imported safe_rewrite (red phase), fall back to
    # setting the attribute so the import resolves once implementation
    # lands.
    monkeypatch.setattr(rewriter_mod, "safe_rewrite", _wrapped, raising=False)
    return spy
