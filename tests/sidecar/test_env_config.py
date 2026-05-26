"""Sidecar env-config validation tests (WOR-308 slice 3).

Covers ``WORTHLESS_LOG_LEVEL`` parsing — the only env knob added in
slice 3. Two layers:

* **Unit** — table-driven check of ``_resolve_log_level`` so we don't
  need a subprocess for every name combination.
* **Subprocess** — one end-to-end check that an invalid level
  short-circuits ``main()`` with rc=1 and a stderr hint, matching
  the contract documented in ``__main__.py``'s module docstring.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

import pytest

from worthless.sidecar.__main__ import _resolve_log_level

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, logging.INFO),
        ("", logging.INFO),
        ("DEBUG", logging.DEBUG),
        ("debug", logging.DEBUG),
        ("INFO", logging.INFO),
        ("WARNING", logging.WARNING),
        ("ERROR", logging.ERROR),
        ("CRITICAL", logging.CRITICAL),
        ("  warning  ", logging.WARNING),
    ],
)
def test_resolve_log_level_accepts_canonical_names(raw: str | None, expected: int) -> None:
    """Canonical level names (case- and whitespace-insensitive) resolve to ints.

    Surface check on the contract: anything in
    ``DEBUG|INFO|WARNING|ERROR|CRITICAL`` is accepted, with the
    common Unix-shell habits (lowercase, leading/trailing spaces)
    tolerated to avoid surprise rc=1 on operator typos.
    """
    assert _resolve_log_level(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["TRACE", "VERBOSE", "WARN", "FATAL", "infomercial", "0", "5"],
)
def test_resolve_log_level_rejects_non_stdlib_names(raw: str) -> None:
    """Anything outside the stdlib set returns ``None`` so callers can rc=1.

    ``WARN`` and ``FATAL`` are deliberately rejected: stdlib
    ``logging`` aliases them to WARNING/CRITICAL but the docstring
    advertises only the canonical five, and silently accepting aliases
    drifts the contract.
    """
    assert _resolve_log_level(raw) is None


def test_invalid_log_level_exits_rc_1(sidecar_env: tuple[Path, dict[str, str]]) -> None:
    """End-to-end: a bad level surfaces as a clean rc=1 with a hint on stderr.

    The bind path requires the basic env to be valid (sidecar_env
    already provides socket/share/uid), so this test exercises the
    log-level guard in isolation: the process must die *before*
    binding, with a stderr message naming the offending env var so
    a Docker operator can debug it without strace.
    """
    _sock, env = sidecar_env
    env = {**env, "WORTHLESS_LOG_LEVEL": "TRACE"}
    proc = subprocess.run(
        [sys.executable, "-m", "worthless.sidecar"],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 1, (
        f"expected rc=1 for invalid log level, got {proc.returncode}\n"
        f"stdout:{proc.stdout}\nstderr:{proc.stderr}"
    )
    assert "WORTHLESS_LOG_LEVEL" in proc.stderr, (
        f"stderr should name the offending env var.\nstderr:{proc.stderr}"
    )
