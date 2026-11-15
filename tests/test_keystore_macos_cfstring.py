"""worthless-7xsa: reading a keychain account name never aborts Python on macOS.

The keychain returns ``kSecAttrAccount`` as a CFString. Asking a CFString for
CFData bytes raises an Objective-C NSException that kills the process — no
Python ``except`` can catch it, so ``doctor --json`` died mid-run and left its
lock behind. Each probe runs in a child process for that reason.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="CoreFoundation is macOS-only")

_PROBE = """
from worthless.cli import keystore_macos as k
print(repr(k._cfstr_to_str({value})))
"""


def _convert(value_expr: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", _PROBE.format(value=value_expr)],
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_an_account_name_stored_as_a_string_is_read_without_crashing() -> None:
    result = _convert("k._cfstr('wl-OPENAI_API_KEY')")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "'wl-OPENAI_API_KEY'"


def test_an_account_name_stored_as_data_is_still_read() -> None:
    result = _convert("k._cfdata(b'wl-ANTHROPIC_API_KEY')")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "'wl-ANTHROPIC_API_KEY'"
