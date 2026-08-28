"""WOR-831: the sidecar disables its own core dumps (macOS + Linux).

T6-rlimit (mandatory, cross-platform): a clean interpreter calls the sidecar's
own disable_core_dumps() and reads RLIMIT_CORE back — asserting the value, not
merely that a function was called. A clamped sandbox can refuse the setrlimit,
so the readback is the load-bearing check.

NOTE: RLIMIT_CORE=(0,0) governs the core *file* path only. On a Linux host with
a piped core_pattern (systemd-coredump/apport) it is bypassed; the sidecar's
piped-core protection is PR_SET_DUMPABLE=0 (asserted separately in
test_hardening.py). This test proves the rlimit is set, not that the pipe path
is closed.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from ._sentinels import null_keyring_env

pytestmark = pytest.mark.real_ipc


def test_sidecar_disable_core_dumps_zeroes_rlimit() -> None:
    code = (
        "from worthless.sidecar._hardening import disable_core_dumps; disable_core_dumps(); "
        "import resource; print(tuple(resource.getrlimit(resource.RLIMIT_CORE)))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env=null_keyring_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "(0, 0)", f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
