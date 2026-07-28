"""Real Ctrl+C at the real uninstall prompt (worthless-6xuv).

The unit test for this bug mocks ``typer.confirm`` to raise and mocks
``_stdin_is_tty`` to return True, then drives the app in-process with
``CliRunner``. That tests a *model* of Ctrl+C. It cannot fail if the real signal
lands somewhere else, which is exactly the class of blind spot tracked in
``worthless-d4h2``.

This test removes every one of those stand-ins:

* the real ``worthless`` console script, spawned as its own process
* a real PTY, so ``sys.stdin.isatty()`` is genuinely true — nothing patched
* a real ``SIGINT`` delivered to the process group, like a real Ctrl+C
* assertions on the real exit code and the bytes really written to the terminal

Remaining honest gap: this runs the console script built from the working tree,
not a ``uv tool install``-ed published wheel. Closing that is ``worthless-d4h2``.
"""

from __future__ import annotations

import os
import pty
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.user_flow

#: The command must reach its confirmation prompt, then die, well inside this.
_TIMEOUT_S = 60.0


def _worthless_bin() -> Path:
    """The real console script next to the interpreter running the tests."""
    return Path(sys.executable).parent / "worthless"


def _clean_env(home: Path) -> dict[str, str]:
    """Hermetic env: drop every inherited WORTHLESS_* so a sibling test can't
    change this child's behaviour, then set only what we control."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("WORTHLESS_")}
    env.update(
        {
            "HOME": str(home),
            "WORTHLESS_HOME": str(home / ".worthless"),
            "WORTHLESS_KEYRING_BACKEND": "null",
            "NO_COLOR": "1",
        }
    )
    return env


def _drain(fd: int, deadline: float, until: bytes | None = None) -> bytes:
    """Read from the PTY master until *until* appears, EOF, or the deadline."""
    buf = b""
    while time.monotonic() < deadline:
        if until is not None and until in buf:
            break
        if not select.select([fd], [], [], 0.2)[0]:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:  # EIO — the child closed the slave side
            break
        if not chunk:
            break
        buf += chunk
    return buf


def test_real_ctrl_c_at_the_uninstall_prompt_cancels_cleanly(tmp_path: Path) -> None:
    """A real SIGINT at the real prompt must say "cancelled", never "internal error".

    Against the pre-fix code this fails with the operator's exact terminal output:
    ``WRTLS-199: an internal error occurred``.
    """
    binary = _worthless_bin()
    if not binary.exists():  # pragma: no cover — depends on how the venv was built
        pytest.skip(f"no worthless console script at {binary}")

    env = _clean_env(tmp_path)

    # Real on-disk state, not a mock: uninstall short-circuits with "nothing to
    # uninstall" unless the home directory exists (uninstall.py checks exactly
    # `home.base_dir.exists()`). The sentinel lets us prove the cancel really
    # left the home alone rather than merely printing that it did.
    home = tmp_path / ".worthless"
    home.mkdir(parents=True)
    sentinel = home / "worthless.db"
    sentinel.write_bytes(b"not-a-real-db")

    master, slave = pty.openpty()
    proc = subprocess.Popen(
        [str(binary), "uninstall"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        start_new_session=True,  # own process group, so we can signal it like a terminal does
        close_fds=True,
    )
    os.close(slave)

    try:
        deadline = time.monotonic() + _TIMEOUT_S
        seen = _drain(master, deadline, until=b"Continue?")
        assert b"Continue?" in seen, (
            f"never reached the confirmation prompt; saw: {seen.decode(errors='replace')!r}"
        )

        # The real thing: Ctrl+C to the whole process group.
        os.killpg(os.getpgid(proc.pid), signal.SIGINT)

        seen += _drain(master, time.monotonic() + _TIMEOUT_S)
        returncode = proc.wait(timeout=_TIMEOUT_S)
    finally:
        os.close(master)
        if proc.poll() is None:  # pragma: no cover — only on an unexpected hang
            proc.kill()
            proc.wait(timeout=10)

    output = seen.decode(errors="replace").lower()
    # The terminal wraps at the PTY width, so collapse whitespace before matching
    # a phrase that could straddle a line break.
    normalized = " ".join(output.split())

    assert "internal error" not in output, (
        "a real Ctrl+C still surfaces an internal error — the user cannot tell "
        f"whether their keys are safe. Full terminal output:\n{seen.decode(errors='replace')}"
    )
    # Pin the whole promise, not just the word "cancelled". A bare "cancel" match
    # would also accept something like "cancelled after partial changes" — the very
    # ambiguity this fix exists to remove, on the command that restores real API
    # keys. The "nothing was changed" half is the safety guarantee.
    assert "cancelled" in normalized and "nothing was changed" in normalized, (
        "an aborted uninstall must confirm it cancelled AND that nothing changed; "
        f"got:\n{seen.decode(errors='replace')}"
    )
    assert returncode == 0, f"cancelling is not a failure, but exited {returncode}"
    assert sentinel.exists(), "cancelling must not remove anything — the home was touched"
