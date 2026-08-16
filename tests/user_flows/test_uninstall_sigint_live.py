"""Real Ctrl+C at a real confirmation prompt (worthless-6xuv).

A unit test cannot prove this. It has no terminal and sends no signal — it tests a
*model* of Ctrl+C. So these drive the real ``worthless`` console script as its own
process, attached to a real pseudo-terminal, and deliver a real ``SIGINT`` to its
process group.

Two things are pinned:

1. **No "internal error".** ``typer.confirm`` raises ``click.Abort`` on Ctrl+C, which
   inherits from ``Exception`` and so was swallowed by the CLI's error boundary into
   ``WRTLS-199: an internal error occurred``. On commands that touch real API keys that
   reads as "it died halfway".
2. **Exit code 130.** The conventional code for "terminated by SIGINT". Exiting 0 tells
   a script or agent the command *succeeded* — a user abort is not a success. Declining
   with "n" is a deliberate choice and still exits 0; that distinction is the point.

The fix belongs in the error boundary, not at individual call sites: there are nine
``typer.confirm`` prompts across uninstall, lock, doctor, service, and the default
command. Patching them one at a time is how this bug survived its first fix.
"""

from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

# `pty` is POSIX-only and import-time — on Windows this module would fail to
# COLLECT, not skip, taking the whole session down with it. Signals work
# differently there too (no SIGINT to a process group), so the scenario cannot
# be expressed; skip before the import rather than guard each test.
if sys.platform == "win32":  # pragma: no cover — POSIX-only by construction
    pytest.skip("needs a POSIX pty and SIGINT process groups", allow_module_level=True)

import pty  # noqa: E402 — must follow the platform guard above

# Scoped to the wheel path only — see the note in test_requests_proxied_live.py.
# The branch run keeps the 30s global guard, where a hang is a real signal.
_TIMEOUT_BUDGET = 60 if os.environ.get("WORTHLESS_TEST_BIN") else 30
pytestmark = [
    pytest.mark.user_flow,
    pytest.mark.wheel_artifact,
    pytest.mark.timeout(_TIMEOUT_BUDGET),
]

_TIMEOUT_S = 60.0


def _worthless_bin() -> Path:
    """The console script under test.

    Defaults to the one beside the interpreter running the tests — the branch
    build. ``WORTHLESS_TEST_BIN`` aims this at a different binary, so CI can run
    the same test against an installed wheel: the artifact a user actually gets
    (worthless-d4h2). Without that, a packaging-only defect passes every test.
    """
    override = os.environ.get("WORTHLESS_TEST_BIN")
    return Path(override) if override else Path(sys.executable).parent / "worthless"


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


def _ctrl_c_at_prompt(
    binary: Path, args: list[str], env: dict[str, str], prompt: bytes
) -> tuple[str, int]:
    """Run ``binary args`` on a real PTY, wait for *prompt*, send a real Ctrl+C.

    Returns the full terminal output and the process exit code.
    """
    master, slave = pty.openpty()
    proc = subprocess.Popen(  # noqa: S603
        [str(binary), *args],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        start_new_session=True,  # own process group, so we can signal it like a terminal does
        close_fds=True,
    )
    os.close(slave)
    try:
        seen = _drain(master, time.monotonic() + _TIMEOUT_S, until=prompt)
        assert prompt in seen, (
            f"never reached the prompt {prompt!r}; saw: {seen.decode(errors='replace')!r}"
        )

        os.killpg(os.getpgid(proc.pid), signal.SIGINT)  # the real thing

        seen += _drain(master, time.monotonic() + _TIMEOUT_S)
        returncode = proc.wait(timeout=_TIMEOUT_S)
    finally:
        os.close(master)
        if proc.poll() is None:  # pragma: no cover — only on an unexpected hang
            proc.kill()
            proc.wait(timeout=10)
    return seen.decode(errors="replace"), returncode


def test_real_ctrl_c_at_the_uninstall_prompt_cancels_cleanly(tmp_path: Path) -> None:
    """Ctrl+C at the uninstall prompt: says nothing changed, exits 130, changes nothing.

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

    output, returncode = _ctrl_c_at_prompt(binary, ["uninstall"], env, b"Continue?")

    # The terminal wraps at the PTY width, so collapse whitespace before matching
    # a phrase that could straddle a line break.
    normalized = " ".join(output.lower().split())

    assert "internal error" not in normalized, (
        "a real Ctrl+C still surfaces an internal error — the user cannot tell "
        f"whether their keys are safe. Full terminal output:\n{output}"
    )
    # Pin the whole promise, not just the word "cancelled". A bare "cancel" match
    # would also accept something like "cancelled after partial changes" — the very
    # ambiguity this fix exists to remove, on the command that restores real API
    # keys. The "nothing was changed" half is the safety guarantee.
    assert "cancelled" in normalized and "nothing was changed" in normalized, (
        f"an aborted uninstall must confirm it cancelled AND that nothing changed;\n{output}"
    )
    assert returncode == 130, (
        "Ctrl+C must exit 130 (terminated by SIGINT), not "
        f"{returncode} — exiting 0 tells a script the uninstall succeeded"
    )
    assert sentinel.exists(), "cancelling must not remove anything — the home was touched"


@pytest.mark.parametrize(
    ("args", "prompt"),
    [
        (["service", "uninstall"], b"Remove the worthless user service?"),
    ],
    ids=["service-uninstall"],
)
def test_ctrl_c_is_handled_at_prompts_beyond_uninstall(
    tmp_path: Path, args: list[str], prompt: bytes
) -> None:
    """The fix must live at the error boundary, not at one call site.

    ``uninstall`` was patched locally first; every other confirmation prompt kept
    printing ``WRTLS-199``. This proves a *different* command's prompt is covered, so
    a future prompt inherits the behaviour instead of repeating the bug.
    """
    binary = _worthless_bin()
    if not binary.exists():  # pragma: no cover
        pytest.skip(f"no worthless console script at {binary}")

    env = _clean_env(tmp_path)
    (tmp_path / ".worthless").mkdir(parents=True, exist_ok=True)

    output, returncode = _ctrl_c_at_prompt(binary, args, env, prompt)
    normalized = " ".join(output.lower().split())

    assert "internal error" not in normalized, (
        f"Ctrl+C at `worthless {' '.join(args)}` still reports an internal error:\n{output}"
    )
    assert "cancel" in normalized, f"an interrupted command must say it cancelled:\n{output}"
    assert returncode == 130, f"Ctrl+C must exit 130, got {returncode}\n{output}"
