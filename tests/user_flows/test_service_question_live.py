"""WOR-859: plain `worthless` asks the explicit service question at a real terminal.

The unit tests mock the prompt. This drives the real console script on a real
PTY, the way a person types. It proves the question a user actually sees names
what it adds, the key-file trade-off and the undo, in the platform's own words
(CI runs it on Linux and macOS), and that "n", a bare Enter, and `--yes` all
leave nothing at login.

Before PR #673 the first test fails at its first assertion: plain `worthless`
locked quietly and never asked.
"""

from __future__ import annotations

import os
import secrets
import socket
import string
import subprocess
import sys
import time
from pathlib import Path

import pytest

if sys.platform == "win32":  # pragma: no cover — pty is POSIX-only
    pytest.skip("pty is POSIX-only", allow_module_level=True)

import pty  # noqa: E402 — must follow the platform guard above
import select  # noqa: E402

from worthless.cli.commands.lock import _CI_ENV_VARS  # noqa: E402
from worthless.cli.platform import _in_container  # noqa: E402

pytestmark = [
    pytest.mark.user_flow,
    pytest.mark.wheel_artifact,
    pytest.mark.timeout(90),
    pytest.mark.skipif(
        _in_container(), reason="inside a container the question is deliberately skipped"
    ),
]

_STEP_S = 30
_QUESTION = b"Install the background service on port"


def _worthless_bin() -> Path:
    """The branch build, or WORTHLESS_TEST_BIN to aim at an installed wheel."""
    override = os.environ.get("WORTHLESS_TEST_BIN")
    return Path(override) if override else Path(sys.executable).parent / "worthless"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _setup(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    """A throwaway home + project with one real-looking key, and an env with CI
    markers removed: the offer treats them as 'nobody is watching', and the
    point here is to be the person who is."""
    home = tmp_path / "home"
    project = tmp_path / "project"
    home.mkdir()
    project.mkdir()
    # Random, not a repeated pattern: lock rightly ignores low-entropy "keys".
    alphabet = string.ascii_letters + string.digits
    key = "sk-proj-" + "".join(secrets.choice(alphabet) for _ in range(40))
    (project / ".env").write_text(f"OPENAI_API_KEY={key}\n")
    drop = set(_CI_ENV_VARS)
    env = {k: v for k, v in os.environ.items() if not k.startswith("WORTHLESS_") and k not in drop}
    env.update(
        {
            "HOME": str(home),
            "WORTHLESS_HOME": str(home / ".worthless"),
            "WORTHLESS_KEYRING_BACKEND": "null",
            "WORTHLESS_PORT": str(_free_port()),
            "NO_COLOR": "1",
        }
    )
    return home, project, env


def _read_until(fd: int, needle: bytes | None, buf: bytes) -> bytes:
    """Read the PTY until *needle* appears, EOF, or the step deadline."""
    deadline = time.monotonic() + _STEP_S
    while (needle is None or needle not in buf) and time.monotonic() < deadline:
        if not select.select([fd], [], [], 0.2)[0]:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:  # EIO — the child closed its side
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _run(
    args: list[str], project: Path, env: dict[str, str], answers: dict[bytes, bytes]
) -> tuple[str, bool]:
    """Run `worthless *args` on a real PTY, typing *answers* when each prompt appears.

    Returns the terminal text and whether a service was installed, recorded
    BEFORE the cleanup below removes it.
    """
    master, slave = pty.openpty()
    proc = subprocess.Popen(  # noqa: S603
        [str(_worthless_bin()), *args],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        cwd=project,
        env=env,
        start_new_session=True,
        close_fds=True,
    )
    os.close(slave)
    seen = b""
    installed = False
    try:
        for prompt, answer in answers.items():
            seen = _read_until(master, prompt, seen)
            if prompt in seen:
                os.write(master, answer)
        seen = _read_until(master, None, seen)
        proc.wait(timeout=_STEP_S * 2)
    finally:
        installed = not _nothing_installed(Path(env["HOME"]))
        os.close(master)
        if proc.poll() is None:  # pragma: no cover — only on an unexpected hang
            proc.kill()
            proc.wait(timeout=10)
        # If a regression DID install the service, remove it before the failing
        # assertion runs: otherwise a real login item / user unit outlives the
        # test on the developer's machine or runner (it happened once, during a
        # mutation check of this very file).
        subprocess.run(  # noqa: S603
            [str(_worthless_bin()), "service", "uninstall", "--yes"],
            env=env,
            capture_output=True,
            timeout=60,
        )
        subprocess.run(  # noqa: S603 — stop the proxy plain `worthless` started
            [str(_worthless_bin()), "down"], env=env, capture_output=True, timeout=30
        )
    return seen.decode(errors="replace").replace("\r", ""), installed


def _nothing_installed(home: Path) -> bool:
    return (
        not (home / "Library/LaunchAgents/sh.worthless.proxy.plist").exists()
        and not (home / ".config/systemd/user/worthless-proxy.service").exists()
    )


@pytest.mark.parametrize("answer", [b"n\n", b"\n"], ids=["typed-n", "bare-enter"])
def test_plain_worthless_asks_explicitly_and_declining_installs_nothing(
    tmp_path: Path, answer: bytes
) -> None:
    _home, project, env = _setup(tmp_path)
    text, installed = _run([], project, env, {b"Lock these keys?": b"y\n", _QUESTION: answer})

    assert "Install the background service on port" in text, (
        f"plain `worthless` never asked about the background service:\n{text}"
    )
    assert "What it adds:" in text
    assert "fernet.key" in text, "the master-key trade-off must be in the question"
    assert "worthless service uninstall (the key file stays)" in text
    assert "Say no" in text
    if sys.platform == "darwin":
        assert "macOS login item" in text
    else:
        assert "lingering" in text, "Linux must be told about lingering before answering"
        assert "loginctl disable-linger" in text
    assert not installed, "declining (or just pressing Enter) must install nothing"


def test_plain_worthless_yes_never_asks_and_installs_nothing(tmp_path: Path) -> None:
    """`worthless --yes` is documented as 'never service install'."""
    _home, project, env = _setup(tmp_path)
    text, installed = _run(["--yes"], project, env, {})

    assert "Lock" in text or "protected" in text, f"--yes did not run the lock at all:\n{text}"
    assert "Install the background service on port" not in text, text
    assert not installed
