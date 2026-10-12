"""WOR-859: plain `worthless` asks the explicit service question at a real terminal.

The unit tests mock the prompt. This drives the real console script on a real
PTY, the way a person types: "y" to lock, "n" to the service. It proves the
question a user actually sees names what it adds, the key-file trade-off and
the undo, and that answering "n" leaves nothing at login.

Before PR #673 this fails at the first assertion: plain `worthless` locked
quietly and never asked.
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

pytestmark = [
    pytest.mark.user_flow,
    pytest.mark.wheel_artifact,
    pytest.mark.timeout(90),
    pytest.mark.skipif(
        Path("/.dockerenv").exists() or Path("/run/.containerenv").exists(),
        reason="inside a container the question is deliberately skipped",
    ),
]

_STEP_S = 30


def _worthless_bin() -> Path:
    """The branch build, or WORTHLESS_TEST_BIN to aim at an installed wheel."""
    override = os.environ.get("WORTHLESS_TEST_BIN")
    return Path(override) if override else Path(sys.executable).parent / "worthless"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _person_at_a_terminal_env(home: Path, port: int) -> dict[str, str]:
    """Hermetic env. CI markers are removed: the offer treats them as 'nobody is
    watching', and the point here is to be the person who is."""
    drop = {*_CI_ENV_VARS}
    env = {k: v for k, v in os.environ.items() if not k.startswith("WORTHLESS_") and k not in drop}
    env.update(
        {
            "HOME": str(home),
            "WORTHLESS_HOME": str(home / ".worthless"),
            "WORTHLESS_KEYRING_BACKEND": "null",
            "WORTHLESS_PORT": str(port),
            "NO_COLOR": "1",
        }
    )
    return env


def _read_until(fd: int, needle: bytes, buf: bytes) -> bytes:
    deadline = time.monotonic() + _STEP_S
    while needle not in buf and time.monotonic() < deadline:
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


def test_plain_worthless_asks_explicitly_and_no_installs_nothing(tmp_path: Path) -> None:
    home = tmp_path / "home"
    project = tmp_path / "project"
    home.mkdir()
    project.mkdir()
    # Random, not a repeated pattern: lock rightly ignores low-entropy "keys".
    key = "sk-proj-" + "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(40)
    )
    (project / ".env").write_text(f"OPENAI_API_KEY={key}\n")
    port = _free_port()
    env = _person_at_a_terminal_env(home, port)

    master, slave = pty.openpty()
    proc = subprocess.Popen(  # noqa: S603
        [str(_worthless_bin())],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        cwd=project,
        env=env,
        start_new_session=True,
        close_fds=True,
    )
    os.close(slave)
    try:
        seen = _read_until(master, b"Lock these keys?", b"")
        assert b"Lock these keys?" in seen, seen.decode(errors="replace")
        os.write(master, b"y\n")

        seen = _read_until(master, b"Install the background service on port", seen)
        text = seen.decode(errors="replace").replace("\r", "")
        assert "Install the background service on port" in text, (
            f"plain `worthless` never asked about the background service:\n{text}"
        )
        assert "What it adds:" in text
        assert "starts Worthless when you log in" in text
        assert "fernet.key" in text, "the master-key trade-off must be in the question"
        assert "worthless service uninstall" in text, "the undo must be in the question"
        assert "Say no" in text
        os.write(master, b"n\n")

        proc.wait(timeout=_STEP_S * 2)
    finally:
        os.close(master)
        if proc.poll() is None:  # pragma: no cover — only on an unexpected hang
            proc.kill()
            proc.wait(timeout=10)
        subprocess.run(  # noqa: S603 — stop the proxy plain `worthless` started
            [str(_worthless_bin()), "down"], env=env, capture_output=True, timeout=30
        )

    assert not (home / "Library/LaunchAgents/sh.worthless.proxy.plist").exists()
    assert not (home / ".config/systemd/user/worthless-proxy.service").exists()
