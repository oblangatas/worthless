"""kill -9 on ``worthless up`` or ``wrap`` leaves nothing behind (worthless-dhfn, yfxm).

Real CLI, real proxy, real sidecar, in a temp HOME with the null keyring. No
API key: ``wrap`` gets a fake one locked first. ``real_ipc`` so CI runs these
in its serial real-process lane.
"""

from __future__ import annotations

import os
import secrets
import shutil
import signal
import socket
import string
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

import psutil
import pytest

from worthless.cli.process import poll_health

# No reruns: these prove timing claims, and a silent second try would hide a real miss.
pytestmark = [pytest.mark.real_ipc, pytest.mark.timeout(90), pytest.mark.flaky(reruns=0)]

_CLI = [str(Path(sys.executable).with_name("worthless"))]


@pytest.fixture
def sandbox() -> Iterator[tuple[Path, dict[str, str]]]:
    """Temp HOME + WORTHLESS_HOME; short path for the AF_UNIX limit."""
    home = Path(tempfile.mkdtemp(prefix="wc-", dir="/tmp"))
    (home / "h").mkdir()
    env = {
        **os.environ,
        "HOME": str(home / "h"),
        "WORTHLESS_HOME": str(home / "w"),
        "WORTHLESS_KEYRING_BACKEND": "null",
    }
    try:
        yield home, env
    finally:
        subprocess.run([*_CLI, "down"], env=env, capture_output=True, timeout=30)
        shutil.rmtree(home, ignore_errors=True)


def _children(pid: int) -> dict[str, psutil.Process]:
    kids: dict[str, psutil.Process] = {}
    for c in psutil.Process(pid).children():
        cmd = " ".join(c.cmdline())
        if "worthless.sidecar" in cmd:
            kids["sidecar"] = c
        elif "uvicorn" in cmd:
            kids["proxy"] = c
    return kids


def _wait_gone(path: Path, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while path.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    return not path.exists()


def _kill_all(*procs: psutil.Process | subprocess.Popen | None) -> None:
    for p in procs:
        if p is None:
            continue
        try:
            p.kill()
        except (psutil.NoSuchProcess, ProcessLookupError):
            pass


def test_kill_9_on_up_takes_the_proxy_sidecar_and_shares_with_it(
    sandbox: tuple[Path, dict[str, str]],
) -> None:
    home, env = sandbox
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    sup = subprocess.Popen(
        [*_CLI, "up", "--port", str(port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    kids: dict[str, psutil.Process] = {}
    try:
        assert poll_health(port, timeout=30.0), "worthless up never became healthy"
        kids = _children(sup.pid)
        run_dir = home / "w" / "run" / str(sup.pid)
        assert (run_dir / "share_a.bin").exists()

        sup.send_signal(signal.SIGKILL)
        sup.wait(timeout=5)

        # dhfn: the sidecar wipes the shares within one 0.5s poll.
        assert _wait_gone(run_dir, 2.0), f"shares left behind: {sorted(run_dir.iterdir())}"
        # yfxm: the proxy sees its liveness pipe close and frees the port.
        kids["proxy"].wait(timeout=2)
        assert not poll_health(port, timeout=0.5), "the port still answers after up died"
        # ...and drops proxy.pid, so `down` can't later kill a reused pid.
        assert not (home / "w" / "proxy.pid").exists(), "stale proxy.pid left behind"
        kids["sidecar"].wait(timeout=8)  # CHANGELOG: "less than 8 seconds"
    finally:
        _kill_all(sup, *kids.values())


def test_kill_9_on_wrap_takes_its_proxy_with_it(sandbox: tuple[Path, dict[str, str]]) -> None:
    home, env = sandbox
    proj = home / "proj"
    proj.mkdir()
    fake = "sk-proj-" + "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(64)
    )
    (proj / ".env").write_text(f"OPENAI_API_KEY={fake}\n")
    lock = subprocess.run(
        [*_CLI, "lock", "--env", ".env"],
        cwd=proj,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert lock.returncode == 0, lock.stdout + lock.stderr
    subprocess.run([*_CLI, "down"], env=env, capture_output=True, timeout=30)

    marker = f"wc-child-{secrets.token_hex(4)}"
    wrap = subprocess.Popen(
        [*_CLI, "wrap", "--", sys.executable, "-c", "import time; time.sleep(60)", marker],
        cwd=proj,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    kids: dict[str, psutil.Process] = {}
    try:
        deadline = time.monotonic() + 30
        while "proxy" not in kids and time.monotonic() < deadline:
            kids = _children(wrap.pid)
            time.sleep(0.2)
        assert "proxy" in kids, "wrap never started its proxy"

        wrap.send_signal(signal.SIGKILL)
        wrap.wait(timeout=5)

        kids["proxy"].wait(timeout=2)
    finally:
        _kill_all(wrap, *kids.values())
        for p in psutil.process_iter(["cmdline"]):  # wrap's orphaned child
            if marker in (p.info["cmdline"] or []):
                _kill_all(p)
