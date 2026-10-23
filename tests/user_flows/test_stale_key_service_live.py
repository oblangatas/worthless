"""A stale key never makes the background service look healthy (worthless-saaz).

Reproduced live before the fix: restore ``~/.worthless`` from a backup (or lock
with ``WORTHLESS_FERNET_KEY`` set to another key) and the service started with
a ``fernet.key`` that opens none of the locked keys. ``/healthz`` said 200 while
every request got a silent 401 — the same answer as a wrong client key.

Everything here is real except the provider: the ``worthless`` console script
as its own process, a real ``lock``, real HTTP, and ``up`` under
``WORTHLESS_SERVICE_MANAGED=1`` — exactly what launchd/systemd run. The
provider answers 200 only for the exact original key, so a 200 proves the key
was rebuilt correctly, not just that something answered.
"""

from __future__ import annotations

import http.server
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from tests.helpers import fake_key, seal_enrolled

_TIMEOUT_BUDGET = 90 if os.environ.get("WORTHLESS_TEST_BIN") else 60
pytestmark = [
    pytest.mark.user_flow,
    pytest.mark.wheel_artifact,
    pytest.mark.timeout(_TIMEOUT_BUDGET),
]


def _real_key(project: str) -> str:
    # High-entropy, or lock's scanner skips it as a placeholder and locks nothing —
    # which would make every assertion below pass vacuously. One per project, or
    # the second lock is a re-lock of the same key, a different code path.
    return fake_key("sk-live-", seed=f"saaz-live-{project}")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _ExactKeyProvider(http.server.BaseHTTPRequestHandler):
    issued: set[str] = set()  # the real keys the projects hold

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        self.rfile.read(int(self.headers.get("content-length") or 0))
        auth = self.headers.get("authorization", "")
        ok = auth.startswith("Bearer ") and auth[7:] in type(self).issued
        body = json.dumps(
            {"id": "x", "choices": [], "usage": {"prompt_tokens": 1, "completion_tokens": 1}}
            if ok
            else {"error": {"message": "invalid key"}}
        ).encode()
        self.send_response(200 if ok else 401)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # noqa: A003
        return


def _worthless_bin() -> Path:
    override = os.environ.get("WORTHLESS_TEST_BIN")
    return Path(override) if override else Path(sys.executable).parent / "worthless"


class _World:
    """One sandboxed user: HOME, WORTHLESS_HOME, a fake provider, a proxy port."""

    def __init__(self, tmp_path: Path) -> None:
        self.bin = _worthless_bin()
        if not self.bin.exists():  # pragma: no cover — depends on how the venv was built
            pytest.skip(f"no worthless console script at {self.bin}")
        self.upstream_port = _free_port()
        self.port = _free_port()
        self.upstream = http.server.HTTPServer(("127.0.0.1", self.upstream_port), _ExactKeyProvider)
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        self.home = tmp_path / "home"
        self.wl = self.home / ".worthless"
        self.wl.mkdir(parents=True)
        (self.wl / "providers.toml").write_text(
            f'[provider.localmock]\nurl = "http://127.0.0.1:{self.upstream_port}/v1"\n'
            'protocol = "openai"\n',
            encoding="utf-8",
        )
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("WORTHLESS_")}
        self.env.update(
            {
                "HOME": str(self.home),
                "WORTHLESS_HOME": str(self.wl),
                "WORTHLESS_KEYRING_BACKEND": "null",
                "WORTHLESS_PORT": str(self.port),
                "NO_COLOR": "1",
            }
        )
        self.procs: list[subprocess.Popen] = []

    def project(self, name: str) -> Path:
        env_file = self.home / name / ".env"
        env_file.parent.mkdir()
        key = _real_key(name)
        _ExactKeyProvider.issued.add(key)
        env_file.write_text(
            f"LOCALMOCK_API_KEY={key}\n"
            f"LOCALMOCK_BASE_URL=http://127.0.0.1:{self.upstream_port}/v1\n",
            encoding="utf-8",
        )
        return env_file

    def run(self, *args: str, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(  # noqa: S603
            [str(self.bin), *args],
            env={**self.env, **extra},
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_BUDGET / 2,
            check=False,
            stdin=subprocess.DEVNULL,
        )

    def lock(self, env_file: Path, **extra: str) -> subprocess.CompletedProcess:
        return self.run("lock", "--env", str(env_file), "--adopt", **extra)

    def start_service(self, log: Path) -> subprocess.Popen:
        """`worthless up` the way the launchd/systemd unit runs it."""
        proc = subprocess.Popen(  # noqa: S603
            [str(self.bin), "up", "--port", str(self.port)],
            env={**self.env, "WORTHLESS_SERVICE_MANAGED": "1"},
            stdout=log.open("w"),
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
        )
        self.procs.append(proc)
        return proc

    def healthz(self, within: float) -> bool:
        deadline = time.monotonic() + within
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(  # noqa: S310 — fixed loopback URL
                    f"http://127.0.0.1:{self.port}/healthz", timeout=1
                ) as resp:
                    return resp.status == 200
            except Exception:  # noqa: BLE001 — not up yet
                time.sleep(0.25)
        return False

    def chat(self, env_file: Path) -> int:
        lines = dict(ln.split("=", 1) for ln in env_file.read_text().splitlines() if "=" in ln)
        req = urllib.request.Request(  # noqa: S310 — fixed loopback URL
            lines["LOCALMOCK_BASE_URL"].strip().rstrip("/") + "/chat/completions",
            data=b'{"model":"m","messages":[{"role":"user","content":"hi"}]}',
            headers={
                "Authorization": f"Bearer {lines['LOCALMOCK_API_KEY'].strip()}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                return int(resp.status)
        except urllib.error.HTTPError as exc:
            return int(exc.code)

    def close(self) -> None:
        self.upstream.shutdown()
        for proc in self.procs:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:  # pragma: no cover
                    proc.kill()
        self.run("down")


@pytest.fixture
def world(tmp_path: Path):
    w = _World(tmp_path)
    try:
        yield w
    finally:
        w.close()


def _said(text: str) -> str:
    return " ".join(text.split())  # the console wraps long lines


def test_a_healthy_service_serves_real_requests(world: _World, tmp_path: Path) -> None:
    """The control: the fix must not break the path that works."""
    proj = world.project("proj1")
    assert world.lock(proj).returncode == 0
    assert _real_key("proj1") not in proj.read_text(), "lock must actually have locked the key"
    world.start_service(tmp_path / "up.log")
    assert world.healthz(within=30), (tmp_path / "up.log").read_text()
    assert world.chat(proj) == 200


def test_a_restored_stale_key_is_refused_loudly_then_heals_when_fixed(
    world: _World, tmp_path: Path
) -> None:
    proj = world.project("proj1")
    assert world.lock(proj).returncode == 0
    assert _real_key("proj1") not in proj.read_text(), "lock must actually have locked the key"
    # The restored backup: a fernet.key that didn't seal these keys.
    key_file = world.wl / "fernet.key"
    good_key = key_file.read_bytes()
    stale_key = Fernet.generate_key()
    key_file.write_bytes(stale_key)
    key_file.chmod(0o600)

    log = tmp_path / "up.log"
    service = world.start_service(log)
    assert not world.healthz(within=8), "a stale key must never answer /healthz"
    said = _said(log.read_text())
    assert "can't unlock any of your 1 locked key" in said, said
    assert "worthless doctor --explain fernet_drift" in said
    assert service.poll() is None, "it must wait, not exit — or launchd/systemd restart-loop it"
    assert said.count("can't unlock any") == 1, "logged once, not on a loop"

    doctor = world.run("doctor", "--json")
    drift = next(c for c in json.loads(doctor.stdout)["checks"] if c["check_id"] == "fernet_drift")
    assert drift["status"] == "error"
    assert len(drift["findings"][0]["cannot_unlock"]) == 1
    plain = _said(world.run("doctor").stdout)
    assert "can't unlock" in plain and "No issues found" not in plain

    # Fix the key: the waiting service exits on its own so its manager restarts it.
    key_file.write_bytes(good_key)
    assert service.wait(timeout=25) == 75, "75 = restart me on the new key"

    key_file.write_bytes(stale_key)
    you = world.run("up", "--port", str(world.port))
    assert you.returncode != 0
    assert "can't unlock any" in _said(you.stdout + you.stderr)


def test_a_different_key_in_the_shell_cannot_lock_and_breaks_nothing(
    world: _World, tmp_path: Path
) -> None:
    first = world.project("proj1")
    assert world.lock(first).returncode == 0
    assert _real_key("proj1") not in first.read_text(), "lock must actually have locked the key"

    second = world.project("proj2")
    before = second.read_bytes()
    refused = world.lock(second, WORTHLESS_FERNET_KEY=Fernet.generate_key().decode())
    assert refused.returncode != 0
    assert "WORTHLESS_FERNET_KEY" in _said(refused.stdout + refused.stderr)
    assert second.read_bytes() == before, "a refused lock leaves the .env untouched"

    world.start_service(tmp_path / "up.log")
    assert world.healthz(within=30), (tmp_path / "up.log").read_text()
    assert world.chat(first) == 200


def test_a_key_that_opens_only_some_projects_serves_them_and_names_the_rest(
    world: _World, tmp_path: Path
) -> None:
    """`lock` now refuses to build this mix, but a backup merge still can: one
    project sealed under a key the service doesn't hold."""
    work = world.project("proj1")
    assert world.lock(work).returncode == 0
    seal_enrolled(world.wl / "worthless.db", Fernet.generate_key(), "side-project")

    log = tmp_path / "up.log"
    world.start_service(log)
    assert world.healthz(within=30), log.read_text()
    assert world.chat(work) == 200, "the project the key opens keeps working"
    said = _said(log.read_text())
    assert "can't unlock: side-project" in said, said

    plain = _said(world.run("doctor").stdout)
    assert "side-project" in plain and "can't unlock" in plain
