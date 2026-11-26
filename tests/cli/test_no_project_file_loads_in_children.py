"""No file in the user's project ever loads inside a worthless child process.

``python -m`` (and ``-c``) put the current folder first on ``sys.path``, and
worthless runs in the user's project. A cloned repo with a ``json.py``, a
``secrets.py`` or its own ``worthless/`` package was imported by the proxy
(which receives the Fernet key) or the sidecar (which holds the shares):
worthless-x31h2, found by the PR #767 security review and Brutus.

The cwd is left alone on purpose: ``WORTHLESS_HOME`` and
``WORTHLESS_FERNET_KEY_PATH`` may be relative to it.
"""

from __future__ import annotations

import socket
import subprocess
import os
import sys
from importlib.metadata import version as pkg_version
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from worthless.cli import process, sidecar_lifecycle
from worthless.cli.platform import python_module_argv

_PLANTED = "open('HIJACKED', 'w').write(__name__)\nraise SystemExit(3)\n"


@pytest.fixture
def cloned_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = tmp_path / "cloned-repo"
    (repo / "worthless").mkdir(parents=True)
    (repo / "worthless" / "__init__.py").write_text(_PLANTED)
    for name in ("json", "secrets", "logging", "runpy", "worthless/__main__"):
        (repo / f"{name}.py").write_text(_PLANTED)
    monkeypatch.chdir(repo)
    return repo


def test_a_child_started_in_a_hostile_project_runs_the_real_worthless(cloned_repo: Path) -> None:
    out = subprocess.run(
        python_module_argv("worthless", "--version"),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert not (cloned_repo / "HIJACKED").exists(), (cloned_repo / "HIJACKED").read_text()
    assert out.returncode == 0, out.stderr
    assert out.stdout.split()[-1] == pkg_version("worthless")


def test_a_project_pythonpath_cannot_bring_the_folder_back(
    cloned_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A project's .envrc can set PYTHONPATH=. — the child inherits it, and it
    lands on sys.path before the boot runs (PR #813 security review)."""
    monkeypatch.setenv("PYTHONPATH", ".:")
    out = subprocess.run(
        python_module_argv("worthless", "--version"),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert not (cloned_repo / "HIJACKED").exists(), (cloned_repo / "HIJACKED").read_text()
    assert out.returncode == 0, out.stderr


def test_the_real_proxy_command_ignores_the_project(cloned_repo: Path) -> None:
    """uvicorn re-inserts its --app-dir itself; run the real proxy argv and see.
    Mutation: drop --app-dir from proxy_cmd -> the planted secrets.py runs."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(
        process.proxy_cmd(port),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        pass  # still running (or stuck in startup) without having imported the plant
    finally:
        proc.kill()
        proc.wait()
    assert not (cloned_repo / "HIJACKED").exists(), (cloned_repo / "HIJACKED").read_text()


def test_the_proxy_child_uses_it() -> None:
    assert process.proxy_cmd(8787)[:5] == python_module_argv("uvicorn")


def test_uvicorn_does_not_put_the_project_back_on_the_path() -> None:
    """uvicorn's --app-dir defaults to "" (the cwd) and it inserts that at
    sys.path[0] itself, after our boot removed it. Found live: a planted
    secrets.py loaded inside the proxy that receives the Fernet key."""
    cmd = process.proxy_cmd(8787)
    app_dir = cmd[cmd.index("--app-dir") + 1]
    assert app_dir == str(Path(os.__file__).parent)
    assert app_dir in sys.path, "uvicorn's insert must only repeat an existing entry"


def test_the_sidecar_child_uses_it(tmp_path: Path) -> None:
    seen: dict = {}

    def stop(argv, **kwargs):
        seen["argv"] = argv
        raise RuntimeError("captured")

    with (
        patch.object(sidecar_lifecycle.subprocess, "Popen", side_effect=stop),
        pytest.raises(RuntimeError, match="captured"),
    ):
        sidecar_lifecycle.spawn_sidecar(tmp_path / "s.sock", MagicMock(), allowed_uid=0)
    assert seen["argv"] == python_module_argv("worthless.sidecar")
