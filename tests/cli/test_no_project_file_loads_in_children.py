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

import subprocess
import sys
from importlib.metadata import version as pkg_version
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import worthless
from worthless.cli import process, sidecar_lifecycle
from worthless.cli.commands import up
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


def test_the_cwd_is_not_changed(cloned_repo: Path) -> None:
    """Relative WORTHLESS_HOME / key paths must still resolve where they did."""
    argv = python_module_argv("worthless", "--version")
    assert argv[0] == sys.executable
    code = argv[argv.index("-c") + 1]
    assert "chdir" not in code


def test_the_proxy_child_uses_it() -> None:
    assert process.proxy_cmd(8787)[:4] == python_module_argv("uvicorn")


def test_uvicorn_does_not_put_the_project_back_on_the_path() -> None:
    """uvicorn's --app-dir defaults to "" (the cwd) and it inserts that at
    sys.path[0] itself, after our boot removed it. Found live: a planted
    secrets.py loaded inside the proxy that receives the Fernet key."""
    cmd = process.proxy_cmd(8787)
    app_dir = cmd[cmd.index("--app-dir") + 1]
    assert app_dir == str(Path(worthless.__file__).resolve().parent.parent)


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


def test_the_default_commands_proxy_uses_it(tmp_path: Path) -> None:
    seen: dict = {}

    def capture(argv, **kwargs):
        seen.update(argv=argv, cwd=kwargs.get("cwd"))
        return MagicMock(pid=1)

    home = MagicMock(base_dir=tmp_path)
    with (
        patch.object(up.subprocess, "Popen", capture),
        patch.object(up, "poll_health_pid", return_value=42),
        patch.object(up.os, "open", return_value=3),
        patch.object(up.os, "close"),
    ):
        up.start_supervised_proxy(home, 8787, tmp_path / "proxy.log", MagicMock())
    assert seen["argv"] == python_module_argv("worthless", "up", "--port", "8787")
