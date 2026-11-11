"""Installing Worthless over an affected websockets, pydantic or opentelemetry-api
upgrades it (#765).

test_dependency_audit_gate.py checks the floors as written in pyproject.toml.
This checks what a user gets: build the real wheel, put the affected releases
in a fresh venv, install Worthless (with the mcp extra) on top with uv, and
read what is installed afterwards. On Python 3.10 websockets has no fixed
release, so there it must stay where it was.

Offline apart from the wheel build's own backend: every requirement resolves
from empty stub wheels made here, so no real package is downloaded.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

REPO = Path(__file__).resolve().parent.parent

# Affected release -> the release with the fix.
AFFECTED = {"websockets": ("17.3", "17.4"), "pydantic": ("2.14.1", "2.14.3")}
if sys.version_info < (3, 11):
    AFFECTED["websockets"] = ("16.1.1", "16.1.1")
MCP_AFFECTED = {"opentelemetry-api": ("1.45.1", "1.45.2")}


def _uv(*args: str) -> str:
    uv = shutil.which("uv")
    assert uv, "uv is not on PATH; this repo's tests run under `uv run`"
    env = {k: v for k, v in os.environ.items() if not k.startswith("UV_") or k == "UV_CACHE_DIR"}
    done = subprocess.run([uv, *args], capture_output=True, text=True, env=env, check=False)
    assert done.returncode == 0, f"uv {' '.join(args)} failed:\n{done.stderr}"
    return done.stdout


def _stub_wheel(dist: Path, name: str, version: str) -> None:
    stem = f"{canonicalize_name(name).replace('-', '_')}-{version}"
    files = {
        f"{stem}.dist-info/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        f"{stem}.dist-info/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = [
        f"{path},sha256={base64.urlsafe_b64encode(hashlib.sha256(body.encode()).digest()).rstrip(b'=').decode()},{len(body)}"
        for path, body in files.items()
    ]
    files[f"{stem}.dist-info/RECORD"] = "\n".join([*record, f"{stem}.dist-info/RECORD,,"]) + "\n"
    with zipfile.ZipFile(dist / f"{stem}-py3-none-any.whl", "w") as whl:
        for path, body in files.items():
            whl.writestr(path, body)


def _lowest_allowed(req: Requirement) -> str:
    floors = [Version(spec.version) for spec in req.specifier if spec.operator in (">=", "==")]
    return str(max(floors, default=Version("1.0")))


def _requires_dist(wheel: Path) -> list[Requirement]:
    with zipfile.ZipFile(wheel) as whl:
        meta = next(n for n in whl.namelist() if n.endswith(".dist-info/METADATA"))
        lines = whl.read(meta).decode().splitlines()
    return [
        Requirement(line.split(":", 1)[1]) for line in lines if line.startswith("Requires-Dist:")
    ]


@pytest.fixture(scope="module")
def installed(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    tmp = tmp_path_factory.mktemp("install")
    source = tmp / "source"
    shutil.copytree(
        REPO / "src", source / "src", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info")
    )
    for name in ("pyproject.toml", "README.md"):
        shutil.copy2(REPO / name, source / name)
    _uv("build", "--wheel", "--out-dir", str(tmp / "dist"), str(source))
    (wheel,) = (tmp / "dist").glob("worthless-*.whl")

    stubs = tmp / "stubs"
    stubs.mkdir()
    env = default_environment()
    for req in _requires_dist(wheel):
        if req.marker is None or req.marker.evaluate({**env, "extra": "mcp"}):
            _stub_wheel(stubs, req.name, _lowest_allowed(req))
    for name, versions in {**AFFECTED, **MCP_AFFECTED}.items():
        for version in versions:
            _stub_wheel(stubs, name, version)

    venv = tmp / "venv"
    _uv("venv", "--python", sys.executable, str(venv))
    python = str(venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
    offline = ("--python", python, "--no-index", "--find-links", str(stubs))
    before = [f"{name}=={versions[0]}" for name, versions in {**AFFECTED, **MCP_AFFECTED}.items()]
    _uv("pip", "install", *offline, *before)
    _uv("pip", "install", *offline, f"worthless[mcp] @ {wheel.as_uri()}")
    listed = json.loads(_uv("pip", "list", "--python", python, "--format", "json"))
    return {canonicalize_name(pkg["name"]): pkg["version"] for pkg in listed}


@pytest.mark.parametrize("name", sorted({**AFFECTED, **MCP_AFFECTED}))
def test_install_leaves_no_affected_release(installed: dict[str, str], name: str) -> None:
    affected, fixed = {**AFFECTED, **MCP_AFFECTED}[name]
    assert "worthless" in installed
    assert installed[name] == fixed, f"{name} {affected} was left at {installed[name]}"
