"""Nothing worthless ships can export request telemetry off the machine.

fastapi >= 0.142 instruments every request through ``opentelemetry-api``. With
the API alone that is a no-op: the provider stays ``ProxyTracerProvider`` and
nothing leaves the process. It becomes real the moment an OpenTelemetry SDK,
exporter, distro or auto-instrumentation package is installed alongside it —
then request metadata can be shipped to whatever ``OTEL_EXPORTER_*`` points at,
which breaks the logging denylist (no prompt content, no raw IPs). worthless-3jjl.

This is the SECOND layer. The first is the proxy switching fastapi telemetry
off itself (tests/test_proxy_emits_no_telemetry.py), which holds whatever is
installed. This one pins the locked tree (runtime plus every extra) — what CI
and ``uv sync`` install. The Docker image (``pip install .``) and ``uv tool
install`` resolve without the lock, so they rely on the first layer.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Packages that turn the no-op API into something that records or sends data.
# ddtrace ships its own OpenTelemetry TracerProvider without opentelemetry-sdk.
_EXPORTING = re.compile(
    r"^(opentelemetry-(sdk|distro|exporter-[\w-]+|instrumentation[\w-]*)"
    r"|opentelemetry_(sdk|distro)|ddtrace)$"
)


def _shipped_packages() -> set[str]:
    out = subprocess.run(  # noqa: S603
        [  # noqa: S607 — `uv` from PATH, as every other uv-invoking test here
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--all-extras",
            "--no-hashes",
            "--no-emit-project",
            "--format",
            "requirements-txt",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {
        re.split(r"[=<>~!;\s\[]", line, maxsplit=1)[0].lower()
        for line in out.splitlines()
        if line and not line.startswith(("#", " ", "-"))
    }


def test_the_shipped_tree_is_readable() -> None:
    """Guard the guard: an empty export would make the real test pass vacuously."""
    shipped = _shipped_packages()
    assert {"fastapi", "cryptography", "httpx"} <= shipped, sorted(shipped)


def test_no_opentelemetry_sdk_or_exporter_ships() -> None:
    offenders = sorted(p for p in _shipped_packages() if _EXPORTING.match(p))
    assert not offenders, (
        "an OpenTelemetry SDK/exporter would ship with worthless, turning fastapi's "
        f"request instrumentation into real telemetry that can leave the machine: {offenders}"
    )
