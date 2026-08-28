"""WOR-834 — enterprise-gateway upstream, proven in a REAL OpenClaw install.

The unit/CLI tests for this feature hand-write an ``openclaw.json`` and never
run OpenClaw at all. That is not enough here, and this test exists because the
gap actually bit: the hand-written fixture shape
(``{baseUrl, apiKey}``) is **not a valid OpenClaw provider entry** — real
OpenClaw 2026.5.3 requires an ``api`` enum member and ``models`` as objects.
Against a real install, an invalid config makes ``openclaw secrets audit``
exit 2, so ``worthless lock``'s audit gate refuses **before** upstream
resolution is ever reached. A test that never boots OpenClaw cannot see that.

So this drives the real path a customer actually has:

* the REAL OpenClaw image (``Dockerfile.oc-worthless`` derives from
  ``ghcr.io/openclaw/openclaw``);
* Worthless installed the REAL way — pinned ``uv`` → ``uv tool install`` of the
  locally-built wheel, the same engine ``install.sh`` (``worthless.sh``) uses,
  but carrying THIS branch instead of whatever is on PyPI;
* a config real OpenClaw validates (``secrets audit`` exit 0);
* the real proxy up, and the real ``worthless lock`` CLI doing the rewrite.

Pinned behaviour:

1. an unregistered Azure gateway's ``baseUrl`` becomes the stored upstream
   (the WOR-834 AC) — not the ``api.openai.com`` registry fallback;
2. a RE-LOCK keeps it. After the first lock the live entry is proxy-shaped, so
   re-resolving from .env/registry silently reverted the alias to
   ``api.openai.com`` on the second lock (found in review on PR #460);
3. a gateway pointed at IPv6-mapped cloud metadata is refused fail-closed with
   nothing enrolled. ``::ffff:100.64.0.1``-style wrappers bypassed the guard on
   py3.13 only (``IPv6Address.is_private`` delegates to the embedded IPv4 from
   3.10.15/3.11.10 on, and CGNAT is not ``is_private``).

Marks: openclaw + docker (opt-in; the default addopts deselect ``docker``).
Requires the derived image to be built first::

    uv build --wheel
    docker build -f tests/openclaw/Dockerfile.oc-worthless \
        -t worthless-oc-test:local dist/
"""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from collections.abc import Iterator

import pytest

from tests._docker_helpers import docker_available

OC_WORTHLESS_IMAGE = "worthless-oc-test:local"

# A real-shaped Azure OpenAI endpoint. Deliberately NOT in the bundled
# registry — that is the whole point of WOR-834.
AZURE_URL = "https://my-corp.openai.azure.com/openai/v1"
# IPv4-mapped IPv6 form of the cloud metadata address.
METADATA_MAPPED_URL = "https://[::ffff:169.254.169.254]/v1"

_HEALTHZ = (
    "python3 -c \"import urllib.request as u;u.urlopen('http://127.0.0.1:8787/healthz',timeout=2)\""
)

# Dump every (alias, base_url) the DB holds. ``find`` rather than glob: the DB
# lives under a dot-directory and glob(**) skips those.
_DUMP_PY = r"""
import sqlite3, subprocess
rows = []
for d in subprocess.run(["find", "/home/node", "-name", "*.db"],
                        capture_output=True, text=True).stdout.split():
    try:
        c = sqlite3.connect(d)
        for tb in [r[0] for r in c.execute(
                "select name from sqlite_master where type='table'")]:
            if "base_url" in [x[1] for x in c.execute("PRAGMA table_info(%s)" % tb)]:
                rows += list(c.execute("select key_alias, base_url from %s" % tb))
    except Exception:
        pass
import json; print(json.dumps([list(r) for r in rows]))
"""


def _image_present(ref: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", ref], capture_output=True).returncode == 0


pytestmark = [
    pytest.mark.openclaw,
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker not available"),
    pytest.mark.skipif(
        not _image_present(OC_WORTHLESS_IMAGE),
        reason=f"{OC_WORTHLESS_IMAGE} not built (see module docstring)",
    ),
    pytest.mark.timeout(900),
]


def _run(args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def _sh(c: str, script: str, *, timeout: int = 180) -> subprocess.CompletedProcess:
    return _run(["docker", "exec", c, "bash", "-c", script], timeout=timeout)


def _provider_entry(provider: str, base_url: str, key: str, api: str) -> str:
    """A provider entry real OpenClaw actually accepts.

    ``api`` must be an enum member and ``models`` a list of OBJECTS — the
    hand-written ``{baseUrl, apiKey}`` shape used elsewhere is rejected as
    invalid config, which trips lock's audit gate before this feature runs.
    """
    return json.dumps(
        {
            "models": {
                "providers": {
                    provider: {
                        "baseUrl": base_url,
                        "apiKey": key,
                        "api": api,
                        "models": [{"id": "m1", "name": "Model One"}],
                    }
                }
            }
        }
    )


def _write_oc_config(container: str, payload: str) -> None:
    _sh(
        container,
        "mkdir -p ~/.openclaw/workspace && cat > ~/.openclaw/openclaw.json "
        f"<<'EOF'\n{payload}\nEOF",
    )


def _stored_upstreams(container: str) -> dict[str, str]:
    res = _sh(container, f"cat > /tmp/dump.py <<'EOF'\n{_DUMP_PY}\nEOF\npython3 /tmp/dump.py")
    return {alias: url for alias, url in json.loads(res.stdout.strip().splitlines()[-1])}


@pytest.fixture
def oc_container() -> Iterator[str]:
    name = f"wor834-{uuid.uuid4().hex[:8]}"
    _run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "-e",
            "WORTHLESS_KEYRING_BACKEND=null",
            "--entrypoint",
            "sleep",
            OC_WORTHLESS_IMAGE,
            "infinity",
        ]
    )
    try:
        yield name
    finally:
        _run(["docker", "rm", "-f", name], timeout=60)


def _start_proxy(container: str) -> None:
    # Foreground only: `up --daemon` is refused with the sidecar (WRTLS-115).
    _run(["docker", "exec", "-d", container, "bash", "-c", "worthless up > /tmp/up.log 2>&1"])
    for _ in range(40):
        if _sh(container, _HEALTHZ, timeout=20).returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError(
        f"proxy never became healthy:\n{_sh(container, 'tail -20 /tmp/up.log').stdout}"
    )


def test_enterprise_gateway_is_the_upstream_survives_relock_and_refuses_metadata(
    oc_container: str,
) -> None:
    """Real OpenClaw + real-installed Worthless: the three WOR-834 guarantees."""
    key = "sk-proj-" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    _write_oc_config(oc_container, _provider_entry("openai", AZURE_URL, key, "openai-completions"))

    # The config must be valid to real OpenClaw, else lock's audit gate refuses
    # before this feature is reached — the gap that motivated this test.
    audit = _sh(oc_container, "openclaw secrets audit; echo EXIT=$?")
    assert "EXIT=0" in audit.stdout, f"real OpenClaw rejected the config:\n{audit.stdout}"

    _start_proxy(oc_container)
    _sh(oc_container, f"mkdir -p ~/work && printf 'OPENAI_API_KEY=%s\\n' '{key}' > ~/work/.env")
    _sh(oc_container, "worthless lock --env /home/node/work/.env")

    # 1) The gateway from openclaw.json is the stored upstream.
    after_first = _stored_upstreams(oc_container)
    assert AZURE_URL in after_first.values(), (
        f"gateway baseUrl did not become the upstream; got {after_first}. "
        "The proxy would forward the reconstructed key to api.openai.com -> 401."
    )
    alias = next(a for a, u in after_first.items() if u == AZURE_URL)

    # Lock really did rewrite the live OpenClaw config to the proxy.
    rewritten = _sh(oc_container, "cat ~/.openclaw/openclaw.json").stdout
    assert "127.0.0.1:8787" in rewritten, f"lock did not rewrite openclaw.json:\n{rewritten}"

    # 2) Re-lock must KEEP the gateway. The live entry is proxy-shaped now, so
    #    the genuine URL is only recoverable from the stored row.
    _sh(oc_container, f"mkdir -p ~/work2 && printf 'OPENAI_API_KEY=%s\\n' '{key}' > ~/work2/.env")
    _sh(oc_container, "worthless lock --env /home/node/work2/.env")
    assert _stored_upstreams(oc_container).get(alias) == AZURE_URL, (
        "re-lock reset the enterprise gateway to the registry default — an "
        "Azure key would 401 against api.openai.com after a second lock."
    )

    # 3) A gateway aimed at IPv6-mapped cloud metadata is refused fail-closed.
    evil = "sk-ant-api03-" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    _write_oc_config(
        oc_container,
        _provider_entry("anthropic", METADATA_MAPPED_URL, evil, "anthropic-messages"),
    )
    _sh(
        oc_container,
        f"mkdir -p ~/work3 && printf 'ANTHROPIC_API_KEY=%s\\n' '{evil}' > ~/work3/.env",
    )
    refused = _sh(oc_container, "worthless lock --env /home/node/work3/.env 2>&1")
    assert "WRTLS-112" in refused.stdout, (
        f"metadata gateway was not refused; output:\n{refused.stdout[-800:]}"
    )
    assert not [a for a in _stored_upstreams(oc_container) if a.startswith("anthropic-")], (
        "an anthropic row was enrolled despite the refusal — a live key would "
        "be forwarded to the cloud-metadata endpoint."
    )
