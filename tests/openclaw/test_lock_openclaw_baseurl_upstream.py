"""WOR-834 — ``worthless lock`` routes the upstream to the provider's
OpenClaw ``baseUrl`` for unregistered (Azure / enterprise / self-hosted)
gateways, behind a lock-time safety guard.

Before this fix, ``_resolve_upstream_base_url`` only consulted the ``.env
*_BASE_URL`` (accepted only if registered) and a registry-lookup-by-name.
An Azure/custom gateway is in neither, so the key was routed to the
``https://api.openai.com/v1`` fallback — wrong upstream, 401 on every
request. The gateway URL DID live in openclaw.json but lock threw it away.

These tests pin:

* the guard's accept/reject contract directly (incl. the honest limit that a
  plausible public URL still passes — a lock-time check can't tell it from a
  real gateway);
* at the CLI surface, a genuine gateway ``baseUrl`` becomes the stored
  upstream (``enc.base_url``);
* at the CLI surface, a dangerous ``baseUrl`` (cleartext / private-IP /
  metadata) is REFUSED — the locally-writable file can't silently redirect a
  live key.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.lock import _validate_upstream_base_url
from worthless.cli.errors import WorthlessError
from worthless.storage.repository import ShardRepository

from tests.helpers import fake_openai_key

runner = CliRunner()

# A real-shaped Azure OpenAI v1 endpoint — NOT in the bundled registry.
AZURE_URL = "https://my-corp.openai.azure.com/openai/v1"


@pytest.fixture
def fixed_key() -> str:
    return fake_openai_key()


@pytest.fixture
def env_file(tmp_path: Path, fixed_key: str) -> Path:
    env = tmp_path / ".env"
    # Deliberately NO OPENAI_BASE_URL — force the openclaw/registry path.
    env.write_text(f"OPENAI_API_KEY={fixed_key}\n")
    return env


@pytest.fixture
def sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pin HOME so lock's detect() probes the sandbox openclaw.json."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(home)
    return home


def _seed_openclaw(sandboxed_home: Path, openai_entry: dict) -> Path:
    """Pre-stage ~/.openclaw/ with a workspace + an ``openai`` provider entry."""
    openclaw_dir = sandboxed_home / ".openclaw"
    (openclaw_dir / "workspace").mkdir(parents=True)
    config_path = openclaw_dir / "openclaw.json"
    config_path.write_text(
        json.dumps({"models": {"providers": {"openai": openai_entry}}}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return config_path


def _alias_for_key(provider: str, value: str) -> str:
    """Mirror lock._make_alias so tests can find the DB row without CLI scraping."""
    digest = hashlib.sha256(bytearray(value.encode())).hexdigest()[:8]
    return f"{provider}-{digest}"


def _base_url(home: WorthlessHome, alias: str) -> str | None:
    async def _run() -> str | None:
        repo = ShardRepository(str(home.db_path), home.fernet_key)
        enc = await repo.fetch_encrypted(alias)
        return enc.base_url if enc is not None else None

    return asyncio.run(_run())


@pytest.mark.parametrize(
    "url",
    [
        "https://my-corp.openai.azure.com/openai/v1",  # real Azure gateway
        "https://generativelanguage.googleapis.com/v1",  # Gemini
        "https://8.8.8.8/v1",  # public IP literal
        "https://evil.com/v1",  # HONEST LIMIT: a plausible public URL passes
    ],
)
def test_validate_upstream_accepts_safe_urls(url: str) -> None:
    _validate_upstream_base_url(url)  # must not raise


@pytest.mark.parametrize(
    "url",
    [
        "http://my-corp.openai.azure.com/v1",  # cleartext
        "https://user:pass@evil.com/v1",  # userinfo
        "https://127.0.0.1/v1",  # loopback
        "https://localhost/v1",  # loopback name
        "https://169.254.169.254/latest/meta-data",  # cloud metadata
        "https://10.0.0.5/v1",  # RFC1918
        "https://192.168.1.10/v1",  # RFC1918
        "https://172.16.5.5/v1",  # RFC1918
        "https://0.0.0.0/v1",  # unspecified
        "https://[::1]/v1",  # IPv6 loopback
        "https://[fd00::1]/v1",  # IPv6 ULA (private)
        "https://[::ffff:169.254.169.254]/v1",  # IPv4-mapped metadata
        "https://127.0.0.1./v1",  # trailing-dot loopback bypass
        "https://169.254.169.254./v1",  # trailing-dot metadata bypass
        "https://2852039166/v1",  # decimal-int encoding of 169.254.169.254
        "https://0xA9.0xFE.0xA9.0xFE/v1",  # hex-octet encoding
        "https://127.1/v1",  # short-form loopback
        "https://[0:0:0:0:0:ffff:a9fe:a9fe]/v1",  # expanded IPv4-mapped metadata
        "https://[::ffff:127.0.0.1]/v1",  # IPv4-mapped loopback
        "https://[64:ff9b::a9fe:a9fe]/v1",  # NAT64-embedded metadata
        "https://[::]/v1",  # IPv6 unspecified
        "https://100.64.0.1/v1",  # RFC6598 CGNAT / shared address space
        "https://100.100.100.200/v1",  # Alibaba Cloud metadata (lives in CGNAT)
    ],
)
def test_validate_upstream_rejects_dangerous_urls(url: str) -> None:
    with pytest.raises(WorthlessError):
        _validate_upstream_base_url(url)


def test_lock_routes_to_openclaw_baseurl_for_unregistered_gateway(
    home_dir: WorthlessHome, env_file: Path, sandboxed_home: Path, fixed_key: str
) -> None:
    """The AC: an Azure gateway URL from openclaw.json becomes the stored
    upstream, instead of the ``api.openai.com`` fallback."""
    _seed_openclaw(sandboxed_home, {"baseUrl": AZURE_URL, "apiKey": fixed_key})

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir), "WORTHLESS_KEYRING_BACKEND": "null"},
    )
    assert result.exit_code == 0, result.output

    alias = _alias_for_key("openai", fixed_key)
    assert _base_url(home_dir, alias) == AZURE_URL, (
        "openclaw gateway baseUrl must be routed as the upstream — "
        "not the api.openai.com fallback (the proxy would 401)."
    )


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://my-corp.openai.azure.com/openai/v1",  # cleartext — key on the wire
        "https://10.0.0.5/v1",  # RFC1918 private
        "https://169.254.169.254/v1",  # cloud metadata (link-local)
    ],
)
def test_lock_refuses_dangerous_openclaw_baseurl(
    home_dir: WorthlessHome, env_file: Path, sandboxed_home: Path, fixed_key: str, bad_url: str
) -> None:
    """A dangerous gateway URL is refused fail-closed — the lock aborts and
    nothing is enrolled (never silently rerouted to OpenAI)."""
    _seed_openclaw(sandboxed_home, {"baseUrl": bad_url, "apiKey": fixed_key})

    result = runner.invoke(
        app,
        ["lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir), "WORTHLESS_KEYRING_BACKEND": "null"},
    )
    assert result.exit_code != 0, f"dangerous baseUrl {bad_url!r} must be refused, got exit 0"

    alias = _alias_for_key("openai", fixed_key)
    assert _base_url(home_dir, alias) is None, (
        "nothing must be enrolled when the gateway is refused"
    )
