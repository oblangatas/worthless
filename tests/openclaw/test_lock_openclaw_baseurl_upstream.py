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
import ipaddress
import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.lock import _upstream_host_ip, _validate_upstream_base_url
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
        # IPv4-mapped CGNAT: py>=3.10.15/3.11.10 delegate is_private to the
        # embedded IPv4, and CGNAT is NOT is_private — so the v6 wrapper slipped
        # the version==4 CGNAT check on py3.13. Regression guard for that split.
        "https://[::ffff:100.64.0.1]/v1",
        "https://[::ffff:100.100.100.200]/v1",
        # Unicode label separators. urlsplit leaves U+FF0E / U+3002 / U+FF61
        # intact, so these read as opaque DNS names and skipped every IP check
        # -- while httpx IDNA/UTS-46-normalizes them straight back to the
        # literal and connects there. Validating a different string than the
        # one we dial; found by adversarial review of PR #460.
        "https://169．254．169．254/v1",  # fullwidth full stop -> metadata
        "https://127。0。0。1/v1",  # ideographic full stop -> loopback
        "https://10．0．0．5/v1",  # fullwidth -> RFC1918
        "https://127｡0｡0｡1/v1",  # halfwidth ideographic -> loopback
        # 6to4 (RFC 3056) wrapping of 127.0.0.1. On py3.10 this is neither
        # is_private nor is_reserved, so it passed there while failing on 3.13.
        "https://[2002:7f00:1::]/v1",
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


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("::ffff:100.64.0.1", "100.64.0.1"),  # the py3.13 bypass
        ("::ffff:169.254.169.254", "169.254.169.254"),
        ("::ffff:127.0.0.1", "127.0.0.1"),
        ("0:0:0:0:0:ffff:a9fe:a9fe", "169.254.169.254"),  # expanded form
        ("64:ff9b::a9fe:a9fe", "169.254.169.254"),  # NAT64 well-known prefix
        ("::ffff:100.64.0.1.", "100.64.0.1"),  # trailing dot + mapped
        ("2002:7f00:1::", "127.0.0.1"),  # 6to4-wrapped loopback
        ("2002:a9fe:a9fe::", "169.254.169.254"),  # 6to4-wrapped metadata
    ],
)
def test_upstream_host_ip_folds_mapped_and_nat64_to_embedded_ipv4(host: str, expected: str) -> None:
    """An IPv4 address wrapped in IPv6 must classify as its embedded IPv4.

    Version-independent invariant. Relying on ``IPv6Address.is_private`` is a
    trap: pre-3.10.15 it blanket-treated ``::ffff:0:0/96`` as private, while
    3.10.15+/3.11.10+ delegate to the embedded IPv4 — so CGNAT (not
    ``is_private``) reached through the wrapper on py3.13 only. Folding to the
    embedded IPv4 before classifying makes the guard behave the same on every
    interpreter, and lets the version==4 CGNAT check actually fire.
    """
    assert _upstream_host_ip(host) == ipaddress.ip_address(expected)


def test_relock_preserves_gateway_upstream(
    home_dir: WorthlessHome,
    env_file: Path,
    sandboxed_home: Path,
    fixed_key: str,
    tmp_path: Path,
) -> None:
    """Re-locking the same key must NOT reset the gateway to the registry default.

    After the first lock, openclaw.json is proxy-shaped, so the genuine gateway
    URL is no longer readable from it. If the upstream is re-resolved from
    .env/registry at that point, an unregistered Azure gateway silently reverts
    to ``api.openai.com`` — WOR-834 all over again, on the second lock.
    """
    _seed_openclaw(sandboxed_home, {"baseUrl": AZURE_URL, "apiKey": fixed_key})
    cli_env = {"WORTHLESS_HOME": str(home_dir.base_dir), "WORTHLESS_KEYRING_BACKEND": "null"}

    first = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
    assert first.exit_code == 0, first.output

    alias = _alias_for_key("openai", fixed_key)
    assert _base_url(home_dir, alias) == AZURE_URL, "first lock must store the gateway"

    # The user pastes the original key again into a second project's .env.
    # (A re-lock of the SAME .env is refused earlier by the already-locked
    # preflight, so this is the path that actually reaches the re-lock branch.)
    proj2 = tmp_path / "proj2"
    proj2.mkdir()
    env2 = proj2 / ".env"
    env2.write_text(f"OPENAI_API_KEY={fixed_key}\n")

    second = runner.invoke(app, ["lock", "--env", str(env2)], env=cli_env)
    assert second.exit_code == 0, second.output

    assert _base_url(home_dir, alias) == AZURE_URL, (
        "re-lock reset the upstream to the registry default — the enterprise "
        "gateway key would 401 against api.openai.com after a second lock."
    )


def _tamper_stored_upstream(home: WorthlessHome, alias: str, evil_url: str) -> None:
    """Rewrite the stored upstream directly, as a local attacker would."""
    con = sqlite3.connect(str(home.db_path))
    try:
        tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
        for tb in tables:
            # Table names come from sqlite_master (our own schema), never from
            # user input — but keep the interpolation provably identifier-safe
            # rather than trusting provenance alone. Values stay parameterized.
            if not tb.isidentifier():
                continue
            cols = [c[1] for c in con.execute(f"PRAGMA table_info({tb})")]  # noqa: S608
            if "base_url" in cols and "key_alias" in cols:
                sql = f"update {tb} set base_url = ? where key_alias = ?"  # noqa: S608
                con.execute(sql, (evil_url, alias))
        con.commit()
    finally:
        con.close()


def test_relock_revalidates_carried_forward_upstream(
    home_dir: WorthlessHome, env_file: Path, sandboxed_home: Path, fixed_key: str, tmp_path: Path
) -> None:
    """A tampered stored upstream must NOT be carried forward unchecked.

    The re-lock path reuses ``db_shard.base_url`` when it is unregistered, so an
    unregistered URL is exactly the branch that skips registry validation. That
    made the DB an unvalidated persistence slot: plant a dangerous URL once (or
    de-register a URL that was registered when first stored) and every later
    lock would carry it forward, re-pointing a live key with nothing re-checking
    it. Found by adversarial review of PR #460. The guard must re-run here.
    """
    _seed_openclaw(sandboxed_home, {"baseUrl": AZURE_URL, "apiKey": fixed_key})
    cli_env = {"WORTHLESS_HOME": str(home_dir.base_dir), "WORTHLESS_KEYRING_BACKEND": "null"}

    first = runner.invoke(app, ["lock", "--env", str(env_file)], env=cli_env)
    assert first.exit_code == 0, first.output

    alias = _alias_for_key("openai", fixed_key)
    assert _base_url(home_dir, alias) == AZURE_URL

    # Local attacker rewrites the stored upstream at the cloud-metadata address.
    _tamper_stored_upstream(home_dir, alias, "https://169.254.169.254/v1")

    proj2 = tmp_path / "proj2"
    proj2.mkdir()
    env2 = proj2 / ".env"
    env2.write_text(f"OPENAI_API_KEY={fixed_key}\n")

    second = runner.invoke(app, ["lock", "--env", str(env2)], env=cli_env)

    assert second.exit_code != 0, (
        "a tampered stored upstream was carried forward without re-validation; "
        f"the proxy would forward a live key to cloud metadata. output: {second.output}"
    )
    # NOT "the row is clean": the guard raises before any upsert, so the
    # tampered row survives the refusal by design (re-lock refuses to
    # PROPAGATE it; it does not remediate the DB — worthless-rzi1 owns that).
    # What must hold is that the refusal is attributable to the tampered value.
    assert "169.254.169.254" in second.output, (
        f"the refusal must name the tampered upstream it rejected; output: {second.output}"
    )
