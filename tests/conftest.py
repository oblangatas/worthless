"""Shared test fixtures for Worthless."""

from __future__ import annotations

import functools
import json
import os
from pathlib import Path

import keyring
import keyring.backends.null
import pytest
from cryptography.fernet import Fernet
from hypothesis import HealthCheck, settings

from worthless.cli import default_command  # used by _isolate_default_command_proxy autouse fixture
from worthless.cli.bootstrap import WorthlessHome, ensure_home
from worthless.crypto import SplitResult
from worthless.crypto.splitter import split_key
from worthless.proxy import app as _proxy_app_module
from worthless.storage.repository import ShardRepository, StoredShard

from tests._fakes.fake_ipc_supervisor import FakeIPCSupervisor
from tests.helpers import fake_openai_key

# Disable the real OS keyring for the entire test session.
#
# Context: on macOS, concurrent ``SecItemAdd`` calls from multiple pytest-xdist
# workers can hang indefinitely on the Keychain API. ``pytest-timeout`` then
# kills the test with a 30 s signal, which surfaces as apparently-random test
# failures that only ``--reruns 1`` was masking.
#
# The null backend is already in ``keystore._REJECTED_BACKENDS``, so
# ``keyring_available()`` returns False and the file-fallback path is used
# — same code path tests always exercised, minus the system-wide contention.
keyring.set_keyring(keyring.backends.null.Keyring())

# Belt-and-braces for SUBPROCESSES (WOR-463): the line above only protects the
# parent pytest Python process. Any test that subprocess-spawns ``worthless``
# (e2e tests, install.sh tests) loads ``keyring`` fresh in its child process
# and ignores the parent's ``set_keyring`` call. Pre-WOR-463 this leaked
# real ``fernet-key-*`` entries into the user's macOS keychain on every run
# (128 orphans found in one machine's dogfood history).
#
# ``WORTHLESS_KEYRING_BACKEND=null`` is honored by ``keystore.keyring_available``
# itself, so children see the same gate. ``setdefault`` (not ``[..]=``) so a
# test that genuinely wants the real backend can opt back in via
# ``monkeypatch.delenv("WORTHLESS_KEYRING_BACKEND")``.
os.environ.setdefault("WORTHLESS_KEYRING_BACKEND", "null")

# Suppress differing_executors health check ONLY when running under mutmut.
# Mutmut runs tests from its mutants/ directory with a different rootdir,
# which triggers this check spuriously.  In normal test runs, the check
# remains active to catch real working-directory issues.
if os.environ.get("MUTANT_UNDER_TEST"):
    settings.register_profile("mutmut", suppress_health_check=[HealthCheck.differing_executors])
    settings.load_profile("mutmut")

# CI profile: cap Hypothesis examples, derandomize for reproducibility,
# disable on-disk database for xdist compatibility.
# Activate with: HYPOTHESIS_PROFILE=ci
settings.register_profile(
    "ci",
    max_examples=50,
    derandomize=True,
    database=None,
)

# Extended profile: thorough property testing for scheduled runs.
# Activate with: HYPOTHESIS_PROFILE=extended
settings.register_profile(
    "extended",
    max_examples=500,
    database=None,
)

_profile = os.environ.get("HYPOTHESIS_PROFILE")
if _profile in ("ci", "extended"):
    settings.load_profile(_profile)


def make_repo(home: WorthlessHome) -> ShardRepository:
    """Build a ShardRepository from a WorthlessHome (test helper)."""
    return ShardRepository(str(home.db_path), home.fernet_key)


# ------------------------------------------------------------------
# CLI bootstrap fixtures
# ------------------------------------------------------------------


@pytest.fixture()
def home_dir(tmp_path) -> WorthlessHome:
    """Bootstrap a fresh WorthlessHome in tmp_path."""
    return ensure_home(tmp_path / ".worthless")


@pytest.fixture()
def home_with_key(home_dir: WorthlessHome, tmp_path: Path) -> WorthlessHome:
    """Home with one enrolled key (openai), bound to a real .env file.

    HF5 (worthless-gmky): the env_path must point at a real file
    containing the OPENAI_API_KEY line so ``is_orphan()`` returns False.
    Pre-HF5 the fixture used a fake `/tmp/.env` path; status didn't check
    .env content so PROTECTED was reported regardless. Post-HF5 a fake
    path correctly reads as BROKEN — fixture updated to match the
    healthy-state contract that its callers assume.
    """
    import asyncio

    key = fake_openai_key()
    sr = split_key(key.encode())
    try:
        alias = "openai-a1b2c3d4"

        # Write the SAME key into the fixture .env so the enrolled shard
        # and the .env line agree. Using a fresh fake_openai_key() here would
        # mismatch the enrolled value — fine today since is_orphan() only
        # checks var-name presence, but fragile if a future check ever cares.
        # CodeRabbit PR #131.
        env_path = tmp_path / ".env"
        env_path.write_text(f"OPENAI_API_KEY={key}\n")

        repo = make_repo(home_dir)
        asyncio.run(repo.initialize())
        stored = stored_shard_from_split(sr, provider="openai")
        asyncio.run(
            repo.store_enrolled(
                alias,
                stored,
                var_name="OPENAI_API_KEY",
                env_path=str(env_path),
            )
        )
    finally:
        sr.zero()
    return home_dir


# ------------------------------------------------------------------
# Adapter-layer fixtures (Phase 2)
# ------------------------------------------------------------------


@pytest.fixture
def sample_openai_body() -> bytes:
    """A minimal OpenAI chat completion request body."""
    return json.dumps({"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]}).encode()


@pytest.fixture
def sample_anthropic_body() -> bytes:
    """A minimal Anthropic messages request body."""
    return json.dumps(
        {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "hi"}],
        }
    ).encode()


@pytest.fixture
def sample_api_key() -> bytearray:
    """A fake API key bytearray for adapter tests (SR-01: no immutable secrets)."""
    return bytearray(b"sk-test-fake-key-1234567890")


@pytest.fixture
def mock_openai_sse_chunks() -> list[bytes]:
    """Realistic OpenAI SSE chunks."""
    return [
        b'data: {"id":"chatcmpl-1","choices":[{"delta":{"content":"Hello"}}]}\n\n',
        b'data: {"id":"chatcmpl-1","choices":[{"delta":{"content":" world"}}]}\n\n',
        b"data: [DONE]\n\n",
    ]


@pytest.fixture
def mock_anthropic_sse_chunks() -> list[bytes]:
    """Realistic Anthropic SSE chunks."""
    return [
        b'event: content_block_delta\ndata: {"type":"content_block_delta",'
        b'"delta":{"type":"text_delta","text":"Hello"}}\n\n',
        b'event: content_block_delta\ndata: {"type":"content_block_delta",'
        b'"delta":{"type":"text_delta","text":" world"}}\n\n',
        b'event: message_stop\ndata: {"type":"message_stop"}\n\n',
    ]


# ------------------------------------------------------------------
# Crypto-layer fixtures (Phase 1)
# ------------------------------------------------------------------


@pytest.fixture()
def sample_api_key_bytes() -> bytes:
    """A realistic-length API key for crypto tests."""
    return b"sk-test-key-1234567890abcdef"


@pytest.fixture()
def sample_long_key() -> bytes:
    """A 64-byte key for testing longer keys."""
    return b"sk-long-" + b"A" * 56


def assert_zeroed(buf: bytearray) -> None:
    """Assert every byte in *buf* is zero."""
    assert all(b == 0 for b in buf), f"Buffer not zeroed: {buf[:8].hex()}..."


def write_shard_a(home: WorthlessHome, alias: str, data: bytes) -> Path:
    """Write a shard_a file with 0o600 perms. Returns the file path."""
    shard_a_path = home.shard_a_dir / alias
    fd = os.open(str(shard_a_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return shard_a_path


# ------------------------------------------------------------------
# Storage-layer fixtures (Phase 1)
# ------------------------------------------------------------------


@pytest.fixture()
def tmp_db_path(tmp_path) -> str:
    """Temporary SQLite database path."""
    return str(tmp_path / "test.db")


@pytest.fixture()
def fernet_key() -> bytes:
    """A freshly generated Fernet key."""
    return Fernet.generate_key()


@pytest.fixture()
def sample_split_result(sample_api_key_bytes: bytes) -> SplitResult:
    """A real SplitResult produced from the sample API key."""
    return split_key(sample_api_key_bytes)


def stored_shard_from_split(sr: SplitResult, provider: str = "openai") -> StoredShard:
    """Build a StoredShard from a SplitResult (wrapping in bytearray per SR-01)."""
    return StoredShard(
        shard_b=bytearray(sr.shard_b),
        commitment=bytearray(sr.commitment),
        nonce=bytearray(sr.nonce),
        provider=provider,
    )


@pytest.fixture()
async def repo(tmp_db_path: str, fernet_key: bytes) -> ShardRepository:
    """An initialized ShardRepository backed by a temp database."""
    r = ShardRepository(tmp_db_path, fernet_key)
    await r.initialize()
    return r


# ------------------------------------------------------------------
# WOR-309 Phase 5: autouse FakeIPCSupervisor injection
# ------------------------------------------------------------------
#
# Phase 3 rewired the proxy to call ``app.state.ipc_supervisor.open(...)``
# instead of an in-process Fernet decrypt. ``app.py:180-189`` honours a
# pre-set ``app.state.ipc_supervisor`` and skips eager-connect when
# ``app.state.ipc_supervisor_preconnected`` is truthy.
#
# Two layers of injection — both autouse, both bypassed by ``real_ipc``:
#
# 1. Session-scoped: wrap ``worthless.proxy.app.create_app`` once at
#    session start. Required because module-scoped fixtures (like
#    ``live_proxy`` in tests/test_contract.py) execute their setup
#    *outside* function-scoped autouse fixtures. If we only patched at
#    function scope, those module fixtures would build a real proxy
#    against a non-existent sidecar socket and 503 every test.
#
# 2. Function-scoped: re-wrap per-test so a leftover patch from a
#    `real_ipc`-marked test (which clobbered the wrap) is restored. Also
#    yields the per-test ``fakes_seen`` list to test code that wants to
#    inspect the fake.


def _make_create_app_wrapper(original_create_app):
    """Return a wrapper that stamps a FakeIPCSupervisor onto every app.

    Uses ``functools.wraps`` so ``inspect.getsource(create_app)`` returns the
    original ``create_app`` source — required by tests in
    ``test_security_properties.py`` that statically scan handler source for
    the gate-before-decrypt invariant.
    """

    @functools.wraps(original_create_app)
    def _wrapped(*args, **kwargs):
        app = original_create_app(*args, **kwargs)
        if getattr(app.state, "ipc_supervisor", None) is None:
            app.state.ipc_supervisor = FakeIPCSupervisor()
            app.state.ipc_supervisor_preconnected = True
        return app

    return _wrapped


_ORIGINAL_CREATE_APP = _proxy_app_module.create_app


@pytest.fixture(autouse=True, scope="session")
def _session_fake_ipc_supervisor():
    """Patch ``create_app`` for the whole test session.

    Walks every already-imported module that captured ``create_app`` by
    ``from ... import create_app`` and rebinds the captured reference to
    the wrapped version. Restored on session teardown.
    """
    import sys

    wrapper = _make_create_app_wrapper(_ORIGINAL_CREATE_APP)

    captured_locations: list[tuple[object, str]] = []
    for mod in list(sys.modules.values()):
        if mod is None or mod is _proxy_app_module:
            continue
        captured = getattr(mod, "create_app", None)
        if captured is _ORIGINAL_CREATE_APP:
            captured_locations.append((mod, "create_app"))
            setattr(mod, "create_app", wrapper)
    _proxy_app_module.create_app = wrapper

    try:
        yield
    finally:
        _proxy_app_module.create_app = _ORIGINAL_CREATE_APP
        for mod, attr in captured_locations:
            setattr(mod, attr, _ORIGINAL_CREATE_APP)


@pytest.fixture(autouse=True)
def _autouse_fake_ipc_supervisor(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    """Per-test wrapping. Honours ``real_ipc`` opt-out.

    ``real_ipc``-marked tests need the *original* ``create_app`` so the
    lifespan really connects to a subprocess sidecar. We unconditionally
    rebind to the original at function-scope; ``monkeypatch`` restores the
    session-scope wrap on teardown.
    """
    if request.node.get_closest_marker("real_ipc") is None:
        return

    import sys

    monkeypatch.setattr(_proxy_app_module, "create_app", _ORIGINAL_CREATE_APP)
    for mod in list(sys.modules.values()):
        if mod is None or mod is _proxy_app_module:
            continue
        captured = getattr(mod, "create_app", None)
        if captured is not None and captured is not _ORIGINAL_CREATE_APP:
            monkeypatch.setattr(mod, "create_app", _ORIGINAL_CREATE_APP)


# Synthetic PID returned by the start_daemon mock below. Must be non-zero —
# POSIX reserves PID 0 for "the calling process's process group", and
# ``os.kill(0, ...)`` signals every process in the group. Liveness probes
# (``os.kill(pid, 0)``) treat PID 0 as a positive ack regardless of whether
# any worthless daemon was actually started, masking bugs. 12345 is a
# synthetic, well-out-of-the-way value that no real long-lived process
# is going to land on. Keep this as a constant so audit greps stay easy.
_FAKE_DAEMON_PID = 12345


@pytest.fixture(autouse=True)
def _isolate_default_command_proxy(request, monkeypatch):
    """Stop ``run_default()`` from spawning a real proxy daemon mid-test.

    Tests that hit the bare ``worthless`` no-args entry point flow through
    ``default_command.run_default()`` → ``_proxy_is_running`` → ``poll_health(8787)``
    → ``start_daemon(..., port=8787, ...)``. Under pytest-xdist, four workers
    racing for the same port produces non-deterministic state: one wins the
    bind, the others see a "running" daemon belonging to a different test's
    home, and assertions diverge. The same race also leaves orphan uvicorn
    children if a worker fails between spawn and cleanup.

    This autouse fixture neutralises the daemon path for every test by
    default. The autouse-everywhere scope is deliberate (not a missed
    narrowing): tests that accidentally invoke ``run_default()`` from any
    code path are auto-protected from spawning a real daemon. The
    measured cost is ~0.8s / 2.9% across the full suite (microseconds
    per test); the safety net is broad and prevents the "future test
    forgets the marker" failure mode entirely.

    Tests that genuinely need a real proxy daemon must opt out with
    ``@pytest.mark.integration`` (already a registered marker in
    pyproject.toml) and own their own daemon teardown.

    Tests that monkeypatch ``start_daemon`` / ``poll_health`` themselves
    still work — pytest's ``monkeypatch`` stacks LIFO within a single test,
    so the per-test override wins over this fixture's default. Verified
    against ``tests/test_cli_default.py`` which already does this for
    ~10 of its tests.

    Mock return values are chosen to match the real shapes:
    - ``_proxy_is_running`` returns ``(running=False, pid=None, port=0)``
      — same tuple production code returns when the daemon is absent.
    - ``start_daemon`` returns ``_FAKE_DAEMON_PID`` (12345). PID 0 would
      hijack ``os.kill`` liveness probes (POSIX-reserved); a non-zero
      synthetic PID lets such probes fail honestly.
    - ``poll_health`` returns ``True`` so callers that only check
      "responsive?" don't loop.

    Closes worthless-ba1c.
    """
    if request.node.get_closest_marker("integration"):
        return

    monkeypatch.setattr(
        default_command,
        "_proxy_is_running",
        lambda home: (False, None, 0),
    )
    monkeypatch.setattr(
        default_command,
        "start_daemon",
        lambda *_a, **_kw: _FAKE_DAEMON_PID,
    )
    monkeypatch.setattr(
        default_command,
        "poll_health",
        lambda port, timeout=10.0: True,
    )
