"""Shared test fixtures for Worthless."""

from __future__ import annotations

import gc
import json
import logging
import os
from pathlib import Path
import threading
import time

import keyring
import keyring.backends.null
import pytest
from cryptography.fernet import Fernet
from hypothesis import HealthCheck, settings


from worthless.cli import default_command  # used by _isolate_default_command_proxy autouse fixture
from worthless.cli.bootstrap import WorthlessHome, ensure_home
from worthless.crypto import SplitResult, split_key
from worthless.storage.repository import ShardRepository, StoredShard

from tests.helpers import fake_openai_key

logger = logging.getLogger(__name__)

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


@pytest.fixture(autouse=True)
def detect_thread_leak(request):
    """Detect and fail on background thread leaks during test run.

    This catches leaked background threads (e.g. from async runners or leaked loops)
    before they can escape, pollute other tests, or cause xdist worker crashes.
    """
    if request.node.get_closest_marker("integration") or request.node.get_closest_marker("docker"):
        yield
        return

    # Capture initial threads
    initial_threads = {t.ident for t in threading.enumerate() if t.ident is not None}

    yield

    # Short-circuit if there are no new thread IDs at all. Avoids sleep tax on clean tests.
    current_threads = threading.enumerate()
    has_mismatch = any(
        t.ident is not None and t.ident not in initial_threads for t in current_threads
    )

    if has_mismatch:
        # Give exiting threads a polling window to clean up (up to 250ms under heavy load).
        # This handles generic background threads spawned by libraries like aiosqlite ('Thread-N')
        # which take a brief moment to join after a database connection is closed.
        for _ in range(25):
            time.sleep(0.01)
            gc.collect()
            current_threads = threading.enumerate()
            has_mismatch = any(
                t.ident is not None and t.ident not in initial_threads for t in current_threads
            )
            if not has_mismatch:
                break

    # Final check for real leaks
    leaked = []
    for t in current_threads:
        if t.ident is None or t.ident in initial_threads:
            continue
        name = t.name or ""
        # Filter out common benign pytest/xdist worker control or standard worker threads
        if any(b in name.lower() for b in ("pytest", "xdist", "mainthread")):
            continue
        if t.is_alive():
            leaked.append(t)

    if leaked:
        leak_details = ", ".join(f"'{t.name}' (repr={t!r})" for t in leaked)
        raise AssertionError(
            f"Thread leak detected: {len(leaked)} thread(s) leaked during test. "
            f"Leaked threads: {leak_details}. Fail-fast to prevent subsequent worker crashes."
        )


def pytest_collection_modifyitems(config, items):
    """Mark tests in tests/quarantined_tests.txt with @pytest.mark.quarantine."""
    quarantine_file = Path(config.rootdir) / "tests" / "quarantined_tests.txt"
    if not quarantine_file.exists():
        return

    try:
        quarantined = set()
        for line in quarantine_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            quarantined.add(line)
    except Exception as exc:
        logger.warning(f"Failed to read quarantined_tests.txt: {exc}")
        return

    if not quarantined:
        return

    quarantine_marker = pytest.mark.quarantine
    for item in items:
        # Match nodeid only (item.name match is too broad)
        if item.nodeid in quarantined:
            item.add_marker(quarantine_marker)


def pytest_runtest_logreport(report):
    """Auto-detect flaky tests (failed once, then passed on rerun) and warn/annotate."""
    if report.when != "call":
        return

    if report.outcome == "passed" and getattr(report, "rerun", 0) > 0:
        nodeid = report.nodeid
        logger.warning(
            f"worthless-quarantine: Flaky test detected: {nodeid}. "
            f"Please investigate the root cause instead of dismissing it as flaky."
        )
