"""Real-subprocess chaos harness for ``worthless lock`` interrupt-safety (WOR-646).

``worthless lock`` is security-critical: it splits each provider API key, writes
``shards`` + ``enrollments`` rows to the sqlite DB and a file-fallback keystore,
then atomically rewrites ``.env`` so the live secret is gone and ``*_BASE_URL``
lines point traffic at the local proxy. The guarantee under test:

    After ANY interrupt, on-disk state is either FULLY LOCKED or FULLY CLEAN —
    never a partial half-state, never an orphaned shard row with no enrollment.

This module does NOT monkeypatch in-process. It spawns the *real* installed CLI
as a subprocess, lets it run for a jittered slice of its pipeline, then delivers
an OS signal to the whole process GROUP (``os.killpg``) — exactly what Ctrl-C in
a shell, a ``kill`` from an operator, or an OOM-killer does in production.

The harness is the assertion. After the child exits we introspect the DB schema
at runtime and classify the on-disk state:

* ``clean``   — n_shards == 0 AND n_enroll == 0 AND .env byte-identical to pre-lock.
* ``locked``  — n_shards == N AND n_enroll == N AND every original secret value is
                gone from .env AND a ``*_BASE_URL`` line was added.
* ``partial`` — anything else: orphan shards (a shard alias with no matching
                enrollment), mismatched shard/enroll counts, or a half-rewritten
                .env (some secrets stripped, others left). This is the FAILURE.

Hitting the dangerous window matters. Empirically the pipeline writes the first
shard row near the *end* of a ~0.7s run and rewrites ``.env`` ~40ms later — the
orphan-vulnerable seam is that narrow band, NOT process startup. A fixed
millisecond jitter would miss it entirely and give a false all-clear. So the
harness SELF-CALIBRATES: :func:`seam` runs one warm-up lock, polls the DB to find
when the first shard appears, and builds a deterministic delay cycle that densely
straddles that measured seam (plus early/late anchors). Jitter is derived from
the trial index, never an RNG, so any failure is reproducible on that machine.

SIGINT / SIGTERM probe Part-1's signal handler + compensating unwind. SIGKILL is
the brutal-honesty probe: no handler can run, so only true write-ordering /
atomic-Pass-1 saves it. Per the WOR-646 honesty rule, known gaps are marked
``xfail(strict=False)`` and the orphan rate is reported — never asserted away.
"""

from __future__ import annotations

import os
import signal
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.helpers import fake_anthropic_key, fake_key

# POSIX-only: the product targets macOS + Linux, and os.killpg / start_new_session
# / SIGKILL semantics are POSIX. Mirrors tests/e2e/conftest.py's platform policy.
pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(sys.platform == "win32", reason="chaos suite is POSIX-only"),
]


# ---------------------------------------------------------------------------
# Harness configuration
# ---------------------------------------------------------------------------

TRIALS_PER_CELL = 30
WAIT_TIMEOUT = 30.0
# Hard ceiling on the calibrated seam in case the warm-up probe misbehaves; a
# real lock completes well under this.
MAX_SEAM = 5.0


def _cli() -> list[str]:
    """argv prefix for the real CLI from the active test venv."""
    return [str(Path(sys.executable).parent / "worthless")]


@dataclass(frozen=True)
class TrialEnv:
    repo: Path
    env_file: Path
    home: Path
    pre_bytes: bytes
    secrets: tuple[str, ...]  # the original live secret VALUES
    n_keys: int


def _make_trial_env(tmp_path: Path, trial: int, n_keys: int) -> TrialEnv:
    """Build a fresh repo + ``.env`` with *n_keys* distinct fake secrets.

    Each trial gets an isolated subdir so trials never share a DB, keystore, or
    ``.env``. Seeds vary per key AND per trial so aliases/decoys differ.
    """
    root = tmp_path / f"t{trial}"
    repo = root / "repo"
    home = root / "home"
    xdg = root / "xdg"
    for d in (repo, home, xdg):
        d.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    secrets: list[str] = []
    # Key 1: OpenAI primary.
    k = fake_key("sk-" + "proj-", seed=f"chaos-oa-{trial}-1")
    lines.append(f"OPENAI_API_KEY={k}")
    secrets.append(k)
    if n_keys >= 2:
        # Key 2: a distinct provider so a second *_BASE_URL is exercised.
        k = (
            fake_anthropic_key()
            if trial % 2 == 0
            else fake_key("sk-" + "ant-" + "api03-", seed=f"chaos-an-{trial}")
        )
        lines.append(f"ANTHROPIC_API_KEY={k}")
        secrets.append(k)
    for extra in range(3, n_keys + 1):
        # Additional OpenAI-family keys via the *_2/_3 alias convention.
        k = fake_key("sk-" + "proj-", seed=f"chaos-oa-{trial}-{extra}")
        lines.append(f"OPENAI_API_KEY_{extra}={k}")
        secrets.append(k)

    env_file = repo / ".env"
    env_file.write_bytes(("\n".join(lines) + "\n").encode())
    return TrialEnv(
        repo=repo,
        env_file=env_file,
        home=home,
        pre_bytes=env_file.read_bytes(),
        secrets=tuple(secrets),
        n_keys=n_keys,
    )


def _child_env(te: TrialEnv) -> dict[str, str]:
    """Child process environment.

    ``WORTHLESS_KEYRING_BACKEND=null`` forces the no-prompt file-fallback
    keystore so the child never blocks on a real OS keychain. ``WORTHLESS_HOME``
    / ``HOME`` / ``XDG_DATA_HOME`` are redirected into the trial sandbox.
    """
    root = te.home.parent
    return {
        **os.environ,
        "WORTHLESS_HOME": str(te.home),
        "WORTHLESS_KEYRING_BACKEND": "null",
        "HOME": str(te.home),
        "XDG_DATA_HOME": str(root / "xdg"),
    }


# ---------------------------------------------------------------------------
# Self-calibration: measure the DB-write -> .env-rewrite seam, then build a
# deterministic jitter cycle that densely straddles it.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def seam(tmp_path_factory: pytest.TempPathFactory) -> float:
    """Measure (once) when the first shard row appears in a warm-up lock.

    Returns the elapsed seconds from spawn to the first shard write — the start
    of the orphan-vulnerable window (DB rows exist, ``.env`` not yet rewritten).
    """
    base = tmp_path_factory.mktemp("seam")
    te = _make_trial_env(base, 0, 2)
    proc = subprocess.Popen(
        [*_cli(), "lock", "--env", str(te.env_file)],
        env=_child_env(te),
        cwd=str(te.repo),
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    t0 = time.time()
    first_shard: float | None = None
    try:
        while proc.poll() is None and (time.time() - t0) < MAX_SEAM:
            db = _db_path(te.home)
            if db is not None:
                try:
                    conn = sqlite3.connect(str(db))
                    n = conn.execute("SELECT count(*) FROM shards").fetchone()[0]
                    conn.close()
                    if n > 0:
                        first_shard = time.time() - t0
                        break
                except sqlite3.Error:
                    pass
            time.sleep(0.004)
    finally:
        try:
            proc.wait(timeout=WAIT_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    # Fallback: if the probe never saw a shard (very fast machine / race), use a
    # conservative late seam so the jitter still lands near completion.
    return first_shard if first_shard is not None else 0.5


def _delays_for(seam_s: float) -> tuple[float, ...]:
    """Deterministic jitter cycle straddling the measured *seam_s*.

    Dense coverage just before, at, and just after the first-shard time (the
    window where DB rows exist but ``.env`` is not yet rewritten), plus a couple
    of early-abort and post-completion anchors. Order is fixed; trial index
    selects by modulo, so every trial's delay is reproducible.
    """
    s = max(0.0, min(seam_s, MAX_SEAM))
    band = [
        0.0,  # early: kill during startup -> expect clean
        s * 0.5,  # mid pipeline
        s - 0.030,
        s - 0.015,
        s - 0.008,
        s,  # first shard row lands here
        s + 0.005,
        s + 0.012,
        s + 0.020,
        s + 0.035,
        s + 0.060,  # likely just after .env rewrite -> expect locked
        s + 0.120,  # late: kill after completion -> expect locked
    ]
    return tuple(max(0.0, d) for d in band)


# ---------------------------------------------------------------------------
# Invariant classifier — the whole test
# ---------------------------------------------------------------------------


@dataclass
class DiskState:
    classification: str  # "clean" | "locked" | "partial"
    n_shards: int
    n_enroll: int
    orphan_shards: list[str]
    env_state: str  # "original" | "locked" | "partial"
    detail: str


def _db_path(home: Path) -> Path | None:
    hits = sorted(home.rglob("*.db"))
    return hits[0] if hits else None


def _db_counts(db: Path) -> tuple[int, int, list[str]]:
    """Return (n_shards, n_enroll, orphan_shards) by runtime schema introspection."""
    conn = sqlite3.connect(str(db))
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        shard_aliases: list[str] = []
        if "shards" in tables:
            shard_aliases = [r[0] for r in conn.execute("SELECT key_alias FROM shards")]
        enroll_aliases: set[str] = set()
        if "enrollments" in tables:
            enroll_aliases = {r[0] for r in conn.execute("SELECT key_alias FROM enrollments")}
        orphans = sorted(a for a in shard_aliases if a not in enroll_aliases)
        return len(shard_aliases), len(enroll_aliases), orphans
    finally:
        conn.close()


def _env_state(te: TrialEnv) -> str:
    """Classify ``.env`` as original / locked / partial.

    * original — bytes identical to pre-lock.
    * locked   — EVERY original secret value is gone AND a ``*_BASE_URL`` line
                 was added (the proxy redirect that marks a completed lock).
    * partial  — anything in between: some secrets stripped but not all, or
                 secrets gone but no BASE_URL written, or a torn/empty file.
    """
    try:
        cur = te.env_file.read_bytes()
    except FileNotFoundError:
        return "partial"
    if cur == te.pre_bytes:
        return "original"
    text = cur.decode("utf-8", errors="replace")
    secrets_present = [s for s in te.secrets if s in text]
    base_url_added = "_BASE_URL=" in text
    if not secrets_present and base_url_added:
        return "locked"
    return "partial"


def classify(te: TrialEnv) -> DiskState:
    db = _db_path(te.home)
    env_state = _env_state(te)
    if db is None:
        n_shards = n_enroll = 0
        orphans: list[str] = []
    else:
        n_shards, n_enroll, orphans = _db_counts(db)

    n = te.n_keys
    clean = n_shards == 0 and n_enroll == 0 and env_state == "original"
    locked = n_shards == n and n_enroll == n and env_state == "locked"

    if clean:
        classification = "clean"
    elif locked:
        classification = "locked"
    else:
        classification = "partial"

    detail = (
        f"n_keys={n} n_shards={n_shards} n_enroll={n_enroll} "
        f"orphan_shards={orphans} env_state={env_state}"
    )
    return DiskState(
        classification=classification,
        n_shards=n_shards,
        n_enroll=n_enroll,
        orphan_shards=orphans,
        env_state=env_state,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Trial driver
# ---------------------------------------------------------------------------


def _kill_group(proc: subprocess.Popen, sig: int) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except ProcessLookupError:
        pass  # already exited — fine, just classify what's on disk.


def _drain(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        _kill_group(proc, signal.SIGKILL)
        proc.wait(timeout=5)
    if proc.stdout:
        proc.stdout.close()
    if proc.stderr:
        proc.stderr.close()


def _run_trial(te: TrialEnv, sig: int, delay: float) -> DiskState:
    """Spawn the real CLI, signal its process group after *delay*, classify."""
    proc = subprocess.Popen(
        [*_cli(), "lock", "--env", str(te.env_file)],
        env=_child_env(te),
        cwd=str(te.repo),
        start_new_session=True,  # own process group -> killpg hits the whole tree
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        time.sleep(delay)
        _kill_group(proc, sig)
        try:
            proc.wait(timeout=WAIT_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            pytest.fail(f"lock hung after sig={sig} delay={delay:.3f}s — a hang is a regression")
    finally:
        _drain(proc)
    return classify(te)


def _assert_no_partial(state: DiskState, *, n_keys: int, sig: int, delay: float) -> None:
    assert state.classification in ("clean", "locked"), (
        f"PARTIAL/ORPHAN on-disk state after interrupt — invariant violated.\n"
        f"  signal={signal.Signals(sig).name} n_keys={n_keys} jitter={delay:.3f}s\n"
        f"  {state.detail}\n"
        f"  Expected: fully clean (rolled back) XOR fully locked. Got partial."
    )


# ---------------------------------------------------------------------------
# Storms — SIGINT / SIGTERM exercise Part-1's handler + unwind
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n_keys", [1, 2, 3], ids=["N1", "N2", "N3"])
def test_sigint_storm(tmp_path: Path, seam: float, n_keys: int) -> None:
    """~30 SIGINT trials per N across the calibrated seam — never partial."""
    delays = _delays_for(seam)
    for trial in range(TRIALS_PER_CELL):
        delay = delays[trial % len(delays)]
        te = _make_trial_env(tmp_path, trial, n_keys)
        state = _run_trial(te, signal.SIGINT, delay)
        _assert_no_partial(state, n_keys=n_keys, sig=signal.SIGINT, delay=delay)


@pytest.mark.parametrize("n_keys", [1, 2, 3], ids=["N1", "N2", "N3"])
def test_sigterm_storm(tmp_path: Path, seam: float, n_keys: int) -> None:
    """~30 SIGTERM trials per N across the calibrated seam — never partial."""
    delays = _delays_for(seam)
    for trial in range(TRIALS_PER_CELL):
        delay = delays[trial % len(delays)]
        te = _make_trial_env(tmp_path, trial, n_keys)
        state = _run_trial(te, signal.SIGTERM, delay)
        _assert_no_partial(state, n_keys=n_keys, sig=signal.SIGTERM, delay=delay)


def test_mashed_sigint(tmp_path: Path, seam: float) -> None:
    """A burst of 5 SIGINTs ~5ms apart must NOT defeat the one-shot handler.

    Part-1 arms a one-shot handler; a panicked operator mashing Ctrl-C must not
    re-enter cleanup or leave a torn state. Invariant still holds.
    """
    n_keys = 2
    delays = _delays_for(seam)
    for trial in range(TRIALS_PER_CELL):
        delay = delays[trial % len(delays)]
        te = _make_trial_env(tmp_path, trial, n_keys)
        proc = subprocess.Popen(
            [*_cli(), "lock", "--env", str(te.env_file)],
            env=_child_env(te),
            cwd=str(te.repo),
            start_new_session=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            time.sleep(delay)
            for _ in range(5):
                if proc.poll() is not None:
                    break
                _kill_group(proc, signal.SIGINT)
                time.sleep(0.005)
            try:
                proc.wait(timeout=WAIT_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
                pytest.fail(f"mashed-SIGINT hung at delay={delay:.3f}s — regression")
        finally:
            _drain(proc)
        state = classify(te)
        _assert_no_partial(state, n_keys=n_keys, sig=signal.SIGINT, delay=delay)


# ---------------------------------------------------------------------------
# SIGKILL — the brutal-honesty atomicity probe
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    reason="WOR-646 Part 2: atomic Pass-1 transaction + atomic-.env. "
    "SIGKILL allows no cleanup; only write-ordering/atomic commit prevents "
    "orphan shards. Current code may leak — documented, not hidden.",
    strict=False,
)
@pytest.mark.parametrize("n_keys", [2, 3], ids=["N2", "N3"])
def test_sigkill_atomicity(tmp_path: Path, seam: float, n_keys: int) -> None:
    """SIGKILL mid-lock: no handler runs, so only true atomicity holds the line.

    Reports the partial/orphan rate. Marked xfail(strict=False) per the WOR-646
    honesty rule: a green-able suite that still surfaces the real gap. If a run
    is fully atomic it PASSES (xpass); any partial state fails the assertion,
    which xfail records rather than hides.
    """
    delays = _delays_for(seam)
    partials: list[str] = []
    for trial in range(TRIALS_PER_CELL):
        delay = delays[trial % len(delays)]
        te = _make_trial_env(tmp_path, trial, n_keys)
        state = _run_trial(te, signal.SIGKILL, delay)
        if state.classification == "partial":
            partials.append(f"delay={delay:.3f}s {state.detail}")

    rate = len(partials) / TRIALS_PER_CELL
    assert not partials, (
        f"SIGKILL produced {len(partials)}/{TRIALS_PER_CELL} partial states "
        f"({rate:.0%} orphan/partial rate) for N={n_keys}.\n"
        + "\n".join(f"  - {p}" for p in partials[:8])
    )
