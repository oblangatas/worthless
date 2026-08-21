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
    # Each storm test SLEEPS ``TRIALS_PER_CELL`` times before signalling, and each
    # sleep is drawn from a band centred on the session-calibrated ``seam``. So the
    # test's floor is ~= TRIALS_PER_CELL * seam, and ``seam`` is measured once from
    # a single warm-up lock whose duration swings with machine load (observed
    # 1.37s idle vs 2.75s cold on the same 10-core box). Against the repo-wide
    # ``timeout = 30`` that meant the suite only passed while seam stayed under
    # ~1.1s — a load-sensitive coin flip, not a product signal.
    #
    # Budget the worst LEGITIMATE runtime, generously. At the MAX_SEAM ceiling
    # the sleep floor alone is TRIALS_PER_CELL * (MAX_SEAM + 0.12) ~= 154s, and
    # full-suite contention was measured inflating this module ~1.8x over an
    # isolated run (mashed_sigint: 33.10s isolated -> 60.67s under `-n auto`),
    # which puts the ceiling near 280s. Observed seams keep climbing as machines
    # get busier -- 1.366s, 2.748s, ~3.0s -- so a snug budget just reintroduces
    # the flake at a higher number.
    #
    # This value is NOT the hang detector; WAIT_TIMEOUT below is, and it fires
    # ~40x sooner with the signal and jitter that wedged the CLI. So erring
    # generous here costs nothing and cannot mask a hang.
    pytest.mark.timeout(600),
    # NEVER auto-retry this module. ``--reruns 1`` is repo-wide (pyproject addopts
    # and .github/workflows/tests.yml), and a rerun that passes is reported green.
    # That is precisely how the budget defect above survived: a systematic failure
    # was retried into a pass run after run, surfacing only as an "occasional
    # flake". The same masking applies to what this suite actually guards -- a
    # PARTIAL/ORPHAN on-disk state is a rare, timing-dependent security bug, so
    # retrying it is how a half-locked `.env` ships.
    #
    # A failure here must be loud and attributable. If that means an intermittent
    # red, the red is the finding.
    pytest.mark.flaky(reruns=0),
]


# ---------------------------------------------------------------------------
# Harness configuration
# ---------------------------------------------------------------------------

TRIALS_PER_CELL = 30
# Guard for "the CLI never exited" — it must stay WELL BELOW the per-test timeout
# above, or the generic pytest timeout fires first and swallows the diagnostic
# (which signal, which jitter) that makes a hang actionable.
#
# Sized from measurement, not guesswork. With 10 CPU hogs saturating a 10-core
# box, signal -> exit was: mashed-SIGINT max 27ms, single-SIGINT max 1.40s, and a
# full *unsignalled* lock (what the ``seam`` warm-up waits on) max 1.64s. 15s is
# ~10x the worst of those, so a trip here means a real hang, not contention.
WAIT_TIMEOUT = 15.0
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


SEAM_FLOOR = 0.05


def _resolve_seam(
    first_shard: float | None,
    *,
    shards_after: int | None = None,
    returncode: int | None = None,
    elapsed: float | None = None,
    stderr: str = "",
) -> float:
    """Turn the probe result into a usable seam, or refuse to run.

    This used to silently substitute ``0.5`` when the probe saw nothing. The
    honest objection to that is NOT "the band lands nowhere near the window" —
    on the one CI runner where calibration actually failed, the true seam was
    ~0.598s and ``_delays_for(0.5)`` spans 0.25–0.62, which straddles it. The
    objection is that a seam nobody measured is UNFALSIFIABLE: it may happen to
    aim correctly, or it may put every trial inside process startup, and a green
    run looks identical either way. So refuse, and say why.

    Two faults produce the same "no measurement" symptom, because the probe loop
    exits when the child does as well as on ``MAX_SEAM``:

    * the lock wrote shards but the 4ms polling missed the moment — a HARNESS
      problem, fix by polling faster or raising the ceiling;
    * the lock wrote nothing at all — a PRODUCT or environment fault, where
      raising the ceiling would only hide it.

    Earlier this guessed between them from the exit code and told the reader to
    go read stderr. It does not need to guess: the rows are still on disk after
    the child exits. ``shards_after`` is that count, and it settles the question
    as fact.

    A measured seam is also bounded. Trusting any non-``None`` float reopens the
    same hole from the other side — a near-zero seam collapses every jitter
    delay into process startup, so nothing reaches the orphan window and the
    suite passes vacuously with a clean conscience.
    """
    if first_shard is not None:
        if SEAM_FLOOR <= first_shard <= MAX_SEAM * 0.9:
            return first_shard
        pytest.fail(
            f"chaos seam calibration returned an implausible seam: {first_shard:.4f}s "
            f"(expected {SEAM_FLOOR}s .. {MAX_SEAM * 0.9:.2f}s).\n"
            "  A seam this small puts every jitter delay inside process startup, so no "
            "trial reaches the window where DB rows exist but .env is not yet rewritten "
            "— the suite would pass without testing anything.\n"
            "  Likely causes: a stale DB from a previous trial, a wrong WORTHLESS_HOME, "
            "or a warm-up lock that wrote its first shard before the probe's first poll."
        )

    if shards_after is None:
        verdict = (
            "the warm-up lock wrote no shard row the probe could see, AND the DB "
            "could not be read afterwards, so the cause cannot be determined here."
        )
    elif shards_after > 0:
        verdict = (
            f"the probe MISSED the write — the DB holds {shards_after} shard row(s) "
            "after the child exited. The lock worked; calibration did not. This is a "
            "HARNESS problem: the 4ms poll interval or the MAX_SEAM ceiling is wrong "
            "for this machine, NOT a product fault."
        )
    else:
        verdict = (
            "the warm-up lock wrote NO shard rows at all — the DB is empty after it "
            "exited. This is a PRODUCT or environment fault; raising MAX_SEAM would "
            "only hide it. Read the stderr tail below."
        )

    detail = f"  child: exit={returncode} elapsed={elapsed:.2f}s shards_after={shards_after}\n"
    tail = f"  stderr tail:\n{stderr[-800:]}\n" if stderr.strip() else "  stderr: (empty)\n"

    pytest.fail(
        "chaos seam calibration FAILED — the orphan-vulnerable window could not be "
        f"located within MAX_SEAM={MAX_SEAM}s.\n"
        f"  Diagnosis: {verdict}\n"
        f"{detail}"
        "  Refusing to substitute a fabricated seam: an unmeasured seam is "
        "unfalsifiable, and a green run would not distinguish it from a real one.\n"
        f"{tail}"
    )


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
        # stderr is CAPTURED, not discarded: when calibration fails it is the
        # only thing that distinguishes "runner too slow" from "lock is broken".
        stderr=subprocess.PIPE,
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
        # communicate(), NOT wait(): stderr is a pipe, and a child that fills the
        # ~64KB buffer blocks forever while we wait for an exit that cannot come.
        # That would surface as returncode=-9 after the kill, which the diagnosis
        # below would report as a PRODUCT fault — a harness deadlock blamed on
        # the product. communicate() drains while it waits.
        try:
            err_bytes = proc.communicate(timeout=WAIT_TIMEOUT)[1]
        except subprocess.TimeoutExpired:
            proc.kill()
            err_bytes = proc.communicate(timeout=5)[1]
    elapsed = time.time() - t0
    err = (err_bytes or b"").decode("utf-8", errors="replace")

    # The child is gone, so the rows it wrote are now stable on disk. Ask.
    # "Probe missed the write" and "lock wrote nothing" are opposite faults with
    # opposite fixes, and guessing between them from an exit code is unnecessary
    # when the DB can simply be read.
    shards_after: int | None = None
    db_path = _db_path(te.home)
    if db_path is not None:
        try:
            conn = sqlite3.connect(str(db_path))
            try:
                shards_after = conn.execute("SELECT count(*) FROM shards").fetchone()[0]
            finally:
                conn.close()
        except sqlite3.Error:
            shards_after = None

    return _resolve_seam(
        first_shard,
        shards_after=shards_after,
        returncode=proc.returncode,
        elapsed=elapsed,
        stderr=err,
    )


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


def _run_trial(te: TrialEnv, sig: int, delay: float, *, ready: Path | None = None) -> DiskState:
    """Spawn the real CLI, signal its process group after *delay*, classify.

    *ready*, when given, is a marker file the child creates once it has armed
    itself and is safe to signal; we poll for it instead of trusting *delay*.
    A blind sleep races interpreter startup, and a signal landing before the
    child is armed KILLS it rather than wedging it — which looks like "no hang
    happened" and silently guts whatever the caller was trying to prove.

    The real chaos trials deliberately pass no *ready*: for them the blind
    delay IS the variable under test, sweeping the orphan-vulnerable window.
    """
    proc = subprocess.Popen(
        [*_cli(), "lock", "--env", str(te.env_file)],
        env=_child_env(te),
        cwd=str(te.repo),
        start_new_session=True,  # own process group -> killpg hits the whole tree
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        if ready is None:
            time.sleep(delay)
        else:
            deadline = time.monotonic() + WAIT_TIMEOUT
            while not ready.exists():
                if proc.poll() is not None:
                    pytest.fail(f"wedge child exited before arming (rc={proc.returncode})")
                if time.monotonic() > deadline:
                    pytest.fail(f"wedge child never signalled ready within {WAIT_TIMEOUT}s")
                time.sleep(0.01)
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

# Each slow test below sits alone in its own class ON PURPOSE. ``--dist loadscope``
# hands a whole GROUP to one xdist worker and cannot split it; the group is the
# MODULE for bare functions but the CLASS for methods. As bare functions these were
# a single ~10.7-minute group pinned to one worker while the other three idled,
# which is what pushed `Test (ubuntu, py3.10)` past its 20m ceiling on an unlucky
# shuffle (worthless-7zl6). One class each = one group each = they spread out.
# Ceiling: the slowest single class is now the floor (~3.7m). If that becomes the
# binding constraint again, split by ``n_keys`` rather than merging these back.
# Do NOT collapse them into plain functions or into one shared class.


class TestSigintStorm:
    @pytest.mark.parametrize("n_keys", [1, 2, 3], ids=["N1", "N2", "N3"])
    def test_sigint_storm(self, tmp_path: Path, seam: float, n_keys: int) -> None:
        """~30 SIGINT trials per N across the calibrated seam — never partial."""
        delays = _delays_for(seam)
        for trial in range(TRIALS_PER_CELL):
            delay = delays[trial % len(delays)]
            te = _make_trial_env(tmp_path, trial, n_keys)
            state = _run_trial(te, signal.SIGINT, delay)
            _assert_no_partial(state, n_keys=n_keys, sig=signal.SIGINT, delay=delay)


class TestSigtermStorm:
    @pytest.mark.parametrize("n_keys", [1, 2, 3], ids=["N1", "N2", "N3"])
    def test_sigterm_storm(self, tmp_path: Path, seam: float, n_keys: int) -> None:
        """~30 SIGTERM trials per N across the calibrated seam — never partial."""
        delays = _delays_for(seam)
        for trial in range(TRIALS_PER_CELL):
            delay = delays[trial % len(delays)]
            te = _make_trial_env(tmp_path, trial, n_keys)
            state = _run_trial(te, signal.SIGTERM, delay)
            _assert_no_partial(state, n_keys=n_keys, sig=signal.SIGTERM, delay=delay)


class TestMashedSigint:
    def test_mashed_sigint(self, tmp_path: Path, seam: float) -> None:
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
# Guard self-test — prove the hang detector actually fires
# ---------------------------------------------------------------------------


def test_hang_guard_fires_with_diagnostic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A wedged CLI must trip ``WAIT_TIMEOUT`` and say which signal/jitter did it.

    ``WAIT_TIMEOUT`` only earns its place if it FIRES. It previously equalled the
    repo-wide ``timeout = 30``, so the generic pytest timeout always won the race
    and this diagnostic was unreachable — a guard nobody had ever seen work. That
    is exactly the failure mode worth a test rather than an assumption.

    Inject a shim that ignores SIGINT and never exits, then assert the harness
    fails fast, with the actionable message, well inside the module timeout.
    """
    shim = tmp_path / "wedged_cli.py"
    ready = tmp_path / "wedged_ready"
    # The marker is written AFTER the handlers are installed, never before: it
    # is the child asserting "I can now survive a signal". Ordering is the whole
    # point — see the ready= gate in _run_trial.
    shim.write_text(
        "import signal, time\n"
        "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"open({str(ready)!r}, 'w').close()\n"
        "while True:\n"
        "    time.sleep(0.05)\n"
    )
    monkeypatch.setattr(
        f"{__name__}._cli",
        lambda: [sys.executable, str(shim)],
    )

    te = _make_trial_env(tmp_path, 0, 1)
    started = time.monotonic()
    with pytest.raises(pytest.fail.Exception, match=r"hung after sig="):
        _run_trial(te, signal.SIGINT, 0.05, ready=ready)
    elapsed = time.monotonic() - started

    # Upper bound is anchored on the module timeout (600s), NOT on a hand-picked
    # margin above WAIT_TIMEOUT: `elapsed` now also covers interpreter startup
    # while we wait for the ready marker, which is load-dependent by nature. The
    # property worth pinning is "fired, and far inside the module timeout" —
    # anything tighter is measuring the machine, not the guard.
    assert WAIT_TIMEOUT <= elapsed < 60.0, (
        f"hang guard fired at {elapsed:.1f}s; expected >= {WAIT_TIMEOUT}s and far "
        f"inside the 600s module timeout. Too early means a hair trigger; too "
        f"late means the per-test timeout will swallow the diagnostic again."
    )


def test_seam_calibration_refuses_to_fabricate() -> None:
    """A seam the probe could not measure must fail, not silently become 0.5.

    The regression this guards is invisible by construction: a fabricated seam
    still produces a green run, so nothing about the output would tell you the
    suite stopped aiming at the orphan window. Assert the refusal directly.
    """
    # A plausible measurement passes through untouched.
    assert _resolve_seam(1.234) == 1.234

    # An IMPLAUSIBLE measurement is refused too. A near-zero seam is not a fast
    # machine, it is a broken probe: _delays_for(0.02) puts every trial inside
    # process startup, so nothing reaches the orphan window and all nine storm
    # tests pass vacuously. That is the same failure the fabricated 0.5 caused,
    # so it gets the same answer. (An earlier version of this test asserted
    # _resolve_seam(0.0) == 0.0 — it blessed the bug.)
    with pytest.raises(pytest.fail.Exception, match=r"implausible"):
        _resolve_seam(0.0)
    with pytest.raises(pytest.fail.Exception, match=r"implausible"):
        _resolve_seam(MAX_SEAM)

    # No measurement + the DB HAS shards -> the lock worked, the probe missed
    # the timing. Actionable as a harness problem.
    with pytest.raises(pytest.fail.Exception, match=r"probe MISSED"):
        _resolve_seam(None, shards_after=2, returncode=0, elapsed=0.4)

    # No measurement + the DB is EMPTY -> the lock never wrote. Product or
    # environment fault; raising MAX_SEAM would only hide it.
    with pytest.raises(pytest.fail.Exception, match=r"wrote NO shard"):
        _resolve_seam(None, shards_after=0, returncode=1, elapsed=0.2, stderr="boom")

    # Unreadable DB -> honest "cannot tell", not a fabricated verdict.
    with pytest.raises(pytest.fail.Exception, match=r"could not be read"):
        _resolve_seam(None, shards_after=None, returncode=0, elapsed=0.3)


# ---------------------------------------------------------------------------
# SIGKILL — the brutal-honesty atomicity probe
# ---------------------------------------------------------------------------


class TestSigkillAtomicity:
    @pytest.mark.xfail(
        reason="WOR-646 Part 2: atomic Pass-1 transaction + atomic-.env. "
        "SIGKILL allows no cleanup; only write-ordering/atomic commit prevents "
        "orphan shards. Current code may leak — documented, not hidden.",
        strict=False,
    )
    @pytest.mark.parametrize("n_keys", [2, 3], ids=["N2", "N3"])
    def test_sigkill_atomicity(self, tmp_path: Path, seam: float, n_keys: int) -> None:
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
