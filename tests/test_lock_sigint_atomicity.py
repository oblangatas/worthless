"""WOR-646: SIGINT/SIGTERM during ``worthless lock`` must roll back atomically.

If an OS interrupt lands after Pass-1 has written enrollment + shard rows but
before the lock completes, ``_lock_keys`` must run ``_compensating_unwind`` so
the DB has zero rows and ``.env`` is byte-identical to pre-lock — the same
all-or-nothing contract a verify-hook failure already satisfies, now extended
to signals.

Signals are the gap the pre-WOR-646 code missed: ``KeyboardInterrupt`` (SIGINT)
and the ``CancelledError`` raised by the loop's SIGTERM handler are both
``BaseException``, which the old ``except Exception:`` could not catch — so the
rollback never fired and rows leaked.

The companion regression (:class:`TestNonInterruptExitCodePreserved`) pins the
inverse: broadening the rollback ``except`` to add the interrupt types must NOT
change how an ordinary (non-interrupt) exception exits. ``typer.Exit`` is a
``RuntimeError`` (an ``Exception``), so it was already caught and unwound by the
pre-WOR-646 ``except Exception:`` — that is the documented post-flight recovery
contract. What this fix must preserve is its **exit code**: a ``typer.Exit(87)``
must still leave the process with code 87, never get swallowed, and never get
mis-converted into a Ctrl-C abort by the new ``CancelledError`` handling.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import signal
import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest
import typer
import typer._click.termui as click_termui
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.console import WorthlessConsole
from worthless.cli.sentinel import is_partial, read_sentinel

from tests.conftest import make_repo as _repo
from tests.helpers import fake_anthropic_key, fake_key

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def two_key_env(tmp_path: Path) -> Path:
    """A ``.env`` with two fresh, unprotected provider keys."""
    env = tmp_path / ".env"
    oa = fake_key("sk-" + "proj-", seed="sigint-atomicity-openai")
    an = fake_anthropic_key()
    env.write_text(f"OPENAI_API_KEY={oa}\nANTHROPIC_API_KEY={an}\n")
    return env


def _sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inject_signal_after_pass1(monkeypatch: pytest.MonkeyPatch, signum: int) -> None:
    """Fire *signum* at this process right after Pass-1 populates ``planned``.

    Wrapping the real ``_pass1_db_writes`` guarantees the DB rows exist (and are
    recorded in ``planned``) before the signal lands — the precise checkpoint
    where the compensating unwind is the only thing standing between an
    interrupt and orphaned rows. The loop signal handler armed by ``_lock_async``
    before Pass-1 cancels the task at the trailing ``await``.
    """
    import worthless.cli.commands.lock as lock_mod

    real_pass1 = lock_mod._pass1_db_writes

    async def _pass1_then_signal(*args: object, **kwargs: object) -> None:
        await real_pass1(*args, **kwargs)
        os.kill(os.getpid(), signum)
        # Yield to the loop so the wakeup-fd callback runs ``task.cancel()``;
        # the resulting CancelledError surfaces here, inside _lock_async's try.
        await asyncio.sleep(0.5)

    monkeypatch.setattr(lock_mod, "_pass1_db_writes", _pass1_then_signal)


def _shard_rows(home_dir: WorthlessHome) -> list:
    if not home_dir.db_path.exists():
        return []
    conn = sqlite3.connect(str(home_dir.db_path))
    try:
        return conn.execute("SELECT key_alias FROM shards").fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 1. Interrupt mid-lock → DB rolled back + .env untouched
# ---------------------------------------------------------------------------


class TestSignalDuringLockRollsBack:
    @pytest.mark.parametrize(
        "signum",
        [signal.SIGINT, signal.SIGTERM],
        ids=["SIGINT", "SIGTERM"],
    )
    def test_signal_after_pass1_unwinds_db_and_leaves_env_identical(
        self,
        home_dir: WorthlessHome,
        two_key_env: Path,
        monkeypatch: pytest.MonkeyPatch,
        signum: int,
    ) -> None:
        pre_sha = _sha256_of(two_key_env)
        _inject_signal_after_pass1(monkeypatch, signum)

        result = runner.invoke(
            app,
            ["lock", "--env", str(two_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

        # An interrupt is never a clean success.
        assert result.exit_code != 0, result.output

        # DB fully rolled back: zero enrollments, zero shard rows.
        enrollments = asyncio.run(_repo(home_dir).list_enrollments())
        assert enrollments == [], (
            f"orphaned enrollments after {signal.Signals(signum).name}: {enrollments!r}"
        )
        assert _shard_rows(home_dir) == [], (
            f"orphaned shard rows after {signal.Signals(signum).name}"
        )

        # .env byte-identical: the interrupt landed before the atomic rewrite.
        assert _sha256_of(two_key_env) == pre_sha, (
            ".env was mutated by an interrupted lock — rewrite must not have run"
        )


# ---------------------------------------------------------------------------
# 2. Regression: a post-commit typer.Exit must NOT roll back a good lock
# ---------------------------------------------------------------------------


class TestNonInterruptExitCodePreserved:
    def test_typer_exit_in_try_keeps_its_exit_code(
        self,
        home_dir: WorthlessHome,
        two_key_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A ``typer.Exit(87)`` raised inside the lock try-block must still exit
        87 — never swallowed, and never mis-converted to a Ctrl-C abort.

        ``typer.Exit`` is an ``Exception`` subclass, so the broadened
        ``except (Exception, KeyboardInterrupt, CancelledError)`` catches it via
        the same ``Exception`` arm the pre-WOR-646 code used; the
        ``isinstance(exc, CancelledError)`` guard must leave its exit code
        untouched. (Whether the DB rows unwind here is pre-existing post-flight
        behavior, not what this test pins.)
        """
        import worthless.cli.commands.lock as lock_mod

        real_rewrite = lock_mod._batch_rewrite

        def _rewrite_then_exit(*args: object, **kwargs: object) -> None:
            # Real rewrite commits .env; the Exit mimics the OpenClaw
            # post-flight gate firing AFTER lock-core is fully committed.
            real_rewrite(*args, **kwargs)
            raise typer.Exit(code=87)

        monkeypatch.setattr(lock_mod, "_batch_rewrite", _rewrite_then_exit)

        result = runner.invoke(
            app,
            ["lock", "--env", str(two_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

        # 87 proves: not swallowed (would be 0) and not converted to the
        # interrupt's abort exit (would be 1) by the new CancelledError path.
        assert result.exit_code == 87, result.output


class TestDbWriteBeforeEnvRewriteOrdering:
    """WOR-277 item 5: shard DB writes (Pass-1) must land BEFORE the .env
    rewrite — so a failure between the two steps leaves the real key still
    readable in the original .env, never destroyed with no working shard
    to recover it from. Proven here by making the rewrite step itself fail
    outright (not a signal — a genuine write failure) and asserting the
    original file survives untouched and the DB unwinds to zero rows."""

    def test_batch_rewrite_failure_leaves_original_env_recoverable(
        self,
        home_dir: WorthlessHome,
        two_key_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import worthless.cli.commands.lock as lock_mod

        original_env_bytes = two_key_env.read_bytes()

        def _rewrite_boom(*args: object, **kwargs: object) -> None:
            raise OSError("simulated disk failure during .env rewrite")

        monkeypatch.setattr(lock_mod, "_batch_rewrite", _rewrite_boom)

        result = runner.invoke(
            app,
            ["lock", "--env", str(two_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

        assert result.exit_code != 0
        # The real key must still be sitting in the original .env, in
        # plaintext and fully recoverable — "still on disk" beats "lost
        # forever" when the rewrite step can't be trusted to have run.
        assert two_key_env.read_bytes() == original_env_bytes

        # Pass-1's DB writes must have been unwound — no orphan shard rows
        # for keys whose .env was never actually rewritten to point at them.
        repo = _repo(home_dir)
        aliases = asyncio.run(repo.list_keys())
        assert aliases == [], f"expected DB rollback to leave zero rows, found {aliases}"


# ---------------------------------------------------------------------------
# 3. Attack journey: mashed Ctrl-C must not abort the rollback
# ---------------------------------------------------------------------------


class TestSecondSignalDuringUnwind:
    def test_mashed_signal_mid_rollback_still_fully_unwinds(
        self,
        home_dir: WorthlessHome,
        two_key_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A user mashing Ctrl-C: the FIRST signal triggers the unwind, a SECOND
        arriving mid-rollback must be absorbed (one-shot handler) — never abort
        the DB deletes partway and orphan the very rows being removed.
        """
        import worthless.cli.commands.lock as lock_mod

        _inject_signal_after_pass1(monkeypatch, signal.SIGINT)

        real_unwind = lock_mod._compensating_unwind

        async def _unwind_with_second_signal(repo: object, planned: object) -> list:
            # Fire a second interrupt and yield so the loop runs the handler.
            # With a one-shot handler this is a no-op; without it, task.cancel()
            # would re-fire here and abort the real unwind below.
            os.kill(os.getpid(), signal.SIGINT)
            await asyncio.sleep(0)
            return await real_unwind(repo, planned)  # type: ignore[arg-type]

        monkeypatch.setattr(lock_mod, "_compensating_unwind", _unwind_with_second_signal)

        result = runner.invoke(
            app,
            ["lock", "--env", str(two_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

        assert result.exit_code != 0, result.output
        enrollments = asyncio.run(_repo(home_dir).list_enrollments())
        assert enrollments == [], (
            f"second Ctrl-C aborted the rollback — orphaned rows: {enrollments!r}"
        )
        assert _shard_rows(home_dir) == [], "second Ctrl-C left orphan shard rows"


# ---------------------------------------------------------------------------
# 4. Degrade journey: signal arming unavailable → lock still works
# ---------------------------------------------------------------------------


class TestSignalArmingDegradesGracefully:
    def test_non_main_thread_lock_still_succeeds(
        self,
        home_dir: WorthlessHome,
        two_key_env: Path,
    ) -> None:
        """Off the main thread (and on Windows' ProactorEventLoop),
        ``loop.add_signal_handler`` raises — the arming is best-effort and must
        not break a normal lock. Running the command in a worker thread
        reproduces that RuntimeError path without monkeypatching asyncio.
        """
        box: dict[str, object] = {}

        def _run() -> None:
            box["result"] = runner.invoke(
                app,
                ["lock", "--env", str(two_key_env)],
                env={"WORTHLESS_HOME": str(home_dir.base_dir)},
            )

        t = threading.Thread(target=_run)
        t.start()
        t.join()

        result = box["result"]
        assert result.exit_code == 0, result.output  # type: ignore[union-attr]
        enrollments = asyncio.run(_repo(home_dir).list_enrollments())
        assert len(enrollments) == 2, (
            f"degraded (no-signal) lock did not enroll both keys: {enrollments!r}"
        )


# ---------------------------------------------------------------------------
# 5. DETERMINISTIC seam: interrupt the exact commit→record window, 100% of runs
# ---------------------------------------------------------------------------


class TestDeterministicCommitRecordSeam:
    def test_interrupt_mid_atomic_write_leaves_no_partial(
        self,
        home_dir: WorthlessHome,
        two_key_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Interrupt INSIDE the atomic Pass-1 write — it must leave no row at all.

        Part 2 folds a key's shard + enrollment into ONE transaction and records
        the rollback entry BEFORE issuing it. We fire SIGINT with no intervening
        yield, so the cancellation is delivered at the first ``await`` inside the
        atomic write (connect / BEGIN / execute) — mid-transaction, before its
        single COMMIT. The connection closes without committing, so the key
        leaves ZERO rows: never the orphaned shard (shard committed, enrollment
        missing) the pre-Part-2 two-commit sequence produced under a real SIGINT.

        Deterministic: reproduces on 100% of runs (vs the chaos storm's ~3%).
        """
        from worthless.storage.repository import ShardRepository

        real_atomic = ShardRepository.upsert_locked_shard_and_enroll
        fired = {"done": False}

        async def _interrupt_mid_atomic_write(self, *args: object, **kwargs: object):  # noqa: ANN001
            if not fired["done"]:
                fired["done"] = True
                # No yield before the real call: the cancel lands at the first
                # await INSIDE it — mid-transaction, before the lone COMMIT.
                os.kill(os.getpid(), signal.SIGINT)
            return await real_atomic(self, *args, **kwargs)

        monkeypatch.setattr(
            ShardRepository, "upsert_locked_shard_and_enroll", _interrupt_mid_atomic_write
        )

        result = runner.invoke(
            app,
            ["lock", "--env", str(two_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )
        assert result.exit_code != 0, result.output

        shard_aliases = {r[0] for r in _shard_rows(home_dir)}
        enrolled = {e.key_alias for e in asyncio.run(_repo(home_dir).list_enrollments())}
        # Atomic + record-first ⇒ shards and enrollments move together: no shard
        # without an enrollment (orphan), no enrollment without a shard.
        assert shard_aliases == enrolled, (
            "interrupt mid-atomic-write left a partial state — "
            f"shards={shard_aliases!r} enrollments={enrolled!r}"
        )


# ---------------------------------------------------------------------------
# 6. Adversarial surface: when the ROLLBACK ITSELF fails, the user must be told
#    how to recover (surface-test-audit gap — the only path that prints the
#    "run `worthless unlock --all`" recovery instruction).
# ---------------------------------------------------------------------------


class TestUnwindFailureWarnsToReconcile:
    def test_rollback_failure_warns_user_to_run_unlock_all(
        self,
        home_dir: WorthlessHome,
        two_key_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Interrupt + the compensating rollback ALSO fails → the user must see the
        recovery instruction, not be left with stale rows and no guidance.

        Fires SIGINT after Pass-1 (so ``planned`` is populated and the unwind runs),
        then sabotages ``delete_enrollment`` so ``_compensating_unwind`` accumulates
        errors and the "Database may contain N stale row(s) … run `worthless unlock
        --all`" warning fires. This is the only code path that prints that message.
        """
        from worthless.storage.repository import ShardRepository

        _inject_signal_after_pass1(monkeypatch, signal.SIGINT)

        async def _delete_boom(self, *args: object, **kwargs: object) -> bool:
            raise RuntimeError("delete failed during compensating unwind")

        monkeypatch.setattr(ShardRepository, "delete_enrollment", _delete_boom)

        result = runner.invoke(
            app,
            ["lock", "--env", str(two_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

        assert result.exit_code != 0, result.output
        # print_warning routes through Rich, which soft-wraps at the console width
        # and can split a token across lines — collapse all whitespace first, then
        # require the CONTIGUOUS recovery phrase so a future refactor can't satisfy
        # the check by scattering the two tokens across unrelated messages.
        normalized = " ".join(result.output.split())
        assert "stale row(s); run `worthless unlock --all` to reconcile" in normalized, (
            "after a failed rollback the user was NOT shown the single recovery "
            f"instruction; output was:\n{result.output}"
        )


# ---------------------------------------------------------------------------
# 7. worthless-3clz: Ctrl-C after the keys are committed must be answered
# ---------------------------------------------------------------------------
#
# Once Pass-1 commits and ``.env`` is rewritten, the OpenClaw steps run
# synchronously: a lock on OpenClaw's config file (``openclaw/config.py``
# ``flock``, unbounded) and a reload wait of up to 15s (``lock.py``
# ``time.sleep`` poll). asyncio's handler only queues a press for the event
# loop, which that stretch never yields to — so Ctrl-C was dropped and the lock
# carried on. The stand-in below has the same shape: child-free, blocking, with
# a real SIGINT landing mid-call. Keys are already locked there, so the answer
# is to stop, keep the lock, and say so — never unwind rows ``.env`` now needs.

_BLOCK_S = 5.0  # how long the stand-in OpenClaw step blocks
_ANSWER_WITHIN_S = 3.0  # a pressed Ctrl-C must end the lock well before that


def _openclaw_step_blocks_then_ctrl_c(
    monkeypatch: pytest.MonkeyPatch, *, step: str, presses: int = 1
) -> list[float]:
    """Swap an OpenClaw *step* for a child-free block; Ctrl-C lands mid-block.

    Returns a list that receives the monotonic time of the first press.
    """
    import worthless.cli.commands.lock as lock_mod

    # A pre-flight gate, so the post-flight re-audit runs; it no-ops unless it
    # is the step under test.
    monkeypatch.setattr(lock_mod, "_openclaw_audit_preflight", lambda *_a, **_k: object())
    monkeypatch.setattr(lock_mod, "_openclaw_audit_postflight", lambda *_a, **_k: None)

    pressed_at: list[float] = []

    def _press() -> None:
        pressed_at.append(time.monotonic())
        for _ in range(presses):
            os.kill(os.getpid(), signal.SIGINT)

    def _blocking_openclaw_step(*_args: object, **_kwargs: object) -> int:
        threading.Timer(0.2, _press).start()
        time.sleep(_BLOCK_S)
        return 0

    monkeypatch.setattr(lock_mod, step, _blocking_openclaw_step)
    return pressed_at


def _invoke_lock_sandboxed(
    home_dir: WorthlessHome,
    env_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *flags: str,
):  # noqa: ANN202 — click's Result
    # A real ~/.openclaw on the dev box would trip the proxy-health gate first;
    # OpenClaw env vars from the developer's shell would point lock at it too.
    """Run ``worthless [flags] lock`` in-process with HOME and OpenClaw env sandboxed."""
    monkeypatch.chdir(tmp_path)
    for var in [v for v in os.environ if v.startswith("OPENCLAW_")] + ["PI_CODING_AGENT_DIR"]:
        monkeypatch.delenv(var, raising=False)
    return runner.invoke(
        app,
        [*flags, "lock", "--env", str(env_file)],
        env={"WORTHLESS_HOME": str(home_dir.base_dir), "HOME": str(tmp_path)},
    )


def _assert_still_locked(
    home_dir: WorthlessHome, env_file: Path, pre_sha: str, output: str
) -> None:
    """Keys stay committed: 2 enrollments, 2 shard rows, and ``.env`` rewritten."""
    unwound = (
        "something after the commit unwound the DB rows that the rewritten .env "
        "now depends on — keys are unrecoverable."
    )
    enrollments = asyncio.run(_repo(home_dir).list_enrollments())
    assert len(enrollments) == 2, f"{unwound} enrollments={enrollments!r}\n{output}"
    shards = _shard_rows(home_dir)
    assert len(shards) == 2, f"{unwound} shard rows={shards!r}\n{output}"
    assert _sha256_of(env_file) != pre_sha, f".env was not left locked:\n{output}"


def _assert_interrupt_recorded(home_dir: WorthlessHome) -> None:
    """``worthless status`` must keep reporting OpenClaw as unfinished."""
    sentinel = read_sentinel(home_dir.base_dir)
    assert is_partial(sentinel), sentinel
    assert [e["code"] for e in sentinel["events"]] == ["openclaw.interrupted"], sentinel


class TestCtrlCAfterCommitIsAnswered:
    @pytest.mark.parametrize(
        ("step", "presses"),
        [
            ("_apply_openclaw", 1),
            ("_apply_openclaw", 3),
            # Runs after the rewrite too. A press used to kill the audit, trigger
            # its retry (deaf again), then exit 87 down the unwind path.
            ("_openclaw_audit_postflight", 1),
        ],
        ids=["openclaw-wiring", "mashed", "postflight-reaudit"],
    )
    def test_ctrl_c_after_commit_stops_and_keeps_keys_locked(
        self,
        step: str,
        presses: int,
        home_dir: WorthlessHome,
        two_key_env: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Ctrl-C in an OpenClaw step after the commit: answered, exit 130, keys kept."""
        import worthless.cli.commands.lock as lock_mod

        pre_sha = _sha256_of(two_key_env)
        pressed_at = _openclaw_step_blocks_then_ctrl_c(monkeypatch, step=step, presses=presses)
        synced: list[object] = []
        monkeypatch.setattr(lock_mod, "_sync_fernet_after_lock", synced.append)
        scans: list[object] = []
        monkeypatch.setattr(lock_mod, "_maybe_prompt_code_scan", scans.append)

        result = _invoke_lock_sandboxed(home_dir, two_key_env, tmp_path, monkeypatch)

        assert pressed_at, f"{step} never ran:\n{result.output}"
        answered_in = time.monotonic() - pressed_at[0]
        assert answered_in < _ANSWER_WITHIN_S, (
            f"Ctrl-C was ignored for {answered_in:.1f}s while {step} blocked "
            f"(exit {result.exit_code}) — worthless-3clz.\n{result.output}"
        )
        assert result.exit_code == 130, result.output
        assert "interrupted" in result.output.lower(), result.output
        # The OpenClaw steps may not have scrubbed the plaintext key yet: never
        # let the message read as "all safe".
        assert "may still be using your real key" in " ".join(result.output.split()), result.output
        _assert_still_locked(home_dir, two_key_env, pre_sha, result.output)
        _assert_interrupt_recorded(home_dir)
        # Before this fix the press was ignored and the lock ran on to its Fernet
        # sync. Interrupting must not newly skip it: the keys ARE locked.
        assert len(synced) == 1, "interrupted lock skipped the post-lock Fernet sync"
        # The user asked to stop: no 30s source scan, no "Scan now?" prompt after it.
        assert scans == [], "an interrupted lock still started the post-lock code scan"

    def test_quiet_lock_still_answers_ctrl_c(
        self,
        home_dir: WorthlessHome,
        two_key_env: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``-q`` hides chatter, not the answer to a key the user just pressed."""
        _openclaw_step_blocks_then_ctrl_c(monkeypatch, step="_apply_openclaw")

        result = _invoke_lock_sandboxed(home_dir, two_key_env, tmp_path, monkeypatch, "-q")

        assert result.exit_code == 130, result.output
        assert "interrupted" in result.output.lower(), (
            f"quiet mode swallowed the answer to Ctrl-C:\n{result.output!r}"
        )


class _InteractiveStdin:
    """A terminal, as far as ``sys.stdin.isatty()`` is concerned."""

    def isatty(self) -> bool:
        return True

    def __getattr__(self, name: str) -> object:
        return getattr(sys.__stdin__, name)


class TestCtrlCAtAdoptionPromptKeepsKeys:
    @pytest.mark.parametrize("key", ["ctrl-c", "ctrl-d"])
    def test_ctrl_c_at_the_real_adoption_prompt_keeps_keys(
        self,
        key: str,
        home_dir: WorthlessHome,
        two_key_env: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The "Route them through Worthless?" prompt runs after ``.env`` is
        rewritten. Click turns Ctrl-C (and Ctrl-D) there into ``typer.Abort`` —
        ``except (KeyboardInterrupt, EOFError): raise Abort()`` — a RuntimeError
        the unwind ``except Exception`` would catch, deleting rows the rewritten
        ``.env`` already needs — on main, Ctrl-D did exactly that. Real prompt;
        Ctrl-C is a real SIGINT while it waits, Ctrl-D is end of input."""
        import worthless.cli.commands.lock as lock_mod

        pre_sha = _sha256_of(two_key_env)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path))
        # Reach the real typer.confirm: an interactive shell + one foreign entry.
        monkeypatch.setattr(sys, "stdin", _InteractiveStdin())
        monkeypatch.setattr(
            lock_mod._openclaw_integration, "preview_unrecognized", lambda *_a, **_k: ["openai"]
        )

        def _user_presses_key_while_prompted(_prompt: str) -> str:
            if key == "ctrl-d":
                raise EOFError  # what input() raises on end of input
            os.kill(os.getpid(), signal.SIGINT)
            time.sleep(_BLOCK_S)  # still waiting for an answer
            return "n"

        monkeypatch.setattr(click_termui, "visible_prompt_func", _user_presses_key_while_prompted)

        with pytest.raises(typer.Exit) as exc:
            lock_mod._lock_keys(two_key_env, home_dir)

        assert exc.value.exit_code == 130
        _assert_still_locked(home_dir, two_key_env, pre_sha, "")
        _assert_interrupt_recorded(home_dir)


class TestExtraCtrlCBeforeAnyKeyIsTouched:
    def test_extra_press_before_first_write_does_not_claim_a_rollback(
        self,
        home_dir: WorthlessHome,
        two_key_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """User ruling (2026-10-08): before any key is touched, Ctrl-C just exits.
        A second press there has nothing to roll back, so it must not say it is
        rolling back."""
        import worthless.cli.commands.lock as lock_mod

        pre_sha = _sha256_of(two_key_env)
        real_pass1 = lock_mod._pass1_db_writes

        async def _two_presses_before_any_write(*args: object, **kwargs: object) -> None:
            os.kill(os.getpid(), signal.SIGINT)
            os.kill(os.getpid(), signal.SIGINT)
            await asyncio.sleep(0.5)  # both presses are handled here, before any write
            await real_pass1(*args, **kwargs)

        monkeypatch.setattr(lock_mod, "_pass1_db_writes", _two_presses_before_any_write)

        result = runner.invoke(
            app,
            ["lock", "--env", str(two_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

        assert result.exit_code != 0, result.output
        assert "still rolling back" not in result.output.lower(), result.output
        assert _shard_rows(home_dir) == [], result.output
        assert _sha256_of(two_key_env) == pre_sha, result.output


class TestSecondCtrlCDuringRollbackIsNeverSilent:
    def test_second_ctrl_c_mid_rollback_explains_and_rollback_finishes(
        self,
        home_dir: WorthlessHome,
        two_key_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """User ruling (2026-10-08): once a key is touched, a second Ctrl-C does
        not cut the rollback short — but it must say why it is not stopping."""
        import worthless.cli.commands.lock as lock_mod

        _inject_signal_after_pass1(monkeypatch, signal.SIGINT)
        real_unwind = lock_mod._compensating_unwind

        async def _unwind_with_second_signal(repo: object, planned: object) -> list:
            os.kill(os.getpid(), signal.SIGINT)
            await asyncio.sleep(0)
            return await real_unwind(repo, planned)  # type: ignore[arg-type]

        monkeypatch.setattr(lock_mod, "_compensating_unwind", _unwind_with_second_signal)

        result = runner.invoke(
            app,
            ["lock", "--env", str(two_key_env)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

        assert "still rolling back" in result.output.lower(), (
            f"a second Ctrl-C during the rollback was silently swallowed:\n{result.output}"
        )
        assert asyncio.run(_repo(home_dir).list_enrollments()) == [], result.output
        assert _shard_rows(home_dir) == [], result.output


class TestNothingRollsBackAfterTheCommit:
    """Defence in depth (worthless-3clz review): once ``.env`` is rewritten, its
    DB rows are load-bearing. Only post-flight's documented ``typer.Exit(87)``
    may still roll them back; nothing else — not a queued press, not a crash."""

    def test_handler_never_cancels_once_committed(self) -> None:
        """Cancels once before the commit, never after; only post-flight 87 may unwind."""
        import worthless.cli.commands.lock as lock_mod

        cancels: list[int] = []

        class _Task:
            def cancel(self) -> None:
                cancels.append(1)

        console = WorthlessConsole()
        before = lock_mod._LockInterrupts(_Task(), [], console)  # type: ignore[arg-type]
        before()
        assert cancels == [1], "first press before the commit must cancel"

        cancels.clear()
        after = lock_mod._LockInterrupts(_Task(), [], console)  # type: ignore[arg-type]
        after.committed = True
        after()
        assert cancels == [], "a press queued for the loop cancelled AFTER the commit"
        assert not after.may_unwind(RuntimeError("boom"))
        assert not after.may_unwind(typer.Exit(code=87)), "any Exit may not unwind keys"
        assert after.may_unwind(lock_mod._PostflightRefused(code=87))  # documented path
        assert before.may_unwind(RuntimeError("boom"))

    def test_crash_after_commit_keeps_the_keys(
        self,
        home_dir: WorthlessHome,
        two_key_env: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unexpected crash after the commit fails the lock but keeps the keys."""
        import worthless.cli.commands.lock as lock_mod

        pre_sha = _sha256_of(two_key_env)

        def _openclaw_step_crashes(*_a: object, **_k: object) -> int:
            raise RuntimeError("unexpected OpenClaw-side crash after the commit")

        monkeypatch.setattr(lock_mod, "_openclaw_steps", _openclaw_step_crashes)

        result = _invoke_lock_sandboxed(home_dir, two_key_env, tmp_path, monkeypatch)

        assert result.exit_code != 0, result.output
        _assert_still_locked(home_dir, two_key_env, pre_sha, result.output)
