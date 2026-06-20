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
import threading
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

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
