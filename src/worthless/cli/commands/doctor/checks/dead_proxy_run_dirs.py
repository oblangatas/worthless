"""worthless-7qb6: run/<pid>/ folders left by a proxy that is no longer running.

The proxy writes both key shares to ``~/.worthless/run/<pid>/`` and deletes
the folder on a clean exit. A crash or a kill leaves it behind, and
``share_a.bin`` + ``share_b.bin`` together rebuild the secret.

Repair: delete the folder. Safe — its process is gone, so nothing reads it.
A folder whose PID is alive (or owned by another user) is never touched.

Does NOT: securely erase (unlink only), or see past PID reuse — a dead
proxy's PID taken by an unrelated live process is left alone.
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

from worthless.cli.commands.doctor.checks._helpers import maybe_fix
from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.cli.sidecar_lifecycle import _RUN_SUBDIR
from worthless.cli.bootstrap import WorthlessHome

logger = logging.getLogger(__name__)
check_id = "dead_proxy_run_dirs"


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # alive, owned by another user
        return True
    return True


def find_dead_run_dirs(home: WorthlessHome) -> list[Path]:
    """``run/<pid>`` folders whose process no longer exists."""
    if os.name != "posix":
        return []
    try:
        entries = list((home.base_dir / _RUN_SUBDIR).iterdir())
    except OSError:
        return []
    dead = [
        p
        for p in entries
        if p.is_dir() and p.name.isdigit() and int(p.name) > 0 and not _pid_alive(int(p.name))
    ]
    return sorted(dead, key=lambda p: int(p.name))


def remove_run_dirs(run_dirs: list[Path]) -> list[Path]:
    """Delete each folder; return the ones that are gone afterwards."""
    removed = []
    for run_dir in run_dirs:
        shutil.rmtree(run_dir, ignore_errors=True)
        if run_dir.exists():
            logger.warning("Could not delete stopped proxy folder %s", run_dir)
        else:
            removed.append(run_dir)
    return removed


def run(ctx: CheckContext) -> CheckResult:
    dead = find_dead_run_dirs(ctx.home)
    findings = [{"run_dir": str(p), "pid": int(p.name)} for p in dead]
    status = "warn" if dead else "ok"
    fixed, status = maybe_fix(
        ctx, dead, lambda items: [{"run_dir": str(p)} for p in remove_run_dirs(items)], status
    )
    n = len(dead)
    return CheckResult(
        check_id=check_id,
        status=status,
        findings=findings,
        summary=(
            f"Key shares left by a stopped proxy in {n} folder{'s' if n != 1 else ''}"
            if n
            else "No folders left by a stopped proxy."
        ),
        fixable=True,
        fixed=fixed,
        skipped_reason=None,
    )
