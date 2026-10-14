"""worthless-7qb6: run/<pid>/ folders left by a proxy that is no longer running.

``worthless up`` / ``wrap`` writes both key shares to ``~/.worthless/run/<pid>/``
(``<pid>`` is the up/wrap process) and deletes the folder on a clean exit. A
crash or a kill leaves it behind, and ``share_a.bin`` + ``share_b.bin``
together rebuild the secret.

A folder counts as dead only when its PID is gone AND its ``sidecar.sock``
does not answer: killing ``up`` with -9 leaves the sidecar and proxy serving
from the folder (PR 699 review repro). While ``proxy.pid`` names a live
process nothing is deleted at all — a proxy whose socket fell back outside
``run/`` cannot be matched to its folder. Deletion re-checks each folder.

Does NOT: securely erase (unlink only); see past PID reuse (a reused PID
reads as alive, so the folder is kept); or protect a ``wrap`` killed with -9
whose socket fell back outside ``run/`` and that wrote no ``proxy.pid``.
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.commands.doctor.checks._helpers import maybe_fix
from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.cli.process import check_pid, pid_path, read_pid
from worthless.cli.sidecar_lifecycle import _RUN_SUBDIR
from worthless.sidecar.health import probe_socket

logger = logging.getLogger(__name__)
check_id = "dead_proxy_run_dirs"
STOP_PROXY_FIRST = (
    "A proxy is running; stop it with `worthless down`, then re-run `worthless doctor --fix`."
)


def _looks_dead(run_dir: Path) -> bool:
    return not check_pid(int(run_dir.name)) and not probe_socket(
        run_dir / "sidecar.sock", timeout=1.0
    )


def proxy_running(home: WorthlessHome) -> bool:
    info = read_pid(pid_path(home))
    return info is not None and check_pid(info[0])


def find_dead_run_dirs(home: WorthlessHome) -> list[Path]:
    """``run/<pid>`` folders whose process is gone and whose sidecar is silent."""
    if os.name != "posix":
        return []
    try:
        entries = list((home.base_dir / _RUN_SUBDIR).iterdir())
    except OSError:
        return []
    dead = [p for p in entries if p.is_dir() and p.name.isdigit() and _looks_dead(p)]
    return sorted(dead, key=lambda p: int(p.name))


def remove_run_dirs(home: WorthlessHome, run_dirs: list[Path]) -> list[Path]:
    """Delete each folder that still looks dead; never while a proxy runs."""
    if proxy_running(home):
        return []
    removed = []
    for run_dir in run_dirs:
        if not _looks_dead(run_dir):  # re-check: time passed since the scan
            continue
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
    skipped_reason = STOP_PROXY_FIRST if dead and proxy_running(ctx.home) else None
    fixed: list[dict] = []
    if skipped_reason is None:
        fixed, status = maybe_fix(
            ctx,
            dead,
            lambda items: [{"run_dir": str(p)} for p in remove_run_dirs(ctx.home, items)],
            status,
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
        skipped_reason=skipped_reason,
    )
