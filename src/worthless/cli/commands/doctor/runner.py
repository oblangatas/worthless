"""WOR-464: doctor JSON-mode runner.

The text-mode runner (`_doctor_run` in the package `__init__.py`) stays
byte-identical to v0.3.6's output. JSON mode is wired here so any future
``--json``-specific behaviour does not bleed into the text path.

Contract:
  Exactly ONE ``typer.echo(json.dumps(...))`` call. No other prints.
  Logging goes to stderr per Python logging defaults; tests assert
  stdout is parseable JSON.
"""

from __future__ import annotations

import json

import typer

from worthless.cli.bootstrap import acquire_lock, get_home
from worthless.cli.commands.doctor.registry import (
    CheckContext,
    CheckResult,
    ensure_registered,
)
from worthless.cli.commands.doctor.schema import SCHEMA_VERSION
from worthless.cli.keystore import read_fernet_key
from worthless.storage.repository import ShardRepository


def _aggregate(results: list[CheckResult]) -> dict:
    """Combine per-check results into the top-level JSON envelope.

    ``ok`` is True iff every check returned status ``ok``. ``warn`` and
    ``error`` rows both count against ``ok`` so JSON consumers can use a
    single boolean as their CI gate.
    """
    total = len(results)
    warn = sum(1 for r in results if r.get("status") == "warn")
    error = sum(1 for r in results if r.get("status") == "error")
    fixed = sum(len(r.get("fixed") or []) for r in results)
    return {
        "schema_version": SCHEMA_VERSION,
        "ok": warn == 0 and error == 0,
        "checks": results,
        "summary": {
            "total": total,
            "warn": warn,
            "error": error,
            "fixed": fixed,
        },
    }


def _doctor_run_json(*, fix: bool, dry_run: bool) -> None:
    """Run every registered check and emit a single JSON document.

    Note: the legacy single-doctor flock (``_doctor_lock``) is intentionally
    NOT acquired here. JSON consumers may script multiple read-only
    invocations and the iCloud-migration state machine that flock guards
    does not fire in JSON mode (no migration is performed in --json).
    """
    home = get_home()
    fernet_key = bytearray(read_fernet_key(home.base_dir))  # SR-01: mutable for zeroing
    repo = ShardRepository(str(home.db_path), fernet_key)

    with acquire_lock(home):
        ctx = CheckContext(home=home, repo=repo, fix=fix, dry_run=dry_run)
        results: list[CheckResult] = []
        for check_module in ensure_registered():
            try:
                results.append(check_module.run(ctx))
            except Exception as exc:  # noqa: BLE001 - SR-04 scrub
                results.append(
                    CheckResult(
                        check_id=getattr(check_module, "check_id", "unknown"),
                        status="error",
                        findings=[],
                        summary=f"check crashed: {type(exc).__name__}",
                        fixable=False,
                        fixed=[],
                        skipped_reason=None,
                    )
                )

    typer.echo(json.dumps(_aggregate(results)))
