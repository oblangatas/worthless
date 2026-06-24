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
import sqlite3

import typer

from worthless.cli.bootstrap import acquire_lock, get_home
from worthless.cli.commands.doctor.checks._remediation import PLAYBOOKS
from worthless.cli.commands.doctor.registry import (
    CheckContext,
    CheckResult,
    ensure_registered,
)
from worthless.cli.commands.doctor.schema import SCHEMA_VERSION
from worthless.cli.errors import WorthlessError
from worthless.cli.keystore import read_fernet_key
from worthless.storage.repository import ShardRepository


def _count_enrollments(home) -> int:  # noqa: ANN001 — WorthlessHome opaque here
    """Best-effort enrollment count straight from SQLite (no key needed).

    Used to size the 'fernet key missing' diagnosis when the key is gone and a
    ``ShardRepository`` can't be opened.
    """
    try:
        con = sqlite3.connect(str(home.db_path))
        try:
            return int(con.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0])
        finally:
            con.close()
    except Exception:  # noqa: BLE001 — diagnosis must never crash
        return -1  # count unavailable (e.g. corrupt DB) — distinct from a real "none"


def _fernet_missing_result(home) -> CheckResult:  # noqa: ANN001
    """Diagnose a broken install: fernet.key gone while enrollments remain.

    BUG-1: the locked keys can't be reconstructed, so the only way forward is a
    forced removal — surfaced here so ``doctor --json`` (a) doesn't crash and
    (b) points the user at ``worthless uninstall --force``.
    """
    n = _count_enrollments(home)
    # n < 0 = the count itself failed (e.g. corrupt DB) — still a broken,
    # unrecoverable install, NOT "0 enrollments". Only a confirmed 0 is a warn.
    count_phrase = "an unknown number of" if n < 0 else str(n)
    return CheckResult(
        check_id="fernet_key_missing",
        status="warn" if n == 0 else "error",
        findings=[
            {
                "issue": "fernet_key_missing",
                "enrollments": n,
                "message": (
                    f"fernet.key is missing but {count_phrase} enrollment(s) exist — the "
                    "locked keys cannot be reconstructed (unrecoverable)."
                ),
                "recommendation": "worthless uninstall --force",
            }
        ],
        summary=f"Fernet key missing; {count_phrase} enrollment(s) unrecoverable.",
        fixable=False,
        fixed=[],
        skipped_reason=None,
    )


def _broken_install_result() -> CheckResult:
    """Diagnose an install that can't even be opened — ``get_home()`` itself raised.

    BUG-1 (corrupt DB / unreadable bootstrap): ``get_home()`` runs DB init and
    throws WRTLS-103 before any check can run, so there is no ``home`` to count
    against. Mirror the text-mode handler: the locked keys can't be
    reconstructed, so the machine-facing diagnostic must still emit valid JSON
    pointing at the forced removal instead of crashing.
    """
    return CheckResult(
        check_id="broken_install",
        status="error",
        findings=[
            {
                "issue": "broken_install",
                "message": (
                    "Worthless can't be read (encryption key or database "
                    "missing/unreadable) — the locked keys cannot be reconstructed."
                ),
                "recommendation": "worthless uninstall --force",
            }
        ],
        summary="Worthless install unreadable; locked keys unrecoverable.",
        fixable=False,
        fixed=[],
        skipped_reason=None,
    )


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


def _stamp_remediation(results: list[CheckResult]) -> None:
    """Attach a static fix playbook to every finding of a failing check.

    Findings that already carry a ``remediation`` (e.g. openclaw's
    per-finding ones) are left untouched.
    """
    for r in results:
        if r.get("status") not in ("warn", "error"):
            continue
        play = PLAYBOOKS.get(r.get("check_id", ""))
        if not play:
            continue
        for finding in r.get("findings") or []:
            finding.setdefault("remediation", play)


def _explain_verdict(play: str) -> str:
    """The opening clause of a playbook — its plain-language verdict — for the catalog."""
    flat = play.replace("\n", " ")
    cut = len(flat)
    for sep in (" — ", ". "):
        i = flat.find(sep)
        if i != -1:
            cut = min(cut, i)
    verdict = flat[:cut].strip()
    if len(verdict) > 50:
        verdict = verdict[:49].rsplit(" ", 1)[0] + "…"
    return verdict


def _doctor_explain_catalog(*, err: bool = False) -> None:
    """List every check id with its one-line verdict (the `--explain list` view)."""
    typer.echo("Worthless doctor checks — `--explain <id>` shows the full fix:", err=err)
    for cid in sorted(PLAYBOOKS):
        typer.echo(f"  {cid:<17} {_explain_verdict(PLAYBOOKS[cid])}", err=err)


def _doctor_explain(check_id: str) -> None:
    """Print one check's fix playbook, the catalog for `list`/`all`, or
    the catalog + an error for an unknown id.

    AI-less and side-effect-free — no home/keyring/ctx needed, so it works
    even under WORTHLESS_FERNET_IPC_ONLY=1.
    """
    if check_id in ("list", "all"):
        _doctor_explain_catalog()
        return
    play = PLAYBOOKS.get(check_id)
    if play is None:
        typer.echo(f"Unknown check '{check_id}'.", err=True)
        _doctor_explain_catalog(err=True)
        raise typer.Exit(2)
    typer.echo(play)


def _doctor_run_json(*, fix: bool, dry_run: bool) -> None:
    """Run every registered check and emit a single JSON document.

    Note: the legacy single-doctor flock (``_doctor_lock``) is intentionally
    NOT acquired here. JSON consumers may script multiple read-only
    invocations and the iCloud-migration state machine that flock guards
    does not fire in JSON mode (no migration is performed in --json).
    """
    try:
        home = get_home()
    except WorthlessError:
        # BUG-1: the install itself can't be opened (corrupt DB / unreadable
        # bootstrap) — get_home() runs DB init and raises WRTLS-103 before any
        # check can run. Mirror the text path: emit valid JSON pointing at the
        # fix, never crash the machine-facing diagnostic.
        typer.echo(json.dumps(_aggregate([_broken_install_result()])))
        return
    try:
        fernet_key = bytearray(read_fernet_key(home.base_dir))  # SR-01: mutable for zeroing
    except WorthlessError:
        # BUG-1: the fernet key is unreadable (missing / corrupt) — a broken
        # install whose locked keys can't be reconstructed. Don't crash the
        # diagnostic; emit a single finding that points at the fix.
        typer.echo(json.dumps(_aggregate([_fernet_missing_result(home)])))
        return
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

    _stamp_remediation(results)
    typer.echo(json.dumps(_aggregate(results)))
