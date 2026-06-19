"""WOR-658: surface ``bind_confirmation`` state from the sentinel.

Lock writes a ``bind_confirmation`` block proving (or not proving) that the
rewritten OpenClaw entry routes through the proxy. Status already shows
DEGRADED on fail — this doctor check turns the same signal into a
diagnostic with a remediation hint, so the user who follows lock's
``Run `worthless doctor``` prompt actually gets a useful answer.

No ``--fix`` is offered: the remediation is to restart OpenClaw's daemon
(daemon-reload trigger is WOR-756 follow-up) or re-run ``worthless lock``.
"""

from __future__ import annotations

from typing import Literal

from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.cli.sentinel import read_sentinel

check_id = "bind_confirmation"

_CheckStatus = Literal["ok", "warn", "error"]


def _classify(sentinel: dict | None) -> tuple[_CheckStatus | None, str]:
    """Map the sentinel's ``bind_confirmation`` block to (status, summary).

    ``status`` is ``None`` when nothing user-actionable was found; the
    summary still names the state for JSON consumers.
    """
    if not sentinel:
        return None, "No sentinel — has `worthless lock` been run on this host?"
    bc = sentinel.get("bind_confirmation")
    if not isinstance(bc, dict):
        return None, "Sentinel predates WOR-658 — no bind-confirmation data."

    status = bc.get("status")
    if status == "pass":
        return None, "Proof-of-routing: PASS."

    if status == "fail":
        return "error", (
            "Proof-of-routing FAILED — the test request reached the proxy "
            "but the rewritten OpenClaw entry is NOT routing. Restart "
            "OpenClaw's daemon (its cached config still points at the old "
            "URL) or re-run `worthless lock`."
        )

    if status == "skipped":
        reason = bc.get("reason", "")
        if reason in ("proxy_unrecognised", "proxy_unrecognised_after"):
            return "warn", (
                "Proof-of-routing inconclusive — the service answering "
                "/healthz on the configured port isn't a worthless proxy. "
                "Check WORTHLESS_PORT, or stop the foreign service on that "
                "port and re-run `worthless lock`."
            )
        if reason in (
            "proxy_unhealthy_before",
            "proxy_unhealthy_after",
            "proxy_check_raised_before",
            "proxy_check_raised_after",
        ):
            return "warn", (
                "Proof-of-routing inconclusive — proxy wasn't healthy when "
                "lock ran. Start the proxy (`worthless up`) and re-run "
                "`worthless lock`."
            )
        if reason == "proxy_restarted":
            return "warn", (
                "Proof-of-routing inconclusive — proxy restarted mid-"
                "confirm. Re-run `worthless lock` once the proxy stabilises."
            )
        if reason == "synthetic_unreachable":
            return "warn", (
                "Proof-of-routing inconclusive — test request couldn't "
                "reach the proxy. Check WORTHLESS_PORT and re-run "
                "`worthless lock`."
            )

    return None, "Bind-confirmation state is fine."


def run(ctx: CheckContext) -> CheckResult:
    sentinel = read_sentinel(ctx.home.base_dir)
    status, summary = _classify(sentinel)

    if status is None:
        return CheckResult(
            check_id=check_id,
            status="ok",
            findings=[],
            summary=summary,
            fixable=False,
            fixed=[],
            skipped_reason=None,
        )

    bc = (sentinel or {}).get("bind_confirmation") or {}
    return CheckResult(
        check_id=check_id,
        status=status,
        findings=[
            {
                "bind_confirmation_status": bc.get("status"),
                "reason": bc.get("reason"),
                "remediation": ("restart OpenClaw daemon or re-run `worthless lock`"),
            }
        ],
        summary=summary,
        fixable=False,
        fixed=[],
        skipped_reason=None,
    )
