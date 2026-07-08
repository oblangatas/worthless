"""WOR-797: enumerate credential surfaces ``lock`` cannot shard.

Worthless shards a metered API key. Most credentials OpenClaw actually
caches for CLI-based providers (Claude Code, Codex, Gemini, MiniMax) are
OAuth refresh tokens, and OpenClaw's own ``auth-profiles.json`` can hold
``oauth``/``token`` entries too — none of these are a static API key, so
none can be routed through the split-the-key proxy. This check enumerates
all 8 such surfaces (see :mod:`worthless.openclaw.unshardable_credentials`
for the full source-verified list) so the user gets an honest "the proxy
isn't load-bearing for this credential" signal instead of assuming ``lock``
already covers it, and can clear any of them via ``--fix``.

Vertex ADC is the one surface with no in-app re-login flow of its own
(real OpenClaw throws instead of returning ``null`` on a missing ADC file) —
its ``fixed`` entry carries an explicit ``gcloud auth
application-default login`` remediation string.
"""

from __future__ import annotations

from worthless.cli.commands.doctor.registry import CheckContext, CheckResult
from worthless.openclaw.unshardable_credentials import (
    VERTEX_REAUTH_COMMAND,
    clear_unshardable_credential,
    detect_unshardable_credentials,
)

check_id = "unshardable_credentials"


def _clear_finding(finding) -> dict | None:  # noqa: ANN001 - UnshardableCredentialFinding
    """Clear one finding; return its ``fixed`` entry, or ``None`` if it's
    still present. Extracted to keep :func:`run` under xenon's budget.
    """
    if not clear_unshardable_credential(finding):
        return None
    entry = {"surface_id": finding.surface_id, "description": finding.description}
    if finding.needs_vertex_reauth_notice:
        entry["remediation"] = f"cleared — re-authenticate with: {VERTEX_REAUTH_COMMAND}"
    return entry


def _summarize(n: int) -> str:
    if n == 0:
        return "No unshardable OAuth/token credentials found."
    return (
        f"{n} unshardable credential{'s' if n != 1 else ''} found (OAuth/token — "
        "the proxy is not load-bearing for these; lock cannot protect them)"
    )


def run(ctx: CheckContext) -> CheckResult:
    findings_data = detect_unshardable_credentials()
    findings = [
        {"surface_id": f.surface_id, "description": f.description, "location": f.location}
        for f in findings_data
    ]

    fixed: list[dict] = []
    if ctx.fix and findings_data and not ctx.dry_run:
        fixed = [e for f in findings_data if (e := _clear_finding(f)) is not None]
    status = "ok" if len(fixed) == len(findings_data) else "warn"

    return CheckResult(
        check_id=check_id,
        status=status,
        findings=findings,
        summary=_summarize(len(findings_data)),
        fixable=True,
        fixed=fixed,
        skipped_reason=None,
    )
