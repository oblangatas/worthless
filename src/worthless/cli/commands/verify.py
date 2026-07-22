"""``worthless verify`` — prove the gateway is alive and routing right now.

WOR-517, the final phase of the WOR-514 OpenClaw incident. Ido killed the
gateway and OpenClaw kept working off a cached token — with no signal that his
traffic was now unprotected. ``verify`` closes that gap: it fires a live
loopback bind-probe and reports GREEN only if the probe routes THIS INSTANT.

A cumulative counter (``requests_proxied``) can never say "now" — it stays
frozen when the gateway dies — so it is deliberately NOT the verdict driver.
GREEN is earned only by a fresh ``bind_probe_count`` delta, reusing lock's
proven ``_confirm_bind_aliases`` machinery.
"""

from __future__ import annotations

import json
import sys

import typer

from worthless.cli.commands.lock import _confirm_bind_aliases
from worthless.cli.commands.service._common import ServiceState
from worthless.cli.commands.service.proxy_state import detect_proxy_runtime
from worthless.cli.commands.status import _list_enrolled_keys, _resolve_home_for_status
from worthless.cli.console import get_console
from worthless.cli.errors import error_boundary

_LOOPBACK = "127.0.0.1"
_EXIT_RED = 73  # match status' degraded convention: a RED verdict exits non-zero
_HONESTY = (
    "Note: proves the proxy is live and routing now; does NOT prove OpenClaw "
    "isn't also bypassing on a cached token — see `worthless status`."
)


def _service_managed(service_state: ServiceState | None) -> bool:
    return service_state is not None and service_state != ServiceState.NOT_INSTALLED


def _evaluate(home) -> dict:  # noqa: ANN001 — WorthlessHome | None, opaque here
    """Compute the verdict without touching output. Returns a plain dict.

    Verdicts:
      * ``red`` / ``proxy_down`` — the gateway isn't running (the loud case).
      * ``yellow`` / ``nothing_locked`` — up, but no keys to protect yet.
      * ``green`` / ``routed`` — a live probe routed through the proxy just now.
      * ``red`` / <reason> — up + locked, but the probe did NOT prove routing
        (silent bypass, squatter, or unreachable).
    """
    state = detect_proxy_runtime(home, port=None) if home is not None else None
    if state is None or not state.running:
        managed = _service_managed(state.service_state) if state is not None else False
        return {
            "verdict": "red",
            "reason": "proxy_down",
            "healthy": False,
            "aliases": [],
            "service_managed": managed,
        }

    aliases = [k["alias"] for k in _list_enrolled_keys(home)]
    if not aliases:
        return {
            "verdict": "yellow",
            "reason": "nothing_locked",
            "healthy": True,
            "aliases": [],
            "service_managed": _service_managed(state.service_state),
        }

    confirm = _confirm_bind_aliases(aliases, host=_LOOPBACK, port=state.port)
    routed = confirm.get("status") == "pass"
    reason = "routed" if routed else (confirm.get("reason") or confirm.get("status") or "unproven")
    return {
        "verdict": "green" if routed else "red",
        "reason": reason,
        "healthy": True,
        # ponytail: the global tri-state gives one verdict for the whole probe
        # batch, so every alias shares it. Per-alias routed flags would need the
        # bind_probe_aliases path — add only if a user locks providers they want
        # verified independently.
        "aliases": [{"alias": a, "routed": routed} for a in aliases],
        "service_managed": _service_managed(state.service_state),
    }


def _print_human(v: dict) -> None:
    write = sys.stderr.write
    verdict, reason = v["verdict"], v["reason"]

    if verdict == "green":
        alias = v["aliases"][0]["alias"] if v["aliases"] else "?"
        write(f"GREEN — proxy is live and a request routed through it just now (alias: {alias}).\n")
        write(f"{_HONESTY}\n")
    elif verdict == "yellow":
        write("YELLOW — gateway is up, but nothing is locked yet.\n")
        write("Run `worthless lock` to protect your API keys.\n")
    elif reason == "proxy_down":
        write(
            "RED — gateway is DOWN. Any agent still holding a cached token may be "
            "sending your key in the clear right now.\n"
        )
        if v["service_managed"]:
            write("Restart it: `worthless service restart`.\n")
        else:
            write("Start it: `worthless service install` (autostart) or `worthless up`.\n")
    elif reason == "fail":
        write(
            "RED — the proxy answered but did NOT route the test request. Your "
            "traffic may be bypassing Worthless right now.\n"
        )
        write("Run `worthless doctor` to diagnose.\n")
    elif reason in ("proxy_unrecognised", "proxy_unrecognised_after"):
        write(
            "RED — the service on the proxy port isn't a Worthless proxy (a "
            "squatter). Routing is NOT proven.\n"
        )
        write("Run `worthless doctor` to diagnose.\n")
    else:
        write(f"RED — couldn't prove the proxy is routing ({reason}).\n")
        write("Run `worthless doctor`, or restart: `worthless service restart` / `worthless up`.\n")

    sys.stderr.flush()


def register_verify_commands(app: typer.Typer) -> None:
    """Register the ``verify`` command on the Typer app."""

    @app.command()
    @error_boundary
    def verify(
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Emit machine-readable JSON (alias for the top-level --json).",
        ),
    ) -> None:
        """Prove the gateway is alive and routing a request right now."""
        console = get_console()
        v = _evaluate(_resolve_home_for_status())

        if console.json_mode or json_output:
            payload = {
                "healthy": v["healthy"],
                "verdict": v["verdict"],
                "aliases": v["aliases"],
                "reason": v["reason"],
            }
            sys.stdout.write(json.dumps(payload) + "\n")
            sys.stdout.flush()
        else:
            _print_human(v)

        raise typer.Exit(code=_EXIT_RED if v["verdict"] == "red" else 0)
