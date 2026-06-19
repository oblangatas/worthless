"""WOR-658 — direct unit coverage for ``_confirm_bind``, ``_coerce_counter``,
and ``_fire_synthetic_request`` defensive branches.

The existing ``test_lock_bind_confirmation.py`` drives lock end-to-end via
the CLI runner and pins the contract under happy / squatter / fail paths.
That harness can't easily exercise the defensive branches where:

* ``check_proxy_health`` itself **raises** before/after the synthetic fire.
* The proxy is recognised at the BEFORE read but vanishes from healthz at
  the AFTER read (a midstream restart between the two probes).
* ``_coerce_counter`` is fed a bool, a numeric string, or an alien type.
* ``_fire_synthetic_request`` gets a real network error from httpx.

These tests call the helpers directly so each defensive branch is exercised
without spinning the whole CLI. Sonar's ``new_coverage`` gate (80%) fails
without them — coverage on the new lines was 70.2% before.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import pytest

from worthless.cli.commands import lock as lock_mod


# ---------------------------------------------------------------------------
# _coerce_counter (lock.py)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        (True, 0),  # bool is intentionally rejected even though bool subclass int
        (False, 0),
        (0, 0),
        (42, 42),
        (-1, -1),  # negative ints pass through; delta-classify handles signs
        ("0", 0),
        ("100", 100),
        ("not-a-number", 0),
        ("", 0),
        (None, 0),
        ([], 0),  # alien type
        ({"x": 1}, 0),
    ],
)
def test_coerce_counter_handles_loose_json_shape(value, expected) -> None:  # noqa: ANN001
    """healthz JSON is loosely-typed; helper widens to a hard int."""
    assert lock_mod._coerce_counter(value) == expected


# ---------------------------------------------------------------------------
# _fire_synthetic_request (lock.py)
# ---------------------------------------------------------------------------


def test_fire_synthetic_request_returns_false_on_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When httpx raises a network error, the helper must return False
    (reached=0) so ``_confirm_bind`` classifies skipped, not fail."""

    class _RaisingClient:
        def __init__(self, *a, **k) -> None: ...
        def __enter__(self):
            return self

        def __exit__(self, *exc) -> bool:
            return False

        def head(self, _url: str):
            raise httpx.ConnectError("simulated proxy down")

    # _fire_synthetic_request imports httpx locally inside the function, so
    # patching the real module name reaches both paths.
    import httpx as real_httpx

    monkeypatch.setattr(real_httpx, "Client", _RaisingClient)

    assert lock_mod._fire_synthetic_request("127.0.0.1", 9999, "alias") is False


def test_fire_synthetic_request_returns_true_on_any_http_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Any HTTP response (incl. 4xx/5xx) counts as ``reached`` — the helper
    only distinguishes 'request hit the handler' vs 'network never got there'."""

    class _OKClient:
        def __init__(self, *a, **k) -> None: ...
        def __enter__(self):
            return self

        def __exit__(self, *exc) -> bool:
            return False

        def head(self, _url: str):
            return httpx.Response(204)

    import httpx as real_httpx

    monkeypatch.setattr(real_httpx, "Client", _OKClient)
    assert lock_mod._fire_synthetic_request("127.0.0.1", 9999, "alias") is True


# ---------------------------------------------------------------------------
# _confirm_bind defensive branches
# ---------------------------------------------------------------------------


@dataclass
class _Planned:
    """Minimal stand-in for ``_PlannedUpdate``. ``_confirm_bind`` only reads
    ``.alias`` on each item."""

    alias: str


def test_confirm_bind_no_aliases_skips_with_reached_zero() -> None:
    """Empty planned list → skipped, no_aliases, reached=0. Pins the
    shape every consumer relies on (status/delta/aliases/reached present)."""
    out = lock_mod._confirm_bind([], host="127.0.0.1", port=9999)
    assert out == {
        "status": "skipped",
        "reason": "no_aliases",
        "delta": 0,
        "aliases": [],
        "reached": 0,
    }


def test_confirm_bind_before_check_raises_skips_proxy_check_raised_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """check_proxy_health raising on the BEFORE read → skipped with the
    proxy_check_raised_before reason. Lock must never crash from this layer."""

    def boom(_port):
        raise RuntimeError("simulated healthz crash")

    monkeypatch.setattr(lock_mod, "check_proxy_health", boom)

    out = lock_mod._confirm_bind([_Planned("a-1")], host="127.0.0.1", port=9999)
    assert out["status"] == "skipped"
    assert out["reason"] == "proxy_check_raised_before"
    assert out["reached"] == 0


def test_confirm_bind_before_unhealthy_skips_proxy_unhealthy_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """healthy=False on the BEFORE read → skipped, proxy_unhealthy_before."""

    monkeypatch.setattr(
        lock_mod,
        "check_proxy_health",
        lambda _port: {
            "healthy": False,
            "port": 0,
            "mode": None,
            "requests_proxied": 0,
        },
    )

    out = lock_mod._confirm_bind([_Planned("a-1")], host="127.0.0.1", port=9999)
    assert out["status"] == "skipped"
    assert out["reason"] == "proxy_unhealthy_before"


def test_confirm_bind_after_check_raises_skips_proxy_check_raised_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """check_proxy_health raising on the AFTER read → skipped with
    proxy_check_raised_after. ``reached`` reflects whatever the synthetic
    fires accomplished before the read crashed."""
    calls = {"n": 0}

    def health(_port):
        calls["n"] += 1
        if calls["n"] == 1:
            return {
                "healthy": True,
                "port": 0,
                "mode": "ok",
                "requests_proxied": 0,
                "bind_probe_count": 5,
            }
        raise RuntimeError("simulated post-fire healthz crash")

    monkeypatch.setattr(lock_mod, "check_proxy_health", health)
    monkeypatch.setattr(lock_mod, "_fire_synthetic_request", lambda *a, **k: True)

    out = lock_mod._confirm_bind([_Planned("a-1")], host="127.0.0.1", port=9999)
    assert out["status"] == "skipped"
    assert out["reason"] == "proxy_check_raised_after"
    assert out["reached"] == 1


def test_confirm_bind_after_unhealthy_skips_proxy_unhealthy_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """healthy=True before but False after (proxy restarted mid-confirm) →
    skipped, proxy_unhealthy_after, NOT fail. brutus #1 regression guard."""
    calls = {"n": 0}

    def health(_port):
        calls["n"] += 1
        if calls["n"] == 1:
            return {
                "healthy": True,
                "port": 0,
                "mode": "ok",
                "requests_proxied": 0,
                "bind_probe_count": 5,
            }
        return {"healthy": False, "port": 0, "mode": None, "requests_proxied": 0}

    monkeypatch.setattr(lock_mod, "check_proxy_health", health)
    monkeypatch.setattr(lock_mod, "_fire_synthetic_request", lambda *a, **k: True)

    out = lock_mod._confirm_bind([_Planned("a-1")], host="127.0.0.1", port=9999)
    assert out["status"] == "skipped"
    assert out["reason"] == "proxy_unhealthy_after"


def test_confirm_bind_after_missing_probe_field_is_unrecognised_not_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CodeRabbit gate-10: BEFORE has bind_probe_count, AFTER doesn't (a
    responder swap mid-call). The field's absence must classify as
    ``proxy_unrecognised_after`` — NOT as a large-negative-delta
    ``proxy_restarted``, and NEVER as a fail. Pins the field re-check."""
    calls = {"n": 0}

    def health(_port):
        calls["n"] += 1
        if calls["n"] == 1:
            return {
                "healthy": True,
                "port": 0,
                "mode": "ok",
                "requests_proxied": 0,
                "bind_probe_count": 5,
            }
        # AFTER: healthy, but the bind_probe_count field has vanished.
        return {"healthy": True, "port": 0, "mode": "ok", "requests_proxied": 0}

    monkeypatch.setattr(lock_mod, "check_proxy_health", health)
    monkeypatch.setattr(lock_mod, "_fire_synthetic_request", lambda *a, **k: True)

    out = lock_mod._confirm_bind([_Planned("a-1")], host="127.0.0.1", port=9999)
    assert out["status"] == "skipped"
    assert out["reason"] == "proxy_unrecognised_after", (
        f"missing field on AFTER must be proxy_unrecognised_after, not a "
        f"guessed restart. Got: {out!r}"
    )
    assert out["status"] != "fail"


def test_confirm_bind_pass_when_counter_ticks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Counter delta > 0 + reached > 0 → pass with the observed delta."""
    state = {"counter": 100}

    def health(_port):
        return {
            "healthy": True,
            "port": 0,
            "mode": "ok",
            "requests_proxied": 0,
            "bind_probe_count": state["counter"],
        }

    def fire(*_args, **_kwargs):
        state["counter"] += 1
        return True

    monkeypatch.setattr(lock_mod, "check_proxy_health", health)
    monkeypatch.setattr(lock_mod, "_fire_synthetic_request", fire)

    out = lock_mod._confirm_bind([_Planned("a-1"), _Planned("a-2")], host="127.0.0.1", port=9999)
    assert out["status"] == "pass"
    assert out["delta"] == 2
    assert out["reached"] == 2
    assert out["aliases"] == ["a-1", "a-2"]


def test_confirm_bind_fail_when_reached_but_no_tick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reached the proxy but counter didn't tick → fail (silent bypass class)."""

    def health(_port):
        return {
            "healthy": True,
            "port": 0,
            "mode": "ok",
            "requests_proxied": 0,
            "bind_probe_count": 5,
        }

    monkeypatch.setattr(lock_mod, "check_proxy_health", health)
    monkeypatch.setattr(lock_mod, "_fire_synthetic_request", lambda *a, **k: True)

    out = lock_mod._confirm_bind([_Planned("a-1")], host="127.0.0.1", port=9999)
    assert out["status"] == "fail"
    assert out["delta"] == 0
    assert out["reached"] == 1


def test_confirm_bind_skipped_when_unrecognised_at_before_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """healthz lacks bind_probe_count → proxy_unrecognised, not fail.
    A squatter on the port must not be treated as a routing failure."""

    monkeypatch.setattr(
        lock_mod,
        "check_proxy_health",
        lambda _port: {
            "healthy": True,
            "port": 0,
            "mode": "ok",
            "requests_proxied": 0,
            # bind_probe_count INTENTIONALLY absent
        },
    )

    out = lock_mod._confirm_bind([_Planned("a-1")], host="127.0.0.1", port=9999)
    assert out["status"] == "skipped"
    assert out["reason"] == "proxy_unrecognised"
