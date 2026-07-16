"""WOR-756 — lock proves OpenClaw's live gateway APPLIED the new baseUrl.

Threat: OpenClaw's gateway caches provider config in memory. Before this, lock
rewrote openclaw.json and printed [OK] without proving the *running* gateway
reloaded it — and the first fix attempt polled ``openclaw config get``, which
reads the file lock just wrote (a guaranteed false pass, WOR-756 report §F3).

What this pins: after apply_lock's write, lock polls ``openclaw logs --json``
for a ``gateway/reload`` event NEWER than a timestamp captured before the write,
and classifies tri-state:
  * "config hot reload applied (models…)"          -> pass  (gateway took it)
  * "config reload skipped (invalid config): …"    -> fail  (gateway rejected it)
  * neither within the timeout / binary absent     -> skipped (inconclusive)

Empirically characterized live against ghcr.io/openclaw/openclaw:2026.5.3-1 on
2026-07-10 — event strings, the ~3-5s log-flush lag, and the invalid-config
failure event are all documented in the WOR-756 engineering report.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from worthless.cli.commands import lock as lock_mod
from worthless.openclaw.audit import AuditGateError

UTC = timezone.utc


# --------------------------------------------------------------------------- #
# Helpers: fabricate an ``openclaw logs --json`` stdout stream.
# --------------------------------------------------------------------------- #
def _log_line(ts: datetime, subsystem: str, message: str) -> str:
    return json.dumps(
        {"time": ts.isoformat(), "level": "info", "subsystem": subsystem, "message": message}
    )


def _logs_stdout(*lines: str) -> str:
    # Real output has a "Log file: …" header line before the JSON lines.
    return "Log file: /tmp/openclaw/openclaw.log\n" + "\n".join(lines) + "\n"


def _fake_run(stdout: str):
    def run(args, **kwargs):  # noqa: ANN001, ANN202
        assert args[1:3] == ["logs", "--json"], args
        return subprocess.CompletedProcess(args, returncode=0, stdout=stdout, stderr="")

    return run


def _planned(*pairs: tuple[str, str]) -> list[SimpleNamespace]:
    return [SimpleNamespace(provider=p, alias=a) for p, a in pairs]


# The live logger prepends this tag to every message — fixtures MUST include it,
# else the tests fabricate a cleaner string than reality and a startswith() bug
# (which the real image exposed) would sail through green (WOR-756).
_RELOAD_TAG = '{"subsystem":"gateway/reload"} '
APPLIED = _RELOAD_TAG + "config hot reload applied (models.providers.openai.baseUrl)"
SKIPPED_INVALID = (
    _RELOAD_TAG + "config reload skipped (invalid config): models.providers.openai.baseUrl"
)


# --------------------------------------------------------------------------- #
# _confirm_openclaw_reload — tri-state
# --------------------------------------------------------------------------- #
def test_fresh_applied_event_is_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lock_mod._oc_audit, "resolve_openclaw_bin", lambda: "/fake/openclaw")
    since = datetime.now(UTC)
    fresh = since + timedelta(seconds=1)
    monkeypatch.setattr(
        lock_mod.subprocess,
        "run",
        _fake_run(_logs_stdout(_log_line(fresh, "gateway/reload", APPLIED))),
    )
    assert (
        lock_mod._confirm_openclaw_reload(since_ts=since, timeout=0.3, poll_interval=0.05) == "pass"
    )


def test_fresh_invalid_config_event_is_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lock_mod._oc_audit, "resolve_openclaw_bin", lambda: "/fake/openclaw")
    since = datetime.now(UTC)
    fresh = since + timedelta(seconds=1)
    monkeypatch.setattr(
        lock_mod.subprocess,
        "run",
        _fake_run(_logs_stdout(_log_line(fresh, "gateway/reload", SKIPPED_INVALID))),
    )
    assert (
        lock_mod._confirm_openclaw_reload(since_ts=since, timeout=0.3, poll_interval=0.05) == "fail"
    )


def test_only_stale_applied_event_is_skipped_not_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """A reload-applied event OLDER than since_ts must not count — it's from a
    prior lock. With nothing fresh, the check is inconclusive (skipped)."""
    monkeypatch.setattr(lock_mod._oc_audit, "resolve_openclaw_bin", lambda: "/fake/openclaw")
    since = datetime.now(UTC)
    stale = since - timedelta(seconds=60)
    monkeypatch.setattr(
        lock_mod.subprocess,
        "run",
        _fake_run(_logs_stdout(_log_line(stale, "gateway/reload", APPLIED))),
    )
    assert (
        lock_mod._confirm_openclaw_reload(since_ts=since, timeout=0.2, poll_interval=0.05)
        == "skipped"
    )


def test_no_events_within_timeout_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lock_mod._oc_audit, "resolve_openclaw_bin", lambda: "/fake/openclaw")
    since = datetime.now(UTC)
    monkeypatch.setattr(lock_mod.subprocess, "run", _fake_run(_logs_stdout()))
    assert (
        lock_mod._confirm_openclaw_reload(since_ts=since, timeout=0.2, poll_interval=0.05)
        == "skipped"
    )


def test_binary_unset_and_absent_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WORTHLESS_OPENCLAW_BIN", raising=False)

    def boom():
        raise AuditGateError("not found")

    monkeypatch.setattr(lock_mod._oc_audit, "resolve_openclaw_bin", boom)
    assert lock_mod._confirm_openclaw_reload(since_ts=datetime.now(UTC), timeout=0.2) == "skipped"


def test_binary_explicitly_configured_but_broken_is_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WORTHLESS_OPENCLAW_BIN", "/nonexistent/openclaw")

    def boom():
        raise AuditGateError("WORTHLESS_OPENCLAW_BIN unresolvable")

    monkeypatch.setattr(lock_mod._oc_audit, "resolve_openclaw_bin", boom)
    assert lock_mod._confirm_openclaw_reload(since_ts=datetime.now(UTC), timeout=0.2) == "fail"


def test_malformed_log_lines_are_skipped_not_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    """Garbage / non-JSON lines must never crash the poll; a valid fresh applied
    event mixed in still yields pass."""
    monkeypatch.setattr(lock_mod._oc_audit, "resolve_openclaw_bin", lambda: "/fake/openclaw")
    since = datetime.now(UTC)
    fresh = since + timedelta(seconds=1)
    # A well-formed event whose only defect is a garbage timestamp: it has the
    # applied prefix + "models", so it must be rejected on the unparsable time
    # alone, not counted as a fresh pass.
    garbage_ts = json.dumps(
        {"time": "garbage-timestamp", "subsystem": "gateway/reload", "message": APPLIED}
    )
    stdout = _logs_stdout(
        "not json at all",
        '{"partial": ',
        _log_line(fresh, "gateway/reload", APPLIED),
        garbage_ts,
    )
    monkeypatch.setattr(lock_mod.subprocess, "run", _fake_run(stdout))
    assert (
        lock_mod._confirm_openclaw_reload(since_ts=since, timeout=0.3, poll_interval=0.05) == "pass"
    )


def test_logs_subprocess_error_keeps_polling_then_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lock_mod._oc_audit, "resolve_openclaw_bin", lambda: "/fake/openclaw")

    def raising_run(args, **kwargs):  # noqa: ANN001, ANN202
        raise OSError("gateway unreachable")

    monkeypatch.setattr(lock_mod.subprocess, "run", raising_run)
    assert (
        lock_mod._confirm_openclaw_reload(
            since_ts=datetime.now(UTC), timeout=0.2, poll_interval=0.05
        )
        == "skipped"
    )


def test_applied_event_matches_any_models_granularity(monkeypatch: pytest.MonkeyPatch) -> None:
    """apply_lock writes the whole config once; OpenClaw may coalesce into a
    single 'config hot reload applied (models)' event rather than per-provider.
    A coarse 'models' applied event must still count as pass."""
    monkeypatch.setattr(lock_mod._oc_audit, "resolve_openclaw_bin", lambda: "/fake/openclaw")
    since = datetime.now(UTC)
    fresh = since + timedelta(seconds=1)
    monkeypatch.setattr(
        lock_mod.subprocess,
        "run",
        _fake_run(
            _logs_stdout(
                _log_line(
                    fresh, "gateway/reload", _RELOAD_TAG + "config hot reload applied (models)"
                )
            )
        ),
    )
    assert (
        lock_mod._confirm_openclaw_reload(since_ts=since, timeout=0.3, poll_interval=0.05) == "pass"
    )


# --------------------------------------------------------------------------- #
# _classify_reload_lines / _parse_log_event_time — robustness (merge-ready panel)
# --------------------------------------------------------------------------- #
def _raw_line(time_str: str, message: str, subsystem: str = "gateway/reload") -> str:
    return json.dumps({"time": time_str, "subsystem": subsystem, "message": message})


def test_naive_event_time_is_coerced_not_crash() -> None:
    """python-pro: an offset-less (naive) event time must not raise TypeError
    against the aware since_ts — that uncaught crash would kill `worthless lock`
    AFTER its writes committed, violating the never-raise contract."""
    since = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)
    applied, rejected = lock_mod._classify_reload_lines(
        [_raw_line("2026-07-10T12:00:01", APPLIED)], since
    )
    assert applied and not rejected


@pytest.mark.parametrize("frac", ["", ".1", ".123", ".123456", ".123456789"])
def test_fractional_second_widths_all_parse(frac: str) -> None:
    """python-pro: pre-3.11 fromisoformat accepts only 0/3/6-digit fractions;
    every width must normalise + parse, else a real reload silently skips."""
    since = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)
    applied, _ = lock_mod._classify_reload_lines(
        [_raw_line(f"2026-07-10T12:00:05{frac}+00:00", APPLIED)], since
    )
    assert applied


def test_reject_without_models_token_still_fails() -> None:
    """brutus #2: a rejection that reports a structural error and never names
    'models' must still classify as reject — missing it (→ skipped → [OK]) is
    the unsafe direction the exit-92 path exists to prevent."""
    since = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)
    msg = _RELOAD_TAG + "config reload skipped (invalid config): JSON parse error at line 5"
    applied, rejected = lock_mod._classify_reload_lines(
        [_raw_line("2026-07-10T12:00:05+00:00", msg)], since
    )
    assert rejected and not applied


def test_reject_wins_within_a_coalesced_message() -> None:
    """brutus #1/#2: applied + reject markers in ONE coalesced message must
    resolve to fail, not pass (reject is checked first)."""
    since = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)
    msg = (
        _RELOAD_TAG
        + "config hot reload applied (models); config reload skipped (invalid config): models.x"
    )
    applied, rejected = lock_mod._classify_reload_lines(
        [_raw_line("2026-07-10T12:00:05+00:00", msg)], since
    )
    assert rejected and not applied


# --------------------------------------------------------------------------- #
# Wiring into _finalise_openclaw_success — exit 92 on fail; pass/skipped proceed.
# --------------------------------------------------------------------------- #
class _Console:
    def __init__(self) -> None:
        self.success: list[str] = []
        self.hint: list[str] = []
        self.warning: list[str] = []
        self.failure: list[str] = []

    def print_success(self, m: str) -> None:
        self.success.append(m)

    def print_hint(self, m: str) -> None:
        self.hint.append(m)

    def print_warning(self, m: str) -> None:
        self.warning.append(m)

    def print_failure(self, m: str) -> None:
        self.failure.append(m)


def _apply_result(**overrides):  # noqa: ANN003, ANN202
    from worthless.openclaw.integration import OpenclawApplyResult

    defaults = dict(
        detected=True,
        config_path=None,
        workspace_path=None,
        skill_path=None,
        providers_set=("openai",),
        providers_skipped=(),
        skill_installed=False,
        events=(),
    )
    defaults.update(overrides)
    return OpenclawApplyResult(**defaults)


def _finalise(console, monkeypatch, tmp_path, *, sentinel_sink=None):  # noqa: ANN001, ANN202
    if sentinel_sink is not None:
        monkeypatch.setattr(
            lock_mod, "_write_lock_sentinel", lambda home, **kw: sentinel_sink.update(kw)
        )
    else:
        monkeypatch.setattr(lock_mod, "_write_lock_sentinel", lambda home, **kw: None)
    return lock_mod._finalise_openclaw_success(
        _planned(("openai", "openai-x")),
        _apply_result(),
        console,
        False,
        SimpleNamespace(base_dir=tmp_path),
        proxy_host="127.0.0.1",
        reload_since_ts=datetime.now(UTC),
    )


def test_reload_fail_exits_92_no_ok_and_skips_bind(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(lock_mod, "_confirm_openclaw_reload", lambda **k: "fail")

    def bind_must_not_run(*a, **k):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("bind-confirmation must not run when reload failed")

    monkeypatch.setattr(lock_mod, "_confirm_bind", bind_must_not_run)
    sentinel: dict = {}
    console = _Console()
    rc = _finalise(console, monkeypatch, tmp_path, sentinel_sink=sentinel)

    assert rc == 92
    assert not any("[OK]" in m for m in console.success)
    assert any("reload" in m.lower() for m in console.failure)
    assert sentinel["status"] == "partial"
    assert sentinel["openclaw"] == "failed"


def test_reload_pass_proceeds_to_ok(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(lock_mod, "_confirm_openclaw_reload", lambda **k: "pass")
    monkeypatch.setattr(
        lock_mod,
        "_confirm_bind",
        lambda *a, **k: {
            "status": "skipped",
            "reason": "no_aliases",
            "delta": 0,
            "aliases": [],
            "reached": 0,
        },
    )
    console = _Console()
    rc = _finalise(console, monkeypatch, tmp_path)
    assert rc == 0
    assert any("[OK] OpenClaw integration:" in m for m in console.success)
    assert not console.failure


def test_reload_skipped_proceeds_with_advisory(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Inconclusive (binary absent / no event) is NOT a failure: lock still
    prints [OK] + a doctor advisory, exits 0, and bind-confirmation still runs."""
    monkeypatch.setattr(lock_mod, "_confirm_openclaw_reload", lambda **k: "skipped")
    bind_ran = {"v": False}

    def bind(*a, **k):  # noqa: ANN002, ANN003, ANN202
        bind_ran["v"] = True
        return {
            "status": "skipped",
            "reason": "no_aliases",
            "delta": 0,
            "aliases": [],
            "reached": 0,
        }

    monkeypatch.setattr(lock_mod, "_confirm_bind", bind)
    console = _Console()
    rc = _finalise(console, monkeypatch, tmp_path)

    assert rc == 0
    assert bind_ran["v"], "bind-confirmation should still run on inconclusive reload"
    assert any("[OK] OpenClaw integration:" in m for m in console.success)
    assert any("doctor" in m.lower() for m in console.hint + console.warning)
