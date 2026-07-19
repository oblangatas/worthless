"""WOR-655 (SR-04): secrets never appear in any Worthless output.

The audit-ready gate for the OpenClaw integration. This is the single
end-to-end tripwire that a real, key-shaped value never rides out of
``lock`` / ``status`` / ``doctor`` / ``unlock`` on ANY channel — stdout,
stderr, stdlib logging (driven at DEBUG so a deferred ``%s`` leak still
materialises), the on-disk ``last-lock-status.json`` sentinel, or any
structured event's ``to_dict()`` payload.

Alongside the integration guard, focused RED/GREEN checks pin the five
fixes this ticket ships:

  1. ``OpenclawIntegrationEvent`` / ``OpenclawIntegrationError`` are born
     redacted — ``detail`` + every ``extra`` value routes through the log
     redactor at construction, so every sink (human console, inline
     sentinel dict, ``to_dict``) inherits the scrub.
  3. ``unlock`` only prints a reconstructed recovery key behind an
     explicit ``--print-recovery`` flag.
  4. ``scan`` renders a flat ``****`` preview and a non-secret
     ``sha256(key)[:8]`` fingerprint under ``--show-suffix`` — never the
     real trailing bytes.
  5. ``--debug`` tracebacks are captured and run through the redactor
     before they reach stderr.

The value-space (does the redactor scrub every key shape?) is already
covered by ``test_log_redaction.py`` +
``test_security_properties.py::TestReprRedaction``; this file proves the
plumbing holds at once on the shapes the ticket describes.
"""

from __future__ import annotations

import base64
import binascii
import io
import json
import logging
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.commands.lock import _make_alias
from worthless.cli.commands.unlock import _PlannedRestore, _print_recovery_keys
from worthless.cli.console import get_console
from worthless.cli.errors import error_boundary, set_debug
from worthless.cli.key_patterns import KEY_PATTERN
from worthless.openclaw.errors import (
    OpenclawErrorCode,
    OpenclawIntegrationError,
    OpenclawIntegrationEvent,
)

from tests.helpers import fake_anthropic_key, fake_openai_key

runner = CliRunner(mix_stderr=False)


# ---------------------------------------------------------------------------
# Shared byte-denylist helpers
# ---------------------------------------------------------------------------


def _encodings(secret: str) -> list[bytes]:
    """Every on-the-wire shape a leak of *secret* could plausibly take.

    A raw ``print`` leaks the ASCII bytes; a ``.hex()`` dump or a base64
    round-trip (e.g. a shard re-encoded before logging) would smuggle the
    same value past a naive substring check — so we deny all three.
    """
    raw = secret.encode("utf-8")
    return [
        raw,
        binascii.hexlify(raw),
        base64.b64encode(raw).rstrip(b"="),
        secret.lower().encode("utf-8"),
    ]


def _assert_absent(secret: str, channels: list[tuple[str, bytes]]) -> None:
    for form in _encodings(secret):
        for label, payload in channels:
            assert form not in payload, (
                f"secret {secret!r} (as {form!r}) leaked in channel {label!r}"
            )


class _DebugLogCapture:
    """Capture every ``worthless`` record at DEBUG into a StringIO.

    Two things must both be true for a future ``logger.debug("%s", key)``
    regression to be visible: the logger's effective level must admit
    DEBUG (else the record is dropped), AND a handler must actually format
    the record (Python defers ``%s`` interpolation until a handler runs,
    so without one the key-bearing string is never even built). This
    installs both.
    """

    def __init__(self) -> None:
        self._stream = io.StringIO()
        self._handler = logging.StreamHandler(self._stream)
        self._handler.setLevel(logging.DEBUG)
        self._logger = logging.getLogger("worthless")
        self._root = logging.getLogger()
        self._prev_level = self._logger.level

    def __enter__(self) -> _DebugLogCapture:
        self._logger.setLevel(logging.DEBUG)
        self._logger.addHandler(self._handler)
        self._root.addHandler(self._handler)
        return self

    def __exit__(self, *exc: object) -> None:
        self._logger.removeHandler(self._handler)
        self._root.removeHandler(self._handler)
        self._logger.setLevel(self._prev_level)

    @property
    def text(self) -> str:
        return self._stream.getvalue()


# ===========================================================================
# Item 1 — OpenClaw events / errors are born redacted (construction-time)
# ===========================================================================


class TestOpenclawEventBornRedacted:
    def test_event_detail_and_extra_redacted_at_construction(self) -> None:
        key = fake_openai_key()
        ev = OpenclawIntegrationEvent(
            code=OpenclawErrorCode.WRITE_FAILED,
            level="error",
            detail=f"apply_lock failed writing {key}",
            extra={"apiKey": key, "path": "/home/x/.openclaw/openclaw.json"},
        )
        assert key not in ev.detail, "detail must be redacted at construction"
        assert "[REDACTED]" in ev.detail
        assert ev.extra is not None
        assert key not in "|".join(str(v) for v in ev.extra.values())
        assert key not in json.dumps(ev.to_dict())
        # The non-secret path value is preserved untouched.
        assert ev.extra["path"] == "/home/x/.openclaw/openclaw.json"

    def test_error_detail_redacted_at_construction(self) -> None:
        key = fake_anthropic_key()
        err = OpenclawIntegrationError(
            OpenclawErrorCode.WRITE_FAILED, f"boom carrying {key} inline"
        )
        assert key not in str(err)
        assert "[REDACTED]" in str(err)


# ===========================================================================
# Item 3 — recovery key only prints behind --print-recovery
# ===========================================================================


class TestPrintRecoveryGate:
    def _recovery_plan(self, key: str) -> _PlannedRestore:
        # env_path=None + var_name=None ⇒ the recovery branch (no .env to
        # write the reconstructed key back into).
        return _PlannedRestore(
            alias="openai-deadbeef",
            provider="openai",
            enrollment=None,
            var_name=None,
            env_path=None,
            key_buf=bytearray(key.encode("utf-8")),
        )

    def test_recovery_aborts_without_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        from worthless.cli.errors import WorthlessError

        key = fake_openai_key()
        with pytest.raises(WorthlessError):
            _print_recovery_keys([self._recovery_plan(key)], get_console(), print_recovery=False)
        captured = capsys.readouterr()
        assert key not in captured.out
        assert key not in captured.err

    def test_recovery_prints_with_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        key = fake_openai_key()
        _print_recovery_keys([self._recovery_plan(key)], get_console(), print_recovery=True)
        captured = capsys.readouterr()
        assert key in captured.out, "with --print-recovery the key IS printed by design"

    # --- Why these call _print_recovery_keys directly ----------------------
    # Driving recovery through `runner.invoke(app, ["unlock", ...])` would be
    # the stronger boundary, but the branch is NOT CLI-reachable for keys
    # locked by the current version:
    #
    #   _load_shard_a() takes the format-preserving path whenever the row has
    #   prefix+charset (every current-version lock), and that path REQUIRES
    #   env_path + var_name — it raises WRTLS-102 ("shard-A is in .env but no
    #   valid env_path") otherwise. Recovery is selected only when var_name is
    #   None, so for a current-version row the two conditions are mutually
    #   exclusive: you get WRTLS-102 long before _print_recovery_keys runs.
    #
    # Recovery therefore fires only for LEGACY rows (shard-A on disk, no
    # prefix/charset), which a CLI test cannot create — it would have to
    # fabricate a storage row and couple this test to the DB schema.
    # Flag propagation (unlock --print-recovery -> _unlock_batch) is verified
    # by inspection; a legacy-row fixture test is tracked separately.


# ===========================================================================
# Item 4 — scan render: flat **** default, fingerprint (not real bytes) on
# --show-suffix
# ===========================================================================


class TestScanRenderRedaction:
    def test_mask_secret_is_flat_stars(self) -> None:
        from worthless.cli.redaction import mask_secret

        assert mask_secret(fake_openai_key()) == "****"
        assert mask_secret("short") == "****"

    def test_default_json_preview_is_flat_stars(self, tmp_path: Path) -> None:
        key = fake_openai_key()
        f = tmp_path / "config.py"
        f.write_text(f'API_KEY = "{key}"\n')
        result = runner.invoke(app, ["scan", "--json", str(f)])
        assert result.exit_code == 1, result.output
        data = json.loads(result.stdout)
        assert data["findings"][0]["value_preview"] == "****"
        # No real prefix bytes anywhere in the structured payload.
        assert key[:8] not in json.dumps(data)

    def test_show_suffix_hides_real_tail_shows_fingerprint(self, tmp_path: Path) -> None:
        key = fake_openai_key()
        f = tmp_path / "config.py"
        f.write_text(f'API_KEY = "{key}"\n')
        result = runner.invoke(app, ["scan", "--show-suffix", str(f)])
        assert result.exit_code == 1, result.output
        combined = result.stdout + result.stderr
        # The old behaviour leaked the last 4 real chars — never again.
        assert key[-4:] not in combined
        # A non-secret fingerprint (first 8 hex of sha256) lets a human tell
        # two keys apart without revealing bytes. _make_alias == provider +
        # that fingerprint, so the 8-hex tail must appear.
        fingerprint = _make_alias("openai", key).split("-")[-1]
        assert fingerprint in combined

    def test_two_keys_on_one_line_get_their_own_fingerprints(self, tmp_path: Path) -> None:
        """Each finding fingerprints ITS OWN key, not the line's first match.

        Minified JSON puts several keys on a single line. Fingerprinting the
        line's first match would stamp every finding on that line with the
        same hash, defeating the whole "tell two keys apart" purpose.
        """
        k1 = fake_openai_key()
        k2 = fake_anthropic_key()
        f = tmp_path / "config.json"
        f.write_text(f'{{"a":"{k1}","b":"{k2}"}}\n')

        result = runner.invoke(app, ["scan", "--show-suffix", str(f)])
        assert result.exit_code == 1, result.output
        combined = result.stdout + result.stderr

        fp1 = _make_alias("openai", k1).split("-")[-1]
        fp2 = _make_alias("anthropic", k2).split("-")[-1]
        assert fp1 != fp2, "distinct keys must have distinct fingerprints"
        assert fp1 in combined, "first key's own fingerprint missing"
        assert fp2 in combined, "second key got the first key's fingerprint"
        # And still no real bytes from either key.
        assert k1[-4:] not in combined
        assert k2[-4:] not in combined


# ===========================================================================
# Item 5 — --debug traceback is redacted before it hits stderr
# ===========================================================================


class TestDebugTracebackRedaction:
    def test_debug_traceback_redacts_key_shaped_message(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import typer

        key = fake_openai_key()

        @error_boundary
        def _cmd() -> None:
            raise RuntimeError(f"upstream rejected {key}")

        set_debug(True)
        try:
            with pytest.raises(typer.Exit):
                _cmd()
        finally:
            set_debug(False)

        err = capsys.readouterr().err
        assert key not in err, "--debug traceback leaked the raw key"
        assert "[REDACTED]" in err, "redactor must have fired on the traceback"


# ===========================================================================
# Item 2 — the end-to-end guard (the tripwire)
# ===========================================================================


def _stage_openclaw(runtime_home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Stage ``~/.openclaw/openclaw.json`` under the RUNTIME-resolved HOME.

    ``_resolve_home`` / ``detect`` read ``Path.home()`` (i.e. ``$HOME``),
    NOT ``WORTHLESS_HOME``. The autouse ``_isolate_process_home`` fixture
    (tests/conftest.py) pins ``$HOME`` to a per-test sandbox; we must stage
    the config there or ``detect()`` returns absent and the OpenClaw
    surfaces this guard exists to cover never execute (a vacuous pass).
    """
    openclaw_dir = runtime_home / ".openclaw"
    (openclaw_dir / "workspace").mkdir(parents=True)
    config_path = openclaw_dir / "openclaw.json"
    config_path.write_text(
        json.dumps({"models": {"providers": {}}}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    # locate_config_path() probes ./openclaw.json before ~/.openclaw — chdir
    # so a project-local file in pytest's cwd can't shadow the sandbox.
    monkeypatch.chdir(runtime_home)
    return config_path


def _shard_a_values(post_lock_files: list[Path], original_key: str) -> set[str]:
    """Every provider-shaped token that lock legitimately wrote to disk.

    Shard-A belongs in ``.env`` + ``openclaw.json`` by design; we harvest
    it from those files (minus the original key) so the guard can prove it
    never *also* escaped onto stdout/stderr/logs.
    """
    found: set[str] = set()
    for path in post_lock_files:
        if not path.exists():
            continue
        for match in KEY_PATTERN.findall(path.read_text(encoding="utf-8", errors="replace")):
            if match != original_key:
                found.add(match)
    return found


def test_no_secret_leaks_across_lock_status_doctor_unlock(
    home_dir,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_key = fake_anthropic_key()
    runtime_home = Path(os.environ["HOME"])  # what _isolate_process_home pinned
    oc_config = _stage_openclaw(runtime_home, monkeypatch)

    env_file = tmp_path / "proj" / ".env"
    env_file.parent.mkdir()
    env_file.write_text(f"ANTHROPIC_API_KEY={original_key}\n")

    env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
    channels: list[tuple[str, bytes]] = []

    with _DebugLogCapture() as logs:
        # 1. lock --env — reads the real key, splits it, wires OpenClaw.
        r_lock = runner.invoke(app, ["lock", "--env", str(env_file)], env=env_vars)
        channels.append(("lock.stdout", r_lock.stdout.encode()))
        channels.append(("lock.stderr", r_lock.stderr.encode()))
        assert r_lock.exit_code == 0, f"lock failed: {r_lock.output}\n{r_lock.stderr}"

        # 2. status (human + --json). Assert each run completed BEFORE trusting
        # its channels — an early crash would satisfy the absence checks below
        # vacuously (nothing printed ⇒ no key printed).
        for extra in ([], ["--json"]):
            r = runner.invoke(app, ["status", *extra], env=env_vars)
            assert r.exit_code == 0, f"status{extra} failed: {r.output}\n{r.stderr}"
            channels.append((f"status{extra}.stdout", r.stdout.encode()))
            channels.append((f"status{extra}.stderr", r.stderr.encode()))

        # 3. doctor (human + --json)
        for extra in (["--yes"], ["--json"]):
            r = runner.invoke(app, ["doctor", *extra], env=env_vars)
            assert r.exit_code == 0, f"doctor{extra} failed: {r.output}\n{r.stderr}"
            channels.append((f"doctor{extra}.stdout", r.stdout.encode()))
            channels.append((f"doctor{extra}.stderr", r.stderr.encode()))

        # 4. unlock --env — plaintext-restore branch (recovery is skipped
        # because env_path+var_name are set), so no --print-recovery needed.
        r_unlock = runner.invoke(app, ["unlock", "--env", str(env_file)], env=env_vars)
        channels.append(("unlock.stdout", r_unlock.stdout.encode()))
        channels.append(("unlock.stderr", r_unlock.stderr.encode()))
        assert r_unlock.exit_code == 0, f"unlock failed: {r_unlock.output}\n{r_unlock.stderr}"

        # 5. doctor --fix --dry-run — the audit/repair surface.
        r_fix = runner.invoke(app, ["doctor", "--fix", "--dry-run", "--yes"], env=env_vars)
        assert r_fix.exit_code == 0, f"doctor dry-run failed: {r_fix.output}\n{r_fix.stderr}"
        channels.append(("doctor-fix-dry.stdout", r_fix.stdout.encode()))
        channels.append(("doctor-fix-dry.stderr", r_fix.stderr.encode()))

    channels.append(("worthless.logs", logs.text.encode()))

    # Sentinel: the on-disk JSON status record read back as raw bytes.
    sentinel = home_dir.base_dir / "last-lock-status.json"
    if sentinel.exists():
        channels.append(("sentinel", sentinel.read_bytes()))

    # Walk every structured event surfaced through --json / the sentinel and
    # assert seeded bytes appear in no code/level/detail/extra value.
    for label, payload in list(channels):
        text = payload.decode("utf-8", errors="replace").strip()
        if not text.startswith("{"):
            continue
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            continue
        for event in doc.get("events", []) or []:
            channels.append((f"{label}.event", json.dumps(event).encode()))

    # --- Denylist 1: the ORIGINAL key must be absent from ALL channels,
    # including the post-lock openclaw.json (it must NOT be the live value).
    original_channels = list(channels)
    if oc_config.exists():
        original_channels.append(("openclaw.json", oc_config.read_bytes()))
    _assert_absent(original_key, original_channels)

    # Positive, anti-vacuous proof that the OpenClaw surfaces actually ran:
    # post-lock openclaw.json carries an apiKey equal to a shard-A value.
    oc_doc = json.loads(oc_config.read_text(encoding="utf-8"))
    providers = oc_doc.get("models", {}).get("providers", {})
    api_keys = [p.get("apiKey") for p in providers.values() if isinstance(p, dict)]
    assert any(api_keys), (
        "OpenClaw never fired: openclaw.json has no apiKey — the guard would be vacuous"
    )

    # --- Denylist 2: shard-A belongs in .env/openclaw.json, but must never
    # have leaked onto stdout/stderr/logs/sentinel.
    shard_a_set = _shard_a_values([env_file, oc_config], original_key)
    assert shard_a_set, "expected to harvest at least one shard-A value written to disk"
    for shard_a in shard_a_set:
        _assert_absent(shard_a, channels)


def test_debug_capture_is_live_and_the_filter_fires_on_the_driven_path(
    home_dir,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two-part proof that the guard above cannot pass vacuously.

    Part A (plumbing is live): a NON-key canary ``logger.debug("%s", canary)``
    injected onto a driven ``lock`` path DOES surface in the DEBUG capture.
    Python defers ``%s`` interpolation until a handler formats the record, so
    this only holds because ``_DebugLogCapture`` drives the ``worthless``
    logger to DEBUG *and* attaches a handler. If a future regression logs a
    secret at DEBUG, the capture will build and see the string.

    Part B (defense-in-depth fires): the SAME injection with a key-shaped
    value comes out ``[REDACTED]`` — never raw — because WOR-277's
    ``RedactingFilter`` scrubs key-shaped log records in place at the handler
    boundary. So the log channel is guarded by two independent layers.
    """
    original_key = fake_anthropic_key()
    _stage_openclaw(Path(os.environ["HOME"]), monkeypatch)

    env_file = tmp_path / "proj" / ".env"
    env_file.parent.mkdir()
    env_file.write_text(f"ANTHROPIC_API_KEY={original_key}\n")

    canary = "WOR655_DEBUG_CANARY_not_key_shaped"  # no provider prefix ⇒ not redacted
    key_shaped = fake_openai_key()
    leak_logger = logging.getLogger("worthless.injected_leak_probe")

    real_make_alias = _make_alias

    def _leaky_make_alias(provider: str, api_key: str) -> str:
        leak_logger.debug("canary=%s key=%s", canary, key_shaped)
        return real_make_alias(provider, api_key)

    monkeypatch.setattr("worthless.cli.commands.lock._make_alias", _leaky_make_alias)

    with _DebugLogCapture() as logs:
        runner.invoke(
            app,
            ["lock", "--env", str(env_file)],
            env={"WORTHLESS_HOME": str(home_dir.base_dir)},
        )

    # Part A: the DEBUG record was captured with its %s args formatted.
    assert canary in logs.text, (
        "DEBUG capture failed to surface an injected record — the guard would be blind"
    )
    # Part B: the key-shaped value was scrubbed by RedactingFilter, not raw.
    assert key_shaped not in logs.text
    assert "[REDACTED]" in logs.text
