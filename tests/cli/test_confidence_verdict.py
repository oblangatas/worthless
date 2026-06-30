"""WOR-779: the "you're protected / seatbelt click" confidence loop.

worthless is loud on failure but near-silent on success. This pins the
*success* side: a plain verdict the moment you lock, a glanceable verdict
you can pull any time (`status`), and an HONEST verdict when you're only
partly safe — without ever letting "safe" lie.

Load-bearing honesty rules under test (from the WOR-779 design panel):
  * The verdict is DERIVED from the worst component — a green banner is
    unreachable when anything is wrong.
  * "Safe at rest" (keys locked) is distinct from "working now" (proxy up).
    A locked key with the proxy DOWN is 🟡 "protected at rest", NOT 🔴
    "at risk" — calling an availability outage a security risk cries wolf.
  * 🔴 / non-zero exit is reserved for a real problem (degraded routing),
    never for "the daemon isn't running".
  * `status` is cwd-independent, so it must DISCLAIM the surface it didn't
    check — point the user at `worthless scan` for `.env` plaintext.

Sibling to WOR-778 (the doctor *error* copy); this is the *success* side.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.scanner import ScanFinding

from tests.cli.conftest import cli_invoke, lock_env

# Stream-separating runner so we can assert "--json on stdout, prose on stderr".
runner = CliRunner(mix_stderr=False)


def _status(home: WorthlessHome, *args: str):
    return runner.invoke(app, ["status", *args], env={"WORTHLESS_HOME": str(home.base_dir)})


def _healthy_proxy(home: WorthlessHome, port: int = 18787):
    """Context manager: make `status` see a healthy worthless proxy."""
    (home.base_dir / "proxy.pid").write_text(f"99999\n{port}\n")

    class _Resp:
        status_code = 200

        def json(self):
            return {"status": "ok", "mode": "up", "requests_proxied": 0}

    mock = patch("worthless.cli.process.httpx")
    handle = mock.start()
    handle.get.return_value = _Resp()
    return mock


# ---------------------------------------------------------------------------
# status verdict header — the glanceable "belt's on" readout
# ---------------------------------------------------------------------------


class TestStatusVerdictHeader:
    def test_protected_proxy_up_leads_with_green_verdict(
        self, home_with_key: WorthlessHome
    ) -> None:
        """Locked keys + proxy up → a plain "you're protected" verdict."""
        mock = _healthy_proxy(home_with_key)
        try:
            result = _status(home_with_key)
        finally:
            mock.stop()
        out = result.stderr + result.stdout
        assert result.exit_code == 0, out
        assert "you're protected" in out.lower(), f"missing green verdict:\n{out}"
        assert "proxy up" in out.lower() or "proxy: running" in out.lower(), out

    def test_locked_but_proxy_down_is_protected_at_rest_not_at_risk(
        self, home_with_key: WorthlessHome
    ) -> None:
        """Proxy down with keys locked is an AVAILABILITY problem, not a
        confidentiality risk. Must read "protected at rest" + point at
        `worthless up`, and must NOT cry "at risk". Exit stays 0 — the belt
        IS on (a stolen .env is still worthless)."""
        result = _status(home_with_key)  # no proxy.pid → proxy down
        out = result.stderr + result.stdout
        assert result.exit_code == 0, out
        assert "at rest" in out.lower(), f"must distinguish safe-at-rest:\n{out}"
        assert "worthless up" in out.lower(), f"must point at `worthless up`:\n{out}"
        assert "at risk" not in out.lower(), (
            f"proxy-down is NOT a security risk — crying 'at risk' trains red-blindness:\n{out}"
        )

    def test_broken_key_reads_as_attention_with_doctor_hint(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """A BROKEN enrollment (lost .env line) is a real problem to fix, but
        not a leak — surfaced as attention + the existing doctor hint."""
        lock_env(env_file, home_dir)
        env_file.write_text("")  # orphan the enrollment

        result = _status(home_dir)
        out = result.stderr + result.stdout
        assert "attention" in out.lower(), f"broken state must surface, not hide:\n{out}"
        assert "worthless doctor --fix" in out.lower(), out

    def test_no_keys_nudges_to_lock(self, home_dir: WorthlessHome) -> None:
        """Fresh install: keep the 'No keys enrolled' signal AND nudge to lock."""
        result = _status(home_dir)
        out = result.stderr + result.stdout
        assert result.exit_code == 0, out
        assert "no keys enrolled" in out.lower(), out
        assert "nothing protected yet" in out.lower(), f"missing nudge:\n{out}"
        assert "worthless lock" in out.lower(), out


# ---------------------------------------------------------------------------
# The verdict and the exit code must never disagree.
# ---------------------------------------------------------------------------


class TestStatusExitMirrorsVerdict:
    def _write_sentinel(self, home: WorthlessHome, payload: dict) -> None:
        from worthless.cli.sentinel import sentinel_path

        sentinel_path(home.base_dir).write_text(json.dumps(payload, sort_keys=True))

    def test_degraded_routing_reads_at_risk_and_exits_nonzero(
        self, home_with_key: WorthlessHome
    ) -> None:
        """Degraded OpenClaw routing is the one real 🔴 status can see:
        verdict says at-risk AND the exit code is non-zero (they agree)."""
        self._write_sentinel(
            home_with_key,
            {
                "ts": "2026-06-19T00:00:00+00:00",
                "status": "partial",
                "openclaw": "failed",
                "alias_count": 1,
                "events": [],
                "bind_confirmation": {
                    "status": "fail",
                    "delta": 0,
                    "reached": 1,
                    "aliases": ["openai-abc"],
                },
            },
        )
        result = _status(home_with_key)
        out = result.stderr + result.stdout
        assert result.exit_code != 0, out
        assert "at risk" in out.lower(), f"non-zero exit must show 🔴 verdict:\n{out}"


# ---------------------------------------------------------------------------
# Scriptability — keep machines and humans on separate rails.
# ---------------------------------------------------------------------------


class TestStatusScriptability:
    def test_json_carries_verdict_enum_on_stdout(self, home_with_key: WorthlessHome) -> None:
        """--json adds a stable `verdict` enum; stdout is pure JSON (no glyphs)."""
        result = _status(home_with_key, "--json")  # proxy down
        assert result.exit_code == 0
        data = json.loads(result.stdout)  # must parse — stdout is pure JSON
        assert data["verdict"] == "protected_at_rest", data
        # Existing envelope preserved.
        assert "keys" in data and "proxy" in data

    def test_quiet_suppresses_prose_keeps_exit(self, home_with_key: WorthlessHome) -> None:
        """--quiet drops the reassurance prose but keeps the exit code.

        (The once-ever AS-IS legal notice is deliberately exempt from --quiet,
        so we assert the verdict/list prose is gone, not that stderr is empty.)
        """
        result = _status(home_with_key, "--quiet")
        assert result.exit_code == 0
        combined = (result.stderr + result.stdout).lower()
        assert "you're protected" not in combined, combined
        assert "protected at rest" not in combined, combined
        assert "enrolled keys" not in combined, combined

    def test_non_tty_keeps_a_text_carrier_not_only_emoji(
        self, home_with_key: WorthlessHome
    ) -> None:
        """CliRunner is non-TTY: the verdict must carry a text signal, never
        rely on the emoji glyph alone (CI logs, screen readers, NO_COLOR)."""
        result = _status(home_with_key)  # proxy down → 🟡
        out = result.stderr + result.stdout
        assert "protected at rest" in out.lower(), f"text carrier missing:\n{out}"


class TestStatusHonestyDisclaimer:
    def test_status_points_at_scan_for_env_plaintext(self, home_with_key: WorthlessHome) -> None:
        """status only checks enrolled keys + proxy. A green verdict must NOT
        imply it checked this folder's .env — it points at `worthless scan`."""
        mock = _healthy_proxy(home_with_key)
        try:
            result = _status(home_with_key)
        finally:
            mock.stop()
        out = result.stderr + result.stdout
        assert "worthless scan" in out.lower(), (
            f"a green verdict must disclaim the .env it never scanned:\n{out}"
        )


# ---------------------------------------------------------------------------
# scan — verdict-first ("3 of 5 are safe, 2 exposed → lock")
# ---------------------------------------------------------------------------


class TestScanVerdictFirst:
    def _finding(self, path: Path, line: int, protected: bool, var: str) -> ScanFinding:
        return ScanFinding(
            file=str(path),
            line=line,
            var_name=var,
            provider="openai",
            is_protected=protected,
            value_preview="sk-p****",
        )

    def test_unprotected_scan_leads_with_exposure_verdict(self, tmp_path: Path) -> None:
        findings = [
            self._finding(tmp_path / ".env", 1, True, "A"),
            self._finding(tmp_path / ".env", 2, False, "B"),
        ]
        with patch("worthless.cli.commands.scan.scan_files", return_value=findings):
            result = runner.invoke(app, ["scan", str(tmp_path / ".env")])
        assert result.exit_code == 1
        low = result.stderr.lower()
        assert "exposed" in low, f"verdict must name the exposure:\n{result.stderr}"
        assert "worthless lock" in low, result.stderr
        assert "1 unprotected" in result.stderr  # detail line preserved

    def test_all_protected_scan_leads_with_all_clear(self, tmp_path: Path) -> None:
        findings = [
            self._finding(tmp_path / ".env", 1, True, "A"),
            self._finding(tmp_path / ".env", 2, True, "B"),
        ]
        with patch("worthless.cli.commands.scan.scan_files", return_value=findings):
            result = runner.invoke(app, ["scan", str(tmp_path / ".env")])
        assert result.exit_code == 0
        low = result.stderr.lower()
        # Distinctive phrase — NOT "all" alone (the tmp path contains the test
        # name "..._all_clear..." and would false-match the printed file path).
        assert "keys are protected" in low, f"all-clear must lead with a verdict:\n{result.stderr}"


# ---------------------------------------------------------------------------
# lock — the click: "you're protected" the moment you lock
# ---------------------------------------------------------------------------


class TestLockVerdictFirst:
    def test_lock_success_leads_with_youre_protected(
        self, home_dir: WorthlessHome, env_file: Path
    ) -> None:
        """The seatbelt click: verdict + proof + next, not a bare [OK]."""
        result = cli_invoke(["lock", "--env", str(env_file)], home_dir)
        assert result.exit_code == 0, result.output
        # Collapse whitespace: Rich wraps long lines at 80 cols, so phrase
        # matches must be wrap-proof (see CLI-output-assertion lesson).
        low = " ".join(result.output.split()).lower()
        assert "you're protected" in low, f"missing the verdict 'click':\n{result.output}"
        assert "worthless status" in low, f"missing the 'check anytime' next:\n{result.output}"
        # Proof + accessibility carrier preserved.
        assert "no longer contains a usable secret" in low, result.output
        assert "[OK]" in result.output, result.output

    def test_partial_openclaw_failure_does_not_claim_protected(self, monkeypatch, capsys) -> None:
        """Honesty (worst-component verdict): on a partial OpenClaw failure the
        .env IS split but agent traffic is NOT gated — lock must NOT print the
        green "You're protected" verdict above the caller's LOCK FAILED footer.
        The factual [OK] split line still prints."""
        from worthless.cli.commands import lock as lock_mod
        from worthless.cli.console import WorthlessConsole

        # _maybe_prompt_code_scan would scan cwd / prompt — stub it out.
        monkeypatch.setattr(lock_mod, "_maybe_prompt_code_scan", lambda *_a, **_k: None)
        console = WorthlessConsole(quiet=False, json_mode=False)
        lock_mod._print_lock_result(
            console,
            fresh_count=1,
            relock_count=0,
            env_path=Path(".env"),
            home_base_dir=Path.home() / ".worthless",
            openclaw_failed=True,
        )
        err = " ".join(capsys.readouterr().err.split()).lower()
        assert "you're protected" not in err, err
        assert "check anytime" not in err, err
        # No success-flavored next-step above LOCK FAILED (CR finding).
        assert "daemon mode" not in err, err
        # The factual split line is true even on a partial failure — keep it.
        assert "no longer contains a usable secret" in err, err
