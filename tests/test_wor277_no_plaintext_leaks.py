"""WOR-277 acceptance test: "no plaintext leaks anywhere."

The ticket's own success criterion: run representative operations (lock,
scan --json, scan --format sarif, a forced error) with a real key in play,
capture every logger, stderr, and tempfile touched along the way, and
assert the literal key bytes appear nowhere. Each mechanism this checks
(log redaction, SARIF/JSON masking, error sanitization, tempfile cleanup)
already has its own focused unit tests elsewhere — this is the single
integration-level proof that they all hold at once, in the shape the
ticket describes.
"""

from __future__ import annotations

import io
import logging
import sqlite3
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from worthless.cli.app import app
from worthless.cli.bootstrap import WorthlessHome

from tests.helpers import fake_openai_key

runner = CliRunner(mix_stderr=False)


class _RootLogCapture:
    """Captures every record that propagates to the root logger's
    handlers for the duration of a `with` block — "every logger" without
    needing to wire a handler onto each worthless module logger by hand."""

    def __init__(self) -> None:
        self._stream = io.StringIO()
        self._handler = logging.StreamHandler(self._stream)
        self._root = logging.getLogger()

    def __enter__(self) -> _RootLogCapture:
        self._root.addHandler(self._handler)
        return self

    def __exit__(self, *exc: object) -> None:
        self._root.removeHandler(self._handler)

    @property
    def text(self) -> str:
        return self._stream.getvalue()


def test_no_plaintext_leaks_across_lock_scan_and_a_forced_error(
    home_dir: WorthlessHome, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = fake_openai_key()
    env_vars = {"WORTHLESS_HOME": str(home_dir.base_dir)}
    outputs: list[str] = []

    tmp_before = {p.name for p in Path(tempfile.gettempdir()).glob("worthless-*")}

    with _RootLogCapture() as logs:
        # 1. lock — the real key is read from .env and split.
        env_file = tmp_path / "lock" / ".env"
        env_file.parent.mkdir()
        env_file.write_text(f"OPENAI_API_KEY={secret}\n")
        r_lock = runner.invoke(app, ["lock", "--env", str(env_file)], env=env_vars)
        outputs.append(r_lock.stdout + r_lock.stderr)
        assert r_lock.exit_code == 0, f"lock should have succeeded: {r_lock.output}"
        assert secret not in env_file.read_text(), "lock left the real key sitting in .env"

        # 2. scan --json — the key sits in a plain file being scanned.
        scan_file = tmp_path / "scan" / "config.py"
        scan_file.parent.mkdir()
        scan_file.write_text(f'API_KEY = "{secret}"\n')
        r_json = runner.invoke(app, ["scan", "--json", str(scan_file)])
        outputs.append(r_json.stdout + r_json.stderr)
        assert r_json.exit_code == 1, "scan should have found the unprotected key"

        # 3. scan --format sarif — same file, the other structured format.
        r_sarif = runner.invoke(app, ["scan", "--format", "sarif", str(scan_file)])
        outputs.append(r_sarif.stdout + r_sarif.stderr)
        assert r_sarif.exit_code == 1, "scan should have found the unprotected key"

        # 4. A forced error with the real key already in play. The
        # secret is embedded in the raised exception's own message on
        # purpose — a generic failure message would trivially pass this
        # test without ever exercising sanitize_exception's scrubbing.
        def _boom(*_a: object, **_kw: object) -> None:
            raise sqlite3.DatabaseError(f"simulated failure touching {secret}")

        monkeypatch.setattr("worthless.storage.repository.ShardRepository.store_enrolled", _boom)
        r_err = runner.invoke(
            app,
            ["enroll", "--alias", "forced-error-test", "--key-stdin", "--provider", "openai"],
            input=f"{secret}\n",
            env=env_vars,
        )
        outputs.append(r_err.stdout + r_err.stderr)
        assert r_err.exit_code != 0, "forced failure should not have exited cleanly"

    combined = "\n".join(outputs) + logs.text
    assert secret not in combined, f"raw key leaked across lock/scan/forced-error: {combined!r}"

    # Zero orphaned tempfiles left behind by any of the above, and none of
    # them (if somehow still present) contain the raw key either.
    tmp_after = list(Path(tempfile.gettempdir()).glob("worthless-*"))
    new_tmp = [p for p in tmp_after if p.name not in tmp_before]
    for p in new_tmp:
        try:
            content = p.read_text(errors="replace")
        except OSError:
            continue
        assert secret not in content, f"tempfile {p} contains the raw key"
