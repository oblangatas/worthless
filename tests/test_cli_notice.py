"""WOR-488 — one-time AS-IS / no-warranty CLI notice.

Proves the notice shows once per install, never corrupts ``--json`` output,
and uses a marker separate from the keystore-bootstrap marker.
"""

from __future__ import annotations

from typer.testing import CliRunner

from worthless.cli.bootstrap import WorthlessHome
from worthless.cli.console import WorthlessConsole
from worthless.cli.notice import AS_IS_NOTICE, maybe_show_as_is_notice

runner = CliRunner(mix_stderr=False)


def _app():
    from worthless.cli.app import app

    return app


def test_marker_is_separate_from_bootstrap(tmp_path) -> None:
    home = WorthlessHome(base_dir=tmp_path)
    assert home.warranty_notice_marker == tmp_path / ".warranty-ack"
    assert home.warranty_notice_marker != home.bootstrapped_marker


def test_notice_text_anchored_on_agpl() -> None:
    upper = AS_IS_NOTICE.upper()
    assert "AS IS" in upper
    assert "WARRANTY" in upper


def test_notice_shown_once_then_marker(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WORTHLESS_HOME", str(tmp_path))
    console = WorthlessConsole()
    assert maybe_show_as_is_notice(console) is True  # first run shows
    assert (tmp_path / ".warranty-ack").exists()
    assert maybe_show_as_is_notice(console) is False  # second run silent


def test_notice_skipped_in_json_mode(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WORTHLESS_HOME", str(tmp_path))
    console = WorthlessConsole(json_mode=True)
    assert maybe_show_as_is_notice(console) is False
    # json must NOT consume the one-shot, so a later human run still sees it.
    assert not (tmp_path / ".warranty-ack").exists()


def test_notice_on_stderr_first_run_only(tmp_path) -> None:
    env = {"WORTHLESS_HOME": str(tmp_path)}
    first = runner.invoke(_app(), ["status"], env=env)
    assert "AS IS" in first.stderr
    second = runner.invoke(_app(), ["status"], env=env)
    assert "AS IS" not in second.stderr


def test_notice_never_pollutes_json_stdout(tmp_path) -> None:
    env = {"WORTHLESS_HOME": str(tmp_path)}
    result = runner.invoke(_app(), ["status", "--json"], env=env)
    assert "AS IS" not in result.stdout
