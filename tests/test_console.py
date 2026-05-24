"""Tests for CLI foundation: console wrapper, error codes, key patterns, and app entry point."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------


class TestErrorCodes:
    def test_error_code_values(self):
        from worthless.cli.errors import ErrorCode

        assert ErrorCode.BOOTSTRAP_FAILED == 100
        assert ErrorCode.ENV_NOT_FOUND == 101
        assert ErrorCode.KEY_NOT_FOUND == 102
        assert ErrorCode.SHARD_STORAGE_FAILED == 103
        assert ErrorCode.PROXY_UNREACHABLE == 104
        assert ErrorCode.LOCK_IN_PROGRESS == 105
        assert ErrorCode.SCAN_ERROR == 106
        assert ErrorCode.PORT_IN_USE == 107
        assert ErrorCode.WRAP_CHILD_FAILED == 108
        assert ErrorCode.UNKNOWN == 199

    def test_worthless_error_format(self):
        from worthless.cli.errors import ErrorCode, WorthlessError

        err = WorthlessError(ErrorCode.BOOTSTRAP_FAILED, "cannot create directory")
        assert str(err) == "WRTLS-100: cannot create directory"

    def test_worthless_error_is_exception(self):
        from worthless.cli.errors import ErrorCode, WorthlessError

        with pytest.raises(WorthlessError):
            raise WorthlessError(ErrorCode.UNKNOWN, "something broke")


# ---------------------------------------------------------------------------
# Key patterns
# ---------------------------------------------------------------------------


class TestKeyPatterns:
    def test_detect_provider_openai(self):
        from worthless.cli.key_patterns import detect_provider

        assert detect_provider("sk-proj-abc123defghijklmnop") == "openai"

    def test_detect_provider_openai_plain(self):
        from worthless.cli.key_patterns import detect_provider

        assert detect_provider("sk-abc123defghijklmnop") == "openai"

    def test_detect_provider_anthropic(self):
        from worthless.cli.key_patterns import detect_provider

        assert detect_provider("sk-ant-abc123defghijklmnop") == "anthropic"

    def test_detect_provider_anthropic_api03(self):
        from worthless.cli.key_patterns import detect_provider

        assert detect_provider("sk-ant-api03-abc123defghijklmnop") == "anthropic"

    def test_detect_provider_google(self):
        from worthless.cli.key_patterns import detect_provider

        assert detect_provider("AIzaSyAbc123defghijklm") == "google"

    def test_detect_provider_xai(self):
        from worthless.cli.key_patterns import detect_provider

        assert detect_provider("xai-abc123defghijklmnop") == "xai"

    def test_detect_provider_unknown(self):
        from worthless.cli.key_patterns import detect_provider

        assert detect_provider("not-a-key") is None

    def test_detect_prefix_openai(self):
        from worthless.cli.key_patterns import detect_prefix

        assert detect_prefix("sk-proj-abc123defghijklmnop", "openai") == "sk-proj-"

    def test_detect_prefix_anthropic_api03(self):
        from worthless.cli.key_patterns import detect_prefix

        assert detect_prefix("sk-ant-api03-abc123defghijklmnop", "anthropic") == "sk-ant-api03-"

    def test_detect_prefix_anthropic_short(self):
        from worthless.cli.key_patterns import detect_prefix

        assert detect_prefix("sk-ant-abc123defghijklmnop", "anthropic") == "sk-ant-"


# ---------------------------------------------------------------------------
# Console wrapper
# ---------------------------------------------------------------------------


class TestConsoleWrapper:
    def test_status_writes_to_stderr(self, capsys):
        from worthless.cli.console import WorthlessConsole

        c = WorthlessConsole(quiet=False, json_mode=False)
        with c.status("working..."):
            pass
        captured = capsys.readouterr()
        # Spinner goes to stderr, nothing to stdout
        assert captured.out == ""

    def test_quiet_mode_suppresses_status(self, capsys):
        from worthless.cli.console import WorthlessConsole

        c = WorthlessConsole(quiet=True, json_mode=False)
        with c.status("working..."):
            pass
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_print_result_json_mode(self, capsys):
        from worthless.cli.console import WorthlessConsole

        c = WorthlessConsole(quiet=False, json_mode=True)
        data = {"key": "value", "count": 42}
        c.print_result(data)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed == data

    def test_print_success_to_stderr(self, capsys):
        from worthless.cli.console import WorthlessConsole

        c = WorthlessConsole(quiet=False, json_mode=False)
        c.print_success("done")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "done" in captured.err

    def test_quiet_mode_suppresses_success(self, capsys):
        from worthless.cli.console import WorthlessConsole

        c = WorthlessConsole(quiet=True, json_mode=False)
        c.print_success("done")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_print_error_to_stderr(self, capsys):
        from worthless.cli.console import WorthlessConsole
        from worthless.cli.errors import ErrorCode, WorthlessError

        c = WorthlessConsole(quiet=False, json_mode=False)
        err = WorthlessError(ErrorCode.ENV_NOT_FOUND, "missing .env")
        c.print_error(err)
        captured = capsys.readouterr()
        assert "WRTLS-101" in captured.err

    def test_print_warning_to_stderr(self, capsys):
        from worthless.cli.console import WorthlessConsole

        c = WorthlessConsole(quiet=False, json_mode=False)
        c.print_warning("be careful")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "be careful" in captured.err

    def test_quiet_mode_suppresses_warning(self, capsys):
        from worthless.cli.console import WorthlessConsole

        c = WorthlessConsole(quiet=True, json_mode=False)
        c.print_warning("be careful")
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_no_color_respected(self):
        from worthless.cli.console import WorthlessConsole

        with patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False):
            c = WorthlessConsole(quiet=False, json_mode=False)
            assert c._no_color is True

    def test_get_set_console(self):
        from worthless.cli.console import WorthlessConsole, get_console, set_console

        c = WorthlessConsole(quiet=True, json_mode=True)
        set_console(c)
        assert get_console() is c


# ---------------------------------------------------------------------------
# App entry point
# ---------------------------------------------------------------------------


class TestAppEntryPoint:
    def test_help_exits_zero(self):
        from typer.testing import CliRunner

        from worthless.cli.app import app

        runner = CliRunner()
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "worthless" in result.output.lower() or "api" in result.output.lower()

    def test_no_args_runs_default_command(self, home_dir):
        # No xdist_group marker needed: the autouse `_isolate_default_command_proxy`
        # fixture in conftest.py stubs the daemon path for every test, so two
        # workers can run this in parallel without racing port 8787.
        # Isolated WORTHLESS_HOME: without it the no-args path resolves the
        # developer's real ~/.worthless and run_default aborts with WRTLS-102
        # on a dogfooding box whose Fernet key lives only in the keyring.
        from typer.testing import CliRunner

        from worthless.cli.app import app

        runner = CliRunner()
        result = runner.invoke(app, [], env={"WORTHLESS_HOME": str(home_dir.base_dir)})
        assert result.exit_code == 0, (
            f"worthless with no args failed:\n"
            f"output:\n{result.output}\n"
            f"exception: {result.exception!r}"
        )
