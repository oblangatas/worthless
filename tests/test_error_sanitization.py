"""Tests for error message sanitization (WOR-96).

Ensures no error path leaks stack traces, file paths, DB paths,
or internal state to end users.
"""

from __future__ import annotations

import json
import re

import pytest


from worthless.cli.errors import ErrorCode, WorthlessError, sanitize_exception
from worthless.proxy.app import _sanitize_upstream_error
from worthless.proxy.errors import (
    auth_error_response,
    gateway_error_response,
    rate_limit_error_response,
    spend_cap_error_response,
)


# ---------------------------------------------------------------------------
# Patterns that must NEVER appear in user-facing error output
# ---------------------------------------------------------------------------

_LEAK_PATTERNS = [
    re.compile(r"/[a-zA-Z0-9_./-]{3,}\.(db|key|sqlite|json|py)"),  # Unix file paths
    re.compile(r"[A-Z]:\\"),  # Windows paths
    re.compile(r"Traceback \(most recent call last\)"),  # Stack traces
    re.compile(r"File \""),  # Stack trace frames
    re.compile(r"line \d+, in "),  # Stack trace frames
    re.compile(r"\.worthless/"),  # Home directory internals
    re.compile(r"shard_a/"),  # Shard directory
    re.compile(r"fernet"),  # Fernet key references (case-insensitive later)
]


def _contains_leak(text: str) -> str | None:
    """Return the first leak pattern matched, or None."""
    for pattern in _LEAK_PATTERNS:
        m = pattern.search(text)
        if m:
            return f"pattern {pattern.pattern!r} matched: {m.group()!r}"
    # Case-insensitive check for fernet
    if "fernet" in text.lower():
        return "contains 'fernet'"
    return None


# ---------------------------------------------------------------------------
# sanitize_exception unit tests
# ---------------------------------------------------------------------------


class TestSanitizeException:
    """Tests for the sanitize_exception helper."""

    def test_generic_message_returned(self):
        exc = Exception("something failed at /home/user/.worthless/worthless.db")
        result = sanitize_exception(exc)
        assert result == "an internal error occurred"

    def test_custom_generic_message(self):
        exc = OSError("Permission denied: /etc/shadow")
        result = sanitize_exception(exc, generic="storage operation failed")
        assert result == "storage operation failed"

    def test_no_file_paths_in_output(self):
        exc = FileNotFoundError(
            "[Errno 2] No such file: '/home/user/.worthless/shard_a/openai-abc'"
        )
        result = sanitize_exception(exc)
        assert _contains_leak(result) is None

    def test_no_db_paths_in_output(self):
        exc = Exception("database is locked: /tmp/worthless.db")
        result = sanitize_exception(exc)
        assert _contains_leak(result) is None

    def test_no_traceback_in_output(self):
        exc = RuntimeError('Traceback (most recent call last):\n  File "/app/main.py"')
        result = sanitize_exception(exc)
        assert _contains_leak(result) is None

    def test_aiosqlite_error_sanitized(self):
        exc = Exception("no such table: shards (in /home/user/.worthless/worthless.db)")
        result = sanitize_exception(exc)
        assert _contains_leak(result) is None

    def test_cryptography_error_sanitized(self):
        exc = Exception("Fernet key must be 32 url-safe base64-encoded bytes")
        result = sanitize_exception(exc)
        assert "fernet" not in result.lower()

    def test_returns_string(self):
        exc = ValueError("bad value")
        result = sanitize_exception(exc)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# WorthlessError format tests
# ---------------------------------------------------------------------------


class TestWorthlessErrorFormat:
    """WorthlessError should produce structured WRTLS-NNN codes, not raw exceptions."""

    def test_error_code_format(self):
        err = WorthlessError(ErrorCode.UNKNOWN, "an internal error occurred")
        text = str(err)
        assert text == "WRTLS-199: an internal error occurred"
        assert _contains_leak(text) is None

    def test_all_error_codes_produce_clean_output(self):
        for code in ErrorCode:
            err = WorthlessError(code, "test message")
            text = str(err)
            assert text.startswith("WRTLS-")
            assert _contains_leak(text) is None


# ---------------------------------------------------------------------------
# Proxy error response tests
# ---------------------------------------------------------------------------


class TestProxyErrorSanitization:
    """Proxy error responses must not leak internal state."""

    def test_auth_error_no_leak(self):
        for provider in ("openai", "anthropic"):
            resp = auth_error_response(provider)
            body = resp.body.decode()
            assert _contains_leak(body) is None
            # Should not contain any path-like strings
            assert "/.worthless" not in body
            assert "shard" not in body.lower()

    def test_gateway_error_no_leak(self):
        for status, msg in [(502, "bad gateway"), (504, "gateway timeout")]:
            resp = gateway_error_response(status, msg)
            body = resp.body.decode()
            assert _contains_leak(body) is None

    def test_spend_cap_error_no_leak(self):
        resp = spend_cap_error_response()
        body = resp.body.decode()
        assert _contains_leak(body) is None

    def test_rate_limit_error_no_leak(self):
        resp = rate_limit_error_response(60)
        body = resp.body.decode()
        assert _contains_leak(body) is None

    def test_sanitize_upstream_error_strips_details(self):
        # Simulate an upstream error that contains internal details
        upstream_body = json.dumps(
            {
                "error": {
                    "message": "Invalid API key: sk-proj-abc123... (from /home/user/.env)",
                    "type": "authentication_error",
                    "param": None,
                    "code": "invalid_api_key",
                }
            }
        ).encode()

        sanitized = _sanitize_upstream_error(401, upstream_body, "openai")
        parsed = json.loads(sanitized)
        assert parsed["error"]["message"] == "upstream provider error"
        assert "sk-proj" not in sanitized.decode()
        assert ".env" not in sanitized.decode()

    def test_sanitize_upstream_error_handles_malformed_json(self):
        sanitized = _sanitize_upstream_error(500, b"not json at all", "openai")
        parsed = json.loads(sanitized)
        assert parsed["error"]["message"] == "upstream provider error"

    def test_sanitize_upstream_error_anthropic_format(self):
        upstream_body = json.dumps(
            {
                "type": "error",
                "error": {
                    "type": "overloaded_error",
                    "message": "Internal server error at shard /data/node-3",
                },
            }
        ).encode()

        sanitized = _sanitize_upstream_error(529, upstream_body, "anthropic")
        parsed = json.loads(sanitized)
        assert parsed["error"]["message"] == "upstream provider error"
        assert parsed["error"]["type"] == "overloaded_error"
        assert "/data/" not in sanitized.decode()


# ---------------------------------------------------------------------------
# _sanitize_upstream_error allowlist unit tests (Fix 6)
# ---------------------------------------------------------------------------


class TestSanitizeUpstreamErrorAllowlist:
    """Direct unit tests for _sanitize_upstream_error's allowlist behaviour."""

    def test_wellformed_preserves_code_type_param_scrubs_message(self):
        """(a) Well-formed body: code, type, param preserved; message scrubbed."""
        body = json.dumps(
            {
                "error": {
                    "message": "secret internal reason: sk-live-abc123",
                    "type": "invalid_request_error",
                    "code": "context_length_exceeded",
                    "param": "messages",
                }
            }
        ).encode()
        result = json.loads(_sanitize_upstream_error(400, body, "openai"))
        assert result["error"]["message"] == "upstream provider error"
        assert result["error"]["type"] == "invalid_request_error"
        assert result["error"]["code"] == "context_length_exceeded"
        assert result["error"]["param"] == "messages"
        assert "sk-live" not in json.dumps(result)

    def test_missing_error_key_returns_generic(self):
        """(b) Missing `error` key -> returns generic body."""
        body = json.dumps({"message": "oops", "status": 500}).encode()
        result = json.loads(_sanitize_upstream_error(500, body, "openai"))
        assert result["error"]["message"] == "upstream provider error"

    def test_error_not_a_dict_returns_generic(self):
        """(c) `error` is not a dict -> returns generic body."""
        body = json.dumps({"error": "just a string"}).encode()
        result = json.loads(_sanitize_upstream_error(400, body, "openai"))
        assert result["error"]["message"] == "upstream provider error"

    def test_extra_top_level_keys_stripped(self):
        """(d) Body has extra top-level keys -> they are stripped."""
        body = json.dumps(
            {
                "error": {"message": "bad", "type": "server_error"},
                "internal_trace_id": "abc-123",
                "request_id": "req-xyz",
            }
        ).encode()
        result = json.loads(_sanitize_upstream_error(500, body, "openai"))
        assert "internal_trace_id" not in result
        assert "request_id" not in result
        assert list(result.keys()) == ["error"]

    def test_unknown_error_keys_stripped_allowlist_regression(self):
        """(e) Upstream error has extra unknown keys -> they are stripped (allowlist regression)."""
        body = json.dumps(
            {
                "error": {
                    "message": "leaked detail: key=sk-secret",
                    "type": "api_error",
                    "code": "rate_limit_exceeded",
                    "param": None,
                    "internal_field": "sensitive data",
                    "stack_trace": "Traceback ...",
                    "request_id": "req-abc",
                }
            }
        ).encode()
        result = json.loads(_sanitize_upstream_error(429, body, "openai"))
        error = result["error"]
        assert "internal_field" not in error
        assert "stack_trace" not in error
        assert "request_id" not in error
        assert error["message"] == "upstream provider error"
        assert error["type"] == "api_error"
        assert error["code"] == "rate_limit_exceeded"
        # param is None so it should NOT be included (allowlist skips None values)
        assert "param" not in error

    def test_completely_unparsable_bytes_returns_generic(self):
        """(f) Completely unparsable bytes -> returns generic body."""
        result = json.loads(_sanitize_upstream_error(500, b"\xff\xfe\x00", "openai"))
        assert result["error"]["message"] == "upstream provider error"

    def test_null_values_excluded_from_allowlist(self):
        """Allowlist skips keys whose upstream value is None/null."""
        body = json.dumps(
            {
                "error": {
                    "message": "bad",
                    "type": "invalid_request_error",
                    "code": None,
                    "param": None,
                }
            }
        ).encode()
        result = json.loads(_sanitize_upstream_error(400, body, "openai"))
        assert result["error"]["type"] == "invalid_request_error"
        assert "code" not in result["error"]
        assert "param" not in result["error"]


# ---------------------------------------------------------------------------
# CLI catch-all handler tests
# ---------------------------------------------------------------------------


class TestCLICatchAllHandlers:
    """Verify that CLI catch-all Exception handlers use sanitize_exception."""

    def test_lock_command_sanitizes_exceptions(self):
        """Lock command's catch-all should not leak raw exception text."""
        # Simulate what the catch-all handler does
        exc = OSError("[Errno 13] Permission denied: '/home/user/.worthless/worthless.db'")
        err = WorthlessError(ErrorCode.UNKNOWN, sanitize_exception(exc))
        text = str(err)
        assert "/home/user" not in text
        assert ".worthless" not in text
        assert "worthless.db" not in text

    def test_storage_exception_sanitized(self):
        """Storage exceptions must not leak DB paths."""
        exc = Exception("unable to open database file: /var/data/worthless.db")
        err = WorthlessError(
            ErrorCode.SHARD_STORAGE_FAILED,
            sanitize_exception(exc, generic="storage operation failed"),
        )
        text = str(err)
        assert "/var/data" not in text
        assert "worthless.db" not in text
        assert "storage operation failed" in text

    def test_bootstrap_exception_sanitized(self):
        """Bootstrap failures must not leak home directory paths."""
        exc = OSError("[Errno 13] Permission denied: '/home/user/.worthless'")
        err = WorthlessError(
            ErrorCode.BOOTSTRAP_FAILED,
            sanitize_exception(exc, generic="failed to initialise home directory"),
        )
        text = str(err)
        assert "/home/user" not in text
        assert "failed to initialise home directory" in text


# ---------------------------------------------------------------------------
# Typer pretty_exceptions_enable=False verification
# ---------------------------------------------------------------------------


class TestWrapCommandSanitization:
    """Wrap command must not leak raw exception details to users."""

    def test_wrap_proxy_spawn_does_not_leak_exception(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When spawn_proxy raises PermissionError, output must not contain the path."""
        from typer.testing import CliRunner

        from worthless.cli.app import app

        runner = CliRunner()

        def _fail(**_kw):
            raise PermissionError("Permission denied: /secret/path")

        monkeypatch.setattr(
            "worthless.cli.commands.wrap.spawn_proxy",
            _fail,
        )
        result = runner.invoke(
            app,
            ["wrap", "--", "echo", "hi"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1
        # Must NOT leak the internal path
        assert "/secret/path" not in result.output
        # Must contain structured error info
        assert "WRTLS-" in result.output or "failed to start proxy" in result.output.lower()

    def test_wrap_child_spawn_does_not_leak_exception(
        self, home_with_key, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When child Popen raises FileNotFoundError, output must not contain the path."""
        from unittest.mock import MagicMock

        from typer.testing import CliRunner

        from worthless.cli.app import app

        runner = CliRunner()

        mock_proxy = MagicMock()
        mock_proxy.poll.return_value = None
        mock_proxy.wait.return_value = 0

        monkeypatch.setattr(
            "worthless.cli.commands.wrap.spawn_proxy",
            lambda **_kw: (mock_proxy, 9999),
        )
        monkeypatch.setattr(
            "worthless.cli.commands.wrap.poll_health",
            lambda *_a, **_kw: True,
        )

        def _fail_popen(*_a, **_kw):
            raise FileNotFoundError("/usr/local/secret/bin")

        monkeypatch.setattr("subprocess.Popen", _fail_popen)

        result = runner.invoke(
            app,
            ["wrap", "--", "nonexistent-binary"],
            env={"WORTHLESS_HOME": str(home_with_key.base_dir)},
        )
        assert result.exit_code == 1
        # Must NOT leak the internal path
        assert "/usr/local/secret/bin" not in result.output
        # Must contain structured error info
        assert "WRTLS-" in result.output or "failed to start child" in result.output.lower()


class TestTyperConfiguration:
    """Verify Typer is configured to suppress pretty exceptions."""

    def test_pretty_exceptions_disabled(self):
        from worthless.cli.app import app

        assert app.pretty_exceptions_enable is False, (
            "pretty_exceptions_enable must be False to prevent stack traces in production"
        )
