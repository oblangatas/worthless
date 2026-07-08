"""WOR-277: prove the redaction filter actually protects the loggers that
matter — most importantly uvicorn's own access logger, not a strawman.

httpx.ASGITransport-based in-process testing (what test_proxy_e2e.py uses)
never exercises uvicorn's protocol-level access-log middleware at all — that
code only runs when a real asyncio server accepts a real connection. So the
one claim this ticket most needs proven ("the proxy access log never records
a key") can only be tested against a genuine running uvicorn server.
"""

from __future__ import annotations

import asyncio
import logging

import aiosqlite
import httpx
import uvicorn

from worthless.cli.log_redaction import RedactingFilter, _redact, install_redaction_filter
from worthless.proxy.app import create_app
from worthless.proxy.config import ProxySettings
from worthless.proxy.rules import RateLimitRule, RulesEngine, SpendCapRule
from worthless.storage.repository import ShardRepository

from tests.helpers import fake_openai_key

# Deterministic runtime-generated fake key (not a source literal) — see
# tests/helpers.py's own docstring: avoids tripping worthless scan / GitHub
# secret scanning / any other regex-based secret detector on this file.
_SECRET = fake_openai_key()


class _CapturingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


# ---------------------------------------------------------------------------
# Unit tests: _redact() and RedactingFilter in isolation
# ---------------------------------------------------------------------------


class TestRedactShapes:
    """Each shape a key can appear in a log line must be scrubbed."""

    def test_bare_key_pattern(self) -> None:
        assert _SECRET not in _redact(f"loaded key {_SECRET} from env")

    def test_authorization_header_line(self) -> None:
        text = _redact(f"Authorization: Bearer {_SECRET}")
        assert _SECRET not in text
        assert "Authorization: Bearer [REDACTED]" == text

    def test_x_api_key_header_line(self) -> None:
        text = _redact(f"x-api-key: {_SECRET}")
        assert _SECRET not in text

    def test_query_string_api_key_param(self) -> None:
        text = _redact(f"GET /openai/v1?api_key={_SECRET} HTTP/1.1")
        assert _SECRET not in text
        assert "?api_key=[REDACTED]" in text

    def test_query_string_bare_key_param(self) -> None:
        text = _redact(f"GET /openai/v1?key={_SECRET}&foo=bar HTTP/1.1")
        assert _SECRET not in text
        assert "&foo=bar" in text, "unrelated query params must survive"

    def test_dict_repr_header_value(self) -> None:
        text = _redact(f"headers={{'x-api-key': '{_SECRET}'}}")
        assert _SECRET not in text

    def test_non_matching_text_untouched(self) -> None:
        text = "GET /health HTTP/1.1 200"
        assert _redact(text) == text


class TestRedactingFilterLazyArgs:
    """uvicorn logs via lazy %-args — the secret lives in record.args, not
    record.msg. A filter that only inspects record.msg would silently miss
    it entirely."""

    def test_filter_redacts_message_built_from_percent_args(self) -> None:
        logger = logging.getLogger("test.wor277.lazyargs")
        logger.propagate = False
        logger.setLevel(logging.DEBUG)
        capture = _CapturingHandler()
        logger.addHandler(capture)
        logger.addFilter(RedactingFilter())

        logger.info('%s - "%s" %d', "127.0.0.1", f"GET /x?api_key={_SECRET} HTTP/1.1", 200)

        assert len(capture.lines) == 1
        assert _SECRET not in capture.lines[0]
        assert "[REDACTED]" in capture.lines[0]

    def test_filter_leaves_non_secret_records_unmodified(self) -> None:
        logger = logging.getLogger("test.wor277.clean")
        logger.propagate = False
        logger.setLevel(logging.DEBUG)
        capture = _CapturingHandler()
        logger.addHandler(capture)
        logger.addFilter(RedactingFilter())

        logger.info('%s - "%s" %d', "127.0.0.1", "GET /health HTTP/1.1", 200)

        assert capture.lines == ['127.0.0.1 - "GET /health HTTP/1.1" 200']


class TestInstallRedactionFilter:
    def test_attaches_to_uvicorn_access_and_error(self) -> None:
        install_redaction_filter()
        for name in ("uvicorn.access", "uvicorn.error"):
            target = logging.getLogger(name)
            assert any(isinstance(f, RedactingFilter) for f in target.filters), (
                f"{name} missing RedactingFilter"
            )

    def test_idempotent(self) -> None:
        install_redaction_filter()
        install_redaction_filter()
        target = logging.getLogger("uvicorn.access")
        count = sum(1 for f in target.filters if isinstance(f, RedactingFilter))
        assert count == 1, f"expected exactly one RedactingFilter, found {count}"


# ---------------------------------------------------------------------------
# The real thing: a genuine uvicorn server, a genuine request, genuine logs
# ---------------------------------------------------------------------------


async def test_real_uvicorn_access_log_never_contains_query_string_key(
    tmp_db_path: str, fernet_key: bytes, repo: ShardRepository
) -> None:
    """A client's own ``?api_key=...`` query string is not something
    worthless's own routing ever puts there (``_extract_shard_a`` only reads
    the Authorization/x-api-key headers) — but a foreign client appending
    one to its request is still a real, persistent leak once
    ``worthless service install`` pipes uvicorn's default access log to a
    log file (launchd) or the systemd journal forever. Runs a genuine
    ``uvicorn.Server`` bound to loopback so uvicorn's real protocol-level
    access-log middleware actually fires.
    """
    settings = ProxySettings(
        db_path=tmp_db_path,
        fernet_key=bytearray(fernet_key),
        default_rate_limit_rps=100.0,
        upstream_timeout=5.0,
        streaming_timeout=5.0,
        allow_insecure=True,
    )
    app = create_app(settings)  # also installs the redaction filter
    db = await aiosqlite.connect(settings.db_path)
    app.state.db = db
    app.state.repo = repo
    app.state.httpx_client = httpx.AsyncClient(follow_redirects=False)
    app.state.rules_engine = RulesEngine(
        rules=[SpendCapRule(db=db), RateLimitRule(default_rps=100.0)]
    )

    capture = _CapturingHandler()
    access_logger = logging.getLogger("uvicorn.access")

    # uvicorn.Config.__init__ calls configure_logging() (dictConfig), which
    # REPLACES uvicorn.access's handler list — attaching `capture` before
    # constructing Config would silently wipe it. Must attach after.
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="info"))
    access_logger.addHandler(capture)
    serve_task = asyncio.create_task(server.serve())
    try:
        for _ in range(500):
            if server.started:
                break
            await asyncio.sleep(0.01)
        assert server.started, "uvicorn server never reported started"

        port = server.servers[0].sockets[0].getsockname()[1]
        async with httpx.AsyncClient() as client:
            await client.get(
                f"http://127.0.0.1:{port}/openai/v1/models",
                params={"api_key": _SECRET},
            )
    finally:
        server.should_exit = True
        await asyncio.wait_for(serve_task, timeout=5)
        access_logger.removeHandler(capture)
        await app.state.httpx_client.aclose()
        await db.close()

    combined = "\n".join(capture.lines)
    assert combined, "expected uvicorn to emit at least one real access-log line"
    assert _SECRET not in combined, f"raw key leaked into uvicorn's access log: {combined!r}"
    assert "[REDACTED]" in combined, (
        f"expected the redaction filter to have fired on a real request, got: {combined!r}"
    )
