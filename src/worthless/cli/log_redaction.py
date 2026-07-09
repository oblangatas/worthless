"""WOR-277: no logger may ever emit a raw key value.

A structural guarantee (attached at the logger/handler level) rather
than a per-callsite one, so a future log statement can't leak a key by
accident. Covers three shapes a key can appear in a log line:
  - the key's own text, wherever it appears (``KEY_PATTERN``)
  - an ``Authorization``/``x-api-key`` header value, even one that
    doesn't itself match a known provider-prefix shape
  - a ``key=``/``api_key=``/``api-key=`` query parameter — uvicorn's
    access log line is ``"METHOD /path?query HTTP/1.1" status``, and a
    client-supplied query string is not something worthless controls
"""

from __future__ import annotations

import logging
import re

from worthless.cli.key_patterns import KEY_PATTERN

_REDACTED = "[REDACTED]"

# Header names must stay in sync with adapters/types.py's
# _SENSITIVE_HEADER_KEYS. Not imported directly: that set treats both
# headers identically (whole value -> "REDACTED"), while these need
# different match shapes (Authorization has a "Bearer " prefix to
# preserve; x-api-key doesn't), so unifying them would force one shape
# on both rather than removing real duplication.
_AUTH_HEADER_RE = re.compile(r"(?i)(authorization[\"']?\s*[:=]\s*[\"']?Bearer\s+)[^\s\"']+")
_API_KEY_HEADER_RE = re.compile(r"(?i)(x-api-key[\"']?\s*[:=]\s*[\"']?)[^\s\"']+")
_QUERY_PARAM_RE = re.compile(r"(?i)([?&](?:api[-_]?key|key)=)[^&\s\"']+")
_CAPTURE_GROUP_PATTERNS = (_AUTH_HEADER_RE, _API_KEY_HEADER_RE, _QUERY_PARAM_RE)

_EXC_FORMATTER = logging.Formatter()


def _redact(text: str) -> str:
    text = KEY_PATTERN.sub(_REDACTED, text)
    for pattern in _CAPTURE_GROUP_PATTERNS:
        text = pattern.sub(rf"\1{_REDACTED}", text)
    return text


class RedactingFilter(logging.Filter):
    """Scrubs key-shaped values out of every log record it sees.

    Redacts ``record.msg`` and each string element of ``record.args`` IN
    PLACE, preserving args' original shape (tuple length, dict keys,
    non-string elements untouched) — uvicorn's own access logger logs via
    lazy %-args, so the secret usually lives in one arg, not the message
    template. Collapsing msg+args into one fully-rendered string (via
    ``record.getMessage()``) and clearing args was tried first and broke
    uvicorn's own ``AccessFormatter``, which unpacks ``record.args`` as a
    structured tuple for its own colorized formatting — confirmed by
    running against a real uvicorn server, not a strawman logger.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _redact(record.msg)
        if isinstance(record.args, dict):
            record.args = {
                k: (_redact(v) if isinstance(v, str) else v) for k, v in record.args.items()
            }
        elif record.args:
            try:
                record.args = tuple(_redact(a) if isinstance(a, str) else a for a in record.args)
            except TypeError:
                pass  # non-iterable args (rare) — leave as-is rather than crash

        # logger.warning(..., exc_info=True) renders a traceback the same
        # way msg/args render — a key in an exception's own message
        # survives an unredacted traceback otherwise. proxy/app.py has
        # reachable exc_info=True call sites (CodeRabbit review, PR #426).
        # Render early, redact, cache the result, and clear exc_info so no
        # formatter downstream can re-derive raw text from it — same
        # cache-then-neutralize pattern as record.msg/args above. Safe to
        # run more than once on the same record (e.g. multiple handlers):
        # exc_info is None on any pass after the first, so it's a no-op.
        if record.exc_info:
            try:
                record.exc_text = _redact(_EXC_FORMATTER.formatException(record.exc_info))
            except Exception:
                record.exc_text = _REDACTED
            record.exc_info = None
        if record.stack_info:
            record.stack_info = _redact(str(record.stack_info))

        return True


def install_redaction_filter() -> None:
    """Attach RedactingFilter everywhere a key could plausibly leak.

    - ``uvicorn.access`` / ``uvicorn.error``: uvicorn logs directly
      through these loggers and sets ``propagate=False`` on both (in its
      own default config, then again programmatically in
      ``Config.configure_logging()``), so a filter on root would never
      see their records — each needs its own attachment.
    - ``logging.lastResort``: the stdlib's built-in stderr fallback used
      when a WARNING+ record has no handler anywhere in its chain —
      covers any *future* ``worthless.*`` module logger call that isn't
      otherwise wired to a handler, without introducing new output that
      doesn't exist today.
    - the root logger's own handlers (if any exist AT CALL TIME): a
      filter attached to a HANDLER runs for every record that
      propagates to it regardless of originating logger, unlike a
      filter attached to a Logger object (which only fires for that
      exact logger, never its descendants — verified empirically, not
      from memory of the docs). This is a snapshot, not a standing
      guarantee like the uvicorn.access/error attachment above: a
      handler added to root AFTER this function runs (e.g. an APM/
      tracing library instrumenting logging at its own startup) is
      invisible to it. No such dependency exists in this project today.
    """
    targets: list[logging.Filterer] = [
        logging.getLogger("uvicorn.access"),
        logging.getLogger("uvicorn.error"),
        *logging.getLogger().handlers,
    ]
    # logging.lastResort is Optional — a user/framework can set it to None
    # to disable the stdlib's stderr fallback entirely.
    if logging.lastResort is not None:
        targets.append(logging.lastResort)
    for target in targets:
        if not any(isinstance(f, RedactingFilter) for f in target.filters):
            target.addFilter(RedactingFilter())
