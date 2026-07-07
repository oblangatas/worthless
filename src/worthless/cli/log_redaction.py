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

_AUTH_HEADER_RE = re.compile(r"(?i)(authorization[\"']?\s*[:=]\s*[\"']?Bearer\s+)[^\s\"']+")
_API_KEY_HEADER_RE = re.compile(r"(?i)(x-api-key[\"']?\s*[:=]\s*[\"']?)[^\s\"']+")
_QUERY_PARAM_RE = re.compile(r"(?i)([?&](?:api[-_]?key|key)=)[^&\s\"']+")


def _redact(text: str) -> str:
    text = KEY_PATTERN.sub(_REDACTED, text)
    text = _AUTH_HEADER_RE.sub(rf"\1{_REDACTED}", text)
    text = _API_KEY_HEADER_RE.sub(rf"\1{_REDACTED}", text)
    text = _QUERY_PARAM_RE.sub(rf"\1{_REDACTED}", text)
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
    - the root logger's own handlers (if any exist): a filter attached
      to a HANDLER runs for every record that propagates to it
      regardless of originating logger, unlike a filter attached to a
      Logger object (which only fires for that exact logger, never its
      descendants — verified empirically, not from memory of the docs).
    """
    targets: list[logging.Filterer] = [
        logging.getLogger("uvicorn.access"),
        logging.getLogger("uvicorn.error"),
        logging.lastResort,
        *logging.getLogger().handlers,
    ]
    for target in targets:
        if not any(isinstance(f, RedactingFilter) for f in target.filters):
            target.addFilter(RedactingFilter())
