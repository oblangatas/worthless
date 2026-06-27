"""Token extraction from provider responses and async spend recording."""

from __future__ import annotations

import json
from dataclasses import dataclass

import aiosqlite


@dataclass(frozen=True)
class UsageInfo:
    """Extracted token usage from a provider response."""

    total_tokens: int
    model: str | None


def extract_usage_openai(data: bytes) -> UsageInfo | None:
    """Extract token usage from an OpenAI response (JSON or SSE).

    For JSON responses: parses usage.total_tokens and model directly.
    For SSE streams: scans for the final chunk containing a "usage" field.
    Returns None if usage data is not found or data is malformed.
    """
    if not data:
        return None

    try:
        parsed = json.loads(data)
        if isinstance(parsed, dict) and "usage" in parsed:
            total = parsed["usage"].get("total_tokens", 0)
            return UsageInfo(total_tokens=total, model=parsed.get("model"))
    except (json.JSONDecodeError, ValueError):
        pass

    try:
        text = data.decode("utf-8", errors="replace")
        for line in reversed(text.splitlines()):
            if not line.startswith("data: "):
                continue
            payload = line[6:].strip()
            if payload == "[DONE]":
                continue
            try:
                chunk = json.loads(payload)
                if isinstance(chunk, dict) and "usage" in chunk:
                    total = chunk["usage"].get("total_tokens", 0)
                    return UsageInfo(total_tokens=total, model=chunk.get("model"))
            except (json.JSONDecodeError, ValueError):
                continue
    except Exception:  # noqa: S110 — best-effort SSE decode; malformed response must not raise  # nosec B110
        pass

    return None


def _find_sse_event_data(
    lines: list[str],
    event_name: str,
    *,
    reverse: bool = False,
) -> dict | None:
    """Find an SSE event by name and parse its data payload."""
    indices = range(len(lines) - 1, -1, -1) if reverse else range(len(lines))
    for i in indices:
        if lines[i].strip() == f"event: {event_name}":
            for j in range(i + 1, len(lines)):
                data_line = lines[j].strip()
                if data_line.startswith("data: "):
                    try:
                        return json.loads(data_line[6:])
                    except (json.JSONDecodeError, ValueError):
                        return None
    return None


def extract_usage_anthropic(data: bytes) -> UsageInfo | None:
    """Extract token usage from an Anthropic response (JSON or SSE).

    For non-streaming JSON: parses usage.input_tokens + usage.output_tokens directly.
    For SSE streams: scans for message_start (input_tokens) and message_delta (output_tokens).
    Returns None if no usage data found.
    """
    if not data:
        return None

    try:
        parsed = json.loads(data)
        if isinstance(parsed, dict) and "usage" in parsed:
            usage = parsed["usage"]
            input_tokens = usage.get("input_tokens", 0)
            cache_creation = usage.get("cache_creation_input_tokens", 0)
            cache_read = usage.get("cache_read_input_tokens", 0)
            output_tokens = usage.get("output_tokens", 0)
            return UsageInfo(
                total_tokens=input_tokens + cache_creation + cache_read + output_tokens,
                model=parsed.get("model"),
            )
    except (json.JSONDecodeError, ValueError):
        pass

    try:
        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
    except Exception:  # noqa: S110 — best-effort SSE decode; malformed response must not raise
        return None

    input_tokens = 0
    model: str | None = None

    start = _find_sse_event_data(lines, "message_start")
    if start:
        msg = start.get("message", {})
        usage = msg.get("usage", {})
        input_tokens = (
            usage.get("input_tokens", 0)
            + usage.get("cache_creation_input_tokens", 0)
            + usage.get("cache_read_input_tokens", 0)
        )
        model = msg.get("model")

    delta = _find_sse_event_data(lines, "message_delta", reverse=True)
    if delta is None or "usage" not in delta:
        return None

    output_tokens = delta["usage"].get("output_tokens", 0)
    return UsageInfo(total_tokens=input_tokens + output_tokens, model=model)


class StreamingUsageCollector:
    """Incrementally extract usage from SSE chunks without buffering.

    Processes each chunk as it arrives, extracting only usage-bearing
    data. Does not store raw chunks — bounded memory regardless of
    stream length.
    """

    def __init__(self, provider: str) -> None:
        self.provider = provider
        self._partial_line: str = ""
        self._input_tokens: int = 0
        self._output_tokens: int = 0
        self._total_tokens: int | None = None
        self._model: str | None = None
        self._pending_event: str | None = None
        self._found_usage = False

    # No legitimate SSE line exceeds 64KB; cap _partial_line to prevent
    # a malicious upstream without newlines from growing it unbounded.
    _MAX_PARTIAL_LINE = 65_536

    def feed(self, chunk: bytes) -> None:
        """Process an SSE chunk, extracting usage data."""
        text = self._partial_line + chunk.decode("utf-8", errors="replace")
        lines = text.split("\n")
        # Last element may be incomplete — save for next feed
        partial = lines[-1]
        if len(partial) > self._MAX_PARTIAL_LINE:
            partial = ""  # discard oversized partial — no legitimate SSE line is this big
        self._partial_line = partial

        for line in lines[:-1]:
            stripped = line.strip()
            if stripped.startswith("event: "):
                self._pending_event = stripped[7:]
            elif stripped.startswith("data: "):
                payload = stripped[6:]
                if payload == "[DONE]":
                    continue
                self._parse_data(payload)

    def _parse_data(self, payload: str) -> None:
        """Parse a single SSE data line and extract usage if present."""
        try:
            parsed = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return

        if not isinstance(parsed, dict):
            return

        if self.provider == "openai":
            usage = parsed.get("usage")
            if usage and isinstance(usage, dict):
                self._total_tokens = usage.get("total_tokens", 0)
                self._model = parsed.get("model", self._model)
                self._found_usage = True
        elif self.provider == "anthropic":
            if self._pending_event == "message_start":
                msg = parsed.get("message")
                if not isinstance(msg, dict):
                    return
                usage = msg.get("usage")
                if isinstance(usage, dict):
                    self._input_tokens = (
                        usage.get("input_tokens", 0)
                        + usage.get("cache_creation_input_tokens", 0)
                        + usage.get("cache_read_input_tokens", 0)
                    )
                self._model = msg.get("model", self._model)
            elif self._pending_event == "message_delta":
                usage = parsed.get("usage")
                if not isinstance(usage, dict):
                    return
                if "output_tokens" in usage:
                    self._output_tokens = usage["output_tokens"]
                    self._found_usage = True

        self._pending_event = None

    def _flush_partial(self) -> None:
        """Parse any leftover data in _partial_line before returning results."""
        if self._partial_line:
            stripped = self._partial_line.strip()
            if stripped.startswith("data: "):
                payload = stripped[6:]
                if payload != "[DONE]":
                    self._parse_data(payload)
            elif stripped.startswith("event: "):
                self._pending_event = stripped[7:]
            self._partial_line = ""

    def result(self) -> UsageInfo | None:
        """Return extracted usage after stream ends."""
        self._flush_partial()
        if self.provider == "openai":
            if self._total_tokens is not None:
                return UsageInfo(total_tokens=self._total_tokens, model=self._model)
            return None
        elif self.provider == "anthropic":
            if not self._found_usage:
                return None
            return UsageInfo(
                total_tokens=self._input_tokens + self._output_tokens,
                model=self._model,
            )
        return None


async def record_spend(
    db_path: str,
    alias: str,
    tokens: int,
    model: str | None,
    provider: str,
) -> None:
    """Insert a spend record into the spend_log table."""
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO spend_log (key_alias, tokens, model, provider) VALUES (?, ?, ?, ?)",
            (alias, tokens, model, provider),
        )
        await db.commit()
