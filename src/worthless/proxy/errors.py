"""Provider-compatible error response factories.

Returns structured JSON error responses matching the provider's native format.
Anti-enumeration: all auth failures return the same uniform body (no alias leaks).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ErrorResponse:
    """Lightweight response object for rule denials (no FastAPI dependency)."""

    status_code: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)


def _openai_error(status: int, message: str, error_type: str) -> bytes:
    return json.dumps(
        {"error": {"message": message, "type": error_type, "param": None, "code": None}}
    ).encode()


def _anthropic_error(status: int, message: str, error_type: str) -> bytes:
    return json.dumps({"type": "error", "error": {"type": error_type, "message": message}}).encode()


def _error_body(status: int, message: str, error_type: str, provider: str) -> bytes:
    if provider == "anthropic":
        return _anthropic_error(status, message, error_type)
    # Default to OpenAI format
    return _openai_error(status, message, error_type)


def auth_error_response(provider: str = "openai") -> ErrorResponse:
    """401 authentication required — uniform body for anti-enumeration."""
    return ErrorResponse(
        status_code=401,
        body=_error_body(401, "authentication required", "authentication_error", provider),
        headers={"content-type": "application/json"},
    )


def spend_cap_error_response(provider: str = "openai") -> ErrorResponse:
    """402 spend cap exceeded."""
    return ErrorResponse(
        status_code=402,
        body=_error_body(402, "spend cap exceeded", "insufficient_quota", provider),
        headers={"content-type": "application/json"},
    )


def rate_limit_error_response(retry_after: int, provider: str = "openai") -> ErrorResponse:
    """429 rate limit exceeded with Retry-After header."""
    return ErrorResponse(
        status_code=429,
        body=_error_body(429, "rate limit exceeded", "rate_limit_error", provider),
        headers={"content-type": "application/json", "Retry-After": str(retry_after)},
    )


def token_budget_error_response(
    period: str, used: int, limit: int, provider: str = "openai"
) -> ErrorResponse:
    """429 token budget exceeded with usage stats."""
    message = f"{period} token budget exceeded: {used:,}/{limit:,}"
    return ErrorResponse(
        status_code=429,
        body=_error_body(429, message, "token_budget_exceeded", provider),
        headers={"content-type": "application/json"},
    )


def time_window_error_response(
    current_time: str, window: str, provider: str = "openai"
) -> ErrorResponse:
    """403 outside allowed time window."""
    message = f"access denied: current time {current_time} outside allowed window {window}"
    return ErrorResponse(
        status_code=403,
        body=_error_body(403, message, "time_window_denied", provider),
        headers={"content-type": "application/json"},
    )


def request_too_large_response(limit_bytes: int) -> ErrorResponse:
    """413 request entity too large — body exceeded WORTHLESS_MAX_REQUEST_BYTES."""
    message = f"request body exceeds maximum allowed size ({limit_bytes:,} bytes)"
    return ErrorResponse(
        status_code=413,
        body=_openai_error(413, message, "invalid_request_error"),
        headers={"content-type": "application/json"},
    )


def gateway_error_response(status: int, message: str, provider: str = "openai") -> ErrorResponse:
    """Gateway error (502/504) — upstream connectivity or timeout failure."""
    return ErrorResponse(
        status_code=status,
        body=_error_body(status, message, "gateway_error", provider),
        headers={"content-type": "application/json"},
    )
