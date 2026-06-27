"""Shared charset definitions for format-preserving key splitting."""

import string

BASE64URL = string.ascii_letters + string.digits + "_-"
ALPHANUMERIC = string.ascii_letters + string.digits
PRINTABLE = "".join(chr(c) for c in range(33, 127))

PROVIDER_CHARSETS: dict[str, str] = {
    "openai": BASE64URL,
    "anthropic": BASE64URL,
    "google": BASE64URL,
    "xai": ALPHANUMERIC,
}
