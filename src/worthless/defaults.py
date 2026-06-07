"""Default configuration values applied at enrollment time."""

from __future__ import annotations

#: Default spend cap in tokens applied to new enrollments. Tokens are an inexact
#: proxy for dollars across models — at 2026 prices 1B tokens is roughly $2.5k on
#: cheap input, ~$30k mid-mix, ~$75k on premium output (Anthropic Opus). A
#: runaway-protection ceiling, NOT a tight budget — pick a real cap for a real
#: budget. Override per-key with ``--spend-cap``, or ``None`` for unlimited.
DEFAULT_SPEND_CAP_TOKENS: int = 1_000_000_000
