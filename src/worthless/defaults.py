"""Default configuration values applied at enrollment time."""

from __future__ import annotations

#: Default spend cap in tokens applied to new enrollments. Tokens are an inexact
#: proxy for dollars across models — at 2026 prices 1B tokens is roughly $2.5k on
#: cheap input, ~$30k mid-mix, ~$75k on premium output (Anthropic Opus). A
#: runaway-protection ceiling, NOT a tight budget — pick a real cap for a real
#: budget. Override per-key with ``--spend-cap``, or ``None`` for unlimited.
DEFAULT_SPEND_CAP_TOKENS: int = 1_000_000_000

#: WOR-696 — token-count floor for every fail-closed metering path.
#:
#: ``settle_at_estimate`` (storage/spend_ledger.py) writes
#: ``max(estimate, GLOBAL_CEILING_TOKENS)`` into ``spend_log`` whenever the
#: actual usage is unreadable (mid-stream disconnect, malformed response,
#: stream-duration kill, idle-chunk kill). Without the floor, a request
#: that reserves 0 (e.g. no ``max_tokens``) settles at 0 and the cap
#: counter doesn't move — the documented bypass WOR-696 closes.
#:
#: Value = the highest documented max-output across every model currently
#: in production (gpt-5 family, Anthropic Opus 4.5). Direction of error
#: is conservative — over-bill on the fallback path, never under-bill.
#:
#: NO model registry. NO ``is_known_model`` / ``ceiling_for`` helpers. The
#: negative-existence guard test forbids any of those from coming back —
#: the global ceiling makes per-model bookkeeping pointless friction.
GLOBAL_CEILING_TOKENS: int = 128_000
