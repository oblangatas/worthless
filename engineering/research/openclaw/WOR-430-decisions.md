# WOR-430 — Verdicts on the 5 Critical Edge Cases

> Parent: [WOR-421 OpenClaw Epic](https://linear.app/plumbusai/issue/WOR-421). This document produces defensible verdicts for the 5 behaviors that must be locked in worthless before OpenClaw ships. Every verdict is grounded in a real competitive prior-art citation. No prior `engineering/research/openclaw/README.md` was on disk at write time; this report stands alone.

---

## 1. Fail-open vs fail-closed when proxy unreachable

**Verdict: Fail-CLOSED. The CLI/SDK shim must refuse to forward traffic if the worthless proxy or its control plane is unreachable.**

**Rationale.** LiteLLM's `allow_requests_on_db_unavailable` flag (PR [#9533, Mar 2025](https://github.com/BerriAI/litellm/pull/9533)) was retrofitted because operators running LiteLLM **inside a VPC** wanted requests to keep flowing when their internal Postgres flapped — the documented condition is explicitly "Only USE when running LiteLLM on your VPC" ([prod best practices §6](https://docs.litellm.ai/docs/proxy/prod)). Even there, LiteLLM still **blocks** on `LiteLLM Budget Errors` when the DB is reachable but over budget — fail-open is scoped to *infrastructure unreachability*, not *policy unreachability*. Cloudflare AI Gateway's [Fallbacks](https://developers.cloudflare.com/ai-gateway/configuration/fallbacks/) pattern fails *over* to a different upstream — it never fails *open* past the gateway itself; the gateway is the trust boundary. Worthless's entire value proposition is the spend cap (PRD §"three architectural invariants" — gate-before-reconstruct). If a stolen key + offline proxy → direct provider call, the attacker has won. Cost overrun on a stolen Anthropic key compounds at ~$15/M input tokens; a 90-second outage of worthless is far cheaper than a 12-hour cap-bypass window. The OpenAI Python SDK on `APIConnectionError` raises after retries (`openai-python/_base_client.py` `_should_retry` returns False on connection errors that exhaust retries) — the SDK already surfaces "I cannot reach my configured base URL" as a hard error, so fail-closed matches the SDK's own contract.

**Test impact.**
- Integration test: kill `worthless-proxy` container; agent SDK call returns connection error within 5 s, never reaches `api.anthropic.com` (verify via egress-blocking netns or `tests/openclaw/docker-compose.yml` with proxy stopped).
- CLI unit test: `worthless wrap -- claude` with `WORTHLESS_PROXY_URL` pointed at unbound port → exit code != 0 with structured error `proxy_unreachable`.
- Property test: no path through `src/worthless/cli/wrap.py` falls back to direct upstream URL.

---

## 2. Mid-stream cap-hit behavior

**Verdict: Inject an SSE error event then close the stream cleanly. Do NOT silently truncate; do NOT finish-then-block.**

**Rationale.** Anthropic's own contract sets the precedent: "When receiving a streaming response via SSE, it's possible that an error can occur after returning a 200 response, in which case error handling wouldn't follow these standard mechanisms" ([Anthropic API errors](https://docs.anthropic.com/en/api/errors)). Their wire format defines an `error` event type for exactly this situation, so SDKs (`anthropic-sdk-python` `_streaming.py`) already handle a mid-stream error frame. LiteLLM's streaming path forwards upstream chunks verbatim and converts upstream errors into a final SSE `data:` payload before closing the connection — the same shape. "Finish current message + block next call" is wrong because by the time the message finishes the cap is already breached: you have already paid for the overrun tokens. "Silently terminate" leaves agents (Claude Code in particular) stuck on a half-message with no signal to surface to the user. The minimum-surprise design is the one Anthropic itself uses: emit `event: error\ndata: {"type":"error","error":{"type":"billing_error",...}}\n\n` with the truncation hint, then close. Agents see a structured terminal frame, can render "spend cap hit at $X.XX of $Y.YY", and stop retrying.

**Test impact.**
- RESPX-backed adapter test (`tests/test_proxy_streaming.py`): mid-stream cap trip emits `event: error` with `code: cap_exceeded`, then EOF. Assert downstream client sees both frames.
- Snapshot test (Syrupy): exact wire bytes of the truncation event match the documented Anthropic shape.
- Live test against `tests/openclaw/docker-compose.yml`: set cap to $0.001, send a long-streaming request, verify Claude Code surfaces a user-visible error rather than hanging.

---

## 3. Atomic increment-and-check on spend cap

**Verdict: Use a Redis Lua script that performs `INCRBYFLOAT` then `GET` and returns BOTH new value and a deny flag in one round-trip; persist to SQLite asynchronously via a leader-elected flush job (LiteLLM pattern).**

**Rationale.** Naïve pre-check + post-record races: 3 parallel sub-agents each pass `if spent < cap` then each call `spent += cost`, and all 3 reconstruct. Stripe solves the analogous problem with idempotency keys: "Stripe's idempotency works by saving the resulting status code and body of the first request made for any given idempotency key... Subsequent requests with the same key return the same result" ([Stripe idempotency](https://docs.stripe.com/api/idempotent_requests)) — but their TTL is 24 h and worthless decisions need millisecond latency, so we use the *atomic-increment* sibling pattern instead. Redis `INCRBY` is atomic and O(1) ([Redis docs](https://redis.io/docs/latest/commands/incrby/)); wrapping `INCRBY` + cap-check + conditional decrement in a Lua `EVAL` makes the whole compare-and-spend single-shot under Redis's single-threaded execution model. LiteLLM's `db_spend_update_writer.py` uses the same shape: in-memory queue → Redis buffer → leader-elected DB flush via `pod_lock_manager.acquire_lock(cronjob_id=DB_SPEND_UPDATE_JOB_NAME)`. The leader-flush avoids N pods racing on the same SQLite row.

**Code sketch (Lua, run via `redis.eval`):**
```lua
-- KEYS[1] = spend:<key_id>:<window>, ARGV[1] = cost_micros, ARGV[2] = cap_micros, ARGV[3] = ttl
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local proposed = current + tonumber(ARGV[1])
if proposed > tonumber(ARGV[2]) then
  return {0, current, ARGV[2]}  -- deny, no mutation
end
redis.call('INCRBY', KEYS[1], ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[3])
return {1, proposed, ARGV[2]}    -- allow
```

**Test impact.**
- Concurrency property test: spawn 100 goroutines/asyncio tasks each charging $0.01 against $0.50 cap → exactly 50 succeed, 50 denied; sum of allowed costs ≤ cap.
- Hypothesis test: random cost vectors, assert `sum(allowed) ≤ cap` invariant under all interleavings.
- Lua-script unit test: feed sequence (50,50,50, cap=100) → returns allow, allow, deny.

---

## 4. `key_known_dead` cache on upstream 401s

**Verdict: Cache `key_dead=true` for **5 minutes** on the *first* 401, set a 24-hour cap on consecutive failures, and invalidate on any successful enrollment-rotation event.**

**Rationale.** Resilience4j's CircuitBreaker uses a `wait duration` after which the breaker transitions OPEN → HALF_OPEN and permits a configurable probe count ([resilience4j docs](https://resilience4j.readme.io/docs/circuitbreaker)) — exactly the shape we need: stop burning KMS calls during the failure window, but auto-probe so the user doesn't have to bounce the proxy after rotation. 5 minutes is the LiteLLM/Portkey norm for ephemeral health caches; long enough to suppress a dead-key retry storm (Claude Code retries with exponential backoff up to 2 min, so 5 min covers the full agent retry envelope), short enough that a `worthless rotate` workflow recovers cold without operator action. The 24-hour ceiling matches Stripe's idempotency retention window — anything older is treated as a fresh decision. **Recovery hooks:** the CLI `worthless rotate <key_id>` and the enrollment endpoint `POST /v1/keys/{id}/rotate` MUST publish a Redis pub/sub `key:invalidated:<id>` event that flushes the dead-key cache immediately; we don't wait for TTL on a known-good rotation.

**Cache key layout.** `dead:<key_id>` → `{first_seen, last_401, count}`; lookup before reconstruct, increment on each 401, drop on rotation event or TTL expiry.

**Test impact.**
- KMS-call-counter test: 100 sequential 401s in 5 min → exactly 1 KMS decrypt (the first); subsequent 99 short-circuit at the cache.
- Recovery test: mark dead, fire `key:invalidated:<id>`, next reconstruct succeeds without TTL wait.
- Time-travel test (`freezegun`): TTL expires → next request probes upstream once.

---

## 5. Non-retryable error code semantics on `cap_exceeded`

**Verdict: Return **HTTP 403** with `error.type: "billing_error"` and `error.code: "cap_exceeded"`; set `x-should-retry: false`. Do NOT use 402, 429, or 503.**

**Rationale.** I read the SDK source directly. `openai-python/_base_client.py` `_should_retry()`: retries on 408, 409, 429, and `>= 500`; if `x-should-retry: false` is present, returns False unconditionally; otherwise non-listed 4xx (including 402/403) **does not retry**. `anthropic-sdk-python/_base_client.py` has the identical algorithm (retries 408/409/429/5xx; honors `x-should-retry`). So:

- **429** → both SDKs retry. WRONG — agents will hammer worthless and the user's monthly cap-hit becomes a tight loop.
- **503** → both SDKs retry (≥500). WRONG for the same reason.
- **402 Payment Required** → semantically tempting, but Anthropic already uses 402 for `billing_error` ([API errors](https://docs.anthropic.com/en/api/errors)) meaning "your Anthropic account has a billing problem" — overloading it confuses agents and operators. Also some HTTP middleware/load-balancers treat 402 as transient.
- **403** → not in either SDK's retry list, has clear "policy denial, not infrastructure" semantics, and is the code Cloudflare AI Gateway uses for guardrail-denied requests.

Belt-and-suspenders: emit `x-should-retry: false` (the explicit override both SDKs honor first) AND a structured body so non-SDK callers (curl, custom agents) parse the reason.

**Body shape:**
```json
{
  "type": "error",
  "error": {
    "type": "billing_error",
    "code": "cap_exceeded",
    "message": "Spend cap of $5.00 exceeded for key sk-***abc. Reset at 2026-05-06T00:00:00Z or raise cap with: worthless cap set 10.00",
    "cap_usd": 5.00,
    "spent_usd": 5.03,
    "reset_at": "2026-05-06T00:00:00Z"
  }
}
```

**Test impact.**
- Adapter unit test: `cap_exceeded` path returns 403 with `x-should-retry: false`.
- Live SDK test: instrument `openai-python` and `anthropic-sdk-python` against a worthless instance with `WORTHLESS_CAP=$0.001`, verify zero retries (count `httpx` requests; expect exactly 1).
- Schemathesis contract test: error body matches the documented shape; `cap_usd`, `spent_usd`, `reset_at` all present.
- Aider/Claude Code manual test: cap-hit produces user-visible "stop, do not retry" UI rather than a spinner.

---

## Citations index

| # | Source | Used for |
|---|---|---|
| 1 | [LiteLLM PR #9533](https://github.com/BerriAI/litellm/pull/9533) | Fail-open scope (DB-only, VPC-only) |
| 2 | [LiteLLM prod best practices](https://docs.litellm.ai/docs/proxy/prod) | `allow_requests_on_db_unavailable` constraints |
| 3 | [Cloudflare AI Gateway Fallbacks](https://developers.cloudflare.com/ai-gateway/configuration/fallbacks/) | Fail-over vs fail-open distinction |
| 4 | [Anthropic API errors](https://docs.anthropic.com/en/api/errors) | Mid-stream SSE error semantics, 402 vs 403 |
| 5 | [openai-python `_base_client.py`](https://github.com/openai/openai-python/blob/main/src/openai/_base_client.py) | `_should_retry`, `x-should-retry` honor logic |
| 6 | [anthropic-sdk-python `_base_client.py`](https://github.com/anthropics/anthropic-sdk-python/blob/main/src/anthropic/_base_client.py) | Same retry algorithm, header override |
| 7 | [Stripe idempotency](https://docs.stripe.com/api/idempotent_requests) | 24-h replay window, store-result-once pattern |
| 8 | [Redis INCRBY](https://redis.io/docs/latest/commands/incrby/) | Atomic O(1) integer increment |
| 9 | [LiteLLM `db_spend_update_writer.py`](https://github.com/BerriAI/litellm/blob/main/litellm/proxy/db/db_spend_update_writer.py) | Leader-elected flush, Redis buffer pattern |
| 10 | [Resilience4j CircuitBreaker](https://resilience4j.readme.io/docs/circuitbreaker) | OPEN → HALF_OPEN probe pattern, wait duration |
| 11 | [Portkey Fallbacks](https://portkey.ai/docs/product/ai-gateway/fallbacks) | Fail-over (not fail-open) prior art |

---

## Open follow-ups (not blocking WOR-430)

- Live test against `tests/openclaw/docker-compose.yml` was not executed in this research pass — treat the verdicts as design-locked, then verify with Brutus stress-test agent in WOR-430 implementation phase.
- Stripe-style idempotency keys on the proxy `/v1/messages` endpoint would let agents safely retry network-blip failures without double-charging cap; out of scope here, file as separate ticket.
- 402 vs 403 may need user research with real Cursor/Aider users — neither SDK source is the same as the agent's own UX layer.
