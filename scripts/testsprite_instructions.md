# Worthless Proxy — TestSprite Test Instructions

You are testing a **split-key API proxy**, not an LLM. A mock upstream
returns static responses immediately (no latency simulation). Your target
is the proxy on :8000 which handles auth, routing, and enforcement.

## Base URL

All requests go to `http://localhost:8000`. No API key or Authorization
header is needed — the proxy uses file-based auth with alias inference
(already configured by the test harness).

## DO NOT GENERATE TESTS FOR THESE SCENARIOS

These scenarios are **impossible to test** in the harness and will always
produce false failures. Do not generate test cases for any of them:

| Scenario | Why untestable |
|---|---|
| Spend cap enforcement (expect 402) | Requires accumulated spend state across many requests; fresh harness has zero spend |
| Rate limiting (expect 429) | Requires sustained burst traffic; single-request tests never trigger it |
| Upstream timeout (expect 504) | Mock upstream always responds immediately; no timeout simulation exists |
| Missing auth → 401 on valid routes | Alias inference is ENABLED — requests without auth headers succeed via alias lookup |
| Oversized payloads >1 MB (expect 413) | Payload must survive tunnel/proxy buffering; synthetic large payloads do not reliably trigger the limit |
| Upstream error propagation | Mock upstream always returns 200; cannot simulate 5xx from provider |
| Token budget exhaustion | Requires cumulative token counting across requests |
| Time-window rule enforcement | Requires clock manipulation not available in harness |

If you are tempted to test any of the above, **skip it entirely**. Do not
attempt workarounds.

## Test Areas (ONLY generate tests from this list)

### 1. Health Endpoints (no auth required)
- `GET /` → 200, body contains `"status": "ok"`
- `GET /healthz` → 200, body contains `"status": "ok"`
- `GET /readyz` → 200, body contains `"status": "ok"`

### 2. OpenAI Chat Completions — Happy Path
- `POST /v1/chat/completions` with `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}` → 200
- Response is valid JSON with a `choices` array containing at least one element
- Response has a `usage` object with integer fields `prompt_tokens`, `completion_tokens`, `total_tokens`
- Do NOT assert on actual message text (mock upstream returns static content)

### 3. Anthropic Messages — Happy Path
- `POST /v1/messages` with `{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"hi"}],"max_tokens":100}` → 200
- Response is valid JSON with a `content` array (NOT `messages` — Anthropic uses `content`)
- Response has a `usage` object with integer fields `input_tokens` and `output_tokens` (NOT `prompt_tokens`/`completion_tokens` — that is OpenAI's format)
- Response has a `role` field equal to `"assistant"`
- Do NOT assert on actual message text

### 4. Streaming
- `POST /v1/chat/completions` with `"stream": true` → `Content-Type: text/event-stream`
- `POST /v1/messages` with `"stream": true` → `Content-Type: text/event-stream`
- Verify response contains `data:` lines (SSE format)
- Do NOT assert on chunk content or count

### 5. Anti-Enumeration (uniform 401)
- `GET /v1/models` → 401
- `GET /nonexistent/path` → 401
- `POST /v1/embeddings` → 401
- All 401 responses have identical JSON shape: `{"error": {"message": ..., "type": ..., "param": null, "code": null}}`
- The proxy NEVER returns 403 or 404 — every unauthorized/unknown request is 401

### 6. Response Header Sanitization
- On any 200 response, no header starts with `x-worthless-`

## What a PASSING assertion looks like

- **Status code**: `assert response.status_code == 200` (or 401 for anti-enum)
- **JSON structure**: `assert "choices" in body` / `assert "content" in body`
- **Type checks**: `assert isinstance(body["usage"]["prompt_tokens"], int)`
- **Header absence**: `assert not any(h.startswith("x-worthless-") for h in response.headers)`
- **SSE format**: `assert "data:" in response.text`

Do NOT assert on: specific message text, token counts being > 0, response
latency, number of SSE chunks, or error message wording.

## Hard Constraints

- **No custom auth headers.** Do not send `Authorization` or `x-api-key`.
  The proxy infers everything via alias lookup.
- **Do not assert on LLM content.** Assert on status codes, JSON structure,
  and headers only.
- **Uniform 401 is intentional.** Do not flag identical error responses or
  try to differentiate auth failure reasons. Anti-enumeration by design.
- **No TLS testing.** Harness runs `allow_insecure=True`.
- **No alias enumeration.** Do not brute-force alias values.
- **No real API keys.** The harness uses generated fake keys.
- **Upstream errors are sanitized.** The proxy strips provider error
  messages and returns generic text. Not a bug.
- **CORS is fully denied.** Browser-origin requests fail by design.
- **No OpenAPI spec.** `docs_url`, `redoc_url`, `openapi_url` are disabled.
  Do not report missing docs endpoints.
- **Anthropic != OpenAI.** Their response schemas differ. Do not copy
  assertions from one provider to the other.
