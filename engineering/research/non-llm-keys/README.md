# Non-LLM bearer keys (Slack, Linear, PostHog): research

*Input to [ADR-002](../../adr/002-non-llm-bearer-credentials.md) and the tool-keys epic
([WOR-968](https://linear.app/plumbusai/issue/WOR-968)). Planning: [wor-968-tool-keys.md](../../planning/wor-968-tool-keys.md).*

> "A leaked `.env` that holds our agent's Slack token is as dead as one that holds its OpenAI key."

Code claims were checked against `main` at `03c6518` on 2026-10-22. Each claim is tagged:

- **[F]** fact, checked against our source, the SDK source, or the vendor's own docs (fetched 2026-10-22).
- **[W]** observed on the wire in Gate B ([WOR-970](https://linear.app/plumbusai/issue/WOR-970)): real SDKs
  (slack_sdk 3.45.0 sync and async, @linear/sdk 99.0.0, posthog 7.75.4) talking to a local capture server with
  canned responses and **fake tokens**. It shows what the clients send, not how the vendors answer.
- **[L]** still needs the live leg: a real test-workspace token against the real vendor.
- **[I]** inference: reasoned from facts, not observed.

## 1. The spike, reviewed

An outside spike (`worthless-passthrough-spike-v2.zip`) proposed a `PassthroughAdapter` so worthless could
protect non-LLM keys. It is a 7-file patch (+203/−6) against `03c6518`, with 10 unit tests. It was never run
live. Its own handoff says so.

### What it got right: the three LLM-specific spots

| # | LLM-specific spot | Where on `main` | Spike's change | Verdict |
|---|---|---|---|---|
| 1 | Adapter dispatch is keyed by request **path** | `_ADAPTERS` in `adapters/registry.py` maps only `/v1/chat/completions` and `/v1/messages`; called at `app.py:690` **[F]** | Key by the row's stored `provider`, path map as fallback | Right idea, wrong key (gap 9 below). We dispatch by protocol; LLM aliases keep path dispatch. |
| 2 | Every upstream `>= 400` body is rewritten into an LLM error envelope | `_sanitize_upstream_error` (`app.py:135`) keeps only `type`/`code`/`param` and replaces `message` with a constant; applied at `app.py:867-869` **[F]** | Passthrough opts out | Keep. Slack's `channel_not_found` and a Linear validation error become byte-identical otherwise. The LLM sanitizer stays as it is. |
| 3 | The inbound credential header is forwarded upstream | `strip_internal_headers` drops only `x-worthless-*` and hop-by-hop headers. `authorization` is not hop-by-hop **[F]** | `PassthroughAdapter` pops `authorization` and `x-api-key` | Keep. The same bug exists in the LLM adapters: `OpenAIAdapter` sets `authorization` but keeps any inbound `x-api-key`, and `AnthropicAdapter` does the reverse (`adapters/openai.py:62-63`, `adapters/anthropic.py:28-29`) **[F]**. That is PR0a ([WOR-979](https://linear.app/plumbusai/issue/WOR-979)). |

The spike also got the threat model right: worthless protects a **leaked file**, not a machine the attacker
already controls (non-goal #1 in `docs/security.md`).

### What it missed

Each gap below would have stopped the spike before or during its first live request.

| # | Gap | Evidence on `03c6518` | What breaks | Fixed by |
|---|---|---|---|---|
| 1 | `enroll` never outputs shard-A | `_enroll_single` (`cli/commands/lock.py:3143-3205`) splits the key, stores shard-B and drops `sr.shard_a` **[F]** | The user never gets the half that goes in `.env`, so nothing can call the proxy | v1 uses `lock`. `enroll` fix is [WOR-992](https://linear.app/plumbusai/issue/WOR-992) |
| 2 | `base_url` is NULL | `_enroll_single` takes the URL from `lookup_by_name(provider)` (`lock.py:3183-3184`). `providers.toml` has no slack/linear/posthog entry. The proxy refuses NULL rows with the uniform 401 (`app.py:598-606`) **[F]** | Every request 401s | PR3 adds the three upstream URLs to the bundled registry |
| 3 | Query string dropped | The catch-all route's `{path:path}` excludes the query; the handler also does `path.split("?")[0]` (`app.py:564`); nothing reads `request.url.query`. The spike built `base_url + clean_path` **[F]** | The async Slack client sends read calls as GET with the arguments in the query, and some POSTs carry a query too **[W]**. `conversations.history?channel=C1` arrives with no channel | PR1a (`build_upstream_url(base, raw_path, query)`) |
| 4 | Trailing slash stripped | `_extract_alias_and_path` does `raw_path.strip("/")` and rebuilds `"/" + parts[1]` (`app.py:115-127`) **[F]** | PostHog's REST paths end in `/` **[F]**. Without it the request hits a different route or a redirect **[I]** | PR1a |
| 5 | httpx collapses `..` | `httpx.URL("https://slack.com/api/../oauth.v2.access")` becomes `https://slack.com/oauth.v2.access` (httpx 0.28.1, run locally). `%2e%2e`, `%2f` and `//` are left alone **[F]** | A crafted path escapes the base path on the same host after the key is rebuilt. httpx's test client also collapses `..` before it reaches the app, so a test needs a raw ASGI scope | PR1a: reject dot segments with the uniform 401 before decrypt |
| 6 | Linear sends the key raw | `_extract_shard_a` (`app.py:96-111`) accepts only `Authorization: Bearer <x>` or `x-api-key` **[F]**. Linear personal keys go in `Authorization: <key>` with no scheme **[F]** | Every Linear call 401s at the proxy. The spike fixed the outbound header (`auth_template="{key}"`) but not inbound extraction | PR1a: mirrored auth |
| 7 | Phantom LLM metering: 402 after about 7,800 calls | The spike says metering is opt-in. It is not for new rows: `store_enrolled` applies `DEFAULT_SPEND_CAP_TOKENS = 1_000_000_000` (`storage/repository.py:554-561`, `defaults.py:10`). A Slack response has no `usage`, so a 2xx settles at estimate (`app.py:825-831`), and the ledger floors that at `GLOBAL_CEILING_TOKENS = 128_000` (`storage/spend_ledger.py:173`, `defaults.py:28`) **[F]** | 1e9 / 128,000 ≈ 7,812. Call ~7,813 gets a 402. Every call also logs "Usage extraction failed" (`app.py:802`) | PR2 ([WOR-984](https://linear.app/plumbusai/issue/WOR-984)) |
| 8 | `lock` can't see tool keys | `PROVIDER_PREFIXES` (`cli/key_patterns.py:8-14`) has no `xoxb-`, `xoxp-`, `lin_api_` or `phx_`. `lock` prints "No unprotected API keys found." (`lock.py:2558`) **[F]** | A live Slack token sits in `.env` under a false all-clear. Via `enroll`, the split has no known prefix, so shard-A loses the `xoxb-` marker (the spike observed `zc-…`) | PR3 |
| 9 | The stored `provider` is the protocol, not the vendor | `lock` resolves the registry name to its wire protocol and stores that: `provider = protocol` (`lock.py:747-759`), then `StoredShard(provider=provider)` (`lock.py:949-954`) **[F]**. The spike keyed `_PASSTHROUGH` by `"slack"`/`"linear"`/`"posthog"` | Any `lock`-made row would store the protocol, so the vendor-keyed dict never matches. Only free-form `enroll --provider slack` would, and that path dead-ends at gaps 1 and 2 **[I]** | PR1a: one `passthrough` protocol; vendor lives in the alias and registry |

Gap 9 also explains a live bug. `unlock` looks up `_PROVIDER_ENV_MAP` by the stored protocol (`unlock.py:273`),
so unlocking an OpenRouter key (stored as `openai`) removes `OPENAI_BASE_URL` instead of `OPENROUTER_BASE_URL`
**[F]**. That is PR0c ([WOR-981](https://linear.app/plumbusai/issue/WOR-981)).

### Other gaps found on the way

- **No protocol check on `*_BASE_URL`.** `_resolve_upstream_base_url` (`lock.py:399-443`) accepts any
  *registered* URL, whatever its protocol **[F]**. Today an Anthropic key with `ANTHROPIC_BASE_URL` set to
  `https://api.openai.com/v1` is accepted and routed to OpenAI **[I]**. Once tool keys exist, the same hole
  sends a Slack token to OpenAI. PR3 adds the protocol-class match.
- **Non-dict `usage` crashes spend recording.** `extract_usage_openai` calls `parsed["usage"].get(...)`
  (`proxy/metering.py:32`). A string `usage` raises `AttributeError`, which the `except` doesn't catch **[F]**.
  PR0b ([WOR-980](https://linear.app/plumbusai/issue/WOR-980)).
- **Response relay.** `relay_response` (`adapters/types.py:117`) buffers the whole non-streaming body with no
  size cap. It strips only `content-encoding`/`content-length`, so `set-cookie` is relayed **[F]**. The upstream
  client has `follow_redirects=False` (`app.py:274`), so a 3xx and its `Location` go straight back to the client
  **[F]**. Every SDK follows redirects, and sync `slack_sdk` keeps the Bearer header across hosts **[W]**, so a
  relayed `Location` would carry shard-A wherever it points. PR1b turns 3xx into 502 and strips `set-cookie`.

> **Correction to the plan:** the plan says PR1b "raises the cap from 64 KiB". There is no response-body cap on
> `03c6518`; the only 64 KiB constant in the proxy is the SSE partial-line buffer (`metering.py:151`). PR1b
> *adds* a cap for relayed bodies. The success-body cap is tracked separately in
> [WOR-996](https://linear.app/plumbusai/issue/WOR-996).

## 2. Code inventory (`03c6518`)

What a passthrough protocol touches, and what it must leave alone.

| Concern | Where | Today | Tool-key implication |
|---|---|---|---|
| Alias + path parse | `proxy/app.py:115-127`, `:564` | Strips slashes; drops query | Passthrough parses `scope["raw_path"]` itself. LLM aliases keep `_extract_alias_and_path` |
| Credential extraction | `proxy/app.py:96-111` | Bearer or `x-api-key` | Passthrough mirrors raw or Bearer, and remembers which |
| Gate order | `rules_engine.evaluate` `app.py:661-668` → `get_adapter` `:690` → `ipc.open` `:700` → reconstruct `:713-731` | One `ipc.open` call site, after the gate | Keep exactly one `ipc.open`. The static check at `tests/test_security_properties.py:348-420` becomes an AST check |
| Retired-key tripwire | `proxy/app.py:617-633` | MACs shard-A against `retired_decoys` | Unchanged; covers passthrough too |
| Rate limit | `RateLimitRule` `proxy/rules.py:452`; `default_rate_limit_rps` 100.0 (`proxy/config.py:181-182`); `enrollment_config.rate_limit_rps REAL NOT NULL DEFAULT 100.0` (`storage/schema.py:91`) | Per alias, provider-agnostic | The only brake on tool keys until request budgets (F8a) |
| Spend cap + token budget | `SpendCapRule` `rules.py:201`; `TokenBudgetRule` `rules.py:249`; settle `app.py:776-861` | Default cap 1B tokens; 128k floor on unreadable usage | Must not run for passthrough (gap 7) |
| Error sanitizer | `proxy/app.py:135`, applied `:867-869` | Every `>= 400` rewritten | Passthrough relays verbatim; LLM path unchanged |
| Upstream client | `proxy/app.py:274` | `follow_redirects=False` | Keep; also refuse 3xx (PR1b) |
| LLM adapters | `adapters/openai.py:54-70` (injects `stream_options.include_usage`); `adapters/anthropic.py:20-35` | Fixed upstream path | Unchanged apart from PR0a |
| Prefix table | `cli/key_patterns.py:8-23` (`PROVIDER_PREFIXES`, `KEY_PATTERN`) | LLM prefixes only | PR3 adds tool prefixes; `KEY_PATTERN` also drives log redaction (`cli/log_redaction.py`) |
| Lock protocols | `lock.py:113-118` (`_PROVIDER_ENV_MAP`, `_SUPPORTED_PROTOCOLS`) | `openai`, `anthropic` | Passthrough is added from the prefix table, never from TOML |
| Proxy URL written to `.env` | `_proxy_base_url` `lock.py:133-141` | Always ends in `/v1` | No `/v1` for passthrough |
| `*_BASE_URL` naming | `_derive_base_url_var` `lock.py:189-198` | `X_API_KEY` → `X_BASE_URL`, else the protocol default (`OPENAI_BASE_URL`) | Tool vars (`SLACK_BOT_TOKEN`) don't end in `_API_KEY`, so today they'd get `OPENAI_BASE_URL`. Needs the `<STEM>_BASE_URL` rule |
| Upstream URL checks | `_validate_upstream_base_url` `lock.py:287`; `_resolve_upstream_base_url` `lock.py:399` | https-only, SSRF denylist; registry membership but not protocol | Move the validator to a neutral module the proxy may import (the proxy may not import `cli.commands`, WOR-309). Add the protocol match |
| Registry | `src/worthless/providers.toml`; `lookup_by_name` `cli/providers.py:177` | 6 LLM entries, `protocol = openai\|anthropic` | Add slack, linear, posthog URLs. Validate protocol strings on parse |
| Storage | `shards.provider/prefix/charset/base_url` (`schema.py:43-52`); `enrollments.decoy_hash` (`schema.py:105`) | No migration needed. `decoy_hash` is never written by the repository | `decoy_hash` is the hook for the pre-gate MAC check ([WOR-991](https://linear.app/plumbusai/issue/WOR-991)) |
| False all-clear precedent | `lock.py:2549-2558` (`worthless-7jn2`) | A skipped OAuth token suppresses "No unprotected API keys found." and the closing verdict | Same mechanism for refused tool tokens (`xapp-`, `xoxe-`) |
| Import guard | `tests/architecture/test_proxy_imports.py` | Bans the splitter from the proxy | Also ban `worthless.cli.commands` |

## 3. Prior art

Every product here protects the **stored** secret: the client never holds the real value. **None stops a
compromised client from *using* the credential** through the broker for whatever the broker allows. That is
the same line worthless draws (F7/F8 are tickets, not v1).

| Product | Mechanism | Real key out of the client? | Stops a compromised client using it? | Source |
|---|---|---|---|---|
| CyberArk Secretless Broker | Plain `HTTP_PROXY` (refuses CONNECT). First regex that matches the full URL picks a connector; headers come from Go templates. **Re-encodes the query** (sorted keys), relays 3xx and `Set-Cookie` | Yes **[F]** | No. Any request the app makes is authenticated **[F]** | github.com/cyberark/secretless-broker |
| Infisical Agent Vault | Open-source `HTTPS_PROXY` with its own CA (TLS interception). Matches host, then path glob; the agent holds a placeholder. Auth form fixed per service. Forwards the raw path and query, strips `Set-Cookie`, **relays 3xx**, retries once on a 401 after an OAuth refresh. 20 req/s per actor and vault. In preview | Yes **[F]** | Partly. It limits *which services*, not which operations **[I]** | github.com/Infisical/agent-vault |
| Claude Managed Agents vaults | Per-end-user vault, hosted. MCP credentials (`mcp_oauth`, `static_bearer`) are injected per server URL. Environment-variable credentials are placeholders swapped on outbound requests | Yes **[F]** | No **[I]** | platform.claude.com/docs/en/managed-agents/vaults |
| LangSmith LLM auth proxy | Self-hosted Envoy proxy (Enterprise). Checks a short-lived LangSmith-signed token, attaches provider credentials, forwards. LLM providers only. Separate sandbox proxies sign AWS requests and inject GCP tokens | Yes **[F]** | Per-request attribution, not operation limits **[I]** | docs.langchain.com/langsmith/llm-auth-proxy-self-hosted |
| Aembit | Workload IAM. Aembit Edge (proxy or in-process SDK) attests the workload's identity, checks access conditions, then injects the credential, usually as an HTTP header | Yes **[F]** | Identity-gated, not operation-gated **[I]** | docs.aembit.io (How Aembit works; Credential Providers) |
| Docker MCP Gateway | Expands secrets into env vars and `${VAR}` headers held by the **MCP server process** (`pkg/mcp/remote.go`). Not a request-path broker | The agent doesn't hold them; the MCP server does **[F]** | No **[I]** | github.com/docker/mcp-gateway |
| superfly/tokenizer (Fly.io) | The client holds a NaCl sealed blob with the secret, its allowed hosts and its auth format. The proxy also wants a second factor (a `Proxy-Authorization` digest, a macaroon, or fly-src). Refuses CONNECT, forces TLS, blocks private addresses on dial. **The closest design to split-key** | Yes **[F]** | Bound to hosts and formats, not operations **[I]** | github.com/superfly/tokenizer |
| OneCLI gateway | Rust TLS-intercepting gateway with per-vendor injection and OAuth refresh. Relays 3xx (e2e-tested). Gateway-made errors carry `x-should-retry: false` | Yes **[F]** | No **[I]** | github.com/onecli/onecli |
| 1Password `op run` | Resolves secret references into the child process's environment at exec | At rest only. At runtime the real key is in the env, `/proc/<pid>/environ` and anything that dumps env **[F]** | No **[F]** | 1Password CLI docs |
| Slack token rotation | 12-hour access tokens (`xoxe.xoxb-…`) plus a refresh token (`xoxe-1-…`). Can't be turned off once on | No, but a leaked access token expires within 12h **[F]** | No **[F]** | docs.slack.dev/authentication/using-token-rotation |
| Scoped tokens | Minimum scopes per token (Slack scopes, read-only Linear keys, scoped PostHog personal keys) | No **[F]** | Limits blast radius, not use **[F]** | vendor docs |

### Read in code: how four comparable proxies handle our rules

A second pass read the source of Agent Vault (`d5836ec`), Secretless Broker (`23b436d`), tokenizer (`12c9cb2`)
and OneCLI (`6eaf878`). File refs are under Sources; anything not read directly in code is tagged **[I]**.

| Our planned rule | Agent Vault | Secretless | tokenizer | OneCLI |
|---|---|---|---|---|
| Forward the raw query | Yes (`RawQuery`) | **No**, re-encoded and sorted | Re-encoded **[I]** | Forwards `path_and_query`; reqwest may normalise it **[I]** |
| Reject dot segments before using the key | No | No | Not handled | A helper knows `.`, `..`, `%2e` mixes and `\`, but not on the forward path |
| Auth form | Fixed per service | Template per config | Pinned when the blob is sealed | Fixed per vendor |
| Upstream 3xx → 502 | No, relayed | No, relayed | Relayed **[I]** | No, relayed |
| Strip `Set-Cookie` | Yes | No | n/a | No |
| Never retry | No: once on 401 (GET/HEAD) | Yes | Yes | No: once on 401 (bodyless) |
| Body cap → 502, abort mid-stream | Unlimited by default; known size over cap → 502, overflow mid-stream aborts | None | None | n/a |
| Rate limit | Per actor and vault | None | None | Policy 429 |
| Proxy's own errors marked | Yes, except its own 429, which looks like the vendor's | 503 with Go error text | n/a | `x-should-retry: false` |
| Slack | Bearer on `slack.com`; xoxb vs xapp chosen by path. Its template warns that Node `@slack/web-api` puts a per-call `token` in the **form body** | Example config; likely always 403 **[I]** | n/a | **Deliberately no Slack** (a test asserts nothing is injected) |
| Linear | Raw `Authorization` | n/a | n/a | Bearer, with OAuth refresh |
| PostHog | None | n/a | n/a | Bearer on `us.`/`eu.`/`app.posthog.com`; leaves capture hosts `*.i.posthog.com` alone |
| Tests against live Slack | None (live tests only for xAI/OpenAI) | None | None | None (black-box e2e against a stub) |

**Validation.** No one else turns 3xx into 502, refuses to retry, rejects dot segments before using the key, or
keeps the query byte-for-byte. Gate B is the evidence that each of those matters for these SDKs. No project
tests against live Slack, so our live leg would be ahead of all of them.

**Adopted from them** (folded into the plan):

1. The dot-segment check covers `.` and `..` in any `%2e` case mix, and `\` (OneCLI's list).
2. The proxy's own 429/502/503 carry a marker header. Because we relay the vendor's `Retry-After` and
   `X-RateLimit-*`, our 429 would otherwise look like Slack's (Agent Vault has exactly this gap). The uniform 401
   stays byte-identical.
3. This alias's shard-A anywhere in the request body gets a 401 before decrypt. Node `@slack/web-api` puts a
   per-call `token` in the form body; forwarding it would leak shard-A to Slack and fail the call.
4. A relayed body that overflows the cap mid-stream aborts the connection; never a truncated 200.

**Considered, not adopted:**

- *Check the rebuilt token's prefix* (Secretless `credentialValidations`). Redundant: `reconstruct_key_fp` checks
  the commitment, so the rebuilt key is exact or the request gets a 401.
- *Pin the auth form per alias* (tokenizer, Agent Vault). The header name and upstream are fixed either way, so
  mirroring can't aim the key anywhere new. See ADR-002, alternatives.
- *A second factor beyond shard-A* (tokenizer). On a loopback proxy it would sit on the same box as shard-A, so
  it adds nothing against a leaked file. F6 is the on-box answer.

**Signal worth noting:** OneCLI chose to drop Slack. Its code doesn't say why **[I]**.

**Where worthless sits.** What leaves the box holds only shard-A: token-shaped, vendor-rejected. A placeholder
in Agent Vault or Managed Agents gives roughly the same leaked-file guarantee **[I]**. Worthless's edge is
reuse: the split, the sidecar, the gate, the tripwire and `lock`/`unlock` already exist, and it runs locally
with no hosted service. Its handicap: unlike `HTTPS_PROXY` brokers, the client must be pointed at a base URL,
so it needs one line of code per vendor.

## 4. Client wire facts

Gate B drove real SDKs against a local capture server (91 requests, fake tokens, canned responses). Vendor docs
were fetched on 2026-10-22. The live leg, real test-workspace tokens against the real vendors, has **not** run.

### Slack Web API

| Topic | What we know | Tag |
|---|---|---|
| Upstream | `https://slack.com/api/<method>`. `WebClient(base_url=…)`, default `https://slack.com/api/`; the SDK adds a missing trailing `/` | **[F] [W]** |
| Where the token goes | Slack's docs prefer the `Authorization` header, also allow a POST body field `token`, and say "Tokens cannot be sent as a query parameter." `slack_sdk` always sends `Authorization: Bearer`, even for a per-call `token=` argument | **[F] [W]** |
| Request shape | **Sync client: always POST**, even `conversations.history`; a call with no arguments sends `Content-Type: application/json` with an empty body. **Async client:** GET with the query for read methods, and a query on some POSTs too (`files.getUploadURLExternal?filename=…&length=…`). The docs allow query, form or JSON, one per request | **[W] [F]** |
| Errors | Every response has a top-level `ok`; failures carry a machine-readable `error`. The docs page does not state the HTTP status of an `ok: false`. On a canned 200 the SDK raises `SlackApiError` with `error="channel_not_found"` | **[F] [W]**; real status **[L]** |
| Rate limit | 429 + `Retry-After` in seconds; limits are per method, per workspace, per app, in tiers 1–4. `slack_sdk` does **not** retry by default; with `RateLimitErrorRetryHandler` it retries once after `Retry-After` | **[F] [W]** |
| Redirects | Every SDK transport follows them; 301/302 become a GET with no body. Sync `slack_sdk` **keeps the Bearer header across hosts**; aiohttp drops it | **[W]** |
| Egress proxy env | `slack_sdk` honours `HTTPS_PROXY`. The async client ignores `NO_PROXY`, so with an egress proxy set it sends shard-A to that proxy (502). `client.proxy = None` fixes it | **[W]** |
| Base-URL env var | None read (`SLACK_API_URL` is ignored) | **[W]** |
| `files_upload_v2` | The second hop, `POST <upload_url>`, goes straight to `files.slack.com` with **no credential**. Only `files.completeUploadExternal` comes back through the proxy. Uploads need direct egress to `files.slack.com` | **[W]** |
| Token shape | No client-side check; the token is sent byte-identical, after `strip()` | **[W]** |

### Linear GraphQL

| Topic | What we know | Tag |
|---|---|---|
| Upstream | `POST https://api.linear.app/graphql`. The SDK's `apiUrl` option is used verbatim; query and trailing slash survive | **[F] [W]** |
| Credential | `apiKey` goes **raw**: `Authorization: lin_api_…`. An OAuth `accessToken` goes as `Bearer` | **[W]** |
| URL check | The SDK allows plain `http://` only for `localhost`, `127.0.0.1` and `[::1]` (`LOCAL_API_HOSTNAMES` in `@linear/sdk` 99.0.0 source). A proxy reached by a container hostname needs TLS | **[W] [F]** |
| Errors | `errors[]` with `extensions.code`. The SDK never retries | **[F] [W]** |
| Rate limit | Linear's docs: HTTP **400** with `extensions.code: "RATELIMITED"`, plus `X-RateLimit-Requests-Limit/-Remaining/-Reset` (epoch ms) and per-endpoint `X-RateLimit-Endpoint-*`. The SDK raises `RatelimitedLinearError` only if `extensions.type: "ratelimited"` is present (else `UnknownLinearError`) and reads the retry fields from the **headers**. Whether the real body carries `type` | **[F] [W]**; body **[L]** |
| Base-URL env var | None (`LINEAR_API_URL` is ignored) | **[W]** |

### PostHog

| Topic | What we know | Tag |
|---|---|---|
| Upstream | `https://us.posthog.com` or `https://eu.posthog.com`, REST paths ending in `/`. `host=` option; the SDK strips one trailing `/` from the host | **[F] [W]** |
| Credential | `secret_key` / `personal_api_key` → `Authorization: Bearer phx_…`. In 7.x `secret_key` also accepts project secret keys (`phs_`) | **[W]** |
| Public key on the same host | Every secret-key call also carries `?token=phc_…`. `/batch/` and `/flags/?v=2` carry `api_key` in JSON. Capture, `/flags` and the automatic `$feature_flag_called` events go to the same `host` with **no credential** | **[W]** |
| Errors | The SDK never raises: it logs and returns `None`. A 401 clears the flags. A 429 isn't retried and `Retry-After` is ignored | **[W]** |
| Base-URL env var | None (`POSTHOG_HOST` is ignored) | **[W]** |
| Which upstream serves what | `us.posthog.com` vs `us.i.posthog.com` for ingestion, `/flags/definitions` and `/api/projects/@current/…` | **[L]** |

### What this changes in the design

1. **Mirrored auth covers every SDK.** The only Basic auth seen is Slack's token-rotation refresh, which stays
   refused **[W]**. A client that sends Slack's token as a POST body `token=` field (allowed by Slack's docs,
   never done by `slack_sdk`) gets the uniform 401, which fails closed **[F] [I]**.
2. **Forward the raw query on every method, POST included, and empty bodies as they are.** Never re-encode **[W]**.
3. **Upstream 3xx → 502 is required, not a nicety.** A 302 turns a POST into a body-less GET, a mangled action,
   and sync `slack_sdk` would carry shard-A to whatever host `Location` names **[W]**.
4. **"Shard-A in the query → 401" must match this alias's shard-A, not a token pattern.** Every PostHog
   secret-key call carries `phc_` in the query **[W]**.
5. **PostHog shares its host with keyless traffic.** In `posthog-python`, the uniform 401 for a missing
   credential would silently drop capture and flags **[W]**. Owner decision (2026-10-22): v1 covers `phx_` for
   direct API use only, where every request carries `Bearer phx_…`; the library's mixed mode waits for
   [WOR-1000](https://linear.app/plumbusai/issue/WOR-1000). Gate B exercised only the library route, so the
   direct-API path is still unobserved: PR3's end-to-end test and a real-account host check (`us.` vs `eu.`)
   during rollout cover it **[L]**.
6. **Snippets.** The async Slack snippet adds `client.proxy = None` unless Gate A shows Mappy has no egress proxy;
   the Linear snippet must use a loopback URL (`localhost`, `127.0.0.1` or `[::1]`) **[W] [F]**.
7. **`files_upload_v2` carries no key on its second hop**, so it has no impact on the token
   ([WOR-995](https://linear.app/plumbusai/issue/WOR-995), closed) **[W]**. One practical note: if R1's
   optional egress allowlist is used, it must allow `files.slack.com`.

## 5. Token types and what v1 does with them

| Prefix | What it is | v1 | Why |
|---|---|---|---|
| `xoxb-` | Slack bot token | **Lock** | Static bearer over HTTPS |
| `xoxp-` | Slack user token | **Lock** (the Mappy rollout does not use it) | Same wire shape; acts as a human, so higher blast radius |
| `xapp-`, `xoxe.xapp-` | Slack app-level token, used for Socket Mode via `apps.connections.open` **[F]** | **Refuse with a reason** | Socket Mode runs over a WebSocket, not request/response **[I]** |
| `xoxe.xoxb-`, `xoxe.xoxp-` | Slack rotating access tokens | **Refuse with a reason** | Expire every 12 hours, and rotation "may not be turned off once it's turned on" **[F]**. The refresh replaces the value lock split **[I]** |
| `xoxe-` | Slack refresh token | **Refuse with a reason** | The refresh call uses `client_secret` and Basic auth, not a bearer call **[F] [W]** |
| `xwfp-` | Slack workflow ("just in time") token, a subset of bot tokens **[F]** | **Refuse with a reason** | Short-lived by design **[I]**; not needed for Mappy |
| Slack signing secret | HMAC key for verifying inbound requests | **Refuse with a reason** | Not a bearer credential; it never goes upstream |
| `lin_api_` | Linear personal API key | **Lock** | Raw `Authorization` |
| `lin_oauth_` | Linear OAuth access token | Out of scope | Bearer on the wire, but refresh-based like Slack rotation **[W] [I]** |
| `phx_` | PostHog personal API key | **Lock**, for direct API use (ADR-002, "PostHog in v1") | Bearer on every request. `posthog-python` mixed mode waits for WOR-1000 |
| `phs_` | PostHog project secret key | **Open**: decide in PR3 | Accepted by posthog-python 7.x's `secret_key` **[W]** |
| `phc_` | PostHog project key | **Refuse, but don't suppress the verdict** | Public by design |
| `AIza` | Google API key | Out of scope | Commonly sent as a `?key=` query parameter |

Refused secrets that stay in `.env` suppress the "You're protected" verdict, the same way a skipped OAuth token
does today (`lock.py:2549`).

## Sources

- Code: `oblangatas/worthless` at `03c6518`.
- Spike: `worthless-passthrough-spike-v2.zip` (patch, spec, handoff). Not in the repo.
- Gate B wire capture ([WOR-970](https://linear.app/plumbusai/issue/WOR-970)): a throwaway harness outside the
  repo; findings summarised in section 4.
- Slack (fetched 2026-10-22): Web API basics (docs.slack.dev/apis/web-api), rate limits
  (docs.slack.dev/apis/web-api/rate-limits), token types (docs.slack.dev/authentication/tokens), token rotation
  (docs.slack.dev/authentication/using-token-rotation). `slack_sdk` 3.45.0 source.
- Linear: rate limiting (linear.app/developers/rate-limiting).
- PostHog: API overview and personal API keys (posthog.com/docs/api).
- Prior art: the URLs in the table above. Code refs for the comparison:
  - Agent Vault `d5836ec`: `internal/mitm/forward.go` (path/query L123-125, L227-233; RoundTrip L337; 401
    retry L350-373; body cap L377-424), `internal/brokercore/brokercore.go` (header replace L93-120,
    `Set-Cookie` L152-158), `internal/ratelimit/config.go` L59-65, `internal/catalog/catalog.go` L36, L52,
    `examples/slack-agent-template/src/slack.ts` L12-36, L57-59.
  - Secretless `23b436d`: `internal/plugin/connectors/http/proxy_service.go` L145-236, L294-307;
    `generic/config.go` L128-138; `generic/connector.go` L41-48.
  - tokenizer `12c9cb2`: `tokenizer.go` L191-229, L376-472; `authorizer.go` L103-121; `processor.go`
    L1110-1254.
  - OneCLI `6eaf878`: `apps/gateway/crates/apps/src/lib.rs` (Linear L383-388, PostHog L2060-2092, Slack test
    L4621-4638), `summary/src/record_links.rs` L70-83, `proxy/src/response.rs` L105-110,
    `apps/gateway-e2e/tests/forwarding.test.ts` L16-41.
  - Docker MCP Gateway `2f72d79`: `pkg/mcp/remote.go` L63-117.
