# WOR-968: tool keys (Slack, Linear, PostHog), delivery plan

*Epic: [WOR-968](https://linear.app/plumbusai/issue/WOR-968). Design: [ADR-002](../adr/002-non-llm-bearer-credentials.md)
(terms are defined there). Evidence: [research/non-llm-keys/README.md](../research/non-llm-keys/README.md).*

## One-sentence outcome

> *"Our agent's `.env` leaked, Slack and Linear tokens included, and nothing in it worked against the vendor."*

Experimental, leaked-file scope only. "Hard spend cap for LLM keys" stays the headline. Mappy, an AI-agent VM,
is the first design partner. Code line refs below were checked against `03c6518`; use the symbol names, since
line numbers drift.

## Features and tickets

Each feature's plain-English card lives in its Linear issue.

| Feature | Outcome | Ticket | Delivered by | Release |
|---|---|---|---|---|
| F1 | Lock your Slack, Linear and PostHog tokens | [WOR-971](https://linear.app/plumbusai/issue/WOR-971) | PR3a, PR3 | v1 |
| F2 | Your bot talks to Slack exactly as before | [WOR-972](https://linear.app/plumbusai/issue/WOR-972) | PR1a, PR1b | v1 |
| F3 | A leaked shard is dead on arrival | [WOR-973](https://linear.app/plumbusai/issue/WOR-973) | PR0a, PR1a, PR1b, PR3 | patch + v1 |
| F4 | Not billed like an LLM | [WOR-974](https://linear.app/plumbusai/issue/WOR-974) | PR0b, PR2 | v1 |
| F5 | Undo in one command | [WOR-975](https://linear.app/plumbusai/issue/WOR-975) | PR0c, PR3 | v1 |
| F6 | The agent can't open the vault | [WOR-976](https://linear.app/plumbusai/issue/WOR-976) | R1 | v1, **gates Mappy go-live** |
| F7 | The agent can only do what you allowed | [WOR-977](https://linear.app/plumbusai/issue/WOR-977) | tickets only | later |
| F8 | Brakes and a pause button | [WOR-978](https://linear.app/plumbusai/issue/WOR-978) | tickets only | F8a budgets v1.1; F8b later |
| Docs | Experimental docs, then positioning | [WOR-988](https://linear.app/plumbusai/issue/WOR-988), [WOR-989](https://linear.app/plumbusai/issue/WOR-989) | PR4a, PR4b | with PR3; after Mappy |

| Slice | Ticket | Size | Status (2026-10-24) |
|---|---|---|---|
| PR0a: LLM adapters forward the other credential header | [WOR-979](https://linear.app/plumbusai/issue/WOR-979) | S | merged (#726) |
| PR0b: non-dict `usage` crashes spend recording | [WOR-980](https://linear.app/plumbusai/issue/WOR-980) | S | draft PR #730 |
| PR0c: `unlock` removes the wrong `*_BASE_URL` | [WOR-981](https://linear.app/plumbusai/issue/WOR-981) | S | draft PR #728 |
| Rate limit can't be dodged with `X-Forwarded-For` | [WOR-1010](https://linear.app/plumbusai/issue/WOR-1010) | S | not started; independent |
| PR1a: passthrough tracer, ships dark | [WOR-982](https://linear.app/plumbusai/issue/WOR-982) | L | blocked on Gate A |
| PR1b: response fidelity and leak hygiene | [WOR-983](https://linear.app/plumbusai/issue/WOR-983) | M | after PR1a |
| PR2: unmetered tool keys | [WOR-984](https://linear.app/plumbusai/issue/WOR-984) | M | after PR1a |
| PR3a: lock plumbing (vendor vs protocol, second lock, OpenClaw exclusion) | [WOR-985](https://linear.app/plumbusai/issue/WOR-985) | M | after PR2 |
| PR3: `lock`/`unlock` for tool keys | [WOR-985](https://linear.app/plumbusai/issue/WOR-985) | L | after PR3a and PR0c |
| R1: Mappy trust-domain recipe | [WOR-986](https://linear.app/plumbusai/issue/WOR-986) | M (mostly ops) | beside the chain |
| Docs before code (this file, ADR-002, research note) | [WOR-987](https://linear.app/plumbusai/issue/WOR-987) | S | in review (#723) |
| Mappy rollout | [WOR-990](https://linear.app/plumbusai/issue/WOR-990) | n/a | after PR3 and R1 |

## Gates before feature code

**Gate A gates PR1a.** PR0 and WOR-1010 can run now.

- **Gate A, Mappy leak inventory** ([WOR-969](https://linear.app/plumbusai/issue/WOR-969), no code). List:
  - the artifacts that leave Mappy (workdir tarballs, transcript exports, CI logs, VM snapshots and backups),
    sorted by ADR-002's "when the protection holds" table;
  - **every consumer of each token** (process, MCP server config, skill) and every host it sends the token to;
  - the tokens and scopes that exist: `xapp-` (Socket Mode)? rotation turned on? `xoxp-`?
  - which Slack SDK Mappy uses (Python `slack_sdk` or Node `@slack/web-api`), and whether the VM sets
    `HTTPS_PROXY`.

  **Stop and rethink** if partial files leaving the box are not the main leak path, or if any consumer can't be
  given a base URL.
- **Gate B, SDK wire capture** ([WOR-970](https://linear.app/plumbusai/issue/WOR-970)): **done** with fake tokens on
  2026-10-22; findings in the research note, section 4. **The live leg** (test-workspace tokens against the real
  vendors) is **required before Mappy go-live**, not before PR1a. It confirms the rows tagged **[L]**.

## TDD slices

**Red** bullets are tests written first and shown failing before the fix. **Guard** bullets protect existing
behaviour and must stay green.

### PR0: existing bugs (three independent PRs)

- **PR0a** (merged, #726). *Red:* shard-A sent in both `authorization` and `x-api-key` to each LLM adapter appears
  in neither prepared request.
- **PR0b.** *Red:* a response with `"usage": "x"` raises nothing and writes no bogus spend row (`extract_usage_openai`).
- **PR0c.** *Red:* an OpenRouter lock followed by unlock removes `OPENROUTER_BASE_URL` (`unlock` uses
  `_derive_base_url_var`, not `_PROVIDER_ENV_MAP`).
- **WOR-1010.** *Red:* N+1 requests to one alias, each with a different `X-Forwarded-For`, get a 429 on N+1.

### PR1a: passthrough tracer, ships dark (L)

**Refactors, no behaviour change**

- Move `_validate_upstream_base_url` out of `cli/commands/lock.py` into a neutral `src/worthless/upstream_url.py`
  that raises `UnsafeUpstreamURL(ValueError)`; `lock` wraps it. Ban `worthless.cli.commands` in both the static
  import guard (`tests/architecture/test_proxy_imports.py`) and the runtime one
  (`tests/ipc/test_proxy_client_unit.py`), because importing `lock.py` would load the splitter (WOR-309).
- Move the e2e fixtures (`_enroll` in `tests/test_proxy_e2e.py`, `FakeIPCSupervisor.open_calls`) into
  `tests/_proxy_harness.py`.

**New code**

- `src/worthless/protocols.py`: `LLM_PROTOCOLS`, `PASSTHROUGH`, `ALL_PROTOCOLS`.
- `ProtocolSpec(name, metered, extract_credential, verbatim_errors)` and `get_protocol()` in `adapters/registry.py`.
- `adapters/passthrough.py`. Header rules (the spike's, written out): drop the inbound `authorization` and
  `x-api-key`; set `authorization` to the real key in the form the client used (`Bearer <key>` or `<key>`);
  pass every other header through, except those PR1b drops. `ProviderAdapter.prepare_request` takes no method,
  path, query or auth form today: pass them to the passthrough adapter without changing the LLM adapters.
- `app.py` passthrough branch:
  - parse the alias once, with today's parser, before branching on the protocol; a passthrough request then
    takes its API path from `scope["raw_path"]` after the `/<alias>` prefix (drop `root_path`; the two must
    agree);
  - unknown protocol → uniform 401;
  - extract the credential in mirrored form **before** the decoy check;
  - run `build_upstream_url(base_url, raw_api_path, query_string)` (plain string join, never `urljoin`) and the
    request-time URL check **before** `rules.evaluate`;
  - one shared decrypt-and-reconstruct helper **in `proxy/app.py`** (the Invariant-3 tests only scan that file);
  - its own `httpx.AsyncClient`, so a slow vendor can't take LLM requests' connections.
- Request-time URL check: passthrough rows only, an exact match against the vendor URL table in code (ADR D8).
  The switch that allows a `127.0.0.1` upstream in tests is set only by test code, never by a `ProxySettings`
  field read from the environment.
- LLM aliases keep `get_adapter(path)` and `_extract_alias_and_path` unchanged.

**Red** (new `tests/test_proxy_passthrough.py`)

1. **Tracer.** GET `/{alias}/conversations.history?channel=C1&limit=2` with Bearer shard-A (async Slack's shape).
   The respx capture shows the exact URL with its query, `Bearer <real>`, no shard-A anywhere, body
   byte-identical.
2. A form-encoded POST arrives verbatim, with no `include_usage` injected. So do a POST with a query string
   (`files.getUploadURLExternal?filename=x.txt&length=5`) and a sync-Slack POST with
   `Content-Type: application/json` and an empty body.
3. Trailing slash and `%20` are preserved; `%2f` and `//` are forwarded as sent.
4. **Dot segments and backslashes** get a 401 with `open_calls == 0` and respx never called: `.`/`..` in any
   `%2e` case mix (`%2e%2e`, `.%2E`, `%2e.`), `..%2f..` (caught after one round of percent-decoding), `\` and
   `%5c`. A literal `..` needs a raw-ASGI-scope helper, because httpx collapses it client-side.
5. **Host pinning.** `//evil.com/x` right after the alias, on PostHog's path-less base URL, stays on
   `us.posthog.com`. A Hypothesis property: `build_upstream_url` never changes the host or escapes the base path.
6. Raw and Bearer forms are mirrored. Basic auth, `x-api-key` and values with spaces get a 401 before decrypt.
7. A row with an unknown protocol, or a stored URL not in the vendor table, gets a 401 before decrypt.
8. A retired decoy shard-A gets a 401, in both Bearer and raw form.
9. A passthrough 429 from the rate limit leaves `open_calls == 0`.
10. **Live.** `live_proxy` (`tests/test_contract.py`) with an echo route proves uvicorn passes `raw_path` and the
    query through.

**Guards**

- Replace the static `source.find("ipc.open")` check (`tests/test_security_properties.py`) with an AST check:
  every call to the shared reconstruct helper comes after `evaluate` and the denial return.
- An openai alias on an arbitrary path still gets a 401. Auth, routing and validation failures stay
  byte-identical to an unknown alias's uniform 401.
- The existing registry, query-param and URL-edge-case tests in `tests/test_adapters.py`, `tests/test_proxy.py`
  and `tests/test_proxy_e2e.py` stay green.

### PR1b: response fidelity and leak hygiene (M)

**Red**

- An upstream 429 relays `Retry-After`, every `X-RateLimit-*` header (Linear's requests, complexity and
  per-endpoint families) and the body.
- A 4xx body arrives verbatim; Linear's 400 with `RATELIMITED` arrives intact.
- `Set-Cookie` is stripped from responses; `Cookie`, `Forwarded` and `X-Forwarded-*` are not sent upstream.
- Any upstream 3xx becomes a 502, with no `Location` rewrite.
- **Size cap.** PR1b adds a cap of about 10 MiB on every buffered passthrough body, any status (there is no
  response cap today; the only 64 KiB constant in the proxy is the SSE line buffer). Over the cap before headers
  are sent → 502. A streamed body that overflows after headers → the connection is aborted, never a truncated
  200. This also covers WOR-996.
- This alias's shard-A bytes anywhere else in the request (path, query, any header, body) → 401 before decrypt.
  Match those exact bytes, never a token pattern (PostHog sends `?token=phc_…` on every call). A request with
  `Content-Encoding` → 401.
- A buffered response that contains the real key's exact bytes → 502.
- The proxy's own 429/502/503/504 carry an `x-worthless-` marker header; a relayed upstream 429 doesn't, and an
  upstream's copy of the marker is stripped.
- The access log has no query string: a filter on `uvicorn.access` drops it, and the new `KEY_PATTERN` prefixes
  redact any token that remains.
- One inbound request makes exactly one upstream call (backs the duplicate-post kill criterion).

**Guards:** the proxy's own httpx client never follows a redirect; the LLM sanitizer is unchanged (WOR-729 is
separate). Scrubbing other secrets from responses is F7.

### PR2: unmetered tool keys, F4 (M)

Can run alongside PR1b.

**Code:** `RulesEngine.evaluate(..., metered=True)`. `SpendCapRule` and `TokenBudgetRule` get
`meters_tokens: ClassVar[bool] = True`. When unmetered: no reservation, no usage extraction, no record or settle
task. For passthrough the rate-limit window is keyed on the alias alone. `TimeWindowRule` still applies. Decide
whether passthrough denials keep today's OpenAI-shaped JSON (`proxy/errors.py`).

**Red** (harness: `_setup_proxy` generalised, `cap=1`)

- not capped (402 today);
- no `spend_log` or `pending_charges` rows, including on 4xx (today an uncapped 4xx records `record_spend(0)`);
- no usage warning in caplog;
- no token-budget reservation;
- the rate limit still returns 429 + `Retry-After`, and rotating `X-Forwarded-For` doesn't reset it.

**Guards:** `metered` defaults to `True`; the OpenAI cap still returns 402; the WOR-696 and WOR-705 suites stay
green.

### PR3a: lock plumbing, no user-visible change (M)

**Code**

- Carry the vendor and the protocol as separate values through `lock` (today `provider = protocol` feeds
  `_make_alias`, `detect_prefix`/`split_key_fp` and `_derive_base_url_var`).
- The tool-vendor URL table lives in code next to the prefix table (ADR D1), not in `providers.toml`.
- Narrow `_detect_already_locked_env` to the `*_BASE_URL` variables of the keys being locked (ADR D7; the
  value-signature rewrite stays WOR-693).
- Exclude passthrough aliases from the OpenClaw integration (apply, capture, scrub).

**Red**

- Lock an OpenAI key, add a second key to the same `.env`, lock again: the second lock succeeds (WRTLS-117 today).
- With OpenClaw present, a passthrough alias never reaches `openclaw.json`.

**Guard:** the existing openai/anthropic/openrouter lock and OpenClaw tests stay unchanged.

### PR3: `lock`/`unlock` for tool keys, F1 + F5 + F3 (L)

Needs PR0c merged.

**Code**

- Prefix table in `cli/key_patterns.py`: `slack: [xoxb-, xoxp-]`, `linear: [lin_api_]`, `posthog: [phx_]`.
- **Vendor-exact URLs (ADR D8):** a tool key resolves only to its own vendor's URL from the code table. Refuse
  any other `*_BASE_URL` (another tool vendor's or an LLM provider's), and never use the OpenClaw `baseUrl`
  route, a carried-forward stored URL, or the hard-coded `api.openai.com/v1` fallback for a tool key. An LLM
  key's `*_BASE_URL` must match its protocol.
- **Opt-in and output:** `--tool-keys` turns locking on. Without it, `lock` warns about detected tool keys instead
  of printing "No unprotected API keys found." The row stores `passthrough` with a vendor-named alias. No `/v1`.
  `<STEM>_BASE_URL` naming for passthrough only, refusing collisions; `_derive_base_url_var` refuses outright for
  passthrough instead of falling back to `OPENAI_BASE_URL`. `lock` prints the client snippet, including the
  async-Slack `client.proxy = None` line where `HTTPS_PROXY` is set, and warns when `WORTHLESS_PROXY_HOST` isn't
  loopback for a Linear key.
- **Refusals:** exactly the table in ADR D7, with its verdict rule (the existing `worthless-7jn2` path).
- **"Next:" line** points at the snippet, not `wrap`. `wrap` skips passthrough aliases.

**Red**

- prefix detection, and one refusal message per row of the ADR D7 table (including `SLACK_SIGNING_SECRET` by
  variable name, `lin_oauth_` and `phs_`);
- the verdict is suppressed while `xapp-` remains, and not suppressed by `phc_`;
- the warn-without-flag output;
- `test_lock_slack_end_to_end`: shard-A keeps `xoxb-`; `SLACK_BOT_BASE_URL` has no `/v1`; the row is passthrough
  with a NULL cap and a `slack-` alias; the proxy round trip delivers the real key to respx;
- `SLACK_BOT_BASE_URL=https://api.linear.app` is refused, as are `https://api.openai.com/v1` and the reverse;
- a tool key never takes its URL from OpenClaw's `baseUrl`, from a URL stored on an earlier row, or from the
  `api.openai.com/v1` fallback (one test per route);
- a user `providers.toml` entry that reuses a tool vendor's URL, or declares `protocol="passthrough"`, is refused;
- `OPENAI_BASE_URL` is never written for a tool key; a variable collision is refused;
- `unlock` removes the variable;
- redaction covers the new prefixes and the raw `Authorization` form;
- a `KEY_PATTERN`↔prefix-table coverage test (no `.gitleaks.toml` coupling);
- the same flow for a Linear raw-auth key, and for a PostHog `phx_` key used directly (Bearer on every request).
  Gate B never exercised PostHog's direct-API path, so this is its first coverage and a required check before
  PostHog's rollout week.

**Guard:** the existing openai/anthropic/openrouter lock tests stay unchanged. The new prefixes also change what
`worthless scan`, the pre-commit hook, the code scanner and the OpenClaw audit report for every user; that is
intended (ADR D1).

### R1: F6 Mappy trust-domain recipe (docs + verification script; code only if the recipe needs it)

- The agent runs under its own uid or container. `~/.worthless` and the Fernet key are unreadable to it.
- The Fernet key lives off any disk a VM snapshot or backup captures, or Mappy explicitly accepts that a VM
  snapshot holds both halves.
- The proxy listens on loopback only.
- **Required:** outbound traffic from the agent's uid to `slack.com`, `api.linear.app`, `uploads.linear.app` and
  `*.posthog.com` is blocked and logged. `files.slack.com` stays reachable for uploads, which carry no key; Gate A
  must show Mappy doesn't download vendor files, because such a download would carry shard-A uncounted.

The verification script runs as the agent user and expects `EACCES` on the store, a failing `unlock`, the Fernet
key off the snapshotted disk (or Mappy's written acceptance that it isn't), a loopback-only listener, a blocked
direct vendor call, and a working proxy call.

### PR4a / PR4b: docs

- **PR4a (with PR3):** `docs/security.md` gets the "when it holds" table, non-goal #9 ("limited only by the rate
  limit until budgets"), and the SR-05/09/11 deltas. A new experimental tool-keys page with per-SDK snippets,
  one line saying feature flags in the PostHog Python library aren't supported yet, and "rollback = `unlock`,
  then restart the agent". Reword `docs/install/mac.md`'s "Non-LLM secrets" bullet.
- **PR4b (only after Mappy meets its success criteria):** README Scope gains a secondary "also tool keys"; the
  LLM headline stays. Also the website FAQ, both `SKILL.md` files, and `personas.md` (P8, agent operator).

## Order of work

- **Now, independently:** these docs, Gate A, PR0b, PR0c, WOR-1010.
- **After Gate A passes:** PR1a → (PR1b and PR2 in parallel) → PR3a → PR3.
- **Beside the chain:** R1. PR4a ships with PR3. PR4b after Mappy succeeds.

## Follow-ups (filed)

| Ticket | What |
|---|---|
| [WOR-991](https://linear.app/plumbusai/issue/WOR-991) | Pre-gate shard-A MAC check (prerequisite for F8 budgets; uses the existing, unwritten `enrollments.decoy_hash` column) |
| [WOR-992](https://linear.app/plumbusai/issue/WOR-992) | `enroll` outputs shard-A and stores the protocol |
| [WOR-993](https://linear.app/plumbusai/issue/WOR-993) | `wrap` support for passthrough aliases |
| [WOR-994](https://linear.app/plumbusai/issue/WOR-994) | Segment-aware format-preserving split for structured Slack tokens (SR-12) |
| [WOR-995](https://linear.app/plumbusai/issue/WOR-995) | Slack `files_upload_v2` second hop. **Closed:** it carries no key; R1 allows `files.slack.com` |
| [WOR-996](https://linear.app/plumbusai/issue/WOR-996) | Size cap for buffered success bodies. **Covered by PR1b** |
| [WOR-997](https://linear.app/plumbusai/issue/WOR-997) | Slack incoming-webhook URLs |
| [WOR-998](https://linear.app/plumbusai/issue/WOR-998) | User-declared generic bearer protocol |
| [WOR-1000](https://linear.app/plumbusai/issue/WOR-1000) | PostHog Python library mode: forward keyless analytics untouched for PostHog aliases only |
| [WOR-693](https://linear.app/plumbusai/issue/WOR-693) | Replace the already-locked heuristic with a value-signature check |

## Mappy rollout ([WOR-990](https://linear.app/plumbusai/issue/WOR-990), after PR3 + R1)

1. Complete Gate A. Minimum token scopes. **Do not roll out `xoxp`.**
2. **Get fresh tokens first** (revoke and reinstall the app; *not* Slack's token-rotation opt-in, which is
   irreversible and refused by v1), then lock them. Keep the originals recoverable off the box, in case shard-B is
   lost (#709).
3. Apply R1 and run its verification script as the agent user. Hard gate. Run the live leg.
4. `worthless service install` with a restart policy and health check. Run an outage drill: the proxy is a single
   point of failure.
5. Lock Slack, patch the one line in Mappy's client factory, and add a prompt hint that names the `*_BASE_URL`
   variable and says never to ask for a "working token". Canary read-only calls first, then writes. No shadowing
   of writes.
6. Rehearse rollback once (`unlock`, then restart the agent) and time the 401 window. Add Linear in week 2.
   PostHog (direct API use only) in week 3, after PR3's PostHog direct-API test passes and the real account's
   host (`us.` or `eu.posthog.com`) is checked.

**Success** (against the week before rollout):

- no substring of the real token, 16 characters or longer, in any audited artifact;
- re-running the Gate A artifact audit finds none holding both halves;
- call success at least 99.5% of baseline over 14 days;
- p50 added latency under 20 ms; p99 reported;
- at most one code line per provider;
- at least 90% of the agent's vendor calls go through the proxy over 100+ tasks. Measured as proxy access-log
  calls against R1's blocked direct calls; vendors don't give app owners failed-auth counts.

**Kill:** a mangled or duplicated action; more than one proxy-caused outage a week; more than one code change
per provider; more than 20% of calls bypassing the proxy; any invariant having to be weakened.

**Rollback:** `worthless unlock`, then restart the agent. No code change: the snippet falls back to the vendor's
own URL.

## Verification

- **Every PR:** `uv run pytest -q` (including the guards above), `uv run ruff check`, `uv run pyright`,
  pre-commit. Each Red test is shown failing before its fix.
- **After PR3, end to end on macOS** (WRTLS-116 is Linux-only):
  1. In a scratch `HOME`, lock an OpenAI key, then `lock --tool-keys` the same `.env` with test-workspace Slack
     and Linear tokens added, then `worthless up`.
  2. Async `slack_sdk`: `auth.test`, a `conversations.history` GET with a query, `chat.postMessage` to a test
     channel, and a bad channel to get the native `ok: false`.
  3. Linear: a query, a mutation, a forced validation error.
  4. PostHog `phx_` direct API: one read, Bearer routing confirmed, shard-A absent upstream.
  5. 10,000 calls, no 402 (the old LLM metering would have refused call ~7,813).
  6. Watch the upstream leg with a mitmproxy addon that compares every header, the query and the body against
     shard-A **in flight** and records only a yes/no count. Expect 0. Nothing that could hold the real key is
     saved.
  7. `unlock` restores the `.env`; restart the client and confirm it reaches the vendor directly.
- **On Mappy:** the R1 verification script, as the agent user.
