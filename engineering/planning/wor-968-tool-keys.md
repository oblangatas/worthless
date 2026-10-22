# WOR-968: tool keys (Slack, Linear, PostHog), delivery plan

*Epic: [WOR-968](https://linear.app/plumbusai/issue/WOR-968). Design: [ADR-002](../adr/002-non-llm-bearer-credentials.md).
Research: [research/non-llm-keys/README.md](../research/non-llm-keys/README.md).*

## One-sentence outcome

> *"Our agent's `.env` leaked, Slack and Linear tokens included, and nothing in it worked against the vendor."*

Experimental, leaked-file scope only. "Hard spend cap for LLM keys" stays the headline. Mappy, an AI-agent VM,
is the first design partner.

Line refs below were checked against `03c6518`.

## Features and tickets

Each feature's ELI5 card lives in its Linear issue. Engineering needs the mapping:

| Feature | Outcome | Ticket | Delivered by | Release |
|---|---|---|---|---|
| F1 | Lock your Slack, Linear and PostHog tokens | [WOR-971](https://linear.app/plumbusai/issue/WOR-971) | PR3 | v1 |
| F2 | Your bot talks to Slack exactly as before | [WOR-972](https://linear.app/plumbusai/issue/WOR-972) | PR1a, PR1b | v1 |
| F3 | A leaked shard is dead on arrival | [WOR-973](https://linear.app/plumbusai/issue/WOR-973) | PR0a, PR1a, PR1b, PR3 (redaction, protocol match) | patch + v1 |
| F4 | Not billed like an LLM | [WOR-974](https://linear.app/plumbusai/issue/WOR-974) | PR2 (PR0b rides here) | v1 |
| F5 | Undo in one command | [WOR-975](https://linear.app/plumbusai/issue/WOR-975) | PR0c, PR3 | v1 |
| F6 | The agent can't open the vault | [WOR-976](https://linear.app/plumbusai/issue/WOR-976) | R1 | v1, **gates Mappy go-live** |
| F7 | The agent can only do what you allowed | [WOR-977](https://linear.app/plumbusai/issue/WOR-977) | tickets only | later |
| F8 | Brakes and a pause button | [WOR-978](https://linear.app/plumbusai/issue/WOR-978) | tickets only | F8a budgets v1.1; F8b later |
| Docs | Experimental docs, then positioning | [WOR-988](https://linear.app/plumbusai/issue/WOR-988), [WOR-989](https://linear.app/plumbusai/issue/WOR-989) | PR4a, PR4b | with PR3; after Mappy |

| PR | Ticket | Size |
|---|---|---|
| PR0a: LLM adapters forward the other credential header | [WOR-979](https://linear.app/plumbusai/issue/WOR-979) | S |
| PR0b: non-dict `usage` crashes spend recording | [WOR-980](https://linear.app/plumbusai/issue/WOR-980) | S |
| PR0c: `unlock` removes the wrong `*_BASE_URL` | [WOR-981](https://linear.app/plumbusai/issue/WOR-981) | S |
| PR1a: passthrough tracer, ships dark | [WOR-982](https://linear.app/plumbusai/issue/WOR-982) | L |
| PR1b: response fidelity and leak hygiene | [WOR-983](https://linear.app/plumbusai/issue/WOR-983) | M |
| PR2: unmetered tool keys | [WOR-984](https://linear.app/plumbusai/issue/WOR-984) | M |
| PR3: `lock`/`unlock` for tool keys | [WOR-985](https://linear.app/plumbusai/issue/WOR-985) | L |
| R1: Mappy trust-domain recipe | [WOR-986](https://linear.app/plumbusai/issue/WOR-986) | M (mostly ops) |
| Docs before code (this file, ADR-002, research note) | [WOR-987](https://linear.app/plumbusai/issue/WOR-987) | S |
| Mappy rollout | [WOR-990](https://linear.app/plumbusai/issue/WOR-990) | n/a |

## Gates before feature code

PR0a–c and these docs can run now. **Gates A and B both gate PR1a.**

- **Gate A, Mappy leak inventory** ([WOR-969](https://linear.app/plumbusai/issue/WOR-969), no code). List the
  artifacts that leave Mappy (workdir tarballs, transcript exports, CI logs, VM backups, anything else) and sort
  them by ADR-002's "when the protection holds" table. Record which tokens exist: `xapp-` (Socket Mode)?
  rotating `xoxe.` tokens? `xoxp-`? Their scopes. **Stop and rethink** if partial files leaving the box are not
  the main leak path.
- **Gate B, SDK wire capture** ([WOR-970](https://linear.app/plumbusai/issue/WOR-970), throwaway, scratchpad, not
  the repo). **Done with fake tokens** on 2026-10-22; results are in the research note, section 4. The live leg
  (test-workspace tokens against the real vendors) is still open. About 50 lines of Starlette serving canned responses and logging method, `raw_path`, query, where
  the credential sits, body keys and any 3xx. Clients: `slack_sdk` sync and async (including `files_upload_v2`'s
  second hop), `@linear/sdk`, `posthog-python` with `phx_` against `us.posthog.com`. Optional live leg with
  test-workspace tokens. It answers:
  1. Is the credential **only** in `Authorization`, raw or Bearer? **Yes.**
  2. Do path, query and trailing slash survive? **Yes, if forwarded as raw bytes.** Async Slack puts a query on
     POSTs too; sync Slack always POSTs.
  3. Does any SDK reject a scrambled shard-A? **No.** Linear does reject non-loopback `http://` URLs.
  4. Does any SDK expect or follow redirects? **None needs one; all follow them**, and sync `slack_sdk` keeps
     the Bearer header across hosts.
  5. Does any SDK read a base-URL env var? **No**, so the one-line snippet is required.

  Gate B also found that `posthog-python` sends keyless analytics to the same host as its `phx_` calls. Owner
  decision (2026-10-22): v1 covers `phx_` for direct API use only; the library's mixed mode is
  [WOR-1000](https://linear.app/plumbusai/issue/WOR-1000). See ADR-002, "PostHog in v1".

## TDD slices

Every bullet under **Red** is a failing test, shown failing before its fix.

### PR0: existing bugs (three independent PRs, can start now)

- **PR0a.** *Red:* in `tests/test_adapters.py`, send shard-A in both `authorization` and `x-api-key` to each LLM
  adapter; neither may appear in the prepared request. *Fix:* each adapter pops the other header
  (`adapters/openai.py:62-63`, `adapters/anthropic.py:28-29`). Framed as correctness (Anthropic gets two auth
  headers), not a leak.
- **PR0b.** *Red:* a response with `"usage": "x"` raises nothing and writes no bogus spend row. *Fix:* guard at
  `proxy/metering.py:32`.
- **PR0c.** *Red:* an OpenRouter lock followed by unlock removes `OPENROUTER_BASE_URL`. *Fix:* use
  `_derive_base_url_var(var_name, provider)` instead of `_PROVIDER_ENV_MAP` at `cli/commands/unlock.py:273`.

### PR1a: passthrough tracer, ships dark (L)

**Refactors, no behaviour change**

- Move `_validate_upstream_base_url` (`cli/commands/lock.py:287`) into a neutral `src/worthless/upstream_url.py`
  that raises `UnsafeUpstreamURL(ValueError)`; `lock` wraps it. Add `worthless.cli.commands` to the banned
  imports in `tests/architecture/test_proxy_imports.py` (importing `lock.py` would load the splitter, WOR-309).
- Move the e2e fixtures into `tests/_proxy_harness.py`. `_enroll` is at `tests/test_proxy_e2e.py:69-100`;
  `FakeIPCSupervisor.open_calls` is at `tests/_fakes/fake_ipc_supervisor.py:120`.

**New code**

- `src/worthless/protocols.py`: `LLM_PROTOCOLS`, `PASSTHROUGH`, `ALL_PROTOCOLS`.
- `ProtocolSpec(name, metered, extract_credential, verbatim_errors)` and `get_protocol()` in
  `adapters/registry.py`.
- `adapters/passthrough.py`, keeping the spike's header logic.
- `app.py` passthrough branch: parse the alias from `scope["raw_path"]` and drop `root_path`; unknown protocol →
  401; extract the credential in mirrored form **before** the decoy check; run
  `build_upstream_url(base_url, raw_api_path, query_string)` **before** `rules.evaluate`; one shared
  decrypt-and-reconstruct helper so `ipc.open` has a single call site.
- LLM aliases keep `get_adapter(path)` and `_extract_alias_and_path` unchanged.

**Red** (new `tests/test_proxy_passthrough.py`)

1. **Tracer.** GET `/{alias}/conversations.history?channel=C1&limit=2` with Bearer shard-A (the async Slack
   shape). The respx capture shows the exact URL with its query, `Bearer <real>`, no shard-A anywhere, body
   byte-identical.
2. A form-encoded POST arrives verbatim, with no `include_usage` injected. So do a POST with a query string
   (`files.getUploadURLExternal?filename=x.txt&length=5`) and a sync-Slack POST with
   `Content-Type: application/json` and an empty body.
3. Trailing slash and `%20` are preserved.
4. **Dot segments** get a 401, `open_calls == 0`, respx never called: `.` and `..` in any `%2e` case mix
   (`%2e%2e`, `.%2E`, `%2e.`), and any `\`. `%2f` and `//` are forwarded as sent. A literal `..` needs a
   raw-ASGI-scope helper, because httpx collapses it client-side.
5. Hypothesis property: `build_upstream_url` never escapes the base.
6. Raw and Bearer forms are mirrored. Basic auth, `x-api-key`, and values with spaces get a 401 before decrypt.
7. A row with an unknown protocol gets a 401 before decrypt.
8. A retired decoy shard-A gets a 401.
9. **Guards.** Replace the static `source.find("ipc.open")` check (`tests/test_security_properties.py:348-420`)
   with an AST check: exactly one `ipc.open`, after `evaluate`. An openai alias on an arbitrary path gets a 401.
   Auth, routing and validation failures are byte-identical to an unknown alias's `_uniform_401`. These stay
   green: `tests/test_adapters.py:347-371`, `tests/test_proxy.py:558`, `tests/test_proxy_e2e.py:504-610`.
10. **Live.** `live_proxy` (`tests/test_contract.py:112`) with an echo route proves uvicorn passes `raw_path`
    and query through. The request-time URL re-check needs a test-settings switch for the `127.0.0.1` upstream.

### PR1b: response fidelity and leak hygiene (M)

**Red**

- An upstream 429 relays `Retry-After`, every `X-RateLimit-*` header (Linear's requests, complexity and
  per-endpoint families) and the body.
- A 4xx body arrives verbatim; Linear's 400 with `RATELIMITED` arrives intact.
- `set-cookie` is stripped.
- Any upstream 3xx becomes a 502, with no `Location` rewrite (Gate B: no SDK needs one, and sync `slack_sdk`
  would follow it with the Bearer header). Also assert the proxy's own httpx client never follows a redirect.
- A body over the cap becomes a 502, never a truncated body.
- This alias's shard-A in the raw query string **or the body** gets a 401 before decrypt (Node `@slack/web-api`
  puts a per-call `token` in the form body). The match is against **this alias's** shard-A bytes only, never a
  token pattern: every PostHog secret-key call carries `?token=phc_…`.
- The proxy's own 429/502/503 carry a marker header; an upstream 429 relayed verbatim does not. The uniform 401
  is unchanged.
- A streamed body that overflows the cap aborts the connection; it never ends as a truncated 200.
- The access log has no query string: a filter on `uvicorn.access` drops it, and new `KEY_PATTERN` prefixes
  redact any token that remains.
- The proxy never retries: one inbound request, exactly one upstream call. This backs the duplicate-post kill
  criterion.

The LLM sanitizer is unchanged (WOR-729 is separate). Scrubbing credentials from 4xx bodies moves to F7.

> **Correction to the approved plan:** it says this PR raises a response cap "from 64 KiB to around 10 MiB".
> `03c6518` has no response-body cap: `relay_response` (`adapters/types.py:117`) buffers whole non-streaming
> bodies, and the only 64 KiB constant in the proxy is the SSE partial-line buffer (`metering.py:151`). So PR1b
> *adds* a cap (~10 MiB) for the bodies it relays. The success-body cap is
> [WOR-996](https://linear.app/plumbusai/issue/WOR-996).

### PR2: unmetered tool keys, F4 (M)

**Code:** `RulesEngine.evaluate(..., metered=True)`. `SpendCapRule` and `TokenBudgetRule` get
`meters_tokens: ClassVar[bool] = True`. When unmetered: `_spend_reservation = 0`, no usage extraction, no record
or settle task.

**Red** (harness: `_setup_proxy` generalised, `cap=1`)

- not capped (402 today);
- no `spend_log` or `pending_charges` rows, including on 4xx (today an uncapped 4xx records `record_spend(0)`);
- no usage warning in caplog;
- no token-budget reservation;
- the rate limit still returns 429 + `Retry-After`.

**Guards:** `metered` defaults to `True`; the OpenAI cap still returns 402; the WOR-696 and WOR-705 suites stay
green.

### PR3: `lock`/`unlock` for tool keys, F1 + F5 + F3 (L)

**Code**

- Prefix table in `cli/key_patterns.py`: `slack: [xoxb-, xoxp-]`, `linear: [lin_api_]`, `posthog: [phx_]`.
  Passthrough comes from this table, **never from TOML**. Bundled `providers.toml` adds the three upstream URLs.
  Protocol strings are validated on parse. No `providers register passthrough`.
- **Protocol-class match:** `_resolve_upstream_base_url` (`lock.py:399`) and `lookup_by_name` refuse a
  `*_BASE_URL` or registry URL whose protocol doesn't match the key's. Fixes Slack→OpenAI and the reverse.
- **Opt-in and output:** `--tool-keys` turns locking on. Without it, `lock` warns about detected tool keys
  instead of printing "No unprotected API keys found." (`lock.py:2558`). Aliases are vendor-named
  (`slack-xxxxxxxx`); the row stores `passthrough`. `_proxy_base_url` (`lock.py:133`) adds no `/v1`.
  `<STEM>_BASE_URL` naming for passthrough only, refusing collisions. `lock` prints the client snippet (no
  `--json` field; lock has no JSON output yet).
- **Refusals with a reason:** `phc_`, `xapp-`, `xoxe-`, `xoxe.xoxb-`, Slack signing secrets. A refused secret
  that remains suppresses the "You're protected" verdict (reuse the `worthless-7jn2` path at `lock.py:2549`);
  `phc_` doesn't, since it's public.
- **"Next:" line** points at the snippet, not `wrap`. `wrap` skips passthrough aliases.

**Red**

- prefix detection and refusal messages;
- the verdict is suppressed while `xapp-` remains;
- the warn-without-flag output;
- `test_lock_slack_end_to_end`: shard-A keeps `xoxb-`; `SLACK_BOT_BASE_URL` has no `/v1`; the row is
  passthrough with a NULL cap and a `slack-` alias; the proxy round trip delivers the real key to respx;
- `SLACK_BOT_BASE_URL=https://api.openai.com/v1` is refused, and the reverse;
- a hand-edited TOML `protocol="passthrough"` on openai is refused;
- `OPENAI_BASE_URL` is never written for tool keys; a variable collision is refused;
- `unlock` removes the variable;
- redaction covers the new prefixes and raw `Authorization`;
- a `KEY_PATTERN`↔registry prefix-coverage test (no `.gitleaks.toml` coupling);
- the same flow for a Linear raw-auth key and a PostHog `phx_` key used directly (Bearer on every request).
  Gate B never exercised PostHog's direct-API path, so this e2e is its first coverage.

**Guard:** the existing openai/anthropic/openrouter lock tests stay unchanged.

### R1: F6 Mappy trust-domain recipe (docs + verification script; code only if the recipe needs it)

The agent runs under its own uid or container. `~/.worthless` and the Fernet key are unreadable to it and kept
out of agent-visible snapshots. The proxy listens on loopback only. `worthless unlock` fails as the agent user.
Optionally, a default-deny egress allowlist. The verification script runs as the agent user and expects `EACCES`
on the store, a failing unlock, and a working proxy call.

### PR4a / PR4b: docs

- **PR4a (with PR3):** `docs/security.md` gets the "when it holds" table, non-goal #9 ("unbounded until
  budgets"), and the SR-05/09/11 deltas. A new experimental tool-keys page with per-SDK snippets, and one line saying feature flags in the PostHog
  Python library aren't supported yet. Reword
  `docs/install/mac.md:164` ("Non-LLM secrets…").
- **PR4b (only after Mappy meets its success criteria):** README Scope gains a secondary "also tool keys"; the
  LLM headline stays. Also the website FAQ, both `SKILL.md` files, and `personas.md` (P8, agent operator).

## Order of work

- **Now, independently:** these docs, Gate A, Gate B, PR0a, PR0b, PR0c.
- **After both gates pass, as a chain:** PR1a → PR1b → PR2 → PR3.
- **Beside the chain:** R1. PR4a ships with PR3. PR4b after Mappy succeeds.

## Follow-ups (filed)

| Ticket | What |
|---|---|
| [WOR-991](https://linear.app/plumbusai/issue/WOR-991) | Pre-gate shard-A MAC check (prerequisite for F8 budgets; uses the existing, unwritten `enrollments.decoy_hash` column) |
| [WOR-992](https://linear.app/plumbusai/issue/WOR-992) | `enroll` outputs shard-A and stores the protocol |
| [WOR-993](https://linear.app/plumbusai/issue/WOR-993) | `wrap` support for passthrough aliases |
| [WOR-994](https://linear.app/plumbusai/issue/WOR-994) | Segment-aware format-preserving split for structured Slack tokens (SR-12) |
| [WOR-995](https://linear.app/plumbusai/issue/WOR-995) | Slack `files_upload_v2` second hop. **Closed:** Gate B saw it carry no key. If R1's egress allowlist is used, allow `files.slack.com` |
| [WOR-1000](https://linear.app/plumbusai/issue/WOR-1000) | PostHog Python library mode: forward keyless analytics untouched for PostHog aliases only |
| [WOR-996](https://linear.app/plumbusai/issue/WOR-996) | Size cap for buffered success bodies |
| [WOR-997](https://linear.app/plumbusai/issue/WOR-997) | Slack incoming-webhook URLs |
| [WOR-998](https://linear.app/plumbusai/issue/WOR-998) | User-declared generic bearer protocol |

## Mappy rollout ([WOR-990](https://linear.app/plumbusai/issue/WOR-990), after PR3 + R1)

1. Complete Gate A. Minimum token scopes. **Do not roll out `xoxp`.** Check whether Mappy's Slack app has
   token rotation on (Slack can't turn it off once enabled), whether the VM sets `HTTPS_PROXY`, and which Slack
   SDK Mappy uses (Python `slack_sdk` or Node `@slack/web-api`).
2. **Rotate the tokens first, then lock the fresh ones.** Keep the originals recoverable off the box, in case
   shard-B is lost (#709).
3. Apply R1 and run its verification script as the agent user. Hard gate.
4. `worthless service install` with a restart policy and health check. Run an outage drill: the proxy is a
   single point of failure.
5. Lock Slack, patch the one line in Mappy's client factory, add a prompt hint. Canary read-only calls first,
   then writes. No shadowing of writes.
6. Rehearse `unlock` once. Add Linear in week 2, PostHog (direct API use only) in week 3, after checking on the
   real account which host serves it (`us.` vs `eu.posthog.com`).

**Success** (against the week before rollout):

- no substring of the real token, 16 characters or longer, in any audited artifact;
- re-running the Gate A artifact audit finds none holding both halves;
- call success at least 99.5% of baseline over 14 days;
- p50 added latency under 20 ms; p99 reported;
- at most one code line per provider;
- at least 90% of generated calls go through the proxy over 100+ tasks (bypass measured by vendor
  `invalid_auth` counts).

**Kill:** a mangled or duplicated action; more than one proxy-caused outage a week; more than one code change
per provider; more than 20% of calls bypassing the proxy; any invariant having to be weakened.

**Rollback:** `worthless unlock`. The snippet's fallback default means no redeploy.

## Verification

- **Every PR:** `uv run pytest -q` (including the guards above), `uv run ruff check`, `uv run pyright`,
  pre-commit. Each red test is shown failing before its fix.
- **After PR3, end to end on macOS** (WRTLS-116 is Linux-only):
  1. In a scratch `HOME`, `lock --tool-keys` a `.env` with test-workspace Slack and Linear tokens, then
     `worthless up`.
  2. Async `slack_sdk`: `auth.test`, a `conversations.history` GET with a query, `chat.postMessage` to a test
     channel, and a bad channel to get the native `ok: false`.
  3. Linear: a query, a mutation, a forced validation error.
  4. 1,000 calls, no 402.
  5. A mitmproxy capture on the upstream leg shows 0 hits for shard-A.
  6. `unlock` restores the `.env`.
- **On Mappy:** the R1 verification script, as the agent user.
