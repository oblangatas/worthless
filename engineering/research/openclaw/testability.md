# OpenClaw Testability: Driving a Real LLM Call Without a Human in the GUI

> Dimension: **OpenClaw testability**. Question: can OpenClaw's agent be driven to make a
> real LLM call headlessly, so we can build a CI test of the full user journey
> (config → model resolves → request shaped → hits proxy → upstream → content returns)?
>
> **Answer: YES, and the headless driver is already proven in the worthless test suite.**
> The journey test does not need to be invented — it needs to be *finished*
> (assert on returned content + add the failure-ladder lanes).

## Provenance (record the HEAD you read)

| Thing | Value |
|---|---|
| OpenClaw clone | `/Users/shachar/Projects/worthless/openclaw` |
| Git HEAD | `2eae30e779cb694b776ba1f52bd24c644cbdd919` |
| Tag | `v2026.5.3-1` (build commit: "prepare 2026.5.3-1 core npm") |
| worthless side | `/Users/shachar/Projects/worthless/worthless-wor621-phase3` |

This is the **same** build the seam map (`engineering/openclaw-integration-reference.md`) pins,
so all file:line below are live-accurate against this clone.

---

## 1. The headless entrypoint: `openclaw agent --message`

OpenClaw's CLI bin is `openclaw.mjs` (root `package.json` `bin.openclaw`). Arg parsing uses
**commander**. The agent command is registered in:

**`src/cli/program/register.agent.ts:25-90`** — `.command("agent")`, described as
*"Run an agent turn via the Gateway (use --local for embedded)"*. This is a single-turn,
**run-prompt-and-exit** command. Relevant options:

| Option | File:line | Meaning for the journey test |
|---|---|---|
| `-m, --message <text>` (**required**) | `register.agent.ts:27` | The fixed prompt. This is the "user sends a chat message" input. |
| `--json` | `register.agent.ts:50` | Machine-readable result on stdout — the CI assertion surface. |
| `--agent <id>` | `register.agent.ts:30` | Pin which agent (e.g. `main`). |
| `--model <id>` | `register.agent.ts:31` | Per-run model override (`provider/model`). Lets one test sweep many model refs. |
| `--session-id <id>` | `register.agent.ts:29` | Explicit session key — used by the existing worthless test for determinism. |
| `--local` | (consumed in `agent-via-gateway.ts:61,229`) | **Run embedded, in-process — no Gateway daemon needed.** |
| `--deliver` | `register.agent.ts:49` | OFF by default — no channel side-effects, pure request/response. |

The action handler (`register.agent.ts:80-90`) calls `agentCliCommand` →
`src/commands/agent-via-gateway.ts`.

### `--local` (and even default) require no running daemon

`src/commands/agent-via-gateway.ts`:
- `:229-230` — `if (opts.local === true) return await agentCommand(localOpts, runtime, deps)`
  → embedded path, directly into `agentCommand` (`src/agents/agent-command.ts:1266`).
- `:239-265` — **even without `--local`, if the Gateway is unreachable or times out it
  automatically falls back to the embedded agent** (`EMBEDDED FALLBACK: ...`). So a test that
  never starts a Gateway still completes a real turn.

`agentCommand` (`src/agents/agent-command.ts:1266`) is the embedded runner; `promptMode`/
`--message` is required (`agent-command.ts:276` throws `"Message (--message) is required"`).
One-shot thinking level is supported (`:330`), confirming this is a single-turn batch path,
not an interactive REPL.

**Bottom line:** `node openclaw.mjs agent --agent main --message "ping" --json [--local]`
is a fully headless, exit-after-one-turn invocation. No TTY, no GUI, no daemon.

---

## 2. The programmatic seam: pure/unit-testable vs running-agent

The map in `openclaw-integration-reference.md` holds. I re-verified every coordinate against
HEAD `2eae30e779`. Drift noted in **bold**.

| Seam behavior | Coordinate @ `2eae30e779` | Pure fn? (hermetic-testable) |
|---|---|---|
| `parseProviderModelRef` (split on first `/`) | `src/config/validation.ts:1165` | **PURE** — closure returning `{provider, model}`. Unit-test directly. |
| "Unknown model" rejection | `src/config/validation.ts:1220-1221` (**was 1220-1221 ✓**) | PURE-ish — config validation, no network. |
| Tool-use gate `supportsTools` | `src/agents/model-tool-support.ts:6` (`return compat?.supportsTools !== false`) | **PURE** — reads `model.compat`. Trivial unit test. |
| `requiresStringContent` gate | `src/agents/pi-embedded-runner/openai-stream-wrappers.ts:87` (`api==="openai-completions" && compat.requiresStringContent===true`) | **PURE** predicate. |
| String-content flatten | `src/agents/openai-transport-stream.ts:1856` (**flatten moved 1856; field def at :1656, default at :1685**) | PURE transform on the messages array. |
| OpenRouter `:free` detection | `src/agents/model-selection-shared.ts:184` (`provider==="openrouter" && model.includes("/") && endsWith(":free")`) | **PURE** predicate. |
| Catalog merge preserves cache baseUrl | `src/config/schema.base.generated.ts:1529` (**was :1520; const "merge" + "preserve non-empty agent models.json baseUrl"**) | Schema/merge logic — testable with two config objects, no network. |
| Resolve ref → provider/model | `src/agents/model-selection-shared.ts:484` `resolveModelRefFromString` | PURE-ish — needs the configured catalog but no I/O. |

**Requires a running (embedded) agent — needs the live headless driver:**
- Anything downstream of model resolution: building the actual HTTP request body, applying the
  `compat` flags *in the real send path*, and the request leaving to `baseUrl`. The transport
  is `complete(...)` from `@mariozechner/pi-ai` (see `src/agents/simple-completion-runtime.ts:1,
  285`), driven by `openai-transport-stream.ts`. **This is exactly the layer the human GUI was
  catching** — pure-fn tests prove each predicate in isolation but not that they compose
  correctly when an agent emits a real array-content + tools request.

**Implication for the client-agnostic / provider-aware invariant:** every seam above is
**OpenClaw-side request shaping** (it decides whether `tools` and array-content go out). The
worthless proxy is provider-aware only (OpenAI vs Anthropic parse/route/error). So the
*generic* protocol correctness (does the proxy forward a well-formed OpenAI body, meter it,
return content) can be covered **hermetically** with any OpenAI-compatible client. What needs
**LIVE OpenClaw** is specifically: *does OpenClaw, given this `compat` config, emit a body the
strict provider accepts?* That is the irreducibly OpenClaw-specific surface and the only thing
the GUI-only path was exercising.

---

## 3. Pointing OpenClaw at a fake local OpenAI server: CONFIRMED

OpenClaw routes purely on `baseUrl` — already exploited by worthless's harness. The fake
upstream lives at **`tests/openclaw/mock-upstream/app.py`** (worthless side): a Flask-style
OpenAI/Anthropic emulator that:
- returns valid chat-completion JSON with real content
  (`_chat_completion_body` → `"content": "Hello from mock upstream!"`, `app.py:47-65`),
- returns `/v1/messages` Anthropic content (`_messages_body`, `app.py:79`),
- and emulates the failure ladder: bad-model 404/400 (`_is_bad_model`, `app.py:29`),
  5xx (`_is_trigger_5xx`, `app.py:33`), prompt-cache usage (`_is_trigger_cache_hit`, `app.py:40`).

Config is injected at runtime without editing files by hand, via OpenClaw's own
`config set` (avoiding the merge-gotcha by going through the catalog API):
`docker exec ... node openclaw.mjs config set models.providers.openai <json> --strict-json`
then `... config set agents.defaults.model.primary <ref>` (see
`tests/openclaw/install_incident/test_proxy_load_bearing.py:181-194`). `baseUrl` is set to
`http://worthless-proxy:8787/<alias>/v1` — the worthless proxy, which then forwards to
`http://mock-upstream:9999/...`.

**Fixed prompt + terminate:** yes — `_route()` does exactly
`node openclaw.mjs agent --session-id <sid> --message "hi" --json` and the process exits with
the turn result (`test_proxy_load_bearing.py:86-89`).

---

## 4. OpenClaw's own test setup (could we hook in?)

- Framework: **vitest** (`vitest.config.ts`, `test/vitest/`). Live-network tests are gated by
  `OPENCLAW_LIVE_TEST=1` (see root `package.json` `android:test:integration`).
- There are existing transport tests that hit local/mock servers
  (`src/agents/anthropic-transport-stream.test.ts`, `.live.test.ts`, etc.).
- **Recommendation: do NOT build the worthless journey test inside OpenClaw's vitest suite.**
  It would couple worthless CI to OpenClaw's TS toolchain and break on every version bump in a
  way unrelated to the seam. Instead drive the *shipped* `openclaw.mjs` binary as a black box
  (subprocess / `docker exec`) — which is exactly what worthless already does. This treats the
  CLI contract (`agent --message --json`) as the stable surface and lets the seam-map re-verify
  greps catch drift.

---

## 5. The punchline: the journey test is 80% built — finish it

**`tests/openclaw/install_incident/test_proxy_load_bearing.py`** already:
- spins up `mock-upstream + worthless-proxy` via
  `tests/openclaw/docker-compose.yml` (pinned image `ghcr.io/openclaw/openclaw:2026.5.3-1`),
- runs real `worthless lock --env`, extracts shard-A, configures OpenClaw's provider to point
  at the proxy alias,
- drives a headless agent turn (`agent --message "hi" --json`),
- proves load-bearing: proxy down → turn fails + mock receives nothing; proxy up → turn
  succeeds + mock receives the request.

Marks: `pytest.mark.openclaw`, `pytest.mark.docker`, skipped when Docker absent
(`test_proxy_load_bearing.py:57-59`). Runner entrypoint exists:
`pyproject.toml:46` `test-openclaw = "worthless.testing.runners:openclaw"`.

### Gaps to close to make it the real-journey test (proposed = WOR-732's 3 lanes)

1. **Assert on returned content, not just returncode.** Today it checks `returncode == 0` and
   `len(_captured) >= 1`. Add: parse `--json` stdout and assert the assistant text contains
   `"Hello from mock upstream!"` — proving content makes the full round trip back into the
   agent, the thing only the GUI proved before.
2. **Drive the failure ladder explicitly** (the four GUI-only catches). The mock already
   supports each — wire one parametrized test per rung:
   - model not in catalog → OpenClaw rejects pre-proxy (`validation.ts:1220`);
   - tools-on-toolless model → 404 (toggle `compat.supportsTools`);
   - array-content to strict provider → 400 (toggle `compat.requiresStringContent`);
   - dead `baseUrl` via the **agent-cache** copy (`agents/main/agent/models.json`) → the
     merge-gotcha (`schema.base.generated.ts:1529`); assert editing only `openclaw.json` is
     silently overridden.
3. **Provider-protocol matrix, not client matrix.** Because worthless is client-agnostic, the
   *generic* lane (well-formed OpenAI/Anthropic body forwarded + metered + content returned)
   can run hermetically against the proxy with a plain HTTP client — no OpenClaw needed; the
   **OpenClaw lane** is reserved for the request-shaping seams in §2 that only an agent emits.

### Caveat: `--json` output shape unverified

I could not grep an explicit `JSON.stringify` of the agent result content in
`agent-command.ts` (the emit is likely inside the gateway/result formatter, not this file).
**Before writing the content assertion, capture one real `--json` turn from the pinned image
and pin the field path** (e.g. `.reply` / `.content` / `.messages[].content`). This is a
5-minute `docker exec` capture, not a code-reading exercise.

---

## Re-verify on OpenClaw version bump

The seam-map's existing grep block (`openclaw-integration-reference.md:146-153`) covers §2.
Add one line for the headless driver itself so a bump that renames the command fails fast:

```bash
grep -n '\.command("agent")' src/cli/program/register.agent.ts
grep -n -- '--message' src/cli/program/register.agent.ts
grep -n "opts.local === true" src/commands/agent-via-gateway.ts
```
