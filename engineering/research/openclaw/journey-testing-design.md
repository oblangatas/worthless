# OpenClaw User-Journey Testing — Design

> **Shape:** a three-lane test design (hermetic / container+mock / live-smoke) that automates the
> config → resolve → shape → gate → upstream → content-returns journey which was previously caught
> only by a human hand-driving the OpenClaw GUI. Mapped to WOR-732.

**Provenance.** Synthesized 2026-06-12 from a multi-agent research effort during WOR-621 Phase 3 PR-1 (prior art across LiteLLM/Helicone/Portkey/OpenRouter, seam-coverage matrix, framework critique). Only the companion `testability.md` shipped in-tree alongside this design; the rest of the input research was not preserved. OpenClaw
clone `/Users/shachar/Projects/worthless/openclaw` @ `2eae30e779cb694b776ba1f52bd24c644cbdd919`
(tag `v2026.5.3-1`) — same build the seam map pins. worthless side: branch
`feature/wor-715-lock-captures-mode`. Two critic-flagged coordinates were re-verified live during
synthesis (see §7): pee0 `model-auth.ts:171-173` (confirmed) and the `agent --json` emit
(`agent-via-gateway.ts:195` → `writeRuntimeJson(runtime, response)`; content lives under
`response.result.payloads[]`, partially confirmed — exact text field still needs a real capture).

---

## 1. TL;DR

**What this IS:** a layered test design that turns the WOR-621 "GUI-only failure ladder" (Unknown
model, 404-no-tools, 400-array-content, dead-baseUrl merge gotcha) into automated assertions across
three lanes — hermetic per-PR (Lane A), container+mock-upstream end-to-end (Lane B), and a gated
nightly/manual live smoke (Lane C). It is built on the rig that **already exists**
(`tests/openclaw/install_incident/test_proxy_load_bearing.py` + `tests/openclaw/docker-compose.yml`)
and on OpenClaw's own headless entrypoint (`openclaw agent --message --json`).

**What this is NOT:** (a) not a real-key-per-PR test — the key-in-CI prohibition forbids it; (b) not a
GUI/Playwright suite — headless `agent --message` replaces pixel-driving, with GUI automation kept only
as a documented fallback *if* a needed seam proves GUI-only; (c) not a claim that "80% done, just
finish it" — two load-bearing facts (AP7 content-field path, embedded-vs-Gateway shaping parity) are
unverified and gate the content assertion (§5, §7); (d) **not, by default, a guard against the pee0
cached-credential bypass** — that needs an explicit adversarial journey test (§7), and a clean-env
journey test gives *false* confidence that `lock` is load-bearing.

---

## 2. The problem (one paragraph)

A whole class of integration breakage — OpenClaw rejecting the model as "Unknown model" before any
request left the client, 404 because `tools` was sent to a tool-less endpoint, 400 because array
content was sent to a string-only provider, and a dead `baseUrl` because editing `openclaw.json`
alone is silently overridden by the agent-cache copy `agents/main/agent/models.json` (the "merge
gotcha") — was caught **only** when a human hand-drove the OpenClaw GUI chat. Every individual
worthless unit test passed; no automated test crossed all the seams in one run (config rewrite →
agent resolves model → request shaped → hits the proxy gate → upstream → content returns). The
journey itself has no test.

---

## 3. The user journey as a testable sequence

Eight ordered assertion points (AP). A lane "covers" an AP if it fails when that AP breaks. Source:
04 §1, cross-checked against 03's matrix.

| AP | Step | Assertion | Failure rung it catches | Owner |
|----|------|-----------|-------------------------|-------|
| **AP1** | `worthless lock --env` rewrites config | **Both** `openclaw.json` *and* `agents/main/agent/models.json` get the proxy `baseUrl` | dead `baseUrl` / merge gotcha | worthless writer |
| **AP2** | Provider/model registered | provider `required:["baseUrl","models"]`; model `required:["id","name"]` present | schema-invalid → provider not loaded | OC schema, worthless emits |
| **AP3** | Agent resolves model ref | `parseProviderModelRef` (split first `/`, `validation.ts:1165`) maps ref → provider+model in catalog | **"Unknown model"** (`validation.ts:1220`), pre-proxy | OpenClaw |
| **AP4** | Request shaped | `tools` omitted when `compat.supportsTools:false`; array content flattened when `compat.requiresStringContent:true` (`openai-transport-stream.ts:1856`) | 404-no-tools; 400-array-content | OpenClaw |
| **AP5** | Hits proxy gate | proxy runs rules engine **before** reconstruct (SR-03) | gate bypass / cap not enforced | worthless |
| **AP6** | Proxy → upstream | real key reconstructed into auth header; body forwarded verbatim; upstream URL by **registry name** | wrong-host 401 (PR #276 regression) | worthless |
| **AP7** | Content returns | non-empty assistant message round-trips back to the agent surface | "wired but chat returns nothing" — the human-only signal | both |
| **AP8** | Spend metered | per-provider usage parsed; reservation + post-hoc recorded | metering miss (WOR-730/731) | worthless |

**Central split (client-agnostic / provider-aware invariant):**
- **AP1–AP4 are OpenClaw-specific** (config rewrite + request *emission*). worthless does not own
  these; a version bump moves them. They need a **real OpenClaw process** in the loop.
- **AP5, AP6, AP8 are provider-protocol-generic** (client-agnostic). A hand-built request reproduces
  them exactly → **hermetic** coverage is sufficient and authoritative.
- **AP7 is the integration of both** — only fully proven when a real agent drives a real request end
  to end. Its assertion *target* is the open question of §5/§7.

> Diagnostic corollary (04 §1): if AP1–AP4 pass (well-formed request leaves OC) and AP5–AP8 fail,
> the bug is worthless-side; otherwise OC-side. The lanes encode this so a red test tells you *which
> side*.

---

## 4. Coverage matrix (behavior → tier)

From 03's matrix, deduped with 04's APs. **H** = hermetic (pure unit or in-repo mock, no OpenClaw).
**C** = container (real OpenClaw + mock upstream). **L** = live (real provider).

| # | Behavior | Tier | Existing coverage | Action |
|---|----------|------|-------------------|--------|
| 1 | Model-ref parse (`validation.ts:1165`) | **C** | none direct | add C case (AP3) |
| 2 | "Unknown model" rejection (`validation.ts:1220`) | **C** | none — GAP (GUI-only class) | add C case; signal = proxy sees zero requests |
| 3 | `supportsTools`/404-no-tools (`model-tool-support.ts:6`) | **C** (emit) + **H** (passthrough) | passthrough H-covered; emit half GAP | add C toggle case (AP4) |
| 4 | `requiresStringContent`/400-array (`openai-transport-stream.ts:1856`) | **C** (flatten) + **H** (400 relay) | relay H-covered; flatten GAP | add C toggle case (AP4) |
| 5 | Catalog-merge baseUrl gotcha (`schema.base.generated.ts:1529`) | **C** | **covered** — `test_routing_contract.py` (stale-models.json/replace/per-model) | reuse; this is the strongest existing C test |
| 6 | Provider routing → upstream URL | **H** | covered — `test_openclaw_e2e.py` (mock) | keep |
| 7 | Usage metering OpenAI vs Anthropic | **H** | covered, strong — `test_metering.py`, `test_streaming_metering.py` | keep |
| 8 | Upstream error passthrough/sanitize | **H** | covered — `test_proxy.py`, `test_error_metering_and_hardening.py` | keep (WOR-729 is a product gap, not a test gap) |
| 9 | Gate-before-reconstruct (SR-03) | **H** | covered, most-tested invariant | keep |
| 10 | **pee0 cached-credential bypass** (`model-auth.ts:171-173`, `models-config.ts`, `auth-profiles/store.ts`) | **C** | **none — highest-value GAP** | add adversarial C case (§7) — **fixtures must prime the cache, then lock, then assert proxy saw it / fails closed** |

Net new tests are concentrated in **rows 1–4 (failure ladder, C)** and **row 10 (pee0 bypass, C,
adversarial)**. Rows 5–9 are already covered; AP8 reservation precision (WOR-730) is a thin H addition.

---

## 5. Recommended framework — lanes, tradeoffs, and resolving the critic's gaps

### Lane A — HERMETIC contract lane (per-PR, blocking)
Pure pytest, no Docker/OpenClaw/network. Marks: `contract` (+ unmarked unit), runs in default
`uv run pytest`. Covers AP1, AP2 + worthless half of AP3/AP4 (as worthless *models* OC) + AP5, AP6,
AP8. Three groups:
1. **Failure-ladder fixtures** — assert worthless's config *writer*: model id lands in the provider
   catalog (Unknown-model class); the `(provider, model) → supportsTools/requiresStringContent`
   compat matrix; and that the writer touches **both** config files with the same `baseUrl` (the
   single highest-value hermetic test — the dead-baseUrl class no unit test currently isolates).
2. **OC config-schema contract fixtures** in `tests/openclaw/contracts/` — pin OC's
   `provider.required` / `model.required` / `compat` field names / the `const:"merge"` +
   "preserve non-empty agent models.json baseUrl" rule as JSON schemas; validate worthless's emitted
   config against them with `jsonschema`. When OC bumps a constraint, the contract test fails with a
   diff. (Automates the seam-map "re-verify" loop.)
3. **Worthless request-lifecycle** — RESPX-backed: gate-before-reconstruct, verbatim forward,
   registry-name URL resolution (the 401 regression), usage extraction.

Tradeoff: <5 s, ~0 flake, $0, total determinism. **Gap (state it):** tests worthless's *model* of OC,
not OC itself — a logic error inside OC that the fixtures also encode wrongly is invisible here. That
is precisely what Lane B catches.

### Lane B — CONTAINER + MOCK-UPSTREAM lane (per-PR if affordable, else nightly + on `main`)
Real OpenClaw container + real worthless proxy + the in-repo `mock-upstream`. Marks: `openclaw` +
`docker` (excluded by default `-m 'not docker'`). Builds on `tests/openclaw/docker-compose.yml`.
Covers AP1–AP8 end-to-end, deterministic, $0.

**Driver — PROVEN, not an open question.** `openclaw agent --message <text> --json` is a real,
exit-after-one-turn headless entrypoint (`register.agent.ts:25-90`; required `-m/--message` at
`:27`; `--json` at `:50`; `--local` embedded at `agent-via-gateway.ts:229`). The existing
`test_proxy_load_bearing.py:86-89` already drives exactly this via `docker exec`. **No Playwright is
required for the journey.** GUI automation (Playwright / `preview_fill` → dispatch input → click send
→ poll for the message node) is retained **only** as a fallback if a future seam proves reachable
only through the Gateway-backed GUI — and §7 flags that we have not yet proven the embedded path
applies the same `compat.*` shaping as the Gateway path.

**Resolving critic gap #1 (the embedded-fallback false-green).** The embedded fallback
(`agent-via-gateway.ts:239-265`) completes a turn *even when the Gateway is unreachable*. A test that
relies on it can go green while routing through a path that differs from the Gateway-backed GUI — or
worse, resolve a cached/default key and return content while **nothing transited worthless**.
Therefore Lane B's pass condition is **NOT** `returncode==0 + non-empty content`. It is, as a hard
gate inherited from `test_proxy_load_bearing.py` §5:
- **the MOCK captured the request** (request-arrival assertion from the upstream side), AND
- **the captured auth header carries the reconstructed real key** (proves AP6, not shard-A), AND
- the negative twin holds: **proxy down → mock receives nothing AND the turn fails** (load-bearing).

**Resolving critic gap #2 (AP7 assertion target).** Confirmed from source that `--json` emits via
`writeRuntimeJson(runtime, response)` (`agent-via-gateway.ts:195`); content lives under
`response.result.payloads[]` (non-json mode formats the same payloads via `formatPayloadForLog`).
The exact text field *within* a payload is **not yet pinned** — this is a 5-minute
`docker exec ... agent --message --json` capture against the pinned image. **Until that capture
exists and pins the field path, the AP7 content assertion is BLOCKED.** Lane B ships first with the
request-arrival + auth-header gates (which need no content-shape knowledge); the content round-trip
assertion lands the moment the capture is done.

**Non-flaky rules (mandatory):** digest-pin the OC image (`:2026.5.3-1@sha256:…`, not `latest`) so a
silent OC release can't flip CI red and so the seam-map line numbers stay trustworthy; health-gate
every dependency + add an explicit "OC loaded the locked provider" readiness probe (closes the
AP2/AP3 race); dynamic host ports + per-run project name; bounded polling, no sleep-and-hope; one
request per test; **on failure, dump artifacts** — OC + proxy `docker logs`, the mock's captured
bodies/headers, and (because the proxy swallows the upstream error, `app.py:130-155` / WOR-729) a
**logging passthrough** teed *upstream of* worthless's sanitizer so every red says "which AP, which
side, what upstream actually returned."

Tradeoff: 60–180 s; low flake if health-gated + digest-pinned; $0; high determinism. **Gap:** mock ≠
real provider — OpenRouter `:free` throttling/guardrails and real 402 are invisible → Lane C.

### Lane C — LIVE SMOKE (opt-in, gated, scheduled — NEVER per-PR)
Real provider, one free model (`liquid/lfm-2.5-1.2b-instruct:free` via OpenRouter). Marks: `live`
(+ `openclaw`), excluded by default. Asserts *liveness* (non-empty content, property assertions —
never exact text). **Key-in-CI prohibition (hard rule, `feedback_no_keys_in_ci`):** real keys NEVER
enter GitHub Actions or any CI secret store. Runs local-only (key from local keychain) or on a
team-controlled self-hosted runner, gated behind `workflow_dispatch`/`schedule` + a manual-approval
environment. Pre-flight `scripts/verify-live-rig.sh` runs first (greps the F1 signature in both the
worktree and the installed package inside the container — catches "I tested the wrong code").

Tradeoff: medium-high flake (provider availability/throttle/balance) — never block PRs; real $ (free
model + worthless's own spend cap). **Gap:** not reproducible in CI by design; its value is the
periodic "reality still matches our mocks" canary, which also owns the mock-fidelity-drift question
(03 tier L) that otherwise has no owner.

### Effort honesty (resolving critic gap #4)
02's "80% built, just finish it" and 04's "multi-day, multi-phase" are reconciled as: **the rig
exists; the journey assertions do not.** Lane B's request-arrival/auth gates are a small extension of
`test_proxy_load_bearing.py` (days). But the AP7 content assertion is blocked on the field-path
capture, the pee0 adversarial case is net-new security work, and digest-pinning + passthrough-capture
are real. Net: Lane A is days and high-ROI; Lane B is "extend, then unblock AP7"; the full design is
multi-day. **02 overstates readiness** — the content-shape caveat alone blocks "just finish it."

### "Reuse OpenClaw's harness" — what it means (resolving critic ambiguity)
01 says "reuse, don't rebuild"; 02 says "do NOT build inside OpenClaw's vitest." **Reconciled:** reuse
the *pattern* (drive the shipped `openclaw.mjs` binary as a black box via `docker exec`, point its
`baseUrl` at the worthless alias, mock the upstream). Do **NOT** couple worthless CI to OpenClaw's TS
vitest toolchain — that would break on every OC bump for reasons unrelated to the seam. The stable
contract is the CLI surface `agent --message --json`, policed by the seam-map re-verify greps.

---

## 6. Prior-art callouts (steal these)

- **OpenClaw's own three-tier suite** (unit/integration · e2e-with-deterministic-mock-OpenAI · live)
  and its e2e mock-agent-turn (`mock-openai/gpt-5.5*`) — the exact "config → resolve → shape → hit →
  content returns" journey minus worthless. Steal the *pattern* (mock upstream on a real port, drive
  the real binary). [docs.openclaw.ai/help/testing] · [reference/test] · [/ci].
  ⚠ All OpenClaw doc specifics here are WebSearch paraphrases (WebFetch blocked) — treat the
  three-tier names / `mock-openai/*` model names / two-knob gate as **unverified** until spot-checked
  against the clone (critic gap #5).
- **OpenClaw's live-gate model** — `LIVE=1` to unskip + `OPENCLAW_LIVE_MODELS=modern|all` to widen
  the matrix, serial (1 worker), env-keys-first. Ready template for Lane C, aligns with
  `feedback_no_keys_in_ci`. [docs.openclaw.ai/help/testing-live] (paraphrased).
- **LiteLLM** (an OpenAI-compatible proxy, the closest analogue) — `mock_response` in
  `litellm_params`, a self-hostable fake-OpenAI server, and `network_mock` at the httpx transport
  layer; auth tests prove unauth requests are rejected (direct analogue to gate-before-reconstruct).
  [deepwiki.com/BerriAI/liteLLM-proxy/5.2-testing] · [docs.litellm.ai/docs/load_test].
- **Gateway-as-`baseUrl` testability** — Promptfoo treats Cloudflare AI Gateway as just another
  provider behind a `baseUrl`; Helicone swaps the OpenRouter URL for the gateway URL. Same "change the
  base URL, run the real client" principle worthless relies on.
  [promptfoo.dev/docs/providers/cloudflare-gateway] · [docs.helicone.ai/.../openrouter].
- **Real-HTTP fake-LLM servers with SSE chunk control** — `aimock`/`ai-mocks`/`mockllm` exist
  *because* WireMock can't do real SSE. The mock upstream must be able to split a JSON event across
  flushes and concatenate two events (OpenClaw issue #32179: two SSE events without `\n\n` →
  LineDecoder splits wrong). [github.com/CopilotKit/aimock] · [github.com/mokksy/ai-mocks] ·
  [github.com/openclaw/openclaw/issues/32179].

---

## 7. Honest limits — what this framework does NOT catch

1. **pee0 cached-credential bypass needs an explicit adversarial journey test — a clean-env journey
   test makes it WORSE than nothing.** `lock` does **not** neutralize a pre-cached plaintext key:
   confirmed live at HEAD, `model-auth.ts:171-173` returns
   `{apiKey: customKey, source: "models.json"}` when `agents/<id>/agent/models.json` (or
   `auth-profiles.json`) already holds a real key — the agent sends the REAL key straight upstream and
   the proxy sees nothing. A naive clean-env test goes green and gives **false confidence that lock is
   load-bearing when it isn't.** The pee0 test MUST: (a) **prime the cache first** (write a plaintext
   key into `models.json`/`auth-profiles.json`), THEN run `lock`, THEN drive a turn; (b) assert the
   **proxy received the request OR the call fails closed**; (c) negative-assert from the mock that the
   real key never arrived on a direct (non-proxy) path. 04's fixtures do not yet encode this — they
   must. **Open: "fails closed" is not yet a defined worthless requirement** (see §8).
2. **Embedded vs Gateway-backed-GUI shaping parity is unverified.** The WOR-621 bug was found through
   the *Gateway-backed GUI*; the headless driver uses the embedded/`--local` path (or the embedded
   fallback). Nobody has confirmed the embedded request-shaping path applies the same `compat.*`
   flattening as the Gateway path. If they diverge, Lane B tests the wrong path and the GUI-only class
   stays GUI-only. Must be verified before Lane B's AP4 cases are trusted.
3. **AP7's exact content field is unpinned** (§5) — blocked on a real `--json` capture.
4. **Anthropic end-to-end is asserted symmetrically but only OpenAI has a real driver today** — the
   mock emits `/v1/messages` but no Anthropic agent turn is demonstrated. Add one or scope the claim.
5. **Live flakiness + key-in-CI prohibition** mean there is **no real-key per-PR test**; reality
   coverage is a nightly canary only.
6. **`acpx` (an alternative headless driver) is cited from doc summaries but never run** — do not let
   it into the design as load-bearing.
7. **Mock-fidelity drift** (is the mock still shaped like the real provider?) is owned by Lane C's
   nightly run; if Lane C is skipped for long stretches, drift goes undetected.

---

## 8. Phased rollout → WOR-732

WOR-732 (*"OpenClaw signature test suite"*, P2, `tests/openclaw/`): "the
`supportsTools`/`requiresStringContent`/merge-baseUrl knowledge becomes a 3-lane test suite so a
version bump fails a test, not production." Lanes map onto existing pytest marks — **no new marks**:
Lane A = `contract`(+unit, default run); Lane B = `openclaw`+`docker`; Lane C = `live`(+`openclaw`).

**Phase 1 — Lane A (highest value / lowest cost, do FIRST).** Encode the failure ladder + merge-baseUrl
gotcha + compat matrix as fast `contract` tests + OC schema-contract fixtures in
`tests/openclaw/contracts/`. Catches the dead-baseUrl and Unknown-model classes per-PR with zero
Docker. No dependencies. **This is the highest-value first lane** — it would have caught most of the
WOR-621 ladder per-PR.

**Phase 2 — Lane B (the load-bearing "did the real journey complete" test).** Extend
`test_proxy_load_bearing.py`: digest-pin the OC image, add the OC-readiness probe + logging-passthrough
artifact capture, and the four failure-ladder agent cases. Ship the **request-arrival + auth-header
gates first** (need no content-shape knowledge); **land the AP7 content assertion only after** the
`--json` field-path capture (§5/§7-3) and the embedded-vs-Gateway parity check (§7-2). Soft dependency:
WOR-729 (un-swallow upstream error) materially improves debuggability — until then the
logging-passthrough is *required*.

**Phase 2.5 — the pee0 adversarial case (security regression detector).** Net-new C test per §7-1.
Sequence it with Phase 2 (same rig) but track it as its own deliverable because it is a *security*
test, not an integration one, and it depends on a maintainer decision (§9) about "fails closed."

**Phase 3 — Lane C (live smoke canary, opt-in).** Wire `verify-live-rig.sh` + `test-live` against the
free OpenRouter recipe on a self-hosted/local runner; nightly + manual dispatch; key-in-CI prohibition
enforced. Value: the "reality still matches our mocks" canary + mock-fidelity-drift owner.

Also add (Phase 1, hermetic): **WOR-730/731** — assert worthless's reservation reads the field OC
actually sends (`max_completion_tokens` / `max_output_tokens`), so AP8 metering regressions fail
per-PR.

---

## 9. Open questions / decisions needed from the maintainer

1. **Is "fails closed" on a pre-cached key an actual worthless requirement, or just hoped for?** The
   pee0 bypass (§7-1) is real and confirmed at HEAD. Before we write the adversarial test we need the
   intended behavior: should `lock` scrub/neutralize `agents/<id>/agent/models.json` +
   `auth-profiles.json`, or is the documented stance "lock assumes a clean profile"? The test's
   pass/fail condition depends entirely on this answer.
2. **Lane B on every PR, or nightly + on `main`?** Budget call: 60–180 s/job. Per-PR catches
   regressions earliest but costs runner minutes; nightly+main is cheaper but lets a bad merge sit a
   day. Recommendation: per-PR if the runner budget allows, else nightly + required-on-`main`.
3. **Who owns capturing the real `agent --message --json` payload shape** (to pin AP7's content field)
   **and verifying embedded-vs-Gateway `compat.*` parity?** Both are small but block the AP7 assertion
   and the trustworthiness of Lane B's AP4 cases. Assign before Phase 2 content work starts.
