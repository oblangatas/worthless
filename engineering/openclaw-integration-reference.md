# OpenClaw Integration Reference

> **What this IS:** a pinned map of the exact OpenClaw source coordinates the worthless
> integration depends on, so a future OpenClaw version bump is debugged by `git diff`,
> not by re-reverse-engineering.
>
> **What this is NOT:** a worthless API spec, nor a list of worthless changes. It documents
> the *seam* between worthless and OpenClaw — behaviors worthless relies on but does not own.

## Pinned versions

| Component | Version | Commit / ref | Source |
|---|---|---|---|
| OpenClaw (source clone) | `2026.5.3-1` | `2eae30e779cb694b776ba1f52bd24c644cbdd919` | `~/Projects/worthless/openclaw` |
| OpenClaw (dev-gui container) | `2026.5.3-1` | image `ghcr.io/openclaw/openclaw:2026.5.3-1` | `worthless-oc-gui` |
| worthless | `0.3.7` | branch `gsd/phase-3-proxy-load-bearing` | this repo |

The clone and the running container are the **same** OpenClaw build, so every `file:line`
below is live-accurate. **When you re-clone a newer OpenClaw, re-verify every line number** —
the "Re-verify" section at the bottom has the grep commands.

---

## Core architecture invariant: worthless is client-agnostic, provider-aware

This is the single most important fact for debugging integration failures.

**Client-agnostic.** `src/worthless/proxy/app.py` has *zero* branching on the calling client
(no user-agent / OpenClaw / Cursor / Windsurf checks). The proxy receives the request body,
gates it, reconstructs the key into the auth header, and forwards the body **verbatim**.
A request from OpenClaw, a curl script, and the Anthropic SDK take the *identical* code path.

> **Corollary:** if a request fails "inside OpenClaw" but a hand-built request to the same
> proxy alias succeeds, the bug is **OpenClaw-side** (request shaping) or **upstream-side**
> (provider constraint) — *never* worthless. Every fix in the WOR-621 free-model debug was
> OpenClaw config; zero worthless changes.

**Provider-aware.** The proxy *does* branch on the upstream provider — OpenAI vs Anthropic —
for exactly three concerns:

| Concern | worthless coordinate |
|---|---|
| Route to upstream URL (registry lookup) | `cli/providers.py::lookup_by_name` / `lookup_by_url` |
| Usage metering (per-provider parse) | `proxy/app.py:471-474` (`provider == "anthropic" ? extract_usage_anthropic : extract_usage_openai`) |
| Native error JSON shape | `proxy/errors.py::_anthropic_error` vs OpenAI form; `proxy/app.py:130-155` error allowlist |

So the "different function signature" between environments is the **provider protocol**
(OpenAI `chat/completions` / `responses` vs Anthropic `/v1/messages`) — **not** the client.

---

## OpenClaw behaviors worthless depends on (the seam map)

| Behavior | OpenClaw coordinate (`2026.5.3-1`) | Why worthless cares |
|---|---|---|
| Model-ref parse (split on **first** `/`) | `src/config/validation.ts:1165` `parseProviderModelRef` | A locked key registered as provider `openai` means model `liquid/lfm-…` is parsed as model under `openai`, not provider `liquid`. |
| "Unknown model" rejection | `src/config/validation.ts:1220-1221` | Any model not in a configured provider's catalog is rejected *before* the request reaches the proxy. |
| Tool-use gate | `src/agents/model-tool-support.ts:6` `return compat?.supportsTools !== false` | OpenClaw (an agent) always sends `tools` unless the model entry sets `compat.supportsTools:false`. Free models with no tool endpoint 404 otherwise. |
| String-content flatten | gate `src/agents/pi-embedded-runner/openai-stream-wrappers.ts:87`; flatten `src/agents/openai-transport-stream.ts:1856` | `compat.requiresStringContent:true` flattens array content (`[{type:text}]`) to plain strings. Strict providers (e.g. Liquid) 400 on array content. |
| Native OpenRouter handling | `src/agents/model-selection-shared.ts:184` (`provider==="openrouter" && model.includes("/") && endsWith(":free")`); `src/agents/model-scan.ts:360-361` | Configure the provider as `openrouter` (not `openai`) so OpenClaw uses OpenRouter semantics. |
| Provider/model config schema | `src/config/schema.base.generated.ts` — provider `required:["baseUrl","models"]`; model item `required:["id","name"]`; `compat` fields ≈ L3150-3180 | Tells us the minimal config to teach OpenClaw a new model + which `compat` flags exist. |
| Catalog merge preserves cache baseUrl | `src/config/schema.base.generated.ts:1520` (`const:"merge"`), `:1529` ("preserve non-empty agent models.json baseUrl values") | **Gotcha:** editing `openclaw.json` `baseUrl` alone is silently overridden by `agents/main/agent/models.json`. Write **both**. |
| Resolve ref → provider/model | `src/agents/model-selection-shared.ts:484` `resolveModelRefFromString` | How the chat-model dropdown value becomes the request `model`. |
| Static-id normalization (manifest-only) | `src/agents/model-ref-shared.ts::normalizeStaticProviderModelId` | Confirms non-OpenAI ids are *not* mangled by default — rules out a normalization red herring. |
| Plaintext key caches (2nd/3rd surfaces) | key resolved from agent cache: `src/agents/model-auth.ts:173` (`source: "models.json"`); cache written: `src/agents/models-config.ts:184` (`agents/<id>/agent/models.json`); profile store: `src/agents/auth-profiles/store.ts` (+ `persisted.js`) → `auth-profiles.json` | The HIGH#3 cached-credential bypass (worthless-pee0) lives here; F1 does not neutralize these. |

### Worthless-side coordinates (the other half of the seam)

| Behavior | worthless coordinate (`0.3.7`, `gsd/phase-3-proxy-load-bearing`) |
|---|---|
| F1 in-place provider rewrite (no `worthless-` decoy) | `openclaw/integration.py:1034`, `:1812` (`provider_name = provider`) |
| Legacy decoy name (dead, tests-only) | `openclaw/integration.py:941` (`f"worthless-{provider}"` in `build_lock_plan`) |
| Upstream URL resolution by **registry name** | `cli/commands/lock.py:162` `_resolve_upstream_base_url`, `:194` `lookup_by_name(registry_name)` |
| Per-provider usage metering | `proxy/app.py:471-474` |
| Spend-cap reservation estimate | `proxy/rules.py:34-49` (`_estimate_tokens`), `:178`, `:307` |
| Upstream error allowlist (swallows message) | `proxy/app.py:130`, `:146` |

---

## Recipe: free / non-OpenAI OpenRouter model through worthless + OpenClaw

Validated end-to-end on the dev-gui rig (real GUI chat returned content through the proxy).

```jsonc
// 1. openclaw.json  AND  agents/main/agent/models.json  (mirror baseUrl — merge gotcha)
"models": { "providers": {
  "openrouter": {
    "api": "openai-completions",
    "apiKey": "<shard-A>",                              // inert; real key reconstructed server-side
    "baseUrl": "http://127.0.0.1:8787/<alias>/v1",      // the worthless proxy alias
    "models": [{
      "id": "liquid/lfm-2.5-1.2b-instruct:free",        // full OpenRouter id
      "name": "lfm (free)",
      "compat": {
        "supportsTools": false,        // free model has no tool endpoint → else 404
        "requiresStringContent": true  // provider rejects array content → else 400
      }
    }]
  }
}},
// 2.
"agents": { "defaults": { "model": { "primary": "openrouter/liquid/lfm-2.5-1.2b-instruct:free" }}}
```

Then: `docker restart` (reload config) → `worthless up` (proxy does not auto-start).
**No `worthless lock` needed between iterations** — the key split is unchanged; only OpenClaw
config changes.

> **Pre-flight (worthless-side):** before trusting *any* live result, run
> `scripts/verify-live-rig.sh`. It greps the F1 signature (`provider_name = provider`) in both
> the worktree source **and** the installed package inside the container, and fails with an exact
> rebuild recipe if they diverge. This catches the "I tested the wrong code" trap — the same one
> that made F1 look un-shipped mid-debug on this PR. The OpenClaw-side re-verify (below) answers
> "did line numbers move?"; this answers "am I even running branch HEAD?".

### Failure ladder (each error = one missing piece)

| Symptom | Missing piece |
|---|---|
| `Unknown model: <provider>/<model>` | Model not in a configured provider's `models` list, or referenced under a provider that isn't configured |
| `404 No endpoints found that support tool use` | `compat.supportsTools:false` |
| `400 provider rejected the request schema` | `compat.requiresStringContent:true` |
| `network connection error` / timeout | `baseUrl` points at a dead endpoint (check the **agent cache** copy too) |
| `402 Insufficient credits` | OpenRouter account balance, not a config issue — paid models need credit; free models need tool-capable + un-throttled + un-guardrailed |

---

## Issues this analysis surfaced

Tracked under epic **WOR-728** (*Worthless stays protocol-correct across every provider and client*), follow-up of WOR-621.

| Issue | Coordinate | Notes |
|---|---|---|
| **WOR-729** (P2, ← bead worthless-nde1) | `proxy/app.py:130-155` | Proxy collapses the upstream's actionable error (e.g. OpenRouter `"Insufficient credits. Add more using …"`) into generic `"upstream provider error"`. This is what made the free-model debug a multi-hour hunt: a billing problem and a schema problem both looked like a worthless failure. Forward upstream status + message. |
| **WOR-730** (P2, ← bead worthless-twla) | `proxy/rules.py:44` | `_estimate_tokens` reads only `max_tokens`. OpenClaw + modern OpenAI send `max_completion_tokens`; Responses API sends `max_output_tokens`. Reservation falls back to 4096 default → under-reserves up to ~2x, weakening the hard-cap TOCTOU guarantee under concurrency. (Post-hoc metering still counts actual usage; this is reservation precision, not a billing miscount.) |
| **WOR-731** (P2) | `proxy/app.py:471-474`, `proxy/usage.py` | Systematic metering audit across OpenAI / Responses / Anthropic + streaming. WOR-730 is one instance of this class. |
| **WOR-732** (P2) | `tests/openclaw/` | The `supportsTools` / `requiresStringContent` / merge-baseUrl knowledge (this doc) becomes a 3-lane test suite so a version bump fails a test, not production. |

---

## Re-verify when OpenClaw bumps versions

Run from the OpenClaw clone after `git pull` to a new tag. Any line drift means the seam moved —
update this doc and re-test the recipe.

```bash
git rev-parse HEAD && git describe --tags
grep -n "supportsTools" src/agents/model-tool-support.ts
grep -n "requiresStringContent" src/agents/pi-embedded-runner/openai-stream-wrappers.ts src/agents/openai-transport-stream.ts
grep -n "Unknown model\|parseProviderModelRef" src/config/validation.ts
grep -n 'endsWith(":free")' src/agents/model-selection-shared.ts
grep -n "preserve non-empty agent models.json baseUrl" src/config/schema.base.generated.ts
```

If a coordinate moved, the fast triage is the WOR-621 capture technique: a logging passthrough
proxy between OpenClaw and the worthless proxy, dumping the exact request body + the upstream
status/body. (The worthless proxy swallows the upstream error — worthless-nde1 — so capture
*upstream* of it, or hit the provider directly with the same body.)
