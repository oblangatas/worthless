# OpenClaw provider routing — verified behavior & test matrix

**Subject:** How OpenClaw selects the HTTP endpoint for an LLM provider request, and whether `worthless lock` rewriting `openclaw.json` is sufficient to make the Worthless proxy load-bearing.
**OpenClaw version:** `ghcr.io/openclaw/openclaw:2026.5.3-1` (all results are pinned to this tag — see Version fragility).
**Method:** Live Docker probes (two mock upstreams + hit counters) + extraction and reading of the `dist/*.js` bundle + bundled docs.
**Status:** Routing question RESOLVED — verified for `openai-completions` AND `anthropic-messages`, under both `merge` and `replace` modes, across infer / agent-local / gateway. Only LOW-value cells remain unrun (model-row order, multi-agent); OAuth is out of scope.
**Related:** WOR-621 (Phase 3 design), `phase3-independent-design-review.md` (the Cursor review that triggered this), WOR-514 (incident).

---

## TL;DR

**`openclaw.json` `models.providers.<id>.baseUrl` is authoritative for routing.** In every cell tested, after rewriting that field to the proxy, the request went to the proxy — regardless of what the per-agent `models.json` baseUrl said (empty *or* populated model table), regardless of a divergent per-model `baseUrl`, and consistently across all three request paths (`infer --local`, `agent --local`, `agent` via gateway).

**Therefore the Phase 3 one-file rewrite (just `openclaw.json`) is load-bearing.** The external (Cursor) review's claim that the agent `models.json` baseUrl "wins" is **refuted at runtime** — it conflated *file-merge preservation* (real) with *runtime routing precedence* (does not happen).

The credential placed in `apiKey` (shard-A) reaches the proxy verbatim as the `Authorization: Bearer` value — a real provider key never leaves via that path.

---

## How OpenClaw routes (verified)

1. The runtime builds the request URL from the **provider** `baseUrl` resolved from `openclaw.json`'s `models.providers.<id>` table (`new URL(baseUrl)` in `dist/shared-*.js`; catalog load in `dist/model-catalog-*.js`).
2. The per-agent `agents/<id>/agent/models.json` provider table can carry its own `baseUrl`. OpenClaw's config **merge** (`mergeWithExistingProviderSecrets` / `shouldPreserveExistingBaseUrl` in `dist/models-config-*.js`) **preserves** a non-empty existing agent `baseUrl` when regenerating from `openclaw.json` — and the bundled `docs/concepts/models.md` states *"Non-empty `baseUrl` already present in the agent `models.json` wins."* **However, this is a file-write/merge rule, not a runtime-routing rule.** At request time the runtime routes from `openclaw.json`'s provider table; the preserved agent `models.json` baseUrl is ignored for routing (proven across cells below).
3. A per-model `baseUrl` (`ModelDefinitionSchema.baseUrl`, optional) can be set and is accepted into config, but is **ignored for routing** (provider baseUrl wins).
4. Credential and endpoint are independent code paths: the SecretRef resolver (`dist/resolve-*.js`) produces only a credential string for the auth header and never touches the URL. SecretRef-backed providers honour `baseUrl` exactly like plaintext ones.
5. SecretRef resolution is a **startup snapshot**; provider/credential changes bind only after a daemon reload (the `infer --local` embedded path picked up a `config set` change without an explicit restart, so the reload requirement is path-dependent; the daemon/gateway needs the reload).

---

## Control parameters (the axes that could change routing)

| # | Parameter | Values | Why it could matter |
|---|---|---|---|
| 1 | `openclaw.json` provider `baseUrl` | absent / A (orig) / B (proxy) | candidate authority |
| 2 | agent `models.json` provider `baseUrl` | absent / A / B | merge preserves it; docs claim it "wins" |
| 3 | agent `models.json` `models[]` population | `[]` / populated / populated+order | claim that empty `[]` "doesn't register" |
| 4 | per-model `baseUrl` (`models[].baseUrl`) | absent / A / B | second override location |
| 5 | request path | infer `--local` / agent `--local` / agent gateway | distinct runtime code paths |
| 6 | credential | plaintext `apiKey` / SecretRef `{source,…}` | resolution path + reload timing |
| 7 | merge mode | `merge` (default) / `replace` | `replace` skips the preserve-merge |
| 8 | api type | `openai-completions` / `anthropic` | api-specific handling (beta-header suppression observed) |
| 9 | model row order | `[A,B]` / `[B,A]` | affects default-model *selection*, not endpoint |

**Output measured:** which mock upstream receives the request — **A** (original/stale) or **B** (proxy / `openclaw.json` value).

---

## Test matrix — cells run

| Probe script | p1 oc.json | p2 models.json | p3 models[] | p4 per-model | p5 path | p6 cred | Result |
|---|---|---|---|---|---|---|---|
| `probe-auth-profiles-bypass.sh` | B | absent (fresh) | – | – | infer + agent | plaintext | **B** |
| `probe-routing-precedence.sh` (A) | A | B (hand-written) | `[]` | – | infer | plaintext | **A** (oc.json) |
| `probe-routing-precedence.sh` (B) | →B | – | – | – | infer | **SecretRef** | **B** |
| `probe-routing-precedence.sh` (D) | B | – | – | – | infer | plaintext | shard-A reaches proxy as Bearer |
| `probe-modelsjson-precedence.sh` | B | A (generated) | `[]` | – | **all 3** | plaintext | **B** |
| `probe-populated-modelsjson.sh` | B | A (hand-written) | **populated** `[gpt-4o, gpt-4o-mini]` | absent | **all 3** | plaintext | **B** |
| `probe-per-model-baseurl.sh` | B (provider) | – | populated | **A** | **all 3** | plaintext | **B** |
| `probe-anthropic-and-replace.sh` (P1) | B | – | populated | – | **all 3** | plaintext | **B** — api type = `anthropic-messages` |
| `probe-anthropic-and-replace.sh` (P2) | B | A (hand-written) | populated | – | **all 3** | plaintext | **B** — `models.mode: replace` |

**Invariant observed:** whenever `openclaw.json` provider `baseUrl = B`, the request went to **B** — on every path (infer / agent-local / gateway), with any agent `models.json` value (empty or populated), with a divergent per-model `baseUrl`, for **both** api types (`openai-completions` and `anthropic-messages`), and under **both** config modes (`merge` and `replace`). The only "A" result is the control case where `openclaw.json` itself pointed at A. Notably, `replace` mode still left the hand-written stale agent `models.json` baseUrl in place, yet routing ignored it — same as `merge`.

**Auth-profiles note:** `auth status` reported `oauth.profiles: []` and credentials resolving from `models.json`; no `auth-profiles.json` cached-credential path intercepted routing in the api-key configuration.

---

## Source-level findings (extracted bundle)

- **Routing:** request URL via `new URL(baseUrl)` (`dist/shared-*.js`); provider catalog load in `dist/model-catalog-*.js`.
- **Merge precedence:** `shouldPreserveExistingBaseUrl` + `mergeWithExistingProviderSecrets` (`dist/models-config-*.js`) preserve the existing agent `models.json` baseUrl on regeneration. Default `mode = cfg.models?.mode ?? "merge"`.
- **SecretRef:** `{ source: env|file|exec, provider, id }` resolved once at startup into an in-memory snapshot, flowing only into the auth header (`dist/resolve-*.js`).
- **Per-model baseUrl:** `ModelDefinitionSchema.baseUrl` is `z.string().min(1).optional()`; `id` and `name` are required (config rejects a model row missing `name`).
- **Schema strictness — CONTESTED / unresolved at the `ModelProviderSchema` level.** Three readings disagree: "yes, `.strict()`, 372 hits" (Cursor); "yes, 146 hits" (first source scan); "NOT `.strict()` at the `ModelProviderSchema` definition, though the wider tree has many `.strict()` calls" (verification reader). **This does not block the design:** Worthless recognises its managed entries via its own DB, not via an in-config marker, so whether a `managedBy` sibling field would be schema-rejected is moot. Recorded here only so nobody relitigates it.

---

## Credential flow

`worthless lock` writes shard-A (format-preserving split value) into `apiKey` (`lock.py` ~591-608). Probe D confirmed the value arriving at the proxy is exactly that `apiKey` string as `Authorization: Bearer …`, never a real `sk-` key. (A stale docstring at `integration.py` ~861-866 still describes an abandoned "stable worthless-16x2 token" design — the live code writes shard-A; reconcile per WOR-621 AC14.)

### Probe fidelity caveat (apiKey values are placeholders)

These are **routing** probes, not faithful end-to-end `worthless lock` runs. They set the provider `apiKey` **directly** in OpenClaw's config (`openclaw config set`), deliberately bypassing `worthless scan`/`lock`, and use a low-entropy placeholder like `sk-SEED-aaaa…`. Two consequences:

- **Routing is value-independent** — OpenClaw forwards whatever string is in `apiKey` as the Bearer (Probe D), so a placeholder vs a real shard-A changes nothing about which endpoint is hit. The routing findings stand.
- **`worthless` itself would NOT accept that placeholder.** `scanner.py:274` skips any value whose Shannon entropy is below `ENTROPY_THRESHOLD = 3.9` (`key_patterns.py:43-47`; `sk-aaaa` ≈ 0.88). A real shard-A is a high-entropy XOR share and clears the guard; the `sk-…aaaa` placeholder would be treated as a non-key and skipped by `scan`/`lock`. This only matters on the scan/lock path, which these routing probes do not exercise.

The end-to-end path (real `worthless lock` → high-entropy shard-A → routing → entropy guard) is a **separate, integration-level test** — see WOR-545 and the contract test below.

---

## Open cells (not yet run)

| Missing cell | Priority | Rationale |
|---|---|---|
| ~~api type = `anthropic`~~ | ~~HIGH~~ | ✅ **RUN** (`probe-anthropic-and-replace.sh` P1) — follows `baseUrl` like OpenAI; no api-type bypass. |
| ~~merge mode = `replace`~~ | ~~MED~~ | ✅ **RUN** (`probe-anthropic-and-replace.sh` P2) — `openclaw.json` authoritative under `replace` too. |
| SecretRef **+** populated `models.json` together | LOW | Each axis shown independently; combination unlikely to interact. |
| model row order `[A,B]` vs `[B,A]` | LOW | Affects default-model *selection*, not endpoint; a fixed model id maps to a fixed provider. One confirm-and-dismiss row. |
| multiple agents (each own `models.json`) | LOW | Single `main` agent is the norm; one row. |
| OAuth credential | OUT OF SCOPE | No splittable key — warn-and-skip per design. |

---

## Version fragility & re-verification

All results are pinned to `2026.5.3-1`. OpenClaw can change routing/merge behavior across releases. **Guard:** the load-bearing subset of this matrix is now an executable, tag-pinned parametrized pytest — `tests/openclaw/test_routing_contract.py` (marks: `openclaw`, `docker`). Each case spins the real image + two mock upstreams and asserts the rewritten `openclaw.json` baseUrl wins on the gateway path. **A tag bump that changes routing turns it red — that is the version-drift signal**; re-verify the lock design and update this doc when it fires. The contract test uses a realistic high-entropy apiKey (`secrets.token_hex`), not a low-entropy `sk-…aaaa` placeholder. The original `probe-*.sh` scaffolding has been folded into the contract test and removed.

---

## Implications for Worthless Phase 3 (WOR-621)

1. **The one-file `openclaw.json` provider-baseUrl rewrite is sufficient and load-bearing** for routing. No mandatory agent `models.json` rewrite, no per-model `baseUrl` clearing. Confirmed for **both** `openai-completions` and `anthropic-messages`, and under **both** `merge` and `replace` modes.
2. **Merge-preserve leaves a stale baseUrl (and possibly a stale key) in the agent `models.json` after lock.** This is NOT a routing issue (ignored at runtime) but a cleanliness / secret-at-rest concern. Surface via `doctor` as a follow-up; Phase 1's audit gate already blocks plaintext keys at lock time. **Downgraded from "blocking" to follow-up.**
3. The Cursor review earned its keep by surfacing the merge-preserve mechanism (a real behavior our first probe hid via empty `models[]`), but its headline ("`openclaw.json` rewrite ≠ load-bearing") is **overstated and refuted** by the populated-`models.json` gateway probe.
