# Independent Design Review — Worthless Phase 3 (OpenClaw proxy load-bearing)

**Reviewer role:** Security architect + skeptic (independent)
**OpenClaw version verified:** `ghcr.io/openclaw/openclaw:2026.5.3-1`
**Date:** 2026-06-01
**Method:** Re-ran Docker probes in-repo, extracted `/app` from image, read bundled docs + `dist/models-config-CP8molHq.js`, `dist/zod-schema.core-CUAOqerC.js`.

---

## Recommendation: **GO-WITH-CHANGES** (not NO-GO)

**Single biggest hole:** OpenClaw’s default merge makes agent `models.json` **win** over `openclaw.json` for `baseUrl`. Phase 3 rewrites only the latter. That can fully explain “proxy killed, agent still works” after a naive lock.

---

## 1. OpenClaw factual claims (7)

| # | Claim | Verdict | Evidence |
|---|--------|---------|----------|
| **1** | Routing driven by `models.providers.<id>.baseUrl`; infer + agent follow rewrite | **CONFIRMED** (this tag) | Bypass probe: B infer `mockA=0 mockB=1`, C agent `mockA=0 mockB=1`. Runtime: `loadModelCatalog` → `ensureOpenClawModelsJson` → PI registry on `models.json` (`dist/model-catalog-Bz9wKhrC.js` ~181–194). HTTP uses `resolveProviderHttpRequestConfig({ baseUrl })` (`dist/shared-CDxBv_gO.js` ~85–102). Docs: https://docs.openclaw.ai/concepts/model-providers |
| **2** | `openclaw.json` authoritative over `agents/.../models.json` | **REFUTED as stated** | Docs: *“Non-empty `baseUrl` already present in the agent `models.json` wins.”* https://docs.openclaw.ai/concepts/models — § “Models registry”. Source: `shouldPreserveExistingBaseUrl` + `mergeWithExistingProviderSecrets` in `dist/models-config-CP8molHq.js` ~138–171. **Rewriting only `openclaw.json` can leave traffic on the old endpoint** if `~/.openclaw/agents/main/agent/models.json` already has non-empty `baseUrl`. Probe A used `models: []` — may not register as a real provider table. |
| **3** | SecretRef providers honor `baseUrl`; cred resolution separate | **CONFIRMED** (with reload) | Probe B after restart: `mockB=1`. Docs: https://docs.openclaw.ai/gateway/secrets — eager activation, not per-request. |
| **4** | No `auth-profiles.json` cache bypassing `baseUrl` for this setup | **CONFIRMED** (api-key path tested) | Bypass probe: `oauth.profiles: []`. **Unverified** for OAuth-mode profiles. |
| **5** | Provider schema `.strict()`; no `managedBy` sibling | **CONFIRMED** | `ModelProviderSchema = z.object({...}).strict()` — `dist/zod-schema.core-CUAOqerC.js` ~207–227. 372 `.strict()` hits in `dist/*.js` (reviewer count; ticket cited 146). |
| **6** | SecretRef = startup snapshot; reload needed; old cred live until bind | **PARTIALLY CONFIRMED** | Docs: snapshot at activation, atomic reload. Bypass Probe B: `config set` baseUrl → infer hit mockB **without** restart — reload requirement is path-dependent. TOCTOU real for daemon/gateway. |
| **7** | `apiKey` value → Bearer at proxy (shard-A, not `sk-`) | **CONFIRMED** | Probe D: `Bearer WORTHLESS-SHARDA-...`. Matches `lock.py` writing shard-A; `integration.py` stable-token docstring is stale. |

**Version fragility:** All claims pinned to **2026.5.3-1**. Pin min/max OpenClaw in Worthless; re-probe on upgrades.

---

## 2. Challenge to evidence method

**Sound:** Two mocks + hit counters test which host receives HTTP. Good for claims 1, 4, 7.

**Gaps:**

1. **`models.json` merge precedence (load-bearing)** — Documented and implemented: agent `models.json` **wins** over `openclaw.json` for `baseUrl` in default `merge` mode. Phase 3 as written does not require updating agent `models.json`.
2. **Per-model `baseUrl`** — `ModelDefinitionSchema` allows optional `baseUrl` per model (`zod-schema.core` ~178).
3. **OAuth / Codex / plugin catalog paths** — Not exercised.
4. **`agents.defaults.models["provider/model"].params`** — Not ruled out.
5. **`proxy.enabled`** — Separate egress forward proxy: https://docs.openclaw.ai/security/network-proxy
6. **Probe B auth header** — Showed `Bearer sk-OPENCLAWJSON-...` after SecretRef rewrite (possible stale state / probe ordering).

---

## 3. Security invariants

| Invariant | Holds? | Notes |
|-----------|--------|-------|
| **(1) Client-side split** | **Stretched, not broken** | Shard-A in `openclaw.json` on same host as agent. Bearer to loopback OK for recon service; bad for SR-04 / `sk-` scanners. |
| **(2) Gate before reconstruct** | **Only if proxy is actually used** | Stale `models.json` → gate never runs. |
| **(3) Reconstructed key never returns to client** | **Yes** (Worthless design) | Probe D: non-`sk-` Bearer at mock. |

- **(a)** Loopback Bearer + shard-A: OK for threat model; terrible for SR-04.
- **(b)** Rollback record design (no plaintext): correct; implementation leakage is the risk (AC9).
- **(c)** TOCTOU: real. Post-reload probe necessary but **not sufficient** without fixing `models.json`.

---

## 4. Bypass enumeration (post-lock)

| Vector | Closeable? | Verdict |
|--------|------------|---------|
| Original provider still in `openclaw.json` | Yes | Phase 3 target |
| **Stale `agents/.../models.json` `baseUrl`** | **Yes — must fix** | **Not explicit in ticket How** |
| User edits config back / new provider | Partially | Honest scope |
| Env / shell / keychain / new provider | Inherent (same UID) | Document |
| OAuth provider | Inherent | Warn-and-skip |
| `worthless-<id>` + old `model.primary` | Yes | Migration AC12 |
| Per-model `baseUrl` in `models[]` | Maybe | Needs test |
| `proxy.enabled` misconfig | Operational | Document |
| Kill proxy only | Desired failure | Only if routing fixed |

**Scope honesty:** “Lock gates config, not compromised host” is mostly honest; **“only rewrite `openclaw.json`” is not** until `models.json` is handled.

---

## 5. Redundancy vs OpenClaw

- **Spend cap before reconstruct** — genuinely additive; OpenClaw has no equivalent.
- **XOR split on one host** — weak vs RCE/same-UID; meaningful vs config exfil.
- OpenClaw **network proxy** is orthogonal (egress filtering, not cap-on-reconstruct).

**Honest headline:** Hard spend cap on the only path that can reconstruct the provider key — not “replace OpenClaw secret storage.”

---

## 6. Prior art / novelty

- Virtual keys + budgets: ~70% packaging — fair.
- **Gate-before-reconstruction** is narrow; deny-before-upstream is common; novelty is split + zero reconstruct.
- **Defensible** if load-bearing routing + cap + legible failure ship; **not** on split alone.

---

## 7. Design soundness

**Right:** rewrite original provider, DB source of truth, no plaintext rollback, unlock offline.

**Incomplete:**

1. **Must include `models.json` in lock transaction** — patch, delete-and-regen, or temporary `models.mode: "replace"`.
2. **Bind-confirmation** — pair with `models.json` fingerprint in doctor.
3. **PR-1** only greens WOR-545 if it includes `models.json` + DB + rewrite original; PR-2 = reload/TOCTOU.

**Biggest architectural risk:** Believing `openclaw.json` rewrite equals load-bearing while merge preserves upstream URL in `models.json`.

---

## 8. Meta — trust calibration

Independently reproduced claims **1, 4, 5, 7** and **refuted claim 2 as stated** from OpenClaw docs + merge source. Highest-risk assertion in the writeup is precedence; Probe A is not valid for precedence until `models.json` has real model rows post-merge.

---

## Blocking changes before “done”

1. Extend lock/unlock/migration to agent `models.json`; test pre-seed `api.openai.com` → assert proxy after lock.
2. Correct internal docs on claim 2 (merge precedence).
3. AC9 (SR-04) — blocking.
4. AC10 — gateway/daemon; document `infer --local` without restart.
5. Pin OpenClaw version + CI probes for supported image tag.

---

## Reproduction commands (worthless repo)

```bash
# The original probe-*.sh scripts were folded into a tag-pinned contract test:
uv run pytest tests/openclaw/test_routing_contract.py -o addopts="" -p no:randomly
# Extract bundle (for source inspection):
docker create ghcr.io/openclaw/openclaw:2026.5.3-1
docker cp <cid>:/app /tmp/openclaw-2026.5.3-1
```

---

## Key source locations (extracted image)

- `dist/models-config-CP8molHq.js` — `shouldPreserveExistingBaseUrl`, `mergeWithExistingProviderSecrets`, `ensureOpenClawModelsJson`
- `dist/zod-schema.core-CUAOqerC.js` — `ModelProviderSchema.strict()`
- `dist/model-catalog-Bz9wKhrC.js` — catalog load path
- `docs/concepts/models.md` — merge precedence (bundled copy under `/tmp/openclaw-2026.5.3-1/docs/`)
