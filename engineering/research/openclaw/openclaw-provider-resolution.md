# OpenClaw provider apiKey + baseUrl resolution (source map)

> Read-only investigation of the OpenClaw TS source cloned at
> `/Users/shachar/Projects/worthless/openclaw`, tag `v2026.5.3-1`
> (HEAD `2eae30e779`, `package.json` version `2026.5.3-1`) — the exact tree the
> Worthless container tests against. All citations are `file:line` into that clone.
>
> Backs Worthless's integration claim: **"`worthless lock` rewrites the entry
> OpenClaw actually reads, so traffic routes through the proxy."**

The literal-`apiKey` paths that matter to Worthless are short-circuits in
`resolveUsableCustomProviderApiKey`. The HTTP layer (URL assembly,
`Authorization` header) lives in the vendored `@mariozechner/pi-ai` /
`@mariozechner/pi-coding-agent` SDK (`package.json:1678-1680`, version `0.71.1`).
That SDK is **not vendored in this clone** (no `node_modules`), so the final
`fetch` call is cited via the OpenClaw boundary that hands the SDK a `Model`
object carrying `baseUrl` + `apiKey`, plus OpenClaw's own docs that pin the
`openai-completions` URL shape. Flagged below where a claim rests on SDK behavior.

---

## 1. The resolution path (agent turn → apiKey + baseUrl)

The `model-auth-*.js` bundle the memory references is the build artifact of
**`src/agents/model-auth.ts`** (source of `resolveUsableCustomProviderApiKey`).

Runtime trace for an agent turn:

1. **Bind site.** The embedded agent runner's auth controller resolves the key
   per candidate profile:
   `src/agents/pi-embedded-runner/run/auth-controller.ts:349-359`
   (`resolveApiKeyForCandidate` → `getApiKeyForModel`), result stored via
   `applyApiKeyInfo` at `:361-385` (`setApiKeyInfo`, then
   `authStorage.setRuntimeApiKey(...)` at `:430`/`:445`).
2. **Model → provider.** `getApiKeyForModel` forwards `model.provider` to
   `resolveApiKeyForProvider`: `src/agents/model-auth.ts:874-896`.
3. **Provider lookup.** `resolveProviderConfig` reads
   `cfg.models.providers[provider]` (with normalized-id fallback):
   `src/agents/model-auth.ts:66-86`.
4. **apiKey resolution.** `resolveUsableCustomProviderApiKey`
   (`src/agents/model-auth.ts:129-203`) returns the key. For a **literal**
   `apiKey` string it short-circuits at `:168-174`:
   `getCustomProviderApiKey` (`:88-106`) returns the literal, and the function
   returns `{ apiKey: customKey, source: "models.json" }` (`:172-173`).
   `resolveApiKeyForProvider` surfaces this at `:610-618` / `:690-694`.
5. **baseUrl.** Carried on the `Model` object, assembled from the same provider
   entry: `src/agents/pi-embedded-runner/model.inline-provider.ts:140-174`
   (`baseUrl: entry?.baseUrl`, `:141`; `api: entry?.api`, `:140`). The runtime
   model's `baseUrl`/headers are applied in
   `auth-controller.ts:84-110` (`applyPreparedRuntimeRequestOverrides`).
6. **HTTP client.** The completed `Model` (provider + `baseUrl` + `apiKey` +
   headers) is handed to the pi-ai SDK's `ModelRegistry` / `AuthStorage`
   (`src/agents/pi-embedded-runner/model.ts:1-7,109-117`). The actual `fetch`
   is inside that SDK *(not in this clone)*.

**Function to cite:** `resolveUsableCustomProviderApiKey`,
`src/agents/model-auth.ts:129`.

---

## 2. Which config location does runtime read? — `models.providers.<name>`

**Decisive: `cfg.models.providers.<name>`.** Every resolver routes through
`resolveProviderConfig`, which reads **only** `cfg.models.providers`:

```
const providers = cfg?.models?.providers ?? {};
const direct = providers[provider] ...
```
`src/agents/model-auth.ts:70-71`.

`getCustomProviderApiKey` (`:92-93`) and `resolveUsableCustomProviderApiKey`
(`:134-135`) both call it. The inline-provider model assembly reads the same
map (`model.inline-provider.ts:127-150`: `Object.entries(providers)` →
`entry?.baseUrl`, `entry?.api`, model list).

On disk this map is **`<agentDir>/models.json`**:
`src/agents/pi-model-discovery.ts:240` (`discoverModels` →
`path.join(agentDir, "models.json")`). The literal-key `source` label is
quite literally `"models.json"` (`model-auth.ts:173`).

`plugins.entries.<name>` is **not** read by this resolver — plugin entries feed
provider *catalog registration*, but the runtime apiKey/baseUrl come from
`models.providers`. No P0 surprise: **Worthless writes the exact location
OpenClaw reads.**

---

## 3. baseUrl → upstream URL

`baseUrl` is normalized (trailing slashes stripped) and otherwise passed through
verbatim onto the `Model`:
- `normalizeBaseUrl`: `src/agents/provider-request-config.ts:387-401`
  (`return raw.replace(/\/+$/, "")` — strips trailing `/`, no path rewriting).
- For `api: "openai-completions"`, the SDK appends `/chat/completions` to the
  configured base. OpenClaw's own docs pin this shape *(SDK-side concat, cited
  via docs)*:
  - `docs/providers/inferrs.md:59-62` — a custom local provider:
    `baseUrl: "http://127.0.0.1:8080/v1"`, `apiKey: "inferrs-local"`,
    `api: "openai-completions"`. **This is the exact Worthless shape.**
  - `docs/providers/claude-max-api-proxy.md:36` — OpenAI-format requests hit
    `http://localhost:3456/v1/chat/completions` (base `…/v1` + `/chat/completions`).

**Therefore:** a provider with
`baseUrl: "http://127.0.0.1:8787/<alias>/v1"` + `api: "openai-completions"`
causes OpenClaw to POST to
`http://127.0.0.1:8787/<alias>/v1/chat/completions` — i.e. the Worthless proxy.
**Confirmed** for the OpenClaw config contract; final string concat is in the
pi-ai SDK (not in this clone).

---

## 4. apiKey → `Authorization: Bearer <apiKey>`

For the standard OpenAI path, the resolved `apiKey` becomes the bearer token.
The literal value flows: `resolveUsableCustomProviderApiKey` →
`ResolvedProviderAuth.apiKey` (`model-auth-runtime-shared.ts:9,28-29`,
`requireApiKey` normalizes it) → `setRuntimeApiKey` (`auth-controller.ts:430`)
→ SDK request build. OpenClaw confirms the `Bearer` shape:
- Plugin-provider reference: `docs/plugins/sdk-provider-plugins.md:555` —
  `headers: { Authorization: \`Bearer ${apiKey}\` }`.
- OpenClaw can also force it explicitly: `applyAuthHeaderOverride` injects
  `headers.Authorization = \`Bearer ${auth.apiKey}\`` when
  `providerConfig.authHeader === true`:
  `src/agents/model-auth.ts:930-957` (esp. `:957`).

Exception worth knowing: a few providers use `api-key` instead of `Authorization`
(`docs/providers/openai.md:655`), but that is Azure-style, not the
`openai-completions` default. **Confirmed: Worthless's shard-A travels as the
upstream `Authorization: Bearer` token** on the openai-completions path; the SDK
emits the header (default), and OpenClaw can force it via `authHeader: true`.

---

## 5. SecretRef / secrets indirection — literal `sk-…` BYPASSES it

OpenClaw has a SecretRef system, but **a literal string is used as-is and never
enters it.** In `resolveUsableCustomProviderApiKey`:

```
const apiKeyRef = coerceSecretRef(customProviderConfig?.apiKey);
if (apiKeyRef) { ... env/file/exec indirection ... }   // model-auth.ts:135-166
const customKey = getCustomProviderApiKey(...);          // :168
if (!isNonSecretApiKeyMarker(customKey))
  return { apiKey: customKey, source: "models.json" };   // :172-173  ← literal path
```

`coerceSecretRef` returns a ref **only** for: a `{source,provider,id}` object,
a legacy provider-less ref object, or an `${ENV_VAR}` template string —
`src/config/types.secrets.ts:79-100`. A bare `sk-…` / shard-A string matches
none of these → returns `null` → the `if (apiKeyRef)` indirection block is
skipped → the literal is returned directly (`:172-173`).
`getCustomProviderApiKey` only normalizes whitespace/Latin-1
(`normalizeOptionalSecretInput`, `src/utils/normalize-secret-input.ts:16-34`) —
no lookup, no resolution.

**Confirmed: a literal shard-A string bypasses SecretRef entirely and is used
verbatim.** This is exactly what Worthless writes — safe.

---

## 6. Caching / mid-session config changes (backs WOR-756 daemon-reload)

**Yes — the resolved key is cached in memory for the life of the agent run.**

- The resolved key is pushed into the SDK's `AuthStorage` via
  `authStorage.setRuntimeApiKey(provider, apiKey)`
  (`auth-controller.ts:430`/`:445`) and mirrored into local `RuntimeAuthState`
  (`:431-434`, fields `generation` / `sourceApiKey`).
- `AuthStorage` is created **once** at runner setup
  (`src/agents/pi-embedded-runner/model.ts:109-117`;
  `discoverAuthStorage`, `src/agents/pi-model-discovery.ts:221-232`) — it holds
  in-memory credentials for the process/run.
- The `cfg` object (`cfg.models.providers`) is the in-memory config snapshot
  passed to `resolveApiKeyForProvider`; resolution re-reads `cfg`, not the file,
  each call. So a `models.json` **edit on disk is NOT picked up** until the
  config snapshot is reloaded.

**Invalidation that exists:** only credential *refresh* for expiring tokens
(`refreshRuntimeAuth`, `auth-controller.ts:160-235`, gated on
`expiresAt` / `RuntimeAuthState.generation`) and profile *failover*
(`advanceAuthProfile`, `:451+`). There is **no file-watch / no invalidation on a
plain `apiKey`/`baseUrl` edit** in `models.providers`.

**Implication for Worthless:** rewriting `models.json` while an OpenClaw
agent/daemon is already running will **not** take effect until OpenClaw reloads
its config snapshot (restart or its own reload path). This is the gap WOR-756
(daemon-reload) addresses.

---

## VERDICT

**Does Worthless write to the location OpenClaw reads at runtime?**

### YES — with one operational caveat (not a correctness defect).

- **Location:** OpenClaw's runtime apiKey/baseUrl resolver reads **only**
  `cfg.models.providers.<name>` (on disk `<agentDir>/models.json`) —
  `src/agents/model-auth.ts:70-71`, sourced from
  `src/agents/pi-model-discovery.ts:240`. Worthless writes exactly here.
- **Literal key:** a literal shard-A string short-circuits to
  `{ apiKey, source: "models.json" }` and **bypasses SecretRef** —
  `src/agents/model-auth.ts:172-173` + `src/config/types.secrets.ts:79-100`.
- **baseUrl → proxy:** `baseUrl` is passed through (trailing-slash trim only,
  `provider-request-config.ts:387-401`); `openai-completions` appends
  `/chat/completions` (`docs/providers/inferrs.md:59-62` — the exact Worthless
  config shape).
- **apiKey → Authorization:** shard-A becomes `Authorization: Bearer <apiKey>`
  on the openai-completions path (`docs/plugins/sdk-provider-plugins.md:555`;
  forceable via `applyAuthHeaderOverride`, `src/agents/model-auth.ts:957`).

**Caveats / flags:**
- ⚠️ **Not a P0, but operational:** resolved auth is cached in-memory per run
  (`auth-controller.ts:430`, `model.ts:109-117`). A mid-session `models.json`
  rewrite is **not** auto-reloaded — backs **WOR-756 (daemon-reload)**.
- ℹ️ **SDK boundary:** the final URL concatenation and header emission live in
  the un-vendored `@mariozechner/pi-ai` `0.71.1` SDK
  (`package.json:1679`). Those two steps are cited via the OpenClaw config
  contract + OpenClaw's own docs, not the SDK source. If absolute proof of the
  byte-level request is required, extract `@mariozechner/pi-ai@0.71.1` and cite
  its `openai-completions` request builder.
