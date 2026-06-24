# OpenClaw Config Schema + Validation + Lifecycle State Machine

**Scope:** OpenClaw `v2026.5.3-1` (clone at `/Users/shachar/Projects/worthless/openclaw`, HEAD `2eae30e779`). This is the exact source for the container image Worthless tests against. All citations are `file:line` against that clone. Goal: determine whether a custom marker field (e.g. `x-worthless-managed`) on a provider entry can survive OpenClaw's config lifecycle.

Schema files live under `src/config/`. The root schema is `OpenClawSchema` in `src/config/zod-schema.ts:293`, closed with `.strict()` at `src/config/zod-schema.ts:1092`. It is **zod**, strict-by-default throughout.

---

## 1. Where the config schema is defined

### `models.providers.<name>` (the baseUrl + apiKey provider)

`ModelProviderSchema` — `src/config/zod-schema.core.ts:352-371`:

```ts
const ModelProviderSchema = z
  .object({
    baseUrl: z.string().min(1),                                    // :354
    apiKey: SecretInputSchema.optional().register(sensitive),      // :355
    auth: z.union([...]).optional(),                               // :356
    api: ModelApiSchema.optional(),                                // :359
    contextWindow / contextTokens / maxTokens / timeoutSeconds...  // :360-363
    injectNumCtxForOpenAICompat: z.boolean().optional(),           // :364
    params: z.record(z.string(), z.unknown()).optional(),          // :365  (nested arbitrary record)
    headers: z.record(z.string(), SecretInputSchema...).optional(),// :366
    authHeader: z.boolean().optional(),                            // :367
    request: ConfiguredModelProviderRequestSchema,                 // :368
    models: z.array(ModelDefinitionSchema),                        // :369
  })
  .strict();                                                       // :371  <-- REJECTS unknown keys
```

Mounted into the tree via `ModelsConfigSchema` — `src/config/zod-schema.core.ts:380-387`:

```ts
export const ModelsConfigSchema = z
  .object({
    mode: z.union([z.literal("merge"), z.literal("replace")]).optional(), // :382
    providers: z.record(z.string(), ModelProviderSchema).optional(),      // :383
    pricing: ModelPricingConfigSchema,                                    // :384
  })
  .strict().optional();                                                   // :386
```

Wired to root at `src/config/zod-schema.ts:597` (`models: ModelsConfigSchema`).

**Verdict for models.providers: `.strict()` — a top-level `x-worthless-managed` key on a provider entry is rejected.**

### `plugins.entries.<name>`

`PluginEntrySchema` — `src/config/zod-schema.ts:186-207`:

```ts
const PluginEntrySchema = z
  .object({
    enabled: z.boolean().optional(),                          // :188
    hooks: z.object({...}).strict().optional(),               // :189-197
    subagent: z.object({...}).strict().optional(),            // :198-204
    config: z.record(z.string(), z.unknown()).optional(),     // :205  <-- arbitrary nested record (escape hatch)
  })
  .strict();                                                  // :207  <-- REJECTS unknown top-level keys
```

Mounted at `src/config/zod-schema.ts:1057-1077` (`plugins.entries: z.record(z.string(), PluginEntrySchema)` at :1075, parent object `.strict()` at :1077).

**Verdict for plugins.entries: `.strict()` at the entry level, BUT a `config` sub-object accepts arbitrary keys** (`z.record(string, unknown)`, :205). A marker placed *inside* `entries.<name>.config.*` survives; a marker placed as a sibling of `enabled` does not.

### Note: the ONE passthrough provider type

`TalkProviderEntrySchema` (`src/config/zod-schema.ts:209-213`) uses `.catchall(z.unknown())` — the only provider-shaped schema that accepts arbitrary keys. This is `talk.providers.<name>` (TTS), **not** `models.providers`. `ChannelsSchema` is `.passthrough()` (`zod-schema.providers.ts:58`) and `HookConfigSchema` is `.passthrough()` (`zod-schema.hooks.ts:87`) — neither is the LLM provider entry.

---

## 2. The exact rejection path

1. `OpenClawSchema.safeParse(normalizedRaw)` — `src/config/validation.ts:633`.
2. On failure, every zod issue is mapped to a `ConfigValidationIssue` — `validation.ts:634-639`. A strict violation surfaces as zod code `unrecognized_keys` with message `Unrecognized key: "<key>"` (handling at `validation.ts:369`, `:468`; message asserted in tests e.g. `io.write-config.test.ts:345`, `validation.allowed-values.test.ts:96`).
3. `validateConfigObjectRaw` returns `{ ok: false, issues }` — `validation.ts:636`. The **whole config** is marked invalid; zod does not return partial data on a strict failure, so there is no "just drop the offending entry" path.
4. **Load path fails closed.** In `loadConfig` (`io.ts:1493`), an invalid result calls `throwInvalidConfig(...)` — `io.ts:1588` → throws an `Error` with `code = "INVALID_CONFIG"` (`io.invalid-config.ts:34-55`). The outer catch rethrows it explicitly: *"Fail closed so invalid configs cannot silently fall back to permissive defaults."* — `io.ts:1630-1632`.

### "Config invalid; doctor will run with best-effort config"

Exact string: `src/commands/doctor-config-preflight.ts:127`.

**What "best-effort config" is:** the doctor / CLI snapshot path does **not** throw. On an invalid snapshot, `readConfigFileSnapshotInternal` returns a snapshot whose `sourceConfig`/`config`/`runtimeConfig` are `coerceConfig(effectiveConfigRaw)` — `io.ts:1796-1798`. `readBestEffortConfig` returns that same raw object: `if (!result.snapshot.valid) return result.snapshot.config;` — `io.ts:1930-1934`. `coerceConfig` is a **pure cast with zero stripping** (`io.ts:299-304`): it only checks the value is a non-array object, then `return value as OpenClawConfig`.

So best-effort config = **the raw JSON5 after `$include` + `${ENV}` resolution, BEFORE schema validation, with the unknown key still present.** It does NOT drop the bad key and does NOT drop the provider. It bypasses the schema entirely for read-only diagnostics.

Caveat: best-effort is a *read-only* fallback for doctor/preflight display. It is never persisted, and `writeConfigFile` re-validates against the strict schema (§3), so the unknown key can never be written back through the normal path.

---

## 3. The config lifecycle state machine

| Transition | Validates? | On invalid | Citation |
|---|---|---|---|
| **Daemon / gateway start** | YES — preflight runs for both loaded and not-loaded start paths | **ABORTS**: `"… aborted: config is invalid … run 'openclaw doctor' to repair."` | `src/cli/daemon-cli/lifecycle-core.ts:248-260` (also :485) |
| **`loadConfig()` (any runtime read)** | YES — `validateConfigObjectWithPlugins` | **THROWS `INVALID_CONFIG`**, fails closed | `io.ts:1566-1594`, rethrow `io.ts:1630-1632` |
| **`config set` (CLI) — load step** | YES — requires a *valid* snapshot before mutating | prints `Config invalid…`, runs doctor hint, `exit(1)` | `src/cli/config-cli.ts:523-534` (`loadValidConfig`) |
| **`config set` / any mutate — write step** | YES — `validateConfigObjectRawWithPlugins(persistCandidate)` | **THROWS** `formatConfigValidationFailure(...)`; write aborted | `io.ts:2025-2034` |
| **`mutate()` apply** | YES — `validateConfigObjectWithPlugins(nextConfig)` before write | rejects | `src/config/mutate.ts:161`, write at `mutate.ts:255` |
| **Snapshot read (doctor/CLI display)** | YES, but **non-fatal** → best-effort | returns raw `coerceConfig(...)` snapshot, key preserved | `io.ts:1786-1804` |
| **`readBestEffortConfig()`** | inherits snapshot validity | invalid → returns raw `snapshot.config` (key preserved, unstripped) | `io.ts:1930-1940` |
| **`readSourceConfigBestEffort()`** | none (try/catch, returns `{}` on any failure) | returns `{}` or `coerceConfig(parsed)` | `io.ts:1942-1968` |
| **Agent turn / model resolution** | reads validated runtime config; merges `models.providers` into the catalog by `mode` (merge/replace) | n/a (already validated at load) | `src/plugins/provider-catalog.ts:38-39`; `plugin-auto-enable.shared.ts:493` |

### Does anything REWRITE / re-serialize and strip unknown keys?

`writeConfigFile` (`io.ts:1970`) re-serializes config on every write. Critically it writes `persistCandidate` (the merge-patched raw), **not** the zod-validated output — comment `io.ts:2049-2052` explains this is deliberate (to avoid persisting injected schema defaults). But before writing, it calls `validateConfigObjectRawWithPlugins(persistCandidate)` at `io.ts:2025`, which runs the same strict `OpenClawSchema.safeParse`. **If `persistCandidate` carries an unknown provider key, the strict parse fails and the write THROWS (`io.ts:2029-2033`) — the file is never written.** So a write does not silently strip the key; it refuses outright.

Net: there is no lifecycle state in which an unknown top-level provider key is both (a) accepted and (b) persisted. Read paths either reject (loadConfig) or pass it through raw without persisting (best-effort). Write paths reject.

---

## 4. `models.providers` vs `plugins.entries`

For a provider with `baseUrl` + `apiKey`, the canonical location in v2026.5.3-1 is **`models.providers.<name>`** (`ModelProviderSchema`, `zod-schema.core.ts:352`). Evidence it is live, not legacy:

- `onboard` itself writes custom providers there: `src/commands/onboard-custom-config.ts:450` (`const providers = params.config.models?.providers ?? {}`), :539, :552.
- Doctor inspects it by name: `src/commands/doctor-auth.ts:79` (`models.providers.${CODEX_PROVIDER_ID}`).
- Runtime model resolution reads it: `src/plugins/provider-catalog.ts:38-39`, `src/config/plugin-auto-enable.shared.ts:493`.
- Secret registry targets it: `src/secrets/target-registry-data.ts:236-240` (`models.providers.*.apiKey`).
- **No `@deprecated` / migration marker** exists on `ModelProviderSchema` or `ModelsConfigSchema` (grep of `zod-schema.core.ts:300-390` for `deprecated|legacy|migrat` returned nothing).

`plugins.entries.<name>` (`PluginEntrySchema`, `zod-schema.ts:186`) is a **different concern**: it enables/configures *plugins* (`enabled`, `hooks`, `subagent`, freeform `config`). It is NOT where a baseUrl+apiKey LLM endpoint lives. The onboard-writes-`plugins.entries` observation refers to plugin/skill enablement (`src/commands/onboard-hooks.ts:58`, `onboard-skills.ts:39-40`), not provider definitions.

**Reconciliation:** the two are not competing locations for the same thing. `models.providers.<name>` = custom LLM endpoint (what Worthless writes, and what routes); `plugins.entries.<name>` = plugin instance config. Worthless writing to `models.providers.<name>` and seeing it route is exactly the supported, canonical path. `mode: "merge"` (default) overlays Worthless's custom provider onto the built-in catalog (`schema.help.ts:848`; `provider-catalog.ts:38`).

---

## 5. Extension point for custom metadata on a provider entry

There is **no sanctioned freeform metadata field on `models.providers.<name>`**. The full field set is the strict object at `zod-schema.core.ts:352-371`. Specifically:

- No `metadata`, no `tags`, no `x-*` allowance, no comments field. (grep of `zod-schema.core.ts` for `metadata|tags|x-worthless|annotations` returns only `metadataSource: z.literal("models-add")` at `:348`, which is a fixed enum on *model* entries, not provider entries, and only accepts the single literal value.)
- `params` (`:365`, `z.record(string, unknown)`) and `headers` (`:366`) accept arbitrary nested keys, but these are **semantically wrong** carriers: `params` is forwarded as request parameters to the upstream model API and `headers` as HTTP headers. They are also nested records, not a provider-level marker slot. Stuffing a marker there would leak it into upstream API calls.
- A top-level sibling key (e.g. `x-worthless-managed: true` next to `baseUrl`) is rejected by `.strict()` (`:371`).

The only schema-blessed freeform slot anywhere near a "provider-ish" entry is `plugins.entries.<name>.config` (`zod-schema.ts:205`) and `skills.entries.<name>.config` (`zod-schema.ts:182`) — both `z.record(string, unknown)`. Those belong to *plugins/skills*, not to `models.providers`.

---

## 6. Version-drift caveat

Stability of this conclusion across OpenClaw versions:

- Recent commits to `src/config/zod-schema.core.ts` are churn-heavy but cosmetic to this question: `caa697e4cb refactor: trim core config schema exports`, `ad3e4dbcce refactor: trim unused exports`, `69b66dd548 fix(config): coerce visible replies booleans` (`git log --oneline -- src/config/zod-schema.core.ts`). The `.strict()` discipline is long-standing and pervasive (hundreds of `.strict()` calls across `zod-schema.*.ts`).
- The fail-closed load behavior is explicitly defended by comment (`io.ts:1631`) and a referenced issue (`#35862` preflight, `lifecycle-core.ts:248`), suggesting it is an intentional, hardened invariant rather than incidental — unlikely to loosen.
- `HookConfigSchema` carries a comment (`zod-schema.hooks.ts:84-86`) explaining *why* it is `.passthrough()` ("handlers can define their own keys … without marking the whole config invalid which triggers doctor/best-effort loads"). This is direct evidence that the maintainers treat strictness as the default and passthrough as a deliberate, narrowly-scoped exception — `models.providers` was NOT granted that exception.
- Risk: a future minor could add a `metadata` field or relax `ModelProviderSchema`, but as of `v2026.5.3-1` there is no such field and no TODO/migration hint pointing toward one.

---

## VERDICT

**Can a custom marker field on a `models.providers.<name>` entry survive OpenClaw's config lifecycle? — NO.**

Decisive citation: `ModelProviderSchema` is `.strict()` at `src/config/zod-schema.core.ts:371`. Any unknown key produces a zod `unrecognized_keys` error. Every persisting path validates against this strict schema and **throws** rather than strips: `loadConfig` fails closed (`io.ts:1588`, `:1630-1632`), `writeConfigFile` aborts the write (`io.ts:2025-2033`), `config set` refuses to load an invalid file (`config-cli.ts:523-534`), and daemon start aborts (`lifecycle-core.ts:248-260`). The only path that tolerates the key is the read-only "best-effort" doctor fallback, which passes the raw object through un-stripped (`io.ts:1930-1934`, `coerceConfig` at `io.ts:299-304`) but never persists it.

**CONDITIONAL escape hatches (if a marker is acceptable off the provider entry):**
1. `plugins.entries.<name>.config.*` — arbitrary `z.record(string, unknown)` (`zod-schema.ts:205`). Survives validation and persistence. Wrong object if the marker must live *on the model provider*, but a viable side-channel keyed by provider name.
2. `talk.providers.<name>` is `.catchall` (`zod-schema.ts:213`) — but that is the TTS provider tree, not `models.providers`.

A marker that must sit *on the `models.providers.<name>` entry itself* cannot survive. Worthless should key any "managed" marker off provider **name/identity** stored elsewhere (its own store, or `plugins.entries.<name>.config`), never as a field on the OpenClaw provider object.
