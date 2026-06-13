# WOR-650 Implementation-Readiness Brief — Managed-Entry Recognition

> **Worthless only rewrites the provider entries it manages.**
> Phase 3 PR-1 · Feature F3 · Iteration 2 · AC6
>
> Repo: `worthless-wor658` @ `0b46758` (branch `feature/wor-658-bind-confirmation`).
> Reviewer: read-only research; no source edits made.

---

## 1. Threat -> User outcome

**Threat (live, per ticket):** `worthless doctor` reports every locked provider as "missing" because it looks up `worthless-{provider}` after F1 already renamed the entry to the bare provider name (`openai`). A user with a working install reads "x openai not wired" and loses trust.

**Threat (latent):** A future re-run of `lock` could trample a user's own custom provider entry that happens to be proxy-shaped (same port as the current proxy) — `_is_proxy_url` is a port heuristic, not proof of provenance (`src/worthless/openclaw/integration.py:808`, comment at `:831` explicitly tags this as the WOR-487 follow-up).

**What user gets after WOR-650 lands:**
- Doctor tells the truth — managed entries are recognised by DB lookup, not by name guessing.
- A user's hand-rolled proxy-shaped provider is left alone on re-lock.

---

## 2. Ticket-vs-code contradiction (must read before planning)

The ticket asserts the **live** doctor bug lives in `health_check` at `integration.py` L1571 / L1594 / L1624, building `f"worthless-{provider}"`. The doctor tests at `tests/openclaw/test_doctor_command_openclaw.py:232` and `:364` are described as *masking* this by mocking `get_provider` with the stale label.

**At `0b46758` this is no longer true.** Evidence:

| Claim | Reality at HEAD |
|---|---|
| health_check builds `worthless-{provider}` | `integration.py:1828` reads `provider_name = provider` with comment `# WOR-621 F1: lock writes the provider in place under its bare name (openai), so look up that entry — not the legacy worthless- decoy.` |
| Docstring at L1571 mentions the stale label | `integration.py:1771` says `compares each worthless-<provider> entry's baseUrl` — **docstring is the only stale artifact left**; the loop body is already fixed. |
| Tests at L232/L364 mock `worthless-openai` to mask the bug | The tests at `test_doctor_command_openclaw.py:232` and `:364` already assert `"worthless-openai" not in out` with comment `# F1: bare provider name, no decoy`. They are *enforcing* the F1 fix, not masking the bug. |
| `grep -c "worthless-{provider}"` in integration.py | **1 hit** — at `:957`, inside `build_lock_plan` (Part B / latent, not Part A / live). |

**Implication for the PR:** Part A (live, user-facing) appears to have shipped in the F1 patch (probably PR #276 / WOR-621 Phase 3 PR-1). What remains is:

- **Part A residue:** the stale **docstring** at `integration.py:1771` (and `worthless-` mentions at `:1795`, `:1826`) — cosmetic but misleading.
- **Part B (still live, test-only blast radius):** `build_lock_plan` at `integration.py:921` still computes `provider_name = f"worthless-{provider}"` at `:957` and uses it for the conflict-skip predicate at `:962-965`. Its only callers are `tests/openclaw/install_incident/test_lock_transaction.py` (5 hits at `:133, :151, :161, :227, :478`). **No live caller** — `apply_lock` runs its own `_apply_lock_write_providers` loop at `:1043+` independently.
- **The actual missing capability (AC6 work):** DB-driven recognition. No existing code parses `alias` out of `baseUrl` to check the `shards` row.

**Recommendation:** confirm with ticket author whether the "live, user-facing" framing should be re-pointed at the WOR-621 PR (already shipped) and this ticket narrowed to (a) docstring cleanup + (b) Part B + (c) AC6 DB-driven recognition.

---

## 3. Current code map (exact citations)

### 3.1 `health_check` (already F1-correct, docstring stale)

- Defined: `src/worthless/openclaw/integration.py:1761`
- Result dataclass: `OpenclawHealthReport` at `:1733-1759` — fields `providers_ok`, `providers_missing`, `providers_drifted: tuple[(name, actual_url, expected_url)]`, `config_unreadable`.
- Stale-label residue (docstring/comments only): `:1771`, `:1795`, `:1826`.
- Loop body (the bit the ticket says is broken): `:1822-1843`:
  ```
  for provider, alias in expected_providers:
      provider_name = provider                      # L1828 — F1-correct
      expected_url = f"{resolved_base}/{alias}/v1"
      entry = _config_mod.get_provider(config_path, provider_name)
      if entry is None:           providers_missing.append(provider_name)
      elif actual_url == expected_url: providers_ok.append(...)
      else:                       providers_drifted.append((provider_name, actual_url, expected_url))
  ```
- Doctor downstream: `src/worthless/cli/commands/doctor/__init__.py:266-300` (`_check_openclaw_section`). Calls `health_check` at `:275`, renders `"{name} not wired in openclaw.json — re-run \`worthless lock\`"` and `"{name} baseUrl mismatch (got X, expected Y) — re-run \`worthless lock\`"`. Bare names, no `worthless-` prefix in user-visible output.

### 3.2 `build_lock_plan` (Part B — latent, test-only)

- Defined: `src/worthless/openclaw/integration.py:921`
- The bug: `:957` `provider_name = f"worthless-{provider}"`
- Conflict-skip predicate `:958-966`:
  ```
  existing_entry = (original_config or {}).get("models", {}).get("providers", {}).get(provider_name)
  if existing_entry is not None:
      existing_url = existing_entry.get("baseUrl", "")
      if existing_url and not _is_proxy_url(existing_url, proxy_base_url):
          providers_to_skip.append((provider_name, "provider_conflict"))
          continue
  providers_to_add.append(provider_name)
  ```
- **Live callers in `src/`:** none beyond the self-reference at `:893` (dataclass docstring). The runtime path is `apply_lock` -> `_apply_lock_write_providers` (`:1043+`) which has its own loop at `:1048` doing `provider_name = provider`. Its comment at `:1062-1071` confirms: *"No conflict-skip here ... DB-driven recognition — so a user's UNRELATED proxy-shaped entry is never adopted — lands in F3."* **F3 = this ticket.**
- **Test callers:** `tests/openclaw/install_incident/test_lock_transaction.py:133, :151, :161, :227, :478`.

### 3.3 Shards row schema — the DB column WOR-650 needs

- DDL: `src/worthless/storage/schema.py` — `CREATE TABLE shards`:
  ```
  key_alias  TEXT PRIMARY KEY,
  shard_b_enc BLOB NOT NULL, commitment BLOB NOT NULL, nonce BLOB NOT NULL,
  provider    TEXT NOT NULL,
  prefix      TEXT, charset TEXT, base_url TEXT,
  shard_a_enc BLOB,
  oc_original_api_key_json TEXT,    -- WOR-651/F4: MAC-bound rollback record
  oc_rollback_mac          TEXT,    -- WOR-621 F2 G2: HMAC tag
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  ```
- Repository: `src/worthless/storage/repository.py:160-203`. `fetch_encrypted(alias)` at `:190` does `SELECT ... FROM shards WHERE key_alias = ?` — the lookup WOR-650 needs.
- **Identifying column for "is this a managed provider entry?":** `shards.key_alias`. There is **no** `managedBy` marker; the WOR-487 comment at `integration.py:831` flags this as a known follow-up. The presence of a row keyed by the alias parsed from the baseUrl is the proxy for "we created this entry."

### 3.4 Rollback record — how it ties in

- Built at `integration.py:159` (`build_oc_rollback_entry_record`).
- Stored in `shards.oc_original_api_key_json` + MAC in `shards.oc_rollback_mac`.
- Unlock parses the original `baseUrl` out of the JSON record (`integration.py:198+`, comment at `:340`: *"oc_original_base_url field on this dataclass was dropped in G5-C"* — never re-introduce a side-channel).
- **For WOR-650:** the rollback record's presence is *another* signal that a shards row is OpenClaw-managed for this provider. Either presence-of-row keyed by alias **OR** presence of `oc_original_api_key_json` for that row qualifies as "managed."

### 3.5 The proxy `baseUrl` format that needs alias-parsing

- Written by `_apply_lock_write_providers` at `integration.py:1051`:
  ```
  base_url = f"{resolved_proxy_base_url.rstrip('/')}/{alias}/v1"
  ```
- Default proxy host: `_DEFAULT_PROXY_BASE_URL = "http://127.0.0.1:8787"` (`integration.py:121`), resolved by `_resolve_proxy_base_url()` (`:367`) — Docker bridge may rewrite to `http://172.17.0.1:8787`.
- Confirmed shape in `src/worthless/openclaw/skill_assets/SKILL.md:160`:
  `OPENAI_BASE_URL=http://127.0.0.1:8787/<alias>/v1  (added by lock)`
- Round-trip into `openclaw.json` via `_config_mod.set_provider(config_path, provider_name, base_url, api_key=...)` (`config.py:308-348`), which idempotently writes `entry["baseUrl"] = base_url` at `:348`.

---

## 4. Design — how recognition should work post-fix

### 4.1 Parse alias out of `baseUrl`

The URL grammar is fixed by the write path at `integration.py:1051`:

```
^(?P<scheme>https?)://(?P<host>[^/]+)/(?P<alias>[A-Za-z0-9_-]+)/v1/?$
```

Implementation suggestion (mirror the style of `_is_proxy_url` at `:808`):

```python
_PROXY_ALIAS_RE = re.compile(r"^https?://[^/]+/(?P<alias>[A-Za-z0-9_-]+)/v1/?$")

def _alias_from_proxy_url(url: str, proxy_base_url: str) -> str | None:
    '''Return the alias segment if url is proxy-shaped; else None.
    Defence-in-depth: only accept if port matches proxy_base_url's port
    (reuses the port heuristic from _is_proxy_url) so a non-proxy URL
    with an accidental /<word>/v1 suffix cannot fake a managed entry.'''
```

Tying the port check to `_is_proxy_url` keeps a single source of truth for "is this our port."

### 4.2 DB lookup -> managed/unmanaged decision

```
alias = _alias_from_proxy_url(entry["baseUrl"], proxy_base_url)
if alias is None:                                 -> unmanaged (leave alone)
if not await shard_reader.fetch_encrypted(alias): -> unmanaged (leave alone)
                                                  -> managed (safe to rewrite/restore)
```

`shard_reader.fetch_encrypted(alias)` already exists at `storage/shard_reader.py:40` and returns `EncryptedShard | None`. No new query needed.

### 4.3 Rollback-record tie-in

When unlock walks `openclaw.json` provider entries to restore, the same predicate applies: parse alias, look up `shards.oc_original_api_key_json` for that alias. If present + MAC verifies, restore from the rollback record. If shards row exists but no rollback record -> entry was locked by an older worthless without F4 -> log + skip (do not synthesise an unsafe restore).

### 4.4 Wiring location

- **build_lock_plan** (`integration.py:921`): replace the name-based conflict-skip at `:958-966` with the DB-driven predicate. Drop `provider_name = f"worthless-{provider}"` at `:957`; use bare provider name like `apply_lock` already does.
- **No new live path needed in `health_check`** — it already uses bare names; only the docstring at `:1771` and the comments at `:1795`/`:1826` need cleanup.
- **AC6 net-new:** introduce `_alias_from_proxy_url` and use it from build_lock_plan + (defensively) from apply_lock's loop at `:1048-1071`, where the comment at `:1067-1071` *explicitly anticipates this work*.

---

## 5. Test fallout

### 5.1 Tests that previously asserted the stale label (already updated — sanity-check)

The doctor test pair at `tests/openclaw/test_doctor_command_openclaw.py` is **already** asserting the F1 contract. Re-confirm these stay green after Part B cleanup:

- `:232` — `test_provider_not_wired`: mocks `worthless.openclaw.config.get_provider` returning `None`, asserts `"openai" in out` and `"worthless-openai" not in out`.
- `:364` — `test_config_none_with_enrollment`: same `not in out` assertion.

Other live `worthless-openai not in` guards (already F1-correct):

- `tests/openclaw/test_integration_injection.py:121, :168` — `assert "worthless-openai" not in result.providers_set`
- `tests/openclaw/test_integration_apply_unlock_restore.py:85` — `assert "worthless-openai" not in mid`

### 5.2 Tests that bind to the Part B stale name and must be updated

`tests/openclaw/install_incident/test_lock_transaction.py` is the only place that exercises `build_lock_plan` directly (`:133, :151, :161, :227, :478`). Each plan assertion that inspects `providers_to_add` / `providers_to_skip` likely keys on `worthless-openai` and needs to flip to `openai`. **Read this file in full during the implementing PR** — it lives under `install_incident/`, was not opened in this brief.

### 5.3 New tests to add

- Alias-parse: positive (`http://127.0.0.1:8787/openai-aaaa1111/v1` -> `"openai-aaaa1111"`), negative (`/v2`, no alias segment, wrong port, missing scheme, querystring).
- Recognition matrix: shards row present -> managed; absent -> unmanaged; wrong-port proxy-shaped URL -> unmanaged; user's hand-rolled `http://127.0.0.1:8787/looks-like/v1` with no DB row -> unmanaged.
- Rollback record tie-in: shards row present but `oc_original_api_key_json` NULL -> managed but unrestorable; surface event, do not synthesise.

---

## 6. Edge cases worth flagging

1. **User has `worthless-*` entry we did not create.** Per F1, we no longer write `worthless-*` entries at all. A pre-existing `worthless-openai` entry from before F1 must be treated like any third-party entry: if its `baseUrl` parses to an alias we have in shards, adopt; else leave alone.
2. **Alias parses but no shards row.** Leave entry alone. Treat exactly as if `baseUrl` were unrelated. This is the AC6 happy path.
3. **DB locked / unreachable.** Recognition predicate must default to *unmanaged*, not crash. Conservative bias: if we cannot prove we own it, do not touch it. Surface a `CONFIG_UNREADABLE`-equivalent event so doctor can flag.
4. **Multiple managed entries collide.** Two providers, two aliases, both shards-row-present, both rewriting same `provider_name` in openclaw.json — apply_lock already iterates `planned_updates` and the in-place rewrite at `:1058+` is order-deterministic. AC6 does not change this; flag if test_lock_transaction.py exercises it.
5. **Stale rollback record + new shards row.** A re-enrol that wrote a new shards row but did not refresh `oc_original_api_key_json` would mean unlock can restore the *wrong* original entry. Mitigation lives in F4 (WOR-651), not F3 (this ticket) — but flag for `apply_unlock` review.
6. **Port collision on shared dev host.** Two worthless instances on the same port (e.g. dev + system service) writing distinct shards DBs — the alias is unique per DB, so cross-instance recognition is silently asymmetric. Out-of-scope but worth a sentence in the PR body.

---

## 7. Open questions for the implementing PR

1. **Is Part A truly already shipped?** Confirm with the ticket author whether the L1571/L1594/L1624 description is stale (matches an older HEAD) or whether I missed a code path. If shipped, narrow the ticket to (a) docstring cleanup + (b) Part B + (c) AC6 DB recognition.
2. **Sync vs async shard lookup in `build_lock_plan`.** `build_lock_plan` is sync (called from `--dry-run` and the live path); `shard_reader.fetch_encrypted` is async. Options: (i) make build_lock_plan accept a synchronous "is alias managed" callback; (ii) pre-fetch the set of aliases before calling build_lock_plan and pass as a parameter. Option (ii) keeps the function pure and matches the existing planned_updates threading.
3. **Should `health_check` also enforce DB recognition?** Today it trusts `expected_providers` derived from enrollments. If a malicious actor inserts a proxy-shaped entry pointing at an alias they control, doctor would happily report it as "drifted" but never as "rogue." Probably out of scope (doctor is advisory) — confirm.
4. **Forward-compat with `managedBy` marker (WOR-487).** Should this PR also start *writing* a `managedBy: "worthless"` field in `set_provider` so future versions can skip the parse-and-lookup dance? Cheap on write, valuable on read. Not in AC6 but a 5-line ask.
5. **What does `test_lock_transaction.py` under `install_incident/` actually assert?** Need full read during implementation — the brief only gathered the grep summary. If it asserts specific stale-name strings, those tests are the bulk of Part B fallout.

---

## 8. Touch-list summary (for PR scoping)

| File | Change |
|---|---|
| `src/worthless/openclaw/integration.py:1771, :1795, :1826` | Docstring/comment cleanup — drop stale `worthless-<provider>` references in `health_check` block. |
| `src/worthless/openclaw/integration.py:921-985` (`build_lock_plan`) | Drop `worthless-{provider}` at `:957`; replace name-based conflict-skip with alias-from-baseUrl + shards lookup. |
| `src/worthless/openclaw/integration.py` (new helper) | Add `_alias_from_proxy_url` next to `_is_proxy_url` (`:808`). |
| `src/worthless/openclaw/integration.py:1048-1071` (`_apply_lock_write_providers`) | Optionally tighten — the comment at `:1067-1071` already anticipates F3. |
| `tests/openclaw/install_incident/test_lock_transaction.py` | Update `providers_to_add` / `providers_to_skip` assertions from `worthless-openai` -> `openai`; add managed/unmanaged recognition cases. |
| `tests/openclaw/test_integration_apply_lock.py` (likely) | Add adversarial case: user's pre-existing proxy-shaped entry with no DB row survives `lock`. |

---

*End of brief. Citations above are file:line at `0b46758`.*
