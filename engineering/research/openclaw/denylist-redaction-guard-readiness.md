# WOR-655 — Implementation Readiness Brief

**Ticket:** WOR-655 *Secrets never appear in any Worthless output*
**Phase:** 3 · Feature F5 · Iteration 3 · SR-04 audit-ready gate · AC9
**Branch:** `feature/wor-658-bind-confirmation` (off `main` 0b46758)

---

## Threat -> what the user gets

> *"A future refactor accidentally `print()`s shard-A in a doctor / status / dry-run / event message. A leaked log file becomes a leaked key."*

Today, nothing leaks. This ticket guards forever: a regression test asserts that the literal shard-A bytes never appear anywhere in `lock`, `unlock`, `dry-run`, `doctor`, or `status` output -- stdout, stderr, structlog/`logging`, JSON sentinel, or event `to_dict()`. The user can ship a Worthless log to support with the SR-04 guarantee that no key material rides along. Rendering is normalised to a fixed `****` placeholder (no prefix, no suffix) wherever a secret-shaped string could otherwise reach an output channel.

---

## 1. Output-channel inventory

### 1.1 CLI human/JSON output (`worthless.cli.console.WorthlessConsole`)
`src/worthless/cli/console.py:81-147` -- five methods (`print_result`, `print_success`, `print_error`, `print_hint`, `print_warning`, `print_failure`) wrap `rich.Console.print`. None of them apply any secret redaction; they only `_rich_escape` markup. **Whatever the caller passes through is what hits the terminal.**

- `WorthlessConsole.print_result` (`console.py:81`): `sys.stdout.write(json.dumps(data, default=str))` -- emits the structured payload **verbatim**. This is the `--json` egress for every command.
- `_err.print(f"[green]{...}")` etc. (lines 93, 103, 112, 122, 132, 147) -- pass-through; risk is upstream callers.

### 1.2 Confirmed **shard-A-touching** print sites (high risk)
- **`src/worthless/cli/commands/unlock.py:293-305` -- `_print_recovery_keys`**
  Writes the reconstructed key to stdout in plaintext when `--env` is absent and an enrollment row has no `env_path`:
  ```
  sys.stdout.write(f"{p.var_name}={p.key_buf.decode('utf-8')}\n")
  sys.stdout.write(f"{p.alias}={p.key_buf.decode('utf-8')}\n")
  ```
  This is a **legitimate recovery channel** -- but the WOR-655 denylist test must allow-list it (e.g. flag the recovery code path or skip the assertion when `_print_recovery_keys` ran) or the test will always fail. Decision required (see Section 6).
- **`src/worthless/cli/commands/lock.py:90`** -- SHA-256 fingerprint over `api_key`. Non-secret (hash, first 8 hex). Safe; flag in test as known-safe.
- **`src/worthless/openclaw/integration.py:1077`** -- passes `api_key=shard_a_str` into the rebuilt OpenClaw entry. Written to disk, not stdout, but the value flows through; verify the rebuilt config write path never logs the entry contents.

### 1.3 `oc_original_api_key_json` channels (the rollback record)
The rollback record is **already key-redacted at construction** via `_deep_redact_key_strings` (`openclaw/integration.py:74-116`), which walks the structure and replaces any string matching `KEY_PATTERN` with `{"kind":"redacted-deep"}` and key-shaped dict keys with `"<redacted-deep-key>"`. So in normal flow the persisted record is safe. Audit-side surfaces:

- `src/worthless/storage/repository.py:200,228,381` -- SQL writes/reads the column. Not printed.
- `src/worthless/cli/commands/unlock.py:380,388,425,452,462` -- passes the JSON string into `OcRestore` / parse routines. Never directly printed.
- `src/worthless/cli/commands/lock.py:575,586,653,665` -- `prior_record=db_shard.oc_original_api_key_json` flows into the integration layer. Not printed.
- **Residual gap** (documented in code at `integration.py` doc comment near line 96): `KEY_PATTERN` is a prefix allowlist (`sk-`, `sk-or-`, `sk-ant-`, `anthropic-`, `AIza`, `xai-`). Unprefixed UUID/JWT/hex admin tokens survive the redactor (tracked as `worthless-3l5l`). For the WOR-655 byte-denylist test this is acceptable because we seed a *prefixed* shard-A; document the gap explicitly in the test.

### 1.4 `apiKey` rewrite path (the live OpenClaw config)
- `src/worthless/openclaw/config.py:309,349,350` -- `entry["apiKey"] = api_key`. Written to `openclaw.json`, not logged. The shard-A value is the rewritten apiKey under the 16x2-revert model (`doctor/__init__.py:354-356`).
- `src/worthless/cli/commands/doctor/__init__.py:384,414,427` -- reads `entry["apiKey"]`, decodes to `bytearray`, attempts reconstruction. The doctor message at line 427 prints the *provider name only*: `f"openclaw.json apiKey for {provider_name!r} is stale and out of sync with DB shards..."` -- safe.

### 1.5 Structured events (`OpenclawIntegrationEvent`)
`src/worthless/openclaw/errors.py:55-80`. `to_dict()` returns `{code, level, detail}` -- `extra` is intentionally omitted from the wire shape. **Risk:** `detail` and `extra` are free-form strings populated by `integration.py` at every `OpenclawIntegrationEvent(...)` call (lines 783, 794, 1056, 1082, 1093, 1105, 1133, 1198, 1250, 1299, 1355, 1363, 1438, 1454, 1470, 1487, 1498, 1510, 1587, 1616, 1640). I verified two `extra` payloads carry only `{"path":..., "provider":..., "baseUrl":..., "nlink":...}` -- non-secret. None I read embed key bytes, but the contract is by-convention, not by-construction. **WOR-655 test must walk every event in the result tuple and assert seeded bytes appear in no `code`/`level`/`detail`/`extra` value.**

### 1.6 `LockPlan.to_dict` (dry-run JSON)
`src/worthless/openclaw/integration.py:910-928` -- emits `{config_path, config_state, providers_to_add, providers_to_skip, skill_to_install}`. `providers_to_add` is a tuple of provider names (strings like `"anthropic"`), not key bytes. `providers_to_skip` is `tuple[tuple[provider_name, reason], ...]`. Safe by construction; assert in test.

### 1.7 `__repr__` / `__str__` already redacted
- `src/worthless/crypto/types.py:49-96` -- `SplitResult.__repr__` and the second class both emit `shard_a=<redacted>` literals.
- `src/worthless/storage/models.py:49-89,89-110` -- `EncryptedShard.__repr__` and `StoredShard.__repr__` emit `<N bytes>` length descriptors only.
- `src/worthless/adapters/types.py:47-55,69-80` -- `AdapterRequest.__repr__` replaces sensitive header values with `"REDACTED"`.
- `src/worthless/cli/keystore_macos.py:83-91` -- subclass `__str__`/`__repr__` scrub.
- `src/worthless/sidecar/backends/fernet.py:85` -- fernet key `__repr__` redacted.

### 1.8 Exceptions / tracebacks
- `src/worthless/cli/errors.py:118` -- `WorthlessError.__str__` = `f"WRTLS-{code}: {self.message}"`. The message is set by call sites; one site at `unlock.py` near `KEY_NOT_FOUND` includes a `Path`, no key.
- `errors.py:130-143` -- `UnsafeRewriteRefused` keeps the public message generic (`_UNSAFE_REWRITE_PUBLIC_MESSAGE`) and logs `reason` only at DEBUG.
- `errors.py:155-165` -- `sanitize_exception` returns a generic string; original is at DEBUG.
- **Concern:** raw tracebacks from Python (uncaught exceptions) traverse module frames where `api_key` lives in local variables. CPython traceback printer does NOT auto-print locals, so this is safe by default. But `logger.debug("UnsafeRewriteRefused: reason=%s", reason.value)` and `logger.debug("Sanitized exception: %r", exc)` could carry a key if a future exception subclass embeds one. Flag this in test (set logger to DEBUG and capture).

### 1.9 Logging surfaces
- `src/worthless/cli/commands/lock.py:57`: `logger = logging.getLogger(__name__)` -- used at `:806, :810, :1039, :1041` for failure paths and sentinel-write errors. No key bytes in the strings.
- `src/worthless/cli/commands/unlock.py:47,506,510`: same shape. The `exc` formatted into the warning is the `OcRollbackError` / generic exception -- does **not** quote shard bytes.
- `doctor/__init__.py:75`, `console.py` callers, `keystore_macos.py`, `keystore_keyring.py`, `cli/process.py`: all `logger.debug/.warning` calls -- none I traced embed key material.
- **No `structlog` usage in `src/worthless`** -- pure stdlib `logging`. Simpler test setup: `caplog` plus `capsys`.

### 1.10 Scan / `value_preview` (partial-mask precedent)
`src/worthless/cli/commands/scan.py:126-142` already implements an existing **prefix+suffix** redaction:
```
preview = f.value_preview                            # short string
if preview.startswith(value[:4]):
    preview = f.value_preview + "..." + value[-4:]   # "sk-a...wXyZ"
lines.append(f"  {f.file}:{f.line}  {f.provider}{var_part}  {status}  {preview}")
```
Also at `scan.py:191`: JSON output emits `"value_preview": f.value_preview`. **This is the principal "needs flattening" site for the "**** no prefix" rule** -- see Section 4. Note `code_scanner.py:301` already carries a comment "unredacted. Known gap -- not a security boundary." for the in-source matched line snippet.

---

## 2. Existing redactors

| Redactor | Location | What it covers | Gaps |
|---|---|---|---|
| `_deep_redact_key_strings` | `openclaw/integration.py:74-116` | walks nested JSON; replaces KEY_PATTERN-matching strings with sentinel dict | prefix allowlist only (`sk-`, `sk-or-`, `sk-ant-`, `anthropic-`, `AIza`, `xai-`); unprefixed tokens leak |
| `SplitResult.__repr__` | `crypto/types.py:49-96` | renders `shard_a=<redacted>` | applies only to `__repr__`/`__str__`; field-level access bypasses |
| `EncryptedShard.__repr__`, `StoredShard.__repr__` | `storage/models.py:49,89` | shows `<N bytes>` length only | same scope limit |
| `AdapterRequest.__repr__` | `adapters/types.py:47` | header dict scrub against `_SENSITIVE_HEADER_KEYS` | not applied to body or to logger formatters |
| `KeystoreMacos.__str__` / `__repr__` | `cli/keystore_macos.py:83,91` | scrub captured values | repr-only |
| `_rich_escape` | `cli/console.py` | markup escape only -- **NOT a secret redactor** | n/a (not its job) |
| `sanitize_exception` | `cli/errors.py:155` | returns generic string | does not protect DEBUG log line |
| `scan.py` preview | `cli/commands/scan.py:126-142` | partial mask `"sk-a...wXyZ"` | **uses prefix+suffix -- WOR-655 wants flat `****`** |

**Inconsistency:** there is no single `mask_secret(value: str) -> str` helper. Each subsystem rolls its own. The ticket's rendering rule implies introducing one canonical helper (proposed: `worthless.cli.redaction.mask_secret() -> "****"` and `worthless.cli.redaction.deep_mask_value(value)` for structured payloads) and routing the scan preview + any future call sites through it.

---

## 3. Denylist log-capture test design

**File:** `tests/openclaw/test_denylist_redaction.py` (new).

**Fixture pattern:**
```python
@pytest.fixture
def seeded_shard_a(monkeypatch) -> bytes:
    # 24-byte ASCII shard-A with a marker prefix unique enough that an
    # accidental match in unrelated bytes is statistically impossible.
    # Use a printable ASCII run so a stdout/stderr leak would still appear
    # as bytes-in-bytes (not hex-encoded, base64-encoded, etc.) -- those
    # transforms are flagged separately (see Section 5).
    return b"WOR655SHARDA_kQ7nP3vR9xL2bF8mT4eD"
```

**Drive the full path** (mirrors `tests/cli/test_lock_unlock_roundtrip.py` if present):
1. Use `tmp_path` as `WORTHLESS_HOME`; write a fake `.env` containing `ANTHROPIC_API_KEY=<sk-ant-prefix>+<seeded-32-byte-marker>` (full real-shaped key whose tail is the seeded marker bytes from the helper above).
2. Plant a minimal `openclaw.json` with a matching provider entry.
3. Run, in sequence and inside one pytest invocation, each of:
   - `worthless lock --dry-run --json`
   - `worthless lock --json`
   - `worthless status --json`
   - `worthless doctor --json`
   - `worthless unlock --dry-run --json`
   - `worthless unlock --json`
4. Capture **all** of: `capsys.readouterr().out`, `.err`, `caplog.records` (DEBUG level), the sentinel file at `$WORTHLESS_HOME/last-lock-status.json` read back as bytes, and any `OpenclawIntegrationEvent.to_dict()` payload obtained from the result struct.

**Assertion (bytes-in-bytes, case-sensitive):**
```python
SEEDED = b"WOR655SHARDA_kQ7nP3vR9xL2bF8mT4eD"
for label, payload in channels:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    assert SEEDED not in payload, f"shard-A leaked in {label}"
    # Also defend against common transforms:
    assert base64.b64encode(SEEDED).rstrip(b"=") not in payload
    assert binascii.hexlify(SEEDED) not in payload
```

**False-positive avoidance:**
- Seeded bytes are 32 chars of mixed-case ASCII with a `WOR655SHARDA_` marker; collision probability with unrelated source/log strings is ~0.
- The marker survives lower-case casing; if a leak ever happens through `.lower()`, the test still catches it (we add a second assertion against `SEEDED.lower()`).
- Recovery-key channel (Section 1.2) must be **disabled in this test** by always supplying `--env` so `_print_recovery_keys` short-circuits at line 296. Document this explicitly.

**Pytest plumbing:** `caplog.set_level(logging.DEBUG, logger="worthless")` to surface the DEBUG `UnsafeRewriteRefused`/`sanitize_exception` lines. Reset structlog if it is ever added later (current code: stdlib `logging` only).

---

## 4. The `****` (no-prefix) rendering rule

The only existing site that emits a *prefix* in a redacted value is the scan preview path:

- `src/worthless/cli/commands/scan.py:126` -- `preview = f.value_preview` (the `CodeFinding.value_preview` field set by `code_scanner.py`).
- `scan.py:135-136` -- `preview = f.value_preview + "..." + value[-4:]` -- **this is the `sk-a...wXyZ` shape the ticket calls out.**
- `scan.py:191` -- JSON path emits `"value_preview": f.value_preview` (same data, JSON channel).
- `scan.py:289` -- `_format_code_findings_human` (human path) reuses the preview string; also surfaced via `cli/commands/lock.py:959` (`typer.echo(_format_code_findings_human(findings))`).

**Flattening plan:** replace the `preview + "..." + suffix` construction with a single `"****"` literal in human + JSON renderers, and drop `value_preview` from `CodeFinding.to_dict()` (or always serialise as `"****"`). Touches:
- `scan.py:126, 135, 136, 142, 191, 289`
- `scan.py:556` (the `sys.stderr.write(_format_code_findings_human(...))` call)
- `cli/commands/lock.py:959` (transitively uses the same formatter)
- Anywhere `code_scanner.CodeFinding.value_preview` is constructed -- review whether to clear it at the source or only at render. Recommendation: clear at render (preserve in-memory for debug, never serialise raw).

No other prefix-redaction sites found.

---

## 5. Edge cases worth flagging

1. **Recovery-key intentional emission.** `_print_recovery_keys` (`unlock.py:293`) is the documented escape hatch for "no `.env` to write into". The denylist test cannot run against it without rewriting product behaviour. Decision required: skip this code path in the test (recommended) or change the recovery flow to require an explicit `--print-recovery` flag.

2. **Bytes-vs-str channels.** `capsys` returns `str`; sentinel file is on disk as bytes; events come through as Python objects. The test must normalise everything to `bytes` before substring search. The OpenClaw config write at `openclaw/integration.py` near `apiKey=shard_a_str` is the only on-disk channel that legitimately contains shard-A -- explicitly exclude `~/.openclaw/openclaw.json` from the denylist sweep (it is supposed to carry the key).

3. **Multi-line strings.** `WorthlessError.__str__` and the `_emit_openclaw_failure` block in `lock.py:1003-1009` call `print_warning` repeatedly with single-line strings. No multi-line keys observed; still, the bytes-in-bytes check handles any line splitting transparently.

4. **Unicode / encoding.** All Worthless internal handling treats keys as ASCII (`api_key.encode("utf-8")` at `crypto/splitter.py:145, 200`). Non-ASCII shard-A is not produced. Safe.

5. **Traceback locals.** CPython's default traceback formatter does **not** print locals; pytest's `--showlocals` does. The CI command in `.github/workflows/` must not use `--showlocals` for the denylist test (or the locals frames at `_print_recovery_keys`, `_pass1_reconstruct`, `apply_lock` will print key bytes by accident).

6. **Structured event JSON key vs value.** `_deep_redact_key_strings` already handles both: KEY_PATTERN-matching dict *keys* are replaced with the `<redacted-deep-key>` placeholder, dict *values* with the sentinel dict. The denylist test covers both via the bytes-in-bytes check on the serialised JSON.

7. **logger string interpolation.** Python's `logging` defers `%s` formatting until the handler runs. If a future call does `logger.debug("key=%s", api_key)` and the level is filtered out at the root logger, the string is never built -- leak avoided. Once a handler is added (e.g. file handler at DEBUG), the leak materialises. The WOR-655 test must explicitly **enable** a DEBUG handler so any future regression at this layer fails the test.

8. **JSON-mode sentinel.** `--json` writes to `$WORTHLESS_HOME/last-lock-status.json` via the sentinel writer. The test must read this file as bytes and run the denylist sweep over it too.

9. **`code_scanner.py:301` known gap.** Comment-confirmed "unredacted. Known gap -- not a security boundary." Worth re-evaluating under WOR-655 -- the matched-source-line text could embed a key. Suggest scoping decision to the implementing PR.

---

## 6. Open questions for the implementing PR

1. **Recovery-key flow scope.** Does WOR-655 cover `_print_recovery_keys` (which is *supposed* to print a reconstructed key)? Proposal: add a `--print-recovery` opt-in and have the denylist test always pass `--env`, so the legitimate channel becomes explicit and the test is unambiguous. Needs product sign-off.

2. **Single helper or per-site fixes?** Centralise in `worthless.cli.redaction.mask_secret()` and route the scan preview through it, or just inline `"****"` in the two existing render sites? Centralisation is a cleaner forward guard (future emitters import the helper); inlining is smaller surface. Recommendation: helper.

3. **`code_scanner.py:301` known gap.** In scope for WOR-655 or split to a follow-up? The line is explicitly tagged "not a security boundary" today, but the ticket's spirit ("never leaks key material") suggests at least adding a column-mask for the matched value within the surrounding line.

4. **Logging handler policy.** Should we ship a runtime guard (custom `logging.Filter`) that scrubs any record whose formatted message matches KEY_PATTERN, regardless of caller intent? That would catch the residual-gap class (someone log-formats a key by mistake) at the handler boundary. Lower-effort, defence-in-depth. Decision: in scope?

5. **Audit channel.** Is `extra={"path": ..., "baseUrl": ...}` on `OpenclawIntegrationEvent` (lines 783, 803, 1109, 1139, 1258, etc.) considered an output channel for AC9? It is dropped from `to_dict()` today but logged at WARNING. If logs are the audit-ready surface, `extra` is in scope and we should grep every emit site for fields named `api_key`, `apiKey`, `shard_*`, `key`, `secret`, `token` and reject at construction time via a `__post_init__` denylist on `OpenclawIntegrationEvent`.

6. **Pytest discovery for the test.** Does `tests/openclaw/test_denylist_redaction.py` belong in the OpenClaw lane (likely) or the security lane? The test crosses both subsystems; recommend the OpenClaw lane with a `@pytest.mark.security` marker so the security lane CI matrix picks it up too.
