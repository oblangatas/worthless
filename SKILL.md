---
name: worthless
description: Split-key proxy that makes leaked API keys worthless. Run `worthless lock` to protect LLM API keys with an enforced spend cap — if the cap is hit, the key never reconstructs.
homepage: https://wless.io
metadata:
  openclaw:
    emoji: 🛡️
    requires:
      bins: [worthless]
    install:
      - id: uv
        kind: shell
        command: uv tool install worthless
        bins: [worthless]
        label: Install worthless (uv — recommended)
      - id: pip
        kind: shell
        command: pip install worthless
        bins: [worthless]
        label: Install worthless (pip)
---

# Worthless Agent Discovery File (SKILL.md)

**Worthless** is a split-key reverse proxy that makes leaked API keys worthless. API keys are split into two information-theoretically secure shards: one stays on the user's machine, one is encrypted on the proxy. The real key only reconstructs in memory for a single API call, then is zeroed. If spending limits are hit, the key never forms at all.

## What Worthless Does

Worthless protects API keys in three scenarios:

1. **Local Development**: `worthless wrap` starts an ephemeral proxy and runs your command through it. Lock has already rewritten `*_BASE_URL` in your `.env` to point at the proxy, so your SDK picks it up via dotenv. The proxy reconstructs the real key only when the request passes the rules engine, then cleans up on exit.
2. **Daemon Mode**: `worthless up` starts a persistent local proxy on port 8787 (configurable) that stays running and protects all enrolled keys.
3. **CI/CD & Sidecar**: The proxy is designed to run as a sidecar container or process, protecting keys across environments with per-key spending limits and time-window gates.

### Scope (important for agents)

Worthless scans for **LLM provider API key prefixes only** — currently `openai` (`sk-`, `sk-proj-`), `anthropic` (`sk-ant-`), `google` (`AIza`), and `xai` (`xai-`). It will NOT detect general secrets: cloud-provider tokens (AWS, GCP, Azure), GitHub Personal Access Tokens, npm tokens, Cloudflare API tokens, database passwords, JWT signing keys, etc. If the user asks for a broad "find all secrets" or full `.env` audit, clarify the boundary and recommend [gitleaks](https://github.com/gitleaks/gitleaks) or [trufflehog](https://github.com/trufflesecurity/trufflehog) as a companion tool. `worthless scan --json` returns `{"schema_version": 2, "findings": [...], "orphans": [...]}` — `findings` are `.env` keys (each with `is_protected`), `orphans` are DB enrollments whose `.env` line was deleted (run `worthless doctor --fix` to clean them up). Both arrays are empty when nothing matches; an empty `findings` on a `.env` full of cloud tokens is correct behaviour, not a miss. Agents iterating findings: `for f in result["findings"]`. Guard against future shape breaks: `assert result["schema_version"] >= 2`. (HF5 changed shape from a bare findings array — schema 1.) `worthless scan --code` is a separate, opt-in scan that detects hardcoded provider base URLs (routing bypasses) in source files — it does NOT scan for key-prefix patterns and does NOT overlap with the default `.env` scan. Both scans have distinct limits: `--code` cannot detect runtime-composed URLs, IP literals, regional endpoints, or env-var interpolation.

---

## Installation & Setup

### Package Info
- **Package name**: `worthless`
- **Version**: 0.3.7
- **Entry point**: `worthless` (CLI command)
- **Python**: 3.10+
- **License**: AGPL-3.0
- **Status**: Beta

### Quick Install
```bash
pipx install worthless
# or: pip install worthless (in a virtualenv)
# or: curl -sSL worthless.sh | sh
```

### First-Time Setup (the magic way)
```bash
cd your-project
worthless
# → Detects API keys in .env, prompts to lock, starts proxy. Done.
```

Running `worthless` with no arguments auto-detects `.env`/`.env.local`, shows detected keys (var name + provider only), prompts `[y/N]` to lock, starts the proxy daemon, and reports healthy. One command from zero to protected.

### First-Time Setup (explicit commands)
```bash
worthless lock                       # Split keys in .env
worthless up -d                      # Start proxy daemon
worthless wrap python your_app.py    # Run code through proxy
```

### Non-interactive / CI
```bash
worthless --yes      # Auto-approve lock + proxy start
worthless --json     # Read-only state report (never writes)
```

---

## CLI Commands

All commands are available via `worthless <command> [OPTIONS]`.

### Global Options (apply to all commands)
- `--quiet`, `-q`: Suppress non-error output
- `--json`: Emit machine-readable JSON output
- `--debug`: Show full tracebacks on error
- `--version`, `-V`: Show version and exit

### Core Commands

#### `worthless lock [OPTIONS]`
**Scan `.env`, split API keys, store shard-B, rewrite `.env` with shard-A.**

Scans the current `.env` and `.env.local` files for high-entropy values that match known API key patterns (OpenAI, Anthropic, etc.). For each detected key:
1. Splits the key into two information-theoretic shards using format-preserving XOR secret sharing
2. Stores Shard B encrypted in the SQLite database at `~/.worthless/worthless.db`
3. Replaces the original key in `.env` with shard-A (format-preserving — same prefix, charset, and length as the original key)
4. Records the location (file, line, variable name) for later recovery

**Options:**
- `--env, -e PATH`: Path to .env file (default: `.env`)
- `--provider, -p NAME`: Override provider auto-detection
- `--token-budget-daily N`: Daily token budget limit for this key

**Output (success):**
```
1 key(s) protected.
  openai-69ccc444  sk-proj-*  PROTECTED
```

#### `worthless unlock [OPTIONS]`
**Reconstruct original API keys from shards and restore `.env`.**

Reverses the `lock` operation. Reads shard-A from `.env`, fetches encrypted Shard B from the database, XOR-merges them to recover the original key, and restores the original key to `.env`.

**Options:**
- (None — unlocks all enrolled keys)

**Behavior:**
- If multiple `.env` files have the same key enrolled, prompts for disambiguation
- Zeros key material from memory after restoration
- Removes DB records and enrollment data

**Use case:** Temporary switch between `wrap`-mode and native SDK mode, or complete teardown.

#### `worthless scan [OPTIONS] [PATHS]`
**Detect exposed API keys in files and environment.**

Scans files for high-entropy strings that match known API key patterns. Ignores shard-A values that were created by Worthless (checks Shannon entropy + format coherence).

**Options:**
- `--deep`: Scan beyond `.env`/`.env.local` — includes `*.yml`, `*.yaml`, `*.toml`, `*.json` in project root, plus env var dump
- `--format {sarif|human}`: Output format (default: human-readable)
- `--code`: Opt-in source-code scan. Walks project source files and matches hardcoded LLM provider base URLs (from the bundled registry) case-insensitively. Warn-only; always exits 0. Skips `.venv`, `node_modules`, `vendor`, `dist`, `build`, `__pycache__`, lockfiles, minified files, and files >1 MB. Respects `.gitignore` via `git ls-files` when inside a git repo. Scanned extensions: `.py`, `.js`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.jsx`, `.go`, `.rs`, `.rb`, `.java`, `.kt`, `.swift`, `.toml`, `.yaml`, `.yml`, `.json`, `.md`. **Does NOT detect**: runtime-composed URLs (e.g. `"https://api." + "openai.com/v1"`), IP literals, regional/Azure/Bedrock endpoints, env-var interpolation (e.g. `base_url=os.environ["OPENAI_BASE_URL"]`), or vendored SDKs.
- `--ai-prompt` / `--no-ai-prompt`: When `--code` finds hardcoded URLs, emits a copy-pasteable prompt block on stderr addressed to the active AI agent (Claude Code, Cursor, etc.), instructing it to replace each hardcoded URL with the suggested env var. On by default when `--code` is active. Suppress with `--no-ai-prompt`. Never emitted on zero findings.
- `PATHS`: Explicit file/directory paths to scan

**JSON output with `--code --json`:** Adds `"code_findings": [...]` to the existing `{"schema_version": 2, "findings": [...], "orphans": [...]}` envelope. Each entry: `{file, line, column, matched_url, provider_name, suggested_env_var, line_text}`. Note: `line_text` has API keys redacted as `[REDACTED]`.

**SARIF output:** Intentionally omits code findings. SARIF covers `.env`-key surface only.

**Output:**
- Lists findings with file, line, value preview, and confidence level
- SARIF format for CI/CD integration

**Use case:** Security audit before deploying; detect accidentally-committed keys in Git history; detect hardcoded provider URLs that bypass the proxy.

#### `worthless status [OPTIONS]`
**List enrolled keys and check proxy health.**

Queries the database for all enrolled key aliases (provider + deterministic ID) and attempts to reach the local proxy on its configured port.

**Options:**
- (None)

**Output:**
```
Locked keys:
  openai-69ccc444   openai      PROTECTED
  anthropic-a1b2c3  anthropic   PROTECTED

Proxy: http://127.0.0.1:8787 (running)
```

### worthless doctor

**Diagnose and repair stuck states across all known failure modes. WOR-464 adds a check registry + `--json` machine-readable output.**

`worthless doctor` runs eight checks: `recovery_import`, `orphan_db`, `openclaw`, `icloud_keychain`, `orphan_keychain`, `stranded_shards`, `fernet_drift`, `broken_status`. Read-only by default. `--fix` enables repair for all checks EXCEPT `fernet_drift` (drift is hardcoded `fixable=False` — only the user can pick which side is canonical, never the tool).

**JSON mode:**

```bash
worthless doctor --json
```

Emits a single document on stdout:

```json
{"schema_version": "1",
 "ok": true,
 "checks": [{"check_id": "orphan_db", "status": "ok", "findings": [],
             "summary": "No orphan enrollments found.",
             "fixable": true, "fixed": [], "skipped_reason": null}, ...],
 "summary": {"total": 8, "warn": 0, "error": 0, "fixed": 0}}
```

`schema_version` is bumped only on breaking shape changes. New `check_id` values, new finding keys, and new optional fields are additive.

**Troubleshooting tree:** `docs/troubleshooting.md` has one section per `check_id` with the user-visible symptom and the exact command to run.

The detailed text-mode output is documented under the `worthless doctor [OPTIONS]` subsection further down.

#### `worthless wrap [OPTIONS] COMMAND [ARGS...]`
**Ephemeral proxy + child process lifecycle.**

Starts a temporary reverse proxy on the same port `worthless lock` wrote into your `.env` (default `8787`, override with `WORTHLESS_PORT`), spawns a child process with the parent environment unchanged, waits for the child to exit, and cleans up the proxy. Pre-8rqs, wrap synthesised `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` into the child env. Post-8rqs (Phase 8), `worthless lock` writes the per-enrollment `*_BASE_URL` directly into your `.env` (preserving your var names — `OPENROUTER_BASE_URL` stays `OPENROUTER_BASE_URL`), so your SDK picks them up via dotenv. Wrap is a passthrough on the env side; on the network side, it binds the port your `.env` already points at so `wrap` and `up` are alternatives — running both at once produces a clean error, not a silent collision.

The child's API SDK calls automatically route through the proxy. No code changes required.

**Options:**
- (None — command and args are pass-through)

**Example:**
```bash
worthless wrap python -c "import openai; print(openai.OpenAI().models.list())"
worthless wrap npm test
worthless wrap pytest
```

**Behavior:**
- Proxy inherits all enrolled keys automatically
- If a spending rule fires, request is rejected with 402 Payment Required
- Cleanup is automatic on child exit (SIGTERM forwarding, process tree termination)

#### `worthless up [OPTIONS]`
**Start the proxy server (foreground or daemon mode).**

Starts a long-lived reverse proxy that protects all enrolled keys. Binds to a configurable port (default 8787).

**Options:**
- `--port PORT`, `-p PORT`: Bind port (default: 8787 or `$WORTHLESS_PORT`)
- `--daemon`, `-d`: Run in background; logs to `~/.worthless/proxy.log`

**Behavior:**
- Foreground mode: logs to stdout, exits with proxy
- Daemon mode: forks to background, returns immediately, writes PID to `~/.worthless/proxy.pid`
- Startup health check ensures proxy is listening before returning
- Rejects new `up` commands if proxy is already running on the configured port

**Example:**
```bash
worthless up                          # foreground, port 8787
worthless up --port 9999              # foreground, custom port
worthless up -d --port 9999           # daemon mode

# In another shell:
export OPENAI_BASE_URL=http://127.0.0.1:8787
python your_app.py
```

#### `worthless down [OPTIONS]`
**Stop the running proxy daemon.**

Reads the PID file (`~/.worthless/proxy.pid`), sends SIGTERM to the process group, polls for graceful shutdown, escalates to SIGKILL after timeout (5s), and cleans up the PID file.

**Options:**
- (None)

**Behavior:**
- Idempotent: succeeds even if proxy is not running
- Graceful: gives proxy time to flush logs and close connections
- Process-tree aware: kills all child processes spawned by the proxy

#### `worthless revoke [OPTIONS] ALIAS`
**Wipe an enrolled key (delete shards and all DB records).**

Deletes Shard B and all associated records (enrollments, spend logs, time windows) from the database in a single atomic transaction. Removes shard-A from `.env` if still present.

**Options:**
- (None — takes alias as argument)

**Alias format:**
- Deterministic: `{provider}-{first8hexofsha256(key)}`
- Example: `openai-69ccc444`, `anthropic-a1b2c3d4`

**Behavior:**
- Atomic DB cleanup: all related records removed in one transaction
- Idempotent: succeeds even if alias doesn't exist

#### `worthless enroll [OPTIONS]`
**Enroll a single API key (scripting/CI primitive).**

Lower-level than `lock` — enrolls one key by alias without scanning `.env`. Designed for CI pipelines and scripts where the key comes from a secret manager.

**Options:**
- `--alias, -a NAME`: Key alias (required)
- `--key, -k VALUE`: API key (use --key-stdin instead to avoid shell history)
- `--key-stdin`: Read API key from stdin
- `--provider, -p NAME`: Provider name (required)

**Use case:** `echo "$OPENAI_KEY" | worthless enroll --alias ci-openai --provider openai --key-stdin`

#### `worthless restore TARGET`
**Atomically rewrite a `.env` from stdin bytes (recovery path).**

Thin wrapper around `safe_restore` for ops runbooks and recovery scripts that need to stamp known-good bytes onto a `.env` while bypassing only the DELTA blowup-ratio gate. Every other invariant still fires (SYMLINK, CONTAINMENT, BASENAME, SNIFF, SIZE, TOCTOU, PATH_IDENTITY, FILESYSTEM).

**Arguments:**
- `TARGET`: Path to the `.env` file to restore.

**Behavior:**
- Reads replacement bytes from stdin; empty stdin refuses.
- On any invariant violation: `.env` is byte-identical (unchanged), exit code 1.

**Use case:** `cat backup.env | worthless restore ./.env`

#### `worthless providers list|register [OPTIONS]`
**Manage the LLM-provider registry (URL → wire-protocol mapping).**

The registry maps known upstream URLs (e.g., `https://api.openai.com/v1`) to a wire protocol (`openai` / `anthropic`) so `worthless lock` can auto-detect protocol when scanning `.env` files.

**Subcommands:**
- `list` — Print the merged registry: bundled + optional `~/.worthless/providers.toml`. Use the global `--json` flag for machine-readable output.
- `register --name NAME --url URL --protocol {openai,anthropic} [--force]` — Append a custom provider to `~/.worthless/providers.toml`. Refuses bundled-name conflicts; refuses bundled-URL conflicts unless `--force`.

**Bundled providers:** openai, anthropic, openrouter, groq, together, ollama. Add more locally via `register` without modifying the package.

**Use case:** Lock keys from any OpenAI-protocol-compatible provider (OpenRouter, Groq, Together, Ollama, internal LLM gateways). The proxy uses each enrollment's stored URL at request time, so multiple providers coexist in one `.env`.

#### `worthless doctor [OPTIONS]`
**Diagnose and repair stuck states. Safe to run at any time.**

Runs three checks in sequence:

1. **Recovery file imports** — if a sibling Mac ran `--fix` and wrote recovery files to `~/.worthless/recovery/`, import any missing keys into this Mac's local keychain automatically.
2. **iCloud-synced keychain entries** — Worthless keys should stay on this Mac only. If any have been synced across your Apple devices via iCloud Keychain, doctor lists them and (`--fix`) migrates them to device-local storage. A one-time recovery copy is saved to `~/.worthless/recovery/` before migration so a second Mac can re-import. The migration prompts with an explicit multi-device warning before any changes.
3. **Orphan DB rows** — DB enrollment rows whose `.env` line was deleted by the user. Surfaces and (`--fix`) purges them. Closes the dogfood-discovered stuck state where `worthless unlock` says "no enrolled keys" but `worthless status` lists them as PROTECTED.

**Options:**

| Flag | Meaning |
|---|---|
| *(no flags)* | Read-only diagnose mode — lists all findings, exit 0, no writes |
| `--fix` | Repair mode — prompts for confirmation before any changes |
| `--fix --yes` / `-y` | Repair without prompt (CI / non-interactive) |
| `--fix --dry-run` | Show planned actions, leave everything intact |

**Example output (clean state):**

```
$ worthless doctor
No issues found.
```

**Example output (iCloud finding):**

```
$ worthless doctor
Found 2 Worthless key(s) stored in iCloud Keychain (syncs across your Apple devices).
Worthless keys should stay on this Mac only.
Run: worthless doctor --fix
```

**Example output (orphan finding):**

```
$ worthless doctor
Can't restore openai-abc123: .env line deleted.
Run: worthless doctor --fix
```

**User-facing wording:** plain English throughout — `"can't restore"`, `"stored in iCloud Keychain"`, `"this Mac only"`. No engineer jargon. The fix command name is always named so the user sees the recovery path.

**Note:** Full check registry + `--json` output land in WOR-464. For now, all output is human-readable text.

**Use cases:**
- `.env` line manually deleted → `worthless doctor --fix` purges the orphan row.
- Keys appearing in iCloud Keychain → `worthless doctor --fix` migrates to device-local storage (multi-device warning shown first).
- Moved to a new Mac → `worthless doctor` auto-imports recovery files left by the originating Mac.

#### `worthless mcp [OPTIONS]`
**Start the MCP server (stdio transport).**

Starts a Model Context Protocol (MCP) server over stdin/stdout. Available when installed with the `[mcp]` extra: `pip install worthless[mcp]`.

Exposes the following tools:
- `worthless_status()`: Show enrolled keys and proxy health (JSON)
- `worthless_lock(env_path)`: Lock all keys in a `.env` file (returns summary)
- `worthless_scan(paths, deep)`: Scan for exposed keys (returns SARIF or JSON)
- `worthless_spend(alias)`: Token spend history per key alias (JSON)

**Options:**
- (None)

**Use case:** Integration with Claude Code, Cursor, OpenClaw, or other AI agents; agents can query proxy status, run code through the proxy, and audit for exposed keys programmatically.

---

## Proxy Rules Engine

The proxy enforces a "gate-before-reconstruct" pipeline: rules are evaluated **before** the key is reconstructed. A denied request never causes the key to form in memory.

### SpendCapRule
**Denies requests when accumulated spend (in tokens) exceeds a per-key cap.**

- Queries `spend_log` table for cumulative tokens spent by the key alias
- Returns HTTP 402 Payment Required if cap is exceeded
- **Note**: Spend cap is a pre-check; actual spend is recorded in the metering layer after the upstream response. Concurrent requests may both pass the cap check before either records its spend (production fix: reserve estimated tokens at check time, reconcile after response).

### RateLimitRule
**Denies requests when the per-key rate exceeds a configured limit (requests per second).**

- Tracks request count in a sliding window
- Returns HTTP 429 Too Many Requests if rate is exceeded
- Per-key: each enrolled key has its own rate limit

### TokenBudgetRule
**Denies requests when token usage exceeds a daily, weekly, or monthly budget.**

- Queries `spend_log` table for tokens spent within the configured time window (day/week/month)
- Returns HTTP 429 Too Many Requests if any budget period is exceeded
- Supports independent daily, weekly, and monthly limits (any or all can be set)
- Configured at enrollment via `worthless lock --token-budget-daily=N`

### TimeWindowRule
**Denies requests outside of a configured time window (e.g., business hours only).**

- Checks current time against enrolled time window (start and end time in a configured timezone)
- Returns HTTP 403 Forbidden if outside the window
- Supports recurring schedules (e.g., "Monday–Friday, 9am–5pm EST")

### Custom Rules
Agents can extend the rules engine by implementing the `Rule` protocol:

```python
from typing import Protocol

@runtime_checkable
class Rule(Protocol):
    async def evaluate(
        self,
        alias: str,
        request: object,
        *,
        provider: str = "openai",
        body: bytes = b""
    ) -> ErrorResponse | None: ...
```

If `evaluate()` returns `None`, the request is allowed. If it returns an `ErrorResponse`, the proxy rejects the request with that error code and message.

---

## MCP Tools

When running `worthless mcp`, these tools are exposed:

### `worthless_status() -> str`
Show enrolled keys and proxy health. Returns JSON:
```json
{
  "keys": [
    {"alias": "openai-69ccc444", "provider": "openai"},
    {"alias": "anthropic-a1b2c3d4", "provider": "anthropic"}
  ],
  "proxy": {
    "running": true,
    "port": 8787,
    "health": "ok"
  }
}
```

### `worthless_lock(env_path: str = ".env") -> str`
Lock all keys in a `.env` file. Returns summary of keys locked.

### `worthless_scan(paths: list[str], deep: bool, code: bool = False) -> str`
Scan files for exposed keys. Returns SARIF or human-readable findings. Pass `code=True` to also scan source files for hardcoded provider base URLs; adds `"code_findings"` array to JSON output. Does NOT detect runtime-composed URLs, IP literals, regional endpoints, or env-var interpolation.

### `worthless_spend(alias: str | None = None) -> str`
Token spend history. Pass alias for one key, omit for all. Returns JSON.

---

## Environment Variables

- `WORTHLESS_PORT`: Default port for `worthless up` (default: 8787)
- `WORTHLESS_DEBUG`: Enable debug logging (when set)
- `*_BASE_URL` (e.g., `OPENAI_BASE_URL`, `OPENROUTER_BASE_URL`): Set in your `.env` by `worthless lock` to point each enrolled key at the local proxy. Your SDK reads them via dotenv. Var names are preserved — lock does not rename `OPENROUTER_BASE_URL` to `OPENAI_BASE_URL`. Pre-8rqs these were synthesised by `wrap`; post-8rqs they live in `.env`.

---

## Database Schema

Worthless stores all state in `~/.worthless/worthless.db` (SQLite):

- `shards`: Encrypted Shard B + metadata (key_alias, provider, created_at)
- `enrollments`: Where each key is enrolled (env file, variable name, line number)
- `spend_log`: Token spend per key alias (for cap enforcement)
- `enrollment_config`: Per-key rules (spend cap, rate limit, time window)

All tables are ACID-transactional. Key deletion via `revoke` is atomic: all records for a single alias are removed in one transaction.

---

## File Locations

- `~/.worthless/`: Home directory for Worthless state
  - `worthless.db`: SQLite database (shards, enrollments, spend logs, rules)
  - `proxy.pid`: PID and port of running proxy (when `up -d` is active)
  - `proxy.log`: Proxy logs (when `up -d` is active)

---

## Common Workflows

### Protect a key in local development
```bash
worthless lock
worthless wrap python your_app.py
```

### Keep proxy running for all your tools
```bash
worthless up -d
export OPENAI_BASE_URL=http://127.0.0.1:8787
# Now all your Python/Node/etc. code routes through the proxy
worthless status                  # check health
worthless down                    # stop when done
```

### Audit for exposed keys
```bash
worthless scan --deep             # .env and config files
worthless scan --code             # source files — hardcoded provider URLs (routing bypasses)
```

### Permanently delete a key
```bash
worthless revoke openai-69ccc444
```

### Restore original key from shards (temporary)
```bash
worthless unlock
# Your .env now has the real key
# Use it directly (not through proxy)
worthless lock
# Split again, back to shard-A
```

### Pre-commit hook (scan before every commit)
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: worthless-scan
        name: Scan for exposed API keys
        entry: worthless scan --format sarif
        language: system
        pass_filenames: false
```

---

## Integration with AI Agents

Agents (Claude Code, Cursor, OpenClaw) can invoke Worthless via:

1. **CLI shell commands** (primary):
   ```bash
   worthless status
   worthless scan --deep
   worthless scan --code             # detect hardcoded provider URLs before lock
   worthless wrap pytest
   ```

2. **MCP server** (when available):
   ```text
   Tool: worthless_status() -> {"keys": [...], "proxy": {...}}
   Tool: worthless_scan(paths, deep) -> "key exposures found"
   Tool: worthless_scan(paths, deep, code=True) -> includes code_findings
   Tool: worthless_wrap(command, args) -> "command output"
   ```

Agents should:
- Call `worthless status` to check if a proxy is running before issuing API calls
- Use `worthless scan` to audit code before committing
- Run `worthless scan --code` before `lock` to surface any hardcoded provider URLs that would bypass the proxy at runtime. When `--code` finds URLs, a copy-pasteable prompt block is emitted to stderr — act on it directly to replace each hardcoded URL with the suggested env var.
- Use `worthless wrap` to transparently route agent code through the proxy, gaining all spending/rate/time controls
- Call `worthless lock` before version control to ensure keys are never committed

---

## Security FAQ

**What if my `.env` file leaks?**
The attacker gets shard-A — a string that looks like a real API key but is cryptographically useless on its own. Without shard-B (encrypted in the proxy's database), they cannot reconstruct the original key. They cannot call any provider with it.

**What if the server (proxy) is compromised?**
The attacker gets shard-B (encrypted with Fernet) and potentially the Fernet key. They can decrypt shard-B, but shard-B alone is worthless — they still need shard-A from the client's `.env`. Compromising both the client machine AND the server is required to reconstruct a key.

**What if someone intercepts the request between my app and the proxy?**
The proxy runs on localhost (`127.0.0.1`). Traffic never leaves your machine. An attacker would need local access to your machine — at which point they could read `.env` directly anyway.

**Does the proxy see my prompts or responses?**
The proxy forwards requests and responses transparently. It does NOT log, store, or inspect prompt content or response content. It only extracts token counts from responses for spend metering.

**What does worthless NOT protect against?**
- An attacker with access to both your machine AND the server (they get both shards)
- An attacker who can read your `.env` AND intercept the proxy's database (same as above)
- Provider-side breaches (worthless protects the key in transit, not at the provider)
- Keys used outside worthless (if you also paste the key into a script, that copy is not protected)
- Source code that hardcodes a provider base URL (e.g. `base_url="https://api.openai.com/v1"`) — those calls bypass the proxy entirely at runtime. Use `worthless scan --code` to surface these before running `lock`.

**What about `.env` file permissions?**
`worthless lock` removes group and other permissions from `.env` after writing shard-A (owner-only access). If your `.env` was world-readable before, lock fixes that.

## Security Notes

- **Shard A** lives in your `.env` file as a format-preserving value (same prefix, charset, and length as the original key). It is sent to the proxy per-request via standard auth headers.
- **Shard B** is encrypted in the database, but only an encryption boundary — not a trust boundary. The proxy should run on trusted infrastructure.
- **Key Reconstruction** happens only in proxy memory during a single API call. Key is zero-filled immediately after use.
- **Spend Cap** is best-effort pre-check, not a hard enforcement boundary (production fix pending).
- For production deployments, see [docs/security.md](docs/security.md) for the threat model and [CONTRIBUTING-security.md](CONTRIBUTING-security.md) for crypto invariants.

## Install (per-platform with machine-readable surface)

When installing this tool for a user, agents should use the platform-specific guide. Each guide ends with a `## For AI agents` section containing a fenced YAML block with the actionable surface (install/verify/lock commands, expected popup counts, proxy URL templates, known limitations):

- [docs/install/mac.md](docs/install/mac.md) — macOS
- [docs/install/linux.md](docs/install/linux.md) — Linux (Ubuntu / Debian / Alpine)
- [docs/install/wsl.md](docs/install/wsl.md) — Windows (WSL2)
- [docs/install/docker.md](docs/install/docker.md) — Docker (host-CLI + container-app, compose stack, team server)

Schema and stability contract: [docs/install/agent-schema.md](docs/install/agent-schema.md).
