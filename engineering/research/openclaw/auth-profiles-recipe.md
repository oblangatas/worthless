# OpenClaw auth-profiles.json — RTFM findings

## Source pages (cited, all fetched & indexed)

- https://docs.openclaw.ai/cli/models (and `.md` mirror) — `openclaw models auth *` commands
- https://docs.openclaw.ai/cli/agents — `openclaw agents add` (does NOT write auth)
- https://docs.openclaw.ai/auth-credential-semantics (and `.md` mirror) — profile types + portability
- https://docs.openclaw.ai/concepts/oauth — exact storage path `~/.openclaw/agents/<agentId>/agent/auth-profiles.json`
- https://docs.openclaw.ai/providers/openai — provider model, `models.providers.openai.baseUrl`, `auth.order.openai`
- https://docs.openclaw.ai/providers/openrouter — OpenRouter base URL `https://openrouter.ai/api/v1` and `OPENROUTER_API_KEY` recipe
- https://docs.openclaw.ai/gateway/authentication — env-var path via `~/.openclaw/.env`

## What was wrong with the prior attempts

1. `models auth paste-token` — **wrong command for an API key**.
   Docs (cli/models.md) state verbatim:
   *"For `openai`, OpenAI API keys and ChatGPT/OAuth token material are different auth shapes. Use `paste-api-key` for `sk-...` OpenAI API keys and `paste-token` only for token auth material."*
   That's why it silently no-op'd into `models.json`.

2. `config set models.providers.openai.apiKey` — writes `openclaw.json`, which is *provider config*, not the agent's auth store. The agent reads `auth-profiles.json` first; provider config `apiKey` is only the literal fallback for non-agent surfaces.

3. `openclaw agents add main` — would not help; `main` is reserved and the agent already exists. `agents add` also only *seeds* portable profiles by copy at create time. It does not paste a new key.

## Profile types (per auth-credential-semantics)

Three kinds live in `auth-profiles.json`:

| `type` | Used for | Portable across agents? |
|---|---|---|
| `api_key` | `sk-...`-style keys (OpenAI, OpenRouter via openai shim) | yes, unless `copyToAgents: false` |
| `token`   | static bearer tokens with optional `expires` | yes |
| `oauth`   | Codex/ChatGPT/Claude OAuth (refresh-token-bearing) | NO by default |

Do not write `type: "aws-sdk"` here — that's routing metadata in `openclaw.json`.

## Exact JSON shape of auth-profiles.json (api_key profile)

Path: `/home/node/.openclaw/agents/main/agent/auth-profiles.json`

```json
{
  "version": 1,
  "profiles": {
    "openai:openrouter": {
      "type": "api_key",
      "provider": "openai",
      "apiKey": "sk-or-v1-...your OpenRouter key...",
      "copyToAgents": true,
      "createdAt": 1717689600000,
      "updatedAt": 1717689600000
    }
  }
}
```

Notes inferred from the docs surface:
- The key map is `profiles[<profileId>]`, profile id is `<provider>:<name>` (default written by `paste-api-key` is `<provider>:manual`).
- `provider` matches the canonical id used in `auth.order.<provider>` and `models.providers.<provider>` — OpenRouter-via-openai uses `openai`.
- For OAuth profiles the same file holds `type: "oauth"` entries with refresh/access material (kept by the runtime as the "token sink" — see /concepts/oauth).

## The exact non-interactive CLI command that writes this file

From cli/models.md (verbatim quote):

> `paste-api-key` accepts API keys generated elsewhere, prompts for the key value, and writes it to the default profile id `<provider>:manual` unless you pass `--profile-id`. In automation, pipe the key on stdin, for example
> `printf "%s\n" "$OPENAI_API_KEY" | openclaw models auth paste-api-key --provider openai`.

Flags honored on `models auth paste-api-key`:
- `--provider <id>`   required
- `--profile-id <id>` optional, defaults to `<provider>:manual`
- `--agent <id>`      target agent's auth store (inherited from parent `models auth --agent`)

### Scriptable command for the `main` agent (no TTY)

```bash
printf '%s\n' "$OPENROUTER_API_KEY" | \
  openclaw models auth --agent main paste-api-key \
    --provider openai \
    --profile-id openai:openrouter
```

That writes the file at `~/.openclaw/agents/main/agent/auth-profiles.json` exactly where the GUI was looking.

## OpenRouter-as-`openai` provider recipe (OpenAI-compatible, baseUrl override)

OpenRouter is OpenAI-compatible. From providers/openrouter and providers/openai (Azure baseUrl override example proves the same pattern works for any custom base URL):

1. Write the API key into the agent's auth store (above).
2. Point the `openai` provider at OpenRouter via `openclaw.json` (provider config layer):

```bash
openclaw config set models.providers.openai.baseUrl "https://openrouter.ai/api/v1"
```

Resulting `openclaw.json` fragment:

```json5
{
  models: {
    providers: {
      openai: {
        baseUrl: "https://openrouter.ai/api/v1"
      }
    }
  }
}
```

3. Optional: pin auth ordering so this profile wins over any other `openai` profile:

```bash
openclaw config set 'auth.order.openai' '["openai:openrouter"]' --strict-json
```

4. Pick a model and verify:

```bash
openclaw models set openai/gpt-4o-mini   # or whatever OpenRouter model id you want via the openai shim
openclaw models auth list --provider openai --agent main --json
openclaw models status --probe --probe-provider openai --agent main
```

WARNING (providers/openrouter): if you repoint to a non-`openrouter.ai/api/v1` base URL, OpenClaw will NOT inject OpenRouter's app-attribution headers or Anthropic cache markers. Use the real OpenRouter base URL above.

Alternative (simpler, no auth-store needed): use the native `openrouter` provider and set `OPENROUTER_API_KEY` in `~/.openclaw/.env`:

```bash
cat >> ~/.openclaw/.env <<'EOF'
OPENROUTER_API_KEY=sk-or-v1-...
EOF
openclaw models set openrouter/auto
```

But the question asked specifically for OpenRouter as `openai` with a baseUrl override; the recipe above is that path.
