# WOR-431 — OpenClaw Skill Authoring Spec for Worthless

**Status:** research, ready for implementation
**Parent:** WOR-421 (Worthless ships as a sideloadable OpenClaw skill)
**Related:** see `openclaw.md` (prior; missing in worktree at write-time — open questions answered here)

This doc replaces the prior research's open experiments with concrete results from
running `clawhub@0.12.2`, `ghcr.io/openclaw/openclaw:latest` (image: `2026.5.3-1`),
and dissecting three real bundled skills.

---

## 1. Real skill autopsy

We pulled `gitcrawl`, `clawsweeper`, `discord-clawd` from
`github.com/openclaw/openclaw/tree/main/.agents/skills/`. We also dissected
`1password`, `nano-pdf` (uv install), and `sherpa-onnx-tts` (download install)
because the three originally requested ones use **no install hooks** (they're
internal openclaw maintenance skills, not sideloaded). The richer schema
patterns live in the bundled-but-public skills shipped inside `/app/skills` of
the docker image.

### 1a. `gitcrawl` (in-repo, no install hook — minimal pattern)

Frontmatter, verbatim:

```yaml
---
name: gitcrawl
description: Use gitcrawl for OpenClaw issue and PR archive search, duplicate discovery, related-thread clustering, and local GitHub mirror freshness checks.
metadata:
  openclaw:
    requires:
      bins:
        - gitcrawl
---
```

Body (~70 lines): `# Gitcrawl`, then `## Default Flow`, `## Freshness Rules`,
`## Boundaries`. Tool invocation is documented with bare bash blocks (no MCP
schema). Repeated convention: H2 sections, fenced bash blocks, terse
imperative second-person prose ("Use this skill before...", "Do not...").

### 1b. `clawsweeper` (in-repo, large workflow doc)

```yaml
---
name: clawsweeper
description: Use ClawSweeper to triage OpenClaw issues, scan and review pull requests, and dispatch bounded repair jobs through the official clawsweeper GitHub App.
metadata:
  openclaw:
    requires:
      bins:
        - gh
        - pnpm
---
```

12 KB body. Sections include `## Start`, `## One Bot, One App` (env-var
contract), `## Commit Reports`, `## Sweep Reports`, `## Create One Repair
Job`, `## Replacement PRs`, `## Gates`, `## Trusted Autofix And Automerge`,
`## Security Boundary`, `## Monitoring`. Tool invocation = `pnpm run`
commands and `gh api` calls in fenced blocks. Conventions: H2 per workflow
phase, env-var names in backticks, explicit "Do not" guardrails inline.

### 1c. `discord-clawd` (in-repo, transport-only)

```yaml
---
name: discord-clawd
description: Use to talk to the Discord-backed OpenClaw agent/session; not for archive search.
---
```

**No `metadata.openclaw.requires` block** — pure prompt-only skill. Body
delegates to a sibling `openclaw-relay` skill via python invocations. Useful
counter-example: skills can ship with zero requires, in which case
`skills check` reports them as "Ready" with no checks.

### 1d. `1password` (canonical install-hook reference, JSON-style metadata)

```yaml
---
name: 1password
description: Set up and use 1Password CLI for sign-in, desktop integration, and reading or injecting secrets.
homepage: https://developer.1password.com/docs/cli/get-started/
metadata:
  {
    "openclaw":
      {
        "emoji": "🔐",
        "requires": { "bins": ["op"] },
        "install":
          [
            {
              "id": "brew",
              "kind": "brew",
              "formula": "1password-cli",
              "bins": ["op"],
              "label": "Install 1Password CLI (brew)",
            },
          ],
      },
  }
---
```

Surprises: (a) `metadata` may be JSON5/object-literal not just YAML —
both forms parse. (b) `homepage` is a top-level key. (c) `emoji` is a
real metadata field. (d) `install[*].bins` is what `skills check` greps for
to decide "satisfied".

### 1e. `nano-pdf` (uv install kind — the closest match for Worthless)

```yaml
metadata:
  openclaw:
    emoji: "📄"
    requires: { bins: ["nano-pdf"] }
    install:
      - id: uv
        kind: uv
        package: nano-pdf
        bins: ["nano-pdf"]
        label: "Install nano-pdf (uv)"
```

### 1f. `sherpa-onnx-tts` (download kind — multi-OS asset hooks)

```yaml
install:
  - id: download-runtime-macos
    kind: download
    os: ["darwin"]
    url: "https://github.com/k2-fsa/sherpa-onnx/releases/download/v1.12.23/sherpa-onnx-v1.12.23-osx-universal2-shared.tar.bz2"
    archive: "tar.bz2"
    extract: true
    stripComponents: 1
    targetDir: "runtime"
    label: "Download sherpa-onnx runtime (macOS)"
```

### Repeated conventions across all bundled skills

- `name` = lowercase-kebab, matches dirname.
- `description` = single sentence, "Use ... for ..." or "Use ... to ...".
- `metadata.openclaw.requires.bins` = list of binaries that must resolve on `$PATH`.
- `install[*]` is a list — each entry is one possible install path.
- Body opens with `# <Title>`, then H2 sections. No HTML, no tables.
- Tool invocations = fenced `bash` blocks. No structured tool schema —
  Pi reads the bash and invokes via the shell tool.
- Guardrails are inline text, not separate metadata.

---

## 2. Open experiment results

### 2a. `clawhub install` from a local folder — **NOT SUPPORTED**

```
$ clawhub install --help
Usage: clawhub install [options] <slug>
Install into <dir>/<slug>
Arguments:
  slug                 Skill slug
Options:
  --version <version>  Version to install
  --force              Overwrite existing folder
```

`<slug>` is a registry slug only. `clawhub install ./local-folder` returns
`Skill not found`. There is **no git-URL install path, no relative-path
install path, no tarball install path.** The only ways skills enter a
workspace are:

1. Hand-author into `~/.openclaw/workspace/skills/<name>/SKILL.md` (manually
   installed — `clawhub list` reports them as `Manually installed (not tracked
   by clawhub)`).
2. `clawhub publish <path>` to push to the registry, then `clawhub install
   <slug>` from any machine.
3. `clawhub sync --root <dir>` — scans local folder, requires `clawhub
   login` (auth-gated).

Install hook unattended on Linux: **moot** — there's no `install ./local`
codepath to test. Hooks only run via the registry-fed `skills.install`
gateway action (or interactive `openclaw skills install`).

### 2b. `openclaw skills check` — **rich validator, JSON ready**

```
$ openclaw skills check --help
Usage: openclaw skills check [options]
Check which skills are ready, visible, or missing requirements
```

Run with stub mounted at `/home/node/.openclaw/workspace/skills`:

```
Skills Status Check
Agent: main
```

(text mode is sparse; `--json` is the production interface)

```json
{
  "agentId": "main",
  "workspaceDir": "/home/node/.openclaw/workspace",
  "managedSkillsDir": "/home/node/.openclaw/skills",
  "summary": {
    "total": 54, "eligible": 7, "modelVisible": 7,
    "commandVisible": 6, "disabled": 0, "blocked": 0,
    "agentFiltered": 0, "notInjected": 0, "missingRequirements": 47
  },
  "missingRequirements": [
    { "name": "1password",
      "missing": { "bins": ["op"], "anyBins": [], "env": [], "config": [], "os": [] },
      "install": [{ "id": "brew", "kind": "brew", "label": "...", "bins": ["op"] }]
    },
    ...
  ]
}
```

Visibility taxonomy: `eligible` ⊇ `modelVisible` ⊇ `commandVisible`.
A skill with unmet `requires` lands in `missingRequirements` and is **silently
hidden from the model** until satisfied.

### 2c. `clawhub install` relative path — **NO** (see 2a).
Git URL — **NO**. Only registry slugs. Settled.

### 2d. Skill discovery order — **workspace wins**

Same skill name in both `/home/node/.openclaw/workspace/skills/dup-skill/` and
`/home/node/.openclaw/skills/dup-skill/`:

```
$ openclaw skills info dup-skill
📦 dup-skill ✓ Ready
WORKSPACE COPY - should win.
Details:
  Source: openclaw-workspace
  Path: ~/.openclaw/workspace/skills/dup-skill/SKILL.md
```

Workspace wins. The `Source:` field is exposed (`openclaw-workspace` vs
`openclaw-managed`), so we can ship a managed copy and let users override.

### 2e. Install kinds enumerated from a real instance

From the live image (`skills check --json` of 47 missing-requirement entries):

| `kind` | Required fields | Used by |
|---|---|---|
| `brew` | `formula`, `bins` | 1password, jq, ... |
| `node` | `package`, `bins` | claude, mcp tools |
| `uv` | `package`, `bins` | nano-pdf, python tools |
| `go` | `package` (or `module`), `bins` | blogwatcher |
| `download` | `url`, `archive`, `extract`, `stripComponents`, `targetDir`, optional `os: [...]` | sherpa-onnx, piper models |

**There is no `pipx`, `cargo`, `pip`, `script`, or `shell` kind.** The hook
schema is closed. There's no arbitrary-script escape hatch.

---

## 3. Worthless skill draft

Path: `<repo>/skills/worthless/SKILL.md` (intended to ship via `clawhub
publish skills/worthless` once we have a publisher account).

```yaml
---
name: worthless
description: Use Worthless to lock LLM API keys behind a local spend-cap proxy and route OpenAI/Anthropic traffic through it without leaking the real key into env or processes.
homepage: https://wless.io
metadata:
  openclaw:
    emoji: "🦞"
    os: ["darwin", "linux"]
    requires:
      bins:
        - worthless
    install:
      - id: uv
        kind: uv
        package: worthless
        bins: ["worthless"]
        label: "Install Worthless CLI (uv tool install)"
      - id: brew
        kind: brew
        formula: "worthless"
        bins: ["worthless"]
        label: "Install Worthless CLI (brew)"
---

# Worthless 🦞

Worthless makes API keys worthless to steal. The real key is split client-side
into two halves; every request flows through a local proxy that enforces a
hard spend cap **before** the key ever reconstructs. Budget blown = key
never forms.

## When to use this skill

- User pastes an OpenAI/Anthropic key in chat and asks to use it.
- User wants to cap weekly spend on an LLM key.
- User asks to "wrap" a script or shell so no real key is exposed.

## Setup (90 seconds, once per machine)

```bash
worthless lock --provider openai --json
```

Stores Shard B encrypted; Shard A persists in OS keychain. Output is
`{"alias":"openai-<sha>","shard_a_present":true,"proxy_url":"http://127.0.0.1:8787"}`.

Start the proxy daemon:

```bash
worthless up --json
```

## Run a command with key access

```bash
worthless wrap --provider openai -- python my_script.py
```

Sets `OPENAI_API_KEY` and `OPENAI_BASE_URL` to the proxy alias for the child
process only. The child sees a deterministic alias (`openai-<sha>`), never the
real `sk-...`.

## Inspect status

```bash
worthless status --json
```

Returns proxy health, current spend, cap remaining, alias→provider table.

## Guardrails

- Never echo a raw `sk-*` or `anthropic-*` value back to the user. If the user
  pasted one in chat, the first thing to do is run `worthless lock` to consume
  it; then redact and confirm.
- If `worthless status --json` returns `"proxy":"down"`, run `worthless up`
  before any wrap call.
- If the proxy refuses with `error_code: cap_exceeded`, do **not** retry.
  Surface the error and ask the user to raise the cap.
```

---

## 4. Install hook implementation strategy

**Problem:** the `openclaw.json` baseUrl rewrite Worthless wants (so the
gateway routes provider traffic through the proxy at `127.0.0.1:8787`)
cannot live in a declarative install block — `kind` is closed (brew/uv/node/
go/download). No script escape hatch.

**Pick:** **Companion CLI verb — `worthless openclaw setup`** — invoked by
the user in a one-liner the SKILL.md instructs Pi to run on first activation.

Justification:
- `always: true` skill-on-first-chat is **not a documented openclaw
  feature**; checking the schema, no such field exists.
- A documentation-only "Pi runs `worthless openclaw setup` after install"
  uses Pi's existing shell-tool capability and keeps logic inside our own
  signed CLI binary, not a fragile post-install hook.
- We control idempotency, OS-specific paths, error codes, and `--json`
  output. The skill body's "When to use" first bullet becomes: *"If
  `worthless status --json | jq .openclaw_configured` is false, run
  `worthless openclaw setup --json` first."*
- Reversal is symmetric: `worthless openclaw teardown`.

The hook does:
1. Locate `~/.openclaw/config.toml` (or platform equivalent).
2. Insert/replace `providers.openai.base_url` and `providers.anthropic.base_url`
   to the proxy's bound address from `worthless status --json`.
3. Print a JSON receipt with the diff.

This earns its keep because Pi is trusted to call CLIs, the SKILL.md is the
contract, and we keep config-mutation logic in code we can ship CVE fixes for.

---

## 5. Failure modes discovered

1. **`gitcrawl` and `clawsweeper` are not on ClawHub.** They live only in
   `github.com/openclaw/openclaw/.agents/skills/` and ship as part of the
   workspace bootstrap, not the registry. If we expect users to find Worthless
   via `clawhub search worthless`, **we must publish to the registry** —
   bundling-with-openclaw is not an option for third-party skills.

2. **`clawhub publish` requires auth (`clawhub login`).** Login is OAuth via
   browser. CI publication needs a `CLAWHUB_TOKEN` — the SDK does honor
   tokens (per `clawhub auth`), but rotation policy is undocumented. File a
   blocker before designing CI publish flow.

3. **JSON5 vs YAML metadata is a footgun.** `1password` ships JSON object-
   literal inside a YAML doc. Both parse, but lints (yamllint, prettier) will
   fight us. Recommend strict YAML for our skill — match `nano-pdf` style.

4. **`requires.bins` resolves on `$PATH` of the openclaw process, not the
   user shell.** If the user installs `worthless` via `uv tool install`
   into `~/.local/bin` and that's not on the daemon's PATH, the skill goes
   into `missingRequirements` silently. The skill will say "missing" even
   though `worthless --version` works in the user terminal. Add a doctor
   note: "If `openclaw skills check` says worthless is missing but `which
   worthless` finds it, fix the daemon's `PATH` (launchd `EnvironmentVariables`
   or systemd `Environment=`)."

5. **`os` field at top-level metadata vs inside `install` entry.** The
   `sherpa-onnx-tts` skill uses both — top-level `os: ["darwin","linux","win32"]`
   gates whether the skill loads at all, while per-`install` `os` gates which
   hook fires. Worthless V1 is darwin+linux (no Windows native — WSL is fine
   but requires the user be inside the WSL shell when running openclaw, which
   makes top-level `os` filtering correct).

6. **Skills with no `requires` block always show "Ready".** `discord-clawd`
   has none and shows up in `eligible`. If we ship a stub-only marketing skill
   with zero requires, openclaw will gladly inject it even when worthless isn't
   installed. Always declare `requires.bins: [worthless]`.

7. **Workspace > managed precedence** lets users override our shipped skill
   with a local fork at `~/.openclaw/workspace/skills/worthless/`. Good for
   power-users; means we cannot rely on shipped content to enforce guardrails
   if a user has hand-edited their workspace copy. Treat the SKILL.md as
   advisory, not security-load-bearing.

8. **No `clawhub install` from a folder, git URL, or tarball.** The "easy
   sideload" UX from the WOR-431 title is half a lie — the only frictionless
   sideload is "manually copy SKILL.md to `~/.openclaw/workspace/skills/
   worthless/`". Recommend we ship `worthless openclaw install-skill` that
   does exactly that copy from a binary-embedded SKILL.md, so the user never
   needs `clawhub` at all. Registry publication becomes a nice-to-have
   discovery layer, not the install path.

---

## Open follow-ups (not blocking WOR-431 scope)

- File a Beads ticket: build `worthless openclaw install-skill` /
  `worthless openclaw setup` / `worthless openclaw teardown` (companion
  verbs called out in §4 and §5.8).
- Decide ClawHub publish identity (org account, CI token rotation).
- Decide whether the SKILL.md ships in the python wheel (under
  `worthless/data/skills/worthless/SKILL.md`) so the embedded-copy install
  path works without a network round-trip.
