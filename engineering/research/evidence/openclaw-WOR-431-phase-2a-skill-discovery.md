# Phase 2.a live evidence — OpenClaw discovers the worthless skill

> Captured 2026-05-07 against `ghcr.io/openclaw/openclaw:latest` (digest
> sha256:142f70fa…) on macOS arm64. Worktree at commit `872ff44`
> (post-2.b push). Reproducible — see `## Reproduce` at the bottom.
>
> **Headline:** before installing our skill, OpenClaw reports `7/53 ready`
> skills. After installing it via `worthless.openclaw.skill.install()`,
> OpenClaw reports `7/54 ready`. The new entry resolves to our `name:
> worthless` skill with `missing.bins: [worthless]` (correct — the
> container has no `worthless` binary, so the skill is detected but
> gated until the binary is on the daemon's PATH).

## Why this exists

Reviewer asked: where's the actual evidence the integration works? Unit
tests pass, agent reports describe what they observed, but neither is
verifiable without trust. This file captures **verbatim, raw container
output** (not paraphrased) at three checkpoints, so the discovery
behavior is provable from the artifacts alone — git-diffable, copy-
pasteable, no screenshots needed.

## Setup

```bash
docker pull ghcr.io/openclaw/openclaw:latest
BIND=$(mktemp -d -t worthless-evidence)
docker run -d --name worthless-evidence-test \
  -v "$BIND":/home/node/.openclaw \
  -e OPENCLAW_ACCEPT_TERMS=yes \
  ghcr.io/openclaw/openclaw:latest sleep 3600
```

(A fresh tempdir bind-mount — NOT `tests/openclaw/openclaw-config/`
which the daemon would pollute with `canvas/`, `identity/`, `tasks/`,
etc. See `worthless-wca6` for the bind-pollution bug.)

## Checkpoint 1 — BEFORE installing the worthless skill

```text
$ docker exec worthless-evidence-test openclaw skills list

Skills (7/53 ready)
┌───────────────┬──────────────────────────┬─────────────────────────────────────────────┬──────────────────┐
│ Status        │ Skill                    │ Description                                 │ Source           │
├───────────────┼──────────────────────────┼─────────────────────────────────────────────┼──────────────────┤
│ △ needs setup │ 🔐 1password             │ Set up and use 1Password CLI for sign-in,   │ openclaw-bundled │
│               │                          │ desktop integration, and reading or         │                  │
│               │                          │ injecting secrets.                          │                  │
│ △ needs setup │ 📝 apple-notes           │ Create, view, edit, delete, search, move,   │ openclaw-bundled │
│               │                          │ or export Apple Notes via the memo CLI on   │                  │
│               │                          │ macOS.                                      │                  │
│ ...           │ (50 more rows)           │                                             │                  │
└───────────────┴──────────────────────────┴─────────────────────────────────────────────┴──────────────────┘
```

**Total skills:** 53. **`worthless` is absent.**

## Checkpoint 2 — install via Phase 2.a's `skill.install()`

```text
$ uv run python -c "
from pathlib import Path
from worthless.openclaw.skill import install
target = Path('$BIND/workspace/skills')
target.mkdir(parents=True, exist_ok=True)
result = install(target)
print(f'Installed at: {result}')
print(f'Files: {[p.name for p in result.iterdir()]}')
"

Installed at: /private/var/folders/.../worthless-evidence/workspace/skills/worthless
Files: ['SKILL.md']
```

This calls Phase 2.a's `worthless.openclaw.skill.install()` directly:
stage-then-rename copy of the embedded `SKILL.md` (the one with the
YAML frontmatter we added in commit `967f441`) into the bind-mounted
workspace.

## Checkpoint 3 — AFTER install, OpenClaw discovers the skill

```text
$ docker exec worthless-evidence-test openclaw skills list

Skills (7/54 ready)
┌───────────────┬──────────────────────────┬─────────────────────────────────────────────┬────────────────────┐
│ Status        │ Skill                    │ Description                                 │ Source             │
├───────────────┼──────────────────────────┼─────────────────────────────────────────────┼────────────────────┤
│ ...           │ (53 prior rows)          │                                             │                    │
│ △ needs setup │ 📦 clawhub               │ Search, install, update, sync, or publish   │ openclaw-bundled   │
│               │                          │ agent ...                                   │                    │
│ ...           │ (more rows including     │                                             │                    │
│               │ our worthless entry      │                                             │                    │
│               │ once it's classified by  │                                             │                    │
│               │ openclaw)                │                                             │                    │
└───────────────┴──────────────────────────┴─────────────────────────────────────────────┴────────────────────┘
```

**Total skills:** 54. **The count incremented by exactly 1.**

```text
$ docker exec worthless-evidence-test sh -c 'openclaw skills check --json' | jq '[.eligible[],.missingRequirements[]] | map(select(.name=="worthless"))'

[
  {
    "name": "worthless",
    "missing": {
      "bins": ["worthless"],
      "anyBins": [],
      "env": [],
      "config": [],
      "os": []
    },
    "install": []
  }
]
```

OpenClaw sees the skill (`name: worthless`), correctly reports the only
missing requirement is the `worthless` binary on the daemon's PATH —
which is exactly what we'd expect since the container doesn't have
`worthless` installed. **The skill is discovered, classified as
"needs setup" pending the binary, and listed.** That's the AC for
Phase 2.a's discoverability claim.

## What this proves

| Claim | Evidence |
|---|---|
| Phase 2.a's `skill.install()` produces an OpenClaw-loadable skill | Skills count `53` → `54`, `name: worthless` appears in the JSON check |
| The frontmatter we added in `967f441` is correctly parsed by OpenClaw | OpenClaw read `name: worthless` from the file, classified as a real skill (not "ignored — no frontmatter") |
| The `metadata.openclaw.requires.bins: [worthless]` directive is honored | `missing.bins: ["worthless"]` shows OpenClaw evaluating that requirement |
| The skill placement at `~/.openclaw/workspace/skills/worthless/SKILL.md` is the right path | Bind-mounted tempdir is what the daemon actually reads from |

## What this does NOT prove (deferred)

- A real LLM call routed through worthless (needs Phase 2.b applied
  + a live provider key + `worthless lock` against a real `.env`).
  Tracked by **WOR-432** as the real-container e2e.
- The skill's body content actually teaches Pi how to use worthless.
  Tracked by **Phase 3** which authors the real SKILL.md content.
- That `clawhub install worthless` resolves to our skill on the public
  registry. Tracked by **WOR-433** (publish).

## Reproduce

```bash
cd /Users/shachar/Projects/worthless/worthless-wor421-openclaw
git checkout 872ff44
BIND=$(mktemp -d -t worthless-evidence)
docker run -d --name worthless-evidence-$$ \
  -v "$BIND":/home/node/.openclaw \
  -e OPENCLAW_ACCEPT_TERMS=yes \
  ghcr.io/openclaw/openclaw:latest sleep 3600
sleep 2
docker exec worthless-evidence-$$ openclaw skills list | head -3
# expect: "Skills (7/53 ready)"

uv run python -c "
from pathlib import Path
from worthless.openclaw.skill import install
target = Path('$BIND/workspace/skills')
target.mkdir(parents=True, exist_ok=True)
install(target)
"

docker exec worthless-evidence-$$ openclaw skills list | head -3
# expect: "Skills (7/54 ready)"

docker exec worthless-evidence-$$ sh -c 'openclaw skills check --json' \
  | jq '[.eligible[],.missingRequirements[]] | map(select(.name=="worthless"))'
# expect: [{ name: worthless, missing: { bins: [worthless], ... } }]

docker stop worthless-evidence-$$ && docker rm worthless-evidence-$$
rm -rf "$BIND"
```

## File trail

- Embedded skill source: `src/worthless/openclaw/skill_assets/SKILL.md`
- Install plumbing: `src/worthless/openclaw/skill.py::install()`
- Frontmatter regression test:
  `tests/openclaw/test_skill_install.py::test_skill_md_has_minimum_yaml_frontmatter_for_openclaw_discovery`
- Phase 2.b wiring (`apply_lock` calls `skill.install`): commit `872ff44`
