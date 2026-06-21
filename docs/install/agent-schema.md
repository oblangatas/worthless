---
title: "Install — Agent Schema"
description: "YAML schema for the `## For AI agents` blocks at the bottom of each install guide."
---

# Agent extraction schema (v1)

Each `docs/install/{mac,linux,wsl,docker}.md` ends with a `## For AI
agents` section carrying a fenced YAML block. This file documents the
schema. Agents installing worthless on a user's behalf should treat the
human prose above each `## For AI agents` block as background context,
and the YAML as the actionable surface.

## Schema

```yaml
schema_version: 1
platform: macos | linux | wsl | docker
commands:
  install: <shell command, runs once>
  verify: <shell command, runs after install>
  first_lock: <shell command, runs in a project dir with .env>
  proxy_restart: <shell command, runs after reboot or manual stop>
expectations:
  install_succeeds_silently: <bool — does install produce no popups>
  first_lock_keychain_popups: <int — how many popups on first lock>
  first_lock_requires_human_interaction: <bool — does the agent need to hand control back to a human>
  subsequent_command_keychain_popups: <int — should be 0>
  proxy_starts_automatically_on_lock: <bool>
  proxy_survives_reboot: <bool — true after `worthless service install` on macOS/Linux; false otherwise>
proxy:
  url_template: <string with <alias> placeholder>
  port: <int>
limitations:
  - <one-line text reference to a tracked ticket>
```

### Optional keys

| Key | Used in | Purpose | Sub-keys |
|---|---|---|---|
| `service_install` | `mac.md`, `linux.md` | Managed install via `worthless service install` (preferred). Legacy manual unit copy-paste removed from guides. | `command: <string>`, `verify: <string>`, `uninstall: <string>` |
| `post_lock_required_step` | `docker.md` | Captures the `127.0.0.1` → `host.docker.internal` `.env` rewrite that today's `worthless lock` doesn't auto-do for containers. | `description: <string>`, `sed_command: <string — runnable as-is>`, `linux_extra: <string — Docker-on-Linux-without-Desktop addendum>` |
| `other_scenarios` | `docker.md` | Lists alternate Docker scenarios (compose stack, team server) with their container URL overrides. | List of `{id: <string>, container_url_template: <string with <alias> placeholder>}` |
| `scenario` | `docker.md` | Names the YAML block's default scenario (Scenario A — app in container, worthless on host). | — |
| `proxy.url_template_host` + `proxy.url_template_container` | `docker.md` | Replaces the single `proxy.url_template` for Docker because the host-side and container-side URLs differ (`127.0.0.1:8787` vs `host.docker.internal:8787`). | strings |

## Agent contract

| Rule | Why |
|---|---|
| Tolerate unknown keys | Lets the schema evolve additively without breaking existing agents |
| `schema_version` bumps on **breaking** changes only | Renamed/removed/retyped keys → new version. Additive is free. |
| `first_lock_requires_human_interaction: true` is a hard stop | Agent must hand control back to the human before proceeding. macOS first-lock keychain popup is the v0.3.3 case. |
| Treat YAML as authoritative when it disagrees with prose | Prose is for humans and may lag the YAML. If you find drift, file an issue. |

### What an agent does on a `schema_version` it doesn't recognize

| Agent's pinned version | YAML's version | Required behavior |
|---|---|---|
| ≥ YAML's | ≤ agent's | Proceed normally — backward compatible. |
| `1` | `2+` | **Warn**, then **proceed best-effort** by reading only the keys you recognize. Skip steps whose semantics depend on schema-version-specific keys. Surface the version mismatch to the user. |
| Any | absent | Treat as `1` (this is v0.3.3-era behavior; future PRs may make this a hard fail). |

`schema_version: 1` is the initial schema (added in v0.3.3 via WOR-438). The next breaking change bumps to `2` and updates this section with the explicit migration steps.

## Discoverability

- `SKILL.md` (agent's primary entry point) links here.
- Each platform guide's `## For AI agents` section links here.
- `docs/install/README.md` Known limitations table mentions agent-schema briefly.
