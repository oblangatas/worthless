# Personas for WOR-300 (worthless.sh install endpoint)

Source: product-manager agent pass, 2026-04-24.

## Ranked by expected first-90-days install volume

1. **P3 — AI agent (autonomous)**. Every Claude Code / Cursor / Aider session that touches a `.env` is a potential installer. Compounds via users who'd never have found us manually. The wedge.
2. **P2 — Non-technical user via AI.** Same flywheel, human in loop. "Claude, protect my OpenAI key" → agent runs the script. Huge latent pool.
3. **P1 — Developer curl-pipe.** HN/Twitter traffic. Spiky, not sustained. Real but smaller than P2+P3.
4. **P4 — Docker-only.** Opinionated minority (~10–15%) who refuse `curl | sh` on principle.
5. **P6 — OpenClaw user.** Uses OpenClaw (third-party AI client) — wants key safety for that tool specifically. Day-1 per product direction.
6. **P5 — Paranoid (`less x.sh`).** Rounding error; design *around* them (auditable script), not *for* them.
7. **P7 — CI/CD pipeline.** GitHub Actions installing worthless to protect keys during test runs. Small now, strategic later. Footnote.

OpenClaw's role clarified: it's a third-party AI client (like Cursor/Cline). Worthless is a provider entry in `openclaw.json`. P6 = OpenClaw users wanting key protection; integration happens via `worthless lock` auto-rewriting `openclaw.json`.

## Magic moments (primary personas)

- **P1 (dev):** `cat .env` after `lock` → real key replaced by token, **app still works**. Zero code changes, key gone from disk.
- **P3 (AI agent):** `worthless lock --json` returns structured success. Agents don't feel delight — they feel *determinism*. Magic = unambiguous exit codes + parseable output.

## Must-be-discoverable within 60s of install

**P1 (dev):**
- `worthless lock` + `worthless up` = two-command story
- `--explain` / `--dry-run` pre-mutation preview
- Link to source + issue tracker in banner
- "Your app code doesn't change" line

**P3 (AI agent):**
- `worthless --help` machine-readable
- `worthless lock --json` / `--dry-run`
- Non-zero exit codes on every failure
- Idempotency guarantee (safe to re-run)
- A single doc URL the agent can fetch

## Product statements

- **P1:** `worthless.sh` exists so that a developer worried about leaking their OpenAI key can replace it with a local proxy token in under 30 seconds.
- **P3:** `worthless.sh` exists so that an AI coding agent can protect its user's API keys without human intervention in a single deterministic command.

## Mis-scoped / drop

- **P5 is vanity.** Keep the script auditable; don't build features for them.
- **P6 belongs on different page** in marketing (openclaw.dev or /self-host) — but `worthless lock` auto-detects openclaw.json on day 1.
- **Enterprise security officer is NOT a P7.** They won't curl-pipe anything; they're a sales motion.
