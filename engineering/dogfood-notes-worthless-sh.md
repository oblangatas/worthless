# Dogfood notes — worthless.sh Worker

> Maintainer's first-hand log of running `curl worthless.sh | sh` against the
> deployed Worker. Skeleton lives here from WOR-349 Phase 7; the actual
> dogfood pass happens against the **preview** URL before tagging v0.3.1.
> WOR-389 is the post-production analog and reuses this same checklist.

## What this is

Three things sit between "Worker code passes vitest" and "real users curl this thing":

1. **Delivery integrity** — does the Worker hand back the script bytes the
   build artifact produced? Already covered automated by
   `deploy-worker.yml` (sha256 body + header check) and
   `worker-url-smoke.yml` (curl|sh delivery completes in a hermetic
   container).
2. **Adversarial wire shapes** — does the Worker stay safe under raw-byte
   UA attacks past curl/undici validation? Already covered automated by
   `worker-wire-attacks.yml` (8 unique byte sequences covering the 9
   sentinels from WOR-374 — two sentinels share input bytes, see
   `scripts/wire-attack-probes.py` docstring — byte-for-byte
   mirrored from `ua-edge-cases.test.ts`).
3. **Lived-in maintainer experience** — does the install actually feel
   right on real OSes? PATH guidance correct? Walkthrough copy useful?
   Time-to-binary acceptable? **No automation can answer this.** That is
   what this dogfood pass exists for.

This file is item 3.

## Pre-flight (before the dogfood pass)

- [ ] `deploy-worker.yml` ran successfully against `target=preview` and
      the workers.dev URL is reachable
- [ ] `worker-url-smoke.yml` workflow_dispatch against the preview URL
      passed
- [ ] `worker-wire-attacks.yml` workflow_dispatch against the preview
      URL passed (exits 0 with "All 8 wire-attack byte sequences passed
      safety invariants")
- [ ] You have at least two real OS targets ready (see matrix below)

## Target matrix

| Target | Shell | Notes |
| --- | --- | --- |
| macOS (Apple silicon) | zsh | Default `~/.zshrc` activation path |
| macOS (Intel) | zsh | If still hardware-available |
| Ubuntu 24.04 | bash | LTS happy path |
| Debian stable | bash | apt-Python edge cases |
| Alpine 3.x | ash | musl, no glibc |
| WSL Ubuntu | bash | `/mnt/c` and Windows PATH crosstalk |
| Fedora latest | bash | dnf-Python edge cases |

Aim for at least 3 of these on a release dogfood. Mark each row as it's
exercised.

## Per-target log template

Copy this block per-platform when you actually run the dogfood. Keep it
honest — if something felt confusing, **write the confusion**, even if
you immediately understood it. The friction is the data.

```text
## <YYYY-MM-DD> — <OS / shell>

Preview URL: <https://worthless-sh-preview.<acct>.workers.dev/>
Maintainer:  <name>
Worker tag:  <git ref printed in X-Worthless-Script-Tag>

### Walk

- [ ] `curl <url>` (no pipe) — first 50 lines look right? Walkthrough
      banner readable? Shebang correct?
- [ ] `curl <url>?explain=1` — walkthrough text serves cleanly?
- [ ] `curl <url> | sh` — install completes? PATH guidance accurate
      for this shell?
- [ ] `worthless --version` works without restarting the shell? If
      not, what activation step did the user have to run?
- [ ] Time from `curl` to `worthless --version` succeeding: ____ s
- [ ] Browser visit to the URL — 302 to wless.io fires?

### Issues found

(Empty if clean. Otherwise: shape > what surprised you > severity guess
> proposed Linear ticket title.)

### Notes
```

## Issues found across releases

When a dogfood run surfaces a real issue, file a Linear ticket and link
it here as a one-line entry: `<ticket> — <one-line>`. This file is the
running diary; the ticket is the canonical fix path.

- _(none yet — this section populates as releases dogfood)_

## Cross-references

- `workers/worthless-sh/DEPLOY.md` — operator runbook for the deploy
  itself (one-time setup, per-release procedure, rollback). Different
  audience: that doc is for the person *deploying*; this doc is for the
  person *using* the deployment.
- `.github/workflows/worker-url-smoke.yml` — automated delivery smoke
- `.github/workflows/worker-wire-attacks.yml` — automated wire-level
  safety floor (WOR-374)
- `workers/worthless-sh/test/ua-edge-cases.test.ts` — `it.fails`
  regression sentinels for the runtime-defended attack shapes
- WOR-389 — post-production manual smoke; reuses this checklist
  against `https://worthless.sh/`
