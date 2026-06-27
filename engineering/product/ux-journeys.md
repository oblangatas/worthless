# UX Journey Maps Per Persona

Source: ux-researcher agent pass, 2026-04-24.

## P1 — Dev in terminal

1. Sees tweet/README → copies `curl worthless.sh | sh`. **Friction:** trust. **Gap:** install.sh header comment with sha256 + "run with `?explain=1` to preview".
2. Runs curl → banner scrolls. **Friction:** wall of text. **Gap:** Bun-style 4-line banner only.
3. `cd` into project → runs `worthless lock`. **Friction:** "will this nuke my .env?" **Copy:** `About to rewrite .env (backup: .env.worthless.bak). Swaps OPENAI_API_KEY → proxy token, OPENAI_BASE_URL → http://localhost:8080. Continue? [y/N]`.
4. Sees diff preview (2 lines of `-/+`) **before** prompt. **Gap:** currently missing — add `--dry-run` default-preview.
5. Types `y` → `Locked. Run 'worthless up' then your app normally.`
6. `worthless up` → `Proxy live on :8080. Your app code is unchanged.` **← First value.**

## P2 — Non-tech human via AI

1. Asks ChatGPT "how do I not leak my OpenAI key". AI pastes curl. **Gap:** worthless.sh googleable with "openai key leak".
2. Pastes into terminal → succeeds. **Friction:** "where did it go?" **Copy:** `Installed to ~/.local/bin/worthless`.
3. Banner: `Next: cd <your project folder> && worthless lock`. **Friction:** "what's a project folder?". **Gap:** link to 60-sec video in banner.
4. Runs lock → reads prompt, panics, pastes prompt back to AI. AI says yes. Types y.
5. Runs up → sees success. Runs their app. Works. **← First value.**

## P3 — AI agent (autonomous)

1. User tells Claude "install worthless". Claude reads README.
2. Claude runs `curl worthless.sh | sh` — UA-sniff could flip to `--script` mode (no colors, JSON tail). **Gap:** `WORTHLESS_OUTPUT=json` env.
3. Claude runs `worthless lock -y` in user's project. **Friction:** non-TTY consent.
4. Gets structured output: `{"status":"locked","backup":".env.worthless.bak","rewrote":["OPENAI_API_KEY","OPENAI_BASE_URL"]}`.
5. Runs `worthless up` → JSON `{"status":"up","port":8080}`.
6. Reports to user: "Done, your key is proxied." **← First value.**

## Consent flow (all three, layered)

- `--yes` / `-y` — primary, explicit, matches apt/npm.
- `WORTHLESS_ASSUME_YES=1` — for CI/Dockerfile where flags are awkward.
- **Never auto-proceed on no-TTY alone.** No-TTY without consent = hard fail `error: lock requires --yes in non-interactive mode`.

Safe because: AI must explicitly pass `-y`, which is an auditable action in its tool-call log.

## Failure UX per persona

`install.sh` should detect `-y` / `WORTHLESS_OUTPUT=json` and on failure emit to stderr:

```
{"error":"platform_unsupported","platform":"freebsd","suggest":"docker run shacharm2/worthless"}
```

Exit codes: `1=network, 2=platform, 3=conflict, 4=consent-missing`.

- **P1:** human-readable + "try: `worthless doctor`".
- **P2:** "Something went wrong. Copy this and paste to your AI: `<one line error code>`".
- **P3:** JSON on stderr, exit code, no ANSI.

## Discoverability of lock → up story

Banner alone is insufficient. Multi-touchpoint:

- `install.sh` prints a 3-line demo at tail: `# Try it: cd ~/your-project && worthless lock && worthless up`
- `worthless` with no args → prints the same 3-line story, NOT `--help` dump
- `worthless lock` when no .env exists → `No .env found. Worthless swaps your OPENAI_API_KEY for a local proxy token. Create a .env first, or run 'worthless demo' to see it work.`
- `?explain=1` surfaces the full story pre-install (AI-first differentiator)

## Top remaining frictions per persona

**P1:** (1) `.env` rewrite feels destructive — show diff pre-prompt. (2) PATH export requires new shell — banner must say `exec $SHELL` or `source ~/.zshrc`. (3) `worthless up` daemon lifecycle unclear — add `worthless status`.

**P2:** (1) "cd into your project" is jargon — link a Loom. (2) Consent prompt scary without context. (3) No rollback story surfaced — banner should mention `worthless unlock` exists.

**P3:** (1) No stable JSON contract yet — spec it in WOR-300. (2) Exit codes undefined. (3) Idempotency — running `lock` twice must be safe and report `already_locked`.

## Over/under-designed flags

- **Over:** UA-sniffing for HTML walkthrough — `?explain=1` + plain curl covers 95%. Skip HTML for v1.
- **Under:** `worthless doctor` and `worthless status` — both implied by failure UX above, neither scoped. Spin sub-tickets.
- **Under:** idempotency contract for `lock` — critical for P3, currently unspecified.
