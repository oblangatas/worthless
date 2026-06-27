# Industry Patterns for `curl | sh` Install Flows

Source: search-specialist agent pass, 2026-04-24. Targets surveyed: `sh.rustup.rs`, `astral.sh/uv/install.sh`, `bun.sh/install`, `get.docker.com`, `install.mise.dev`, `get.ghostty.org`, Claude/Cursor/Aider install paths.

## Worth copying

- **UA-sniff** (rustup pattern): browser hits URL → HTML walkthrough; curl hits URL → script. Zero extra endpoint.
- **Silent-by-default, accept `-y`/`--yes`** (apt, npm, rustup). No industry-wide `CI=1` or curl-header convention exists; the flag is grep-able in agent tool-call logs. Safe.
- **Embed sha256 of fetched binary INSIDE install.sh** (mise pattern). Defense that actually moves the needle in HN threads — a supply-chain compromise of the upstream (Astral/uv) is detected by the pin inside our script.
- **Bun-style banner**: install path + one PATH export line + one next-command. Template:
  ```
  bun was installed successfully to ~/.bun/bin/bun
  Added "~/.bun/bin" to $PATH in ~/.zshrc
  To get started, run:
     exec /bin/zsh && bun --help
  ```
- **Failure copy**: detected-platform summary + ONE troubleshooting URL + `<tool> doctor` command. No phone numbers; GitHub Issues/Discord links are idiomatic.
- **`?explain=1` walkthrough** — novel, nobody ships it. Cheap on a Cloudflare Worker. **Good AI-first differentiator.**

## Worth avoiding

- **Long marketing banner before a prompt** (rustup interactive is tolerable for humans, hostile to agents).
- **"We use TLS" / "script is short, read it"** as a security pitch — pure theater per HN consensus. Skip.
- **Giving Docker equal footing** — every tool surveyed picks a hero install path and lists the rest as alternatives.

## Neutral / low-signal

- GPG-signed variant (mise ships `install.sh.sig`): low user adoption, mild trust signal. Sigstore is the modern replacement.
- Shell-rc auto-edit: universal but universally mildly resented; we should gate behind a prompt.

## Key AI-consent finding

**No industry-standard non-TTY consent signal** beyond `-y`/`--yes`. Safe design for worthless:
- Primary: `--yes` / `-y` flag (rustup, apt convention)
- Secondary: `WORTHLESS_ASSUME_YES=1` env (for CI/Dockerfile where flags are awkward)
- **Never auto-proceed on no-TTY alone** — too dangerous (cron, pipes, ssh). No-TTY without `-y` = hard fail with `error: lock requires --yes in non-interactive mode`.

## Docker positioning

Every surveyed tool that offers both curl|sh and Docker picks curl|sh as hero, Docker as escape hatch. No tool treats them as equals.

Implication for WOR-300: primary landing = curl|sh pitch. Docker path linked below, not prominent.
