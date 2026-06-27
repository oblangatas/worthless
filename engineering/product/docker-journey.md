# Docker Path UX

Source: ux-researcher Docker pass + review of WOR-249 backlog.

## Journey — P4 (Docker-only)

1. User sees `curl worthless.sh/docker | sh` in README/tweet.
2. Pastes. Terminal:
   ```
   worthless.sh/docker — Docker install path
   Checking Docker... found docker 24.0.7
   Pulling shacharm2/worthless:v0.3.0 (~50MB)...
   ████████████████████████ 100%
   ```
3. Consent prompt (unless `--yes`):
   ```
   About to add alias to ~/.zshrc:
     # BEGIN worthless
     alias worthless='docker run --rm -it -v $PWD:/work -v ~/.worthless:/root/.worthless shacharm2/worthless:v0.3.0'
     # END worthless
   Continue? [y/N]:
   ```
4. `y` → alias written. Banner:
   ```
   ✅ worthless installed via Docker.
   Reload your shell:  exec $SHELL
   Try:                cd your-project && worthless lock
   Source:             https://github.com/shacharm2/worthless
   ```
5. User `exec $SHELL`. Runs `worthless lock`. **Same magic moment as P1**: .env rewritten, backup created, app still works.

## Fail-safes

- Docker missing → `exit 20` + link to `https://docs.docker.com/get-docker/`. Never attempt to install Docker for them.
- Docker present but daemon not running → `exit 21` + `systemctl start docker` hint.
- Pull fails (network/ratelimit) → `exit 10`, retry hint.
- User refuses alias (`n` at prompt) → print alternate usage:
  ```
  Not writing alias. Run worthless with:
    docker run --rm -it -v $PWD:/work -v ~/.worthless:/root/.worthless shacharm2/worthless:v0.3.0 <subcommand>
  ```

## Where consent matters most

**Modifying shell rc file is the consent gate.** Pull is zero-risk (no state change beyond disk cache). Alias write modifies user's shell. Defaults to prompt, `--yes` bypasses.

## AI (P3) Docker flow

AI Claude tells user "I'll install worthless via Docker." Runs `curl worthless.sh/docker | sh -s -- --yes` (or equivalent). Gets structured output. Reports back.

AI variant likely less common (P3 volume is already primarily non-Docker), but shouldn't be blocked. Same `--yes` + JSON output contract as the uv path.

## OpenClaw users (P6) on Docker path

OpenClaw users run Docker? Maybe. But `worthless lock` detection of `openclaw.json` happens INSIDE the container after alias is set up. Same rewrite logic. Works identically.

Open question: does `worthless lock` inside a Docker container see the host's `openclaw.json`? Yes, if `-v $PWD:/work` is mounted (alias does this). OK.

## Banner parity with uv path

Both banners must end with `cd your-project && worthless lock` as the ONE next command. Consistency across install paths is a feature for users switching or asking AIs.

## Discoverability

- README shows both one-liners: curl|sh uv (hero), curl|sh docker (alternate, smaller).
- wless.io landing has a "Docker?" link that goes to a subsection.
- `?explain=1` walkthrough mentions both paths.

## What's NOT in WOR-300

- The Docker Hub image content (WOR-249)
- Non-root user inside container (WOR-249)
- Multi-arch builds (WOR-249)
- Image size optimization (WOR-249)
- Post-install container lifecycle (WOR-249)

WOR-300 ships the **serving** of `/docker` — the content of `docker-install.sh` + the image it pulls are WOR-249's scope.

## Question to escalate to product

Should `/docker` path require explicit `?confirm=1` or just serve immediately? Some tools (mise) gate the docker variant behind a separate URL/flag. Our Worker serves both routes freely; decision: ship freely, let the alias-write prompt be the consent gate inside the script.
