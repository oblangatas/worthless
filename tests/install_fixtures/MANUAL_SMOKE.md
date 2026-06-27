# install.sh manual smoke checklist (WOR-235)

Filled out per release. Run the full list before pushing a new install.sh
to `worthless.sh`.

For supply-chain trust roots, see
[docs/install-security.md](../../docs/install-security.md).

## Pre-flight

- [ ] CI green on `tests.yml`, `install-smoke.yml`, and the Docker integration job for the tagged commit
- [ ] `UV_VERSION` / `ASTRAL_INSTALLER_SHA256` triplet re-verified (see "Bumping UV_VERSION" below)
- [ ] `WORTHLESS_VERSION_PIN` in `install.sh` == latest published PyPI release (bump it when you publish a new release; `release-sync-check.yml` fails if it lags)

## Evidence capture

For every public `curl -sSL https://worthless.sh | sh` smoke below, copy the
terminal output into the release Linear ticket, PR, or release notes. Include:

- the exact install command and installer output
- `worthless --version` or `uv run --no-project worthless --version`
- any failure output and the remediation text the user saw

This checklist is the public-domain release proof. Per-PR CI runs checkout-local
`sh ./install.sh`; it does not prove the deployed `worthless.sh` Worker.

## Personal Mac (current dev machine)

- [ ] Run `curl -sSL https://worthless.sh | sh`
  - Existing uv: re-run is idempotent (fast-path short-circuits when the pinned version is already installed; otherwise `uv tool install --force worthless==<pin>`)
  - Existing pipx-installed worthless: warns with exit 30 + uninstall command
- [ ] Verify activation one-liner matches `$SHELL`
- [ ] After activation, `worthless --version` works
- [ ] Smoke-test `worthless doctor` (if shipped) reports clean

## Fresh DigitalOcean / Hetzner Ubuntu 24.04 droplet

- [ ] Provision smallest box; SSH in
- [ ] Confirm `python3` not installed: `command -v python3` returns nothing
- [ ] `curl -sSL https://worthless.sh | sh`
- [ ] Time-to-success: target <90s on a typical broadband link
- [ ] `source ~/.bashrc && worthless --version` succeeds

## Fresh macOS (clean user account)

- [ ] Create a new user via System Settings (no Homebrew, no Xcode tools)
- [ ] Open Terminal as that user
- [ ] `curl -sSL https://worthless.sh | sh`
- [ ] Verify Gatekeeper does NOT prompt on the uv binary
- [ ] Verify per-shell activation message matches `zsh` (default since Catalina)

## Behind a corporate proxy (squid simulation)

- [ ] `export HTTPS_PROXY=http://localhost:3128 HTTP_PROXY=http://localhost:3128`
- [ ] `curl -sSL https://worthless.sh | sh`
- [ ] If install fails, error message must surface `HTTPS_PROXY` / `UV_PYTHON_INSTALL_MIRROR` / `SSL_CERT_FILE` hints
- [ ] Re-run with `UV_PYTHON_INSTALL_MIRROR` set to internal mirror — must succeed

## WSL2 (Ubuntu under Windows 11)

- [ ] Inside WSL2 home (`~`), `curl -sSL https://worthless.sh | sh` succeeds
- [ ] Inside `/mnt/c/Users/<name>/`, install warns about path location but does not crash

## Negative path

- [ ] Running on Windows native (Git Bash / MINGW): exit 20 with link to `docs.wless.io/install/wsl`
- [ ] Running on macOS 10.15 (Catalina, in a VM): exit 20 with version requirement message
- [ ] `astral.sh` simulated down (block via `/etc/hosts`): exit 10 with proxy / retry hint

## Bumping UV_VERSION

When pulling in a new uv release, the SHA pin in `install.sh` must be
recomputed from the live Astral CDN — not copied from release notes.

- [ ] Set the target version: `NEW=0.11.8`  *(replace with actual)*
- [ ] Fetch + hash the Astral installer:
  ```
  curl -sSL "https://astral.sh/uv/${NEW}/install.sh" | sha256sum
  ```
- [ ] Edit `install.sh`: update `UV_VERSION` and `ASTRAL_INSTALLER_SHA256` together in one commit
- [ ] Edit `tests/install_fixtures/Dockerfile.ubuntu-with-uv` ONLY if the lockstep
      `awk` extraction has been disabled — the fixture sources `UV_VERSION` and
      `ASTRAL_INSTALLER_SHA256` directly from the copied `install.sh` at build
      time, so a single edit in `install.sh` propagates automatically.
- [ ] Re-run `pytest -m docker tests/test_install_docker.py` to confirm the bare-Ubuntu E2E still passes with the new pair

Never accept a SHA256 from a pull request without re-fetching yourself.
A malicious PR that bumps both `UV_VERSION` and the SHA together to
attacker-controlled values is exactly the attack this pin is supposed
to prevent.

## Bumping base image digests (WOR-319)

The Docker fixtures pin every base image by `@sha256:<digest>` instead of a
floating tag (`ubuntu:24.04`). Floating tags let a compromised upstream ship
malware through our matrix. Pinning makes the supply chain reproducible.

When refreshing for a newer minor (e.g. ubuntu 24.04 patch refresh), bump
all fixtures together — partial bumps drift one fixture against another.

- [ ] Resolve the digest for each base via the registry API:
  ```sh
  TOKEN="$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/ubuntu:pull" | jq -r .token)"
  curl -sI -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.oci.image.index.v1+json" \
    "https://registry-1.docker.io/v2/library/ubuntu/manifests/24.04" \
    | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}'
  ```
- [ ] Repeat for `library/alpine:3.20`, `library/debian:12-slim`, `library/ubuntu:22.04`
- [ ] Update every `FROM <name>:<tag>@sha256:<digest>` line under `tests/install_fixtures/`
      in one commit (test_dockerfiles_pin_base_image_digests enforces all-or-nothing)
- [ ] Re-run `pytest tests/test_install_static.py -k pin_base_image_digests` to confirm
- [ ] Re-run `pytest -m docker tests/test_install_docker.py` to confirm matrix still builds

Never accept a digest from a pull request without re-fetching yourself.
The same supply-chain logic applies — a digest pinned to attacker-controlled
content is the attack this pin is supposed to prevent.

## Sign-off

- [ ] All boxes ticked
- [ ] Release tag pushed
- [ ] Linear WOR-235 closed with PR + commit references
