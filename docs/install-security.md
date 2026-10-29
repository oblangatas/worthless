---
title: "Install Security"
description: "Supply-chain model for the curl|sh installer."
---

# Install Security

Supply-chain model for `curl -sSL https://worthless.sh | sh`: which hosts
the installer talks to, and what it verifies today.

For general vulnerability reporting, see [SECURITY.md](https://github.com/oblangatas/worthless/blob/main/SECURITY.md).
For the cryptographic architecture, see [security.md](/security/).

## Trust roots

Running `curl -sSL https://worthless.sh | sh` depends on four external
parties. Anyone who can forge TLS or modify the payload can own your box.

| Host | What it serves | How `install.sh` verifies it |
|---|---|---|
| `worthless.sh` (Cloudflare) | `install.sh` itself | TLS only — the user's `curl` trusts the system CA bundle and Cloudflare's cert. |
| `astral.sh` | `uv` installer script | `install.sh` pins `ASTRAL_INSTALLER_SHA256` for a specific `UV_VERSION`. Mismatch → exit `EXIT_NETWORK=10`. |
| Astral release server | `uv` binary + managed Python | `uv`'s own signature verification (out of this installer's scope). |
| `pypi.org` | `worthless` package and its dependencies | HTTPS only. `install.sh` pins the `worthless` version, not its files or its dependencies' versions. See [Dependencies](#dependencies). |

### What this means

- **Compromised Cloudflare or `worthless.sh` DNS → game over.** A malicious `install.sh` served from the canonical URL has the user's trust. The only in-script mitigation is the Astral SHA pin, which stops a substituted uv installer underneath a legit `install.sh`.
- **Compromised Astral → the uv pin catches it** *only if* the attacker doesn't also control `worthless.sh` (a compromised `install.sh` could simply rewrite the pin).
- **MITM by a passive network attacker → TLS catches it.** A TLS-terminating proxy your machine already trusts (e.g. a corporate network) does *not* — see "What this does NOT defend against" below.

## What `install.sh` does NOT verify today

- No detached signature (cosign / minisign) for `install.sh` itself
- No `install.sh.sha256` manifest published alongside it
- No second-reviewer gate on releases (solo maintainer)
- No kill-switch: if `install.sh` is ever discovered to be compromised, there is no pre-wired mechanism to serve a 503 from `worthless.sh` — the only recourse today is revoking Cloudflare credentials and pulling the asset manually

Until those land, users who want stronger guarantees can audit before running.

**Read a plain-English walkthrough of exactly what the script does** (no need to parse shell):

```bash
curl -sSL 'https://worthless.sh?explain=1' | less
```

**Or inspect the raw script and run it locally** rather than piping to `sh`:

```bash
curl -sSL https://worthless.sh -o install.sh
less install.sh    # inspect
sh install.sh
```

There is no `/install.sh` path. The bare `https://worthless.sh` URL *is* the
script — it is served to curl-family clients, while browsers are redirected to
the marketing site. `https://worthless.sh/install.sh` returns `404` by design,
so the installer has exactly one canonical source.

## What this does NOT defend against (and what you can do)

`curl … | sh` runs code before you read it. Be honest about the limits — and what's in your control:

- **Origin compromise is the real risk, not the wire.** The `X-Worthless-Script-Sha256` header lets you confirm the bytes weren't tampered *in transit*, but it comes from the same Worker as the script — so a compromised `worthless.sh` / Cloudflare account / DNS serves a matching malicious script *and* header. The header catches transit and cache tampering; it does **not** prove the origin is honest.
- **The PyPI package: pinned by default, but not byte-verified.** `install.sh` installs a *pinned* `worthless==<version>` (the `WORTHLESS_VERSION_PIN` constant, hand-bumped per release like the `uv` pin and kept at the latest published release; a CI drift check flags it if it falls behind) — **not** whatever PyPI calls `latest`. This closes the window where a brand-new compromised release auto-installs on every fresh `curl … | sh` — the class behind ctx (2022), Ultralytics (2024), and ua-parser-js (2021). It does **not** verify the package *bytes*: `uv tool install` has no `--require-hashes`, so pinning selects *which* release, not *which bytes*. It therefore does not protect against the *pinned* release itself being compromised (a freshly poisoned release at that exact version would still install; PyPI's version immutability does prevent silently swapping bytes under an already-published version). Independent wheel-hash verification is a tracked follow-up. Override the pinned version with:
  ```bash
  WORTHLESS_VERSION=x.y.z curl -sSL https://worthless.sh | sh
  ```
- **A trusted TLS-terminating proxy can rewrite the script.** Plain TLS stops a passive network attacker, but a corporate/MITM proxy your machine already trusts can rewrite the piped bytes. On an untrusted network, download-and-inspect (above) instead of piping straight to `sh`.

Cryptographic receipts you could verify *independently* of `worthless.sh` — cosign/Sigstore signatures and SLSA provenance on the released artifacts — are tracked in [WOR-303](https://linear.app/plumbusai/issue/WOR-303). Until they ship, the controls above are what's real; we'd rather say so than imply more.

## Dependencies

Which versions of worthless's dependencies you get depends on how you install it. CI audits one set: the versions pinned in `uv.lock`, checked by pip-audit on every pull request (`.github/workflows/dependency-audit.yml`). Dependabot proposes a new release as a routine update only after it is 7 days old.

| How you install | Dependency versions you get | Audited? |
|---|---|---|
| Docker image (`ghcr.io/oblangatas/worthless-proxy`) | Exactly the versions in `uv.lock`, so only as new as its last update: a dependency fix reaches the image when `uv.lock` is bumped and a new image is published. Each file is checked against the hash recorded there, and the build stops if `uv.lock` doesn't match `pyproject.toml`. | Yes. The audit checks `uv.lock` on every pull request and every push to main. One gap: the tool that builds worthless itself during the image build (setuptools) is still downloaded unpinned, and it can write to the packages the image ships ([WOR-1084](https://linear.app/plumbusai/issue/WOR-1084)). |
| `install.sh`, `pip install worthless`, `uv tool install`, `uvx` | The newest release of each dependency that meets worthless's minimum versions in `pyproject.toml`, as PyPI has them on the day you install (for `uvx`, the first run: later runs reuse that environment). `pip install worthless` into an environment that already has a dependency keeps the version it has, if that meets the minimum. | No. You can get a version the audit has never seen, including one published minutes ago. |

**What we promise for installs that don't read `uv.lock`: the minimums.** When an advisory is published against a dependency worthless runs, the next release sets that dependency's minimum in `pyproject.toml` past the fix, not just its version in `uv.lock`, even if worthless only uses it through another package. A fresh install of that release can't get the vulnerable version. `cryptography>=50.0.0` (PYSEC-2026-3552) and `msgpack>=1.2.4` (CVE-2026-114613) are two. This is a manual step at release time: no CI check yet fails when a minimum sits below a known-vulnerable version ([WOR-1085](https://linear.app/plumbusai/issue/WOR-1085)).

This does not protect you from:

- **A version published after our release.** A new dependency release, vulnerable or compromised, can reach a fresh install until it is found and either we raise a minimum or PyPI removes it.
- **An install you already have.** It keeps its dependency versions until you refresh them or install a newer worthless release. Running `install.sh` again doesn't refresh them: when the pinned worthless is already installed, it stops there. To pick up a dependency fix and keep the worthless version you have (`worthless --version` shows it):
  - `install.sh` or `uv tool install`: `uv tool install --upgrade "worthless==<version>"`.
  - `pip`: `pip install --upgrade --upgrade-strategy eager "worthless==<version>"`. Plain `--upgrade` changes a dependency only when worthless's minimum requires it.
  - `uvx`: `uvx --refresh "worthless@<version>"`, or `uvx worthless@latest`, which also takes the newest worthless.

  Unlike `install.sh`, these commands read your own uv or pip configuration, including any package index it names. `install.sh` ignores uv's config files and index variables; to do the same, run the `uv` command with `UV_NO_CONFIG=1` and none of `UV_INDEX`, `UV_INDEX_URL`, `UV_DEFAULT_INDEX` or `UV_EXTRA_INDEX_URL` set.

**Why we don't publish a constraints file.** `install.sh` could pass the versions in `uv.lock` to `uv tool install --constraints`. We don't, because:

- It would pin versions, not files. `uv tool install` can't check hashes, so it still wouldn't give you what the Docker image gives you.
- It would hold every new install at release-day versions. That's the trade the Docker image makes, and on every path it would leave no way to get a dependency's fix published after our release until we cut another one. With minimums, a fresh install gets the fix the day it ships.
- It would cover `install.sh` only. `pip install worthless`, `uvx` and the `mcp` extra resolve from the package's own requirements whatever we publish. The minimums are the one rule every path follows.
- `install.sh` would have to fetch the file from another host, adding a trust root to the table above, or carry it inline and keep it in step with each release and with `WORTHLESS_VERSION` overrides.

A 7-day `--exclude-newer` in `install.sh` would bring Dependabot's wait to installs with no file at all. But every release that raised a minimum to a fix published days earlier would fail to install for the rest of that week, and so would each new worthless release, unless `install.sh` carried a hand-kept exemption for each one. A failed install is safer than an unvetted one, but these failures would come exactly when an advisory makes upgrading urgent. So it isn't on by default.

**Which to choose.** The Docker image gives you the versions the audit checked, but a dependency fix reaches it only with our next `uv.lock` update and image. `install.sh` and `pip` give you the newest releases, fixes included, along with versions no one here has audited.

Planned hardening is tracked in Linear under [WOR-257](https://linear.app/plumbusai/issue/WOR-257). This file describes what's real today; controls move in here when they ship.
