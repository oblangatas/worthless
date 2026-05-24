---
title: "Install Security"
description: "Supply-chain model for the curl|sh installer."
---

# Install Security

Supply-chain model for `curl -sSL https://worthless.sh | sh`: which hosts
the installer talks to, and what it verifies today.

For general vulnerability reporting, see [SECURITY.md](../SECURITY.md).
For the cryptographic architecture, see [security.md](security.md).

## Trust roots

Running `curl -sSL https://worthless.sh | sh` depends on four external
parties. Anyone who can forge TLS or modify the payload can own your box.

| Host | What it serves | How `install.sh` verifies it |
|---|---|---|
| `worthless.sh` (Cloudflare) | `install.sh` itself | TLS only — the user's `curl` trusts the system CA bundle and Cloudflare's cert. |
| `astral.sh` | `uv` installer script | `install.sh` pins `ASTRAL_INSTALLER_SHA256` for a specific `UV_VERSION`. Mismatch → exit `EXIT_NETWORK=10`. |
| Astral release server | `uv` binary + managed Python | `uv`'s own signature verification (out of this installer's scope). |
| `pypi.org` | `worthless` package | `uv` uses HTTPS + hash-locked resolution. |

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

Planned hardening is tracked in Linear under [WOR-257](https://linear.app/plumbusai/issue/WOR-257). This file describes what's real today; controls move in here when they ship.
