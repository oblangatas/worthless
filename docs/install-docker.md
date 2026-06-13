---
title: "Install — Docker"
description: "Pull a pre-built, signed multi-arch image from GHCR."
---

# Install -- Docker (from GHCR)

Pull a pre-built, multi-arch image from the GitHub Container Registry. No clone, no build. Every image is vulnerability-scanned with [Grype](https://github.com/anchore/grype) on both architectures and signed with cosign before publish.

```bash
docker run -d --name worthless -p 127.0.0.1:8787:8787 \
  ghcr.io/shacharm2/worthless-proxy:0.3.7
```

The proxy starts on `localhost:8787`. Enroll your keys exactly like the Compose flow:

```bash
printf '%s' "${OPENAI_API_KEY:?set OPENAI_API_KEY first}" | docker exec -i worthless \
  worthless enroll --alias openai --key-stdin --provider openai
```

For a production setup with volumes, secrets, and resource limits, use [`deploy/docker-compose.yml`](https://github.com/shacharm2/worthless/blob/main/deploy/docker-compose.yml) as a reference — it's the same image wired up with read-only root, capability-dropped, memory-capped.

## Pin the version

```bash
docker pull ghcr.io/shacharm2/worthless-proxy:0.3.7   # recommended
docker pull ghcr.io/shacharm2/worthless-proxy:latest  # moves on every stable release
```

Pin to `:X.Y.Z` in anything you care about. `:latest` moves on every stable tag — fine for trying it out, a silent auto-upgrade footgun for deployed systems.

## Architectures

Both `linux/amd64` and `linux/arm64` (Apple Silicon, Graviton) are published. Docker selects the right one automatically; you don't have to do anything.

## Verify the signature (optional)

Every image is signed with [Sigstore cosign](https://www.sigstore.dev/) using keyless OIDC — no long-lived keys; the signature is cryptographically bound to a tag-triggered run of **this** workflow file (`.github/workflows/publish-docker.yml`) in this repo. Verifying proves the image digest was produced by that specific workflow identity and the tag you pulled resolves to that digest. It defends against tampered registries and images built outside this CI. It does **not** by itself defend against a compromised maintainer with tag-push rights running the legitimate workflow.

```bash
cosign verify ghcr.io/shacharm2/worthless-proxy:0.3.7 \
  --certificate-identity-regexp 'https://github.com/shacharm2/worthless/\.github/workflows/publish-docker\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository shacharm2/worthless
```

The regex pins the verifier to tag-triggered runs of the publish workflow. Install cosign via `brew install cosign` or see [sigstore.dev/install](https://www.sigstore.dev/install).

If you don't run this, you still get [SLSA build provenance](https://slsa.dev/) and an SBOM attached to the image manifest — they're just not cryptographically verified as coming from a specific workflow run.

## Troubleshooting

**`docker pull` returns 403 or 404 right after a new release.**
GHCR packages are private by default on first publish. Our CI tries to flip visibility to public automatically; if that fails the release workflow shows a red "Flip GHCR package visibility" job with the exact `gh api` command to run once. Until that's done, the image exists but isn't pullable.

**`cosign verify` returns "no matching signatures".**
You're probably using an older image published before signing was added (pre v0.3.1), or the identity regex needs to match the owner of the repo you're pulling from (change both `shacharm2` occurrences if you forked).

## Compared to

- [Solo Developer install](/install-solo/) — pipx / pip install, runs on your local machine directly. Simpler, no Docker needed. Recommended for individual dev laptops.
- [Self-hosted Compose config](https://github.com/shacharm2/worthless/tree/main/deploy) — clone the repo, `docker compose up`. Use when you want to customize the build or run the hardened compose configuration.
- This doc — pull the pre-built image. Use when you want the persistent proxy running without cloning anything.
