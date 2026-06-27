# Docker Container Hardening Research

## Current State

The proxy container already has solid baseline hardening:

| Control | Status |
|---------|--------|
| Non-root user (`worthless`) | Done |
| `read_only: true` | Done |
| `cap_drop: ALL` | Done |
| `no-new-privileges: true` | Done |
| tmpfs `/tmp` with noexec,nosuid | Done |
| Memory limit (512M) | Done |
| CPU limit (1.0) | Done |
| Separate secrets volume | Done |
| Log rotation (10m x 3) | Done |
| Localhost-only port binding | Done |
| Multi-stage build | Done |
| `tini` init process | Done |
| HEALTHCHECK defined | Done |
| `PYTHONDONTWRITEBYTECODE=1` | Done |

This puts us ahead of most projects. The gaps below are incremental improvements.

---

## Gap Analysis (ranked by impact)

### HIGH IMPACT - Implement Now

#### 1. seccomp profile (default or custom)
**What**: Restricts which syscalls the container can make. Docker's default seccomp profile blocks ~44 dangerous syscalls (including `mount`, `reboot`, `kexec_load`).
**Gap**: Not explicitly set. Docker Engine applies a default profile unless overridden, but Compose does not guarantee this in all runtimes (Podman, rootless Docker, cloud container runtimes).
**Fix**: Add `security_opt: - seccomp=default` or ship a custom profile that further restricts to only syscalls Python/uvicorn needs.
**Effort**: Low (one line for default, medium for custom profile)

#### 2. `pids_limit` to prevent fork bombs
**What**: Caps the number of processes inside the container.
**Gap**: Not set. A bug or attack could fork-bomb the host.
**Fix**: `pids_limit: 100` in compose (Python/uvicorn typically needs <20 PIDs).
**Effort**: One line.

#### 3. Network isolation for backend services
**What**: Mark internal networks so containers cannot reach the internet directly.
**Gap**: No network definition. The proxy needs outbound HTTPS to LLM providers, but if Redis/DB services are added later, they should be on `internal: true` networks.
**Fix**: Define two networks: `frontend` (proxy, with external access) and `backend` (internal only, for Redis/DB).
**Effort**: Low. Add now even with single service to establish the pattern.

#### 4. Pin base image by digest, not just tag
**What**: `python:3.12.9-slim` can be republished. Pinning by `@sha256:...` ensures reproducible builds.
**Gap**: Currently pinned by tag only.
**Fix**: `FROM python:3.12.9-slim@sha256:<digest>` and document the update-quarterly process.
**Effort**: Low.

#### 5. Remove shell from runtime image
**What**: Reduces attack surface. If an attacker gets RCE, no shell to drop into.
**Gap**: Runtime image has full `python:3.12.9-slim` including bash, apt, etc.
**Fix**: Two options:
  - **Short term**: `RUN apt-get purge -y --auto-remove bash && rm -f /bin/sh` (breaks CMD shell form -- switch to exec form)
  - **Long term**: Switch to distroless Python base (`gcr.io/distroless/python3-debian12`)
**Effort**: Medium. Requires changing CMD to exec form and testing.

#### 6. HEALTHCHECK should not use Python interpreter
**What**: Current healthcheck spawns a full Python process every 30s. This is slow, uses memory, and requires the Python binary to be reachable.
**Gap**: Uses `python -c "import urllib.request; ..."`.
**Fix**: Use a statically compiled binary like `wget --spider` or a tiny Go healthcheck binary, or simply `test -f /tmp/healthy` with uvicorn writing a sentinel.
**Effort**: Low-medium.

### MEDIUM IMPACT - Implement Soon

#### 7. Image scanning in CI (Trivy)
**What**: Scan built images for known CVEs before pushing.
**Tools comparison**:

| Tool | Free? | CI Integration | Notes |
|------|-------|----------------|-------|
| **Trivy** | Yes, fully OSS | GitHub Actions native | Best free option. Scans OS pkgs + Python deps + Dockerfile misconfig. Fast. |
| **Grype** | Yes, OSS (Anchore) | CLI, easy CI | Good alternative to Trivy. Slightly less Dockerfile analysis. |
| **Dockle** | Yes, OSS | CLI | Focused on Dockerfile best practices (CIS benchmark). Complements Trivy. |
| **Docker Scout** | Free tier (3 repos) | Docker Desktop + CI | Good if using Docker Hub. Limited free tier. |
| **Snyk Container** | Free tier (100 tests/mo) | GitHub, CLI | Good but rate-limited on free tier. |
| **Anchore Engine** | OSS version free | Self-hosted | Heavy. Better for enterprises. |

**Recommendation**: Trivy + Dockle in CI. Trivy for CVEs, Dockle for CIS Docker benchmark compliance.

```yaml
# GitHub Actions snippet
- uses: aquasecurity/trivy-action@v0.28.0
  with:
    image-ref: 'worthless-proxy:${{ github.sha }}'
    severity: 'CRITICAL,HIGH'
    exit-code: '1'
```

#### 8. Image signing with cosign
**What**: Cryptographically sign container images so deployments can verify provenance.
**Gap**: No image signing.
**Fix**: Use `sigstore/cosign` in CI after build. Keyless signing with GitHub OIDC is zero-config.
**Effort**: Medium. Requires container registry (GHCR recommended).

#### 9. `.dockerignore` hardening
**What**: Prevent secrets, tests, and dev files from entering the build context.
**Gap**: Need to verify `.dockerignore` exists and excludes `.env`, `.git`, `tests/`, `.planning/`, etc.
**Fix**: Create/update `.dockerignore`.
**Effort**: Low.

#### 10. User namespace remapping
**What**: Maps container UID 0 to an unprivileged host UID. Even if an attacker escapes to root inside the container, they are unprivileged on the host.
**Gap**: Not configured (requires Docker daemon config, not per-container).
**Fix**: Document as a deployment recommendation. Cannot enforce in compose file alone.
**Effort**: Documentation only.

### LOWER IMPACT - Implement Later

#### 11. AppArmor profile
**What**: MAC (Mandatory Access Control) profile restricting file/network access beyond what Linux DAC provides.
**Gap**: Using Docker's default AppArmor profile (if AppArmor is available on host).
**Fix**: Custom AppArmor profile that restricts the proxy to only: read Python files, write to /tmp and /data, connect to TCP 443 outbound.
**Effort**: High. Requires testing on AppArmor-enabled hosts. Linux-only.

#### 12. Read-only volumes where possible
**What**: Mount `/data` as read-only if the proxy only reads from it (writes happen at enrollment time only).
**Gap**: `/data` is mounted read-write.
**Fix**: If the proxy only reads the DB at runtime, mount `:ro`. Enrollment would need a separate service/container.
**Effort**: Medium. Requires architectural decision about enrollment vs proxy separation.

---

## Secrets in Containers - State of the Art

| Approach | Complexity | Security | Fits Worthless? |
|----------|-----------|----------|-----------------|
| **Env vars** (current) | Trivial | Low (visible in inspect/proc) | Current approach via `env_file`. Acceptable for non-key-material config. |
| **Docker secrets** (Swarm) | Low | Medium (tmpfs-backed, `/run/secrets/`) | Only works in Swarm mode. Not portable. |
| **tmpfs-mounted file** | Low | Medium-High | Already used for fernet key via volume. Could use tmpfs instead of named volume for secrets. |
| **HashiCorp Vault agent** | High | High (dynamic secrets, auto-rotation) | Overkill for V1. Good for Team/Enterprise tier. |
| **SOPS + age** | Medium | Medium-High (encrypted at rest, decrypted at deploy) | Good for encrypted env files in git. Fits self-hosted. |
| **Cloud secret managers** | Medium | High (audit trail, rotation) | AWS Secrets Manager, GCP Secret Manager. Good for cloud deploys. |

**Recommendation for V1**:
1. Keep fernet key on separate volume (already done).
2. Switch `env_file` secrets to Docker secrets or tmpfs-mounted files where possible.
3. Document Vault integration path for Enterprise tier.
4. Consider SOPS + age for encrypted compose env files shipped to self-hosters.

**Critical rule**: The Worthless encryption key (`WORTHLESS_FERNET_KEY_PATH`) MUST NEVER be in an environment variable. File mount only. This is already correct.

---

## Immediate Action Items

These changes can be made in one PR with minimal risk:

### docker-compose.yml additions
```yaml
services:
  proxy:
    # ... existing config ...
    pids_limit: 100
    security_opt:
      - no-new-privileges:true
      - seccomp=default          # explicit, survives runtime changes
    networks:
      - frontend

networks:
  frontend:
    driver: bridge
  backend:
    internal: true               # ready for Redis/DB services
```

### Dockerfile improvements
1. Pin base image by digest
2. Add `.dockerignore` with: `.env`, `.git`, `.planning`, `tests/`, `docs/`, `*.md`, `.beads/`
3. Add `LABEL` metadata (maintainer, version, description)
4. Switch HEALTHCHECK to a lighter mechanism
5. Add `--no-install-recommends` to pip install (already using `--no-cache-dir`)

### CI additions
1. Add Trivy scan step (block on CRITICAL/HIGH)
2. Add Dockle lint step (block on FATAL/WARN)
3. Both are single GitHub Action steps, ~2 min added to CI

---

## Priority Implementation Order

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| P0 | `pids_limit: 100` | 1 line | Prevents fork bombs |
| P0 | Explicit `seccomp=default` | 1 line | Guarantees syscall filtering |
| P0 | `.dockerignore` | New file | Prevents secret/dev file leakage |
| P1 | Pin base image by digest | 1 line change | Reproducible builds |
| P1 | Trivy in CI | ~10 line workflow | Catches CVEs before deploy |
| P1 | Dockle in CI | ~10 line workflow | CIS Docker benchmark |
| P1 | Network isolation | ~5 lines | Defense in depth |
| P2 | Lighter healthcheck | Small refactor | Reduces attack surface |
| P2 | Remove/minimize shell | Medium refactor | Reduces post-exploit surface |
| P2 | cosign image signing | CI addition | Supply chain security |
| P3 | Custom seccomp profile | Research + testing | Minimal syscall whitelist |
| P3 | SOPS for env files | Tooling addition | Encrypted secrets at rest |
| P3 | Distroless base image | Significant refactor | Minimal attack surface |
