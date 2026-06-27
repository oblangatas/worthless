# NOTE: pin patch versions; update quarterly or on CVE.
FROM python:3.13-slim-bookworm@sha256:fcbd8dfc2605ba7c2eca646846c5e892b2931e41f6227985154a596f26ab8ed7 AS builder

WORKDIR /build
COPY pyproject.toml ./
COPY src/ src/

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir .

# -----------------------------------------------------------
FROM python:3.13-slim-bookworm@sha256:fcbd8dfc2605ba7c2eca646846c5e892b2931e41f6227985154a596f26ab8ed7

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 10001 worthless \
    # gid 10002 is the sidecar's exclusive group — proxy uid is not a
    # member, so when fernet.key chowns to worthless-crypto:worthless-crypto
    # 0400 (under WORTHLESS_FERNET_IPC_ONLY=1) the kernel rejects open()
    # from the proxy. See deploy/entrypoint.sh.
    && groupadd -r -g 10002 worthless-crypto \
    && useradd -r -u 10001 -g worthless -d /data -s /sbin/nologin worthless-proxy \
    && useradd -r -u 10002 -g worthless -G worthless-crypto -d /nonexistent -s /sbin/nologin worthless-crypto \
    && mkdir -p /data /secrets /run/worthless \
    && chown worthless-proxy:worthless /data \
    # CR-3204010091 (MAJOR): /secrets must NOT be proxy-writable.  A
    # proxy-RCE could otherwise unlink/replace fernet.key inside the
    # secrets volume.  Keep /secrets root:worthless 0750 — root owns,
    # worthless group can list+traverse so the sidecar (worthless-crypto)
    # can read fernet.key when WORTHLESS_FERNET_KEY_PATH points there;
    # the proxy uid (also in group worthless) gets only group r-x which
    # cannot create/unlink files at the dir level.
    && chown root:worthless /secrets \
    && chmod 0750 /secrets \
    && chown root:worthless /run/worthless \
    && chmod 0770 /run/worthless \
    # OpenClaw shared-config dir (#192): pre-created so `worthless lock` can
    # detect openclaw before the openclaw container starts. entrypoint.sh
    # seeds openclaw.json and widens the mode at runtime when
    # WORTHLESS_OPENCLAW_CONFIG_SHARED=1; default mode stays restrictive.
    && mkdir -p /data/.openclaw \
    && chown worthless-proxy:worthless /data/.openclaw

COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin/worthless /usr/local/bin/worthless
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY deploy/entrypoint.sh /entrypoint.sh
COPY deploy/start.py /deploy/start.py

# HOME=/data so Path.home() resolves to the writable /data volume, not
# /home/worthless on the read-only root. The user-provider registry
# (`worthless providers register` writes ~/.worthless/providers.toml)
# would otherwise fail mid-write under read_only:true. 8rqs's lock-time
# URL validation (M3) makes the registry mandatory for non-bundled
# upstreams, so this is now a hard correctness need.
ENV WORTHLESS_HOME=/data \
    WORTHLESS_DB_PATH=/data/worthless.db \
    WORTHLESS_SHARD_A_DIR=/data/shard_a \
    HOME=/data \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8787 \
    WORTHLESS_SIDECAR_SOCKET=/run/worthless/sidecar.sock \
    WORTHLESS_PROXY_UID=10001 \
    WORTHLESS_PROXY_GID=10001 \
    WORTHLESS_FERNET_IPC_ONLY=1

EXPOSE 8787

# WOR-466: hybrid sidecar healthcheck — proves the AF_UNIX accept loop is
# alive end-to-end (stat + S_ISSOCK + IPC HELLO handshake). The previous HTTP
# /healthz probe only proved uvicorn was answering, missing the false-greens
# the WOR-310 spec called out (stale socket inode, hung accept loop).
# Exec form skips /bin/sh: ~10ms faster per probe and avoids signal-forwarding
# bugs. See .planning/wor-310/design-sidecar-health-cli.md.
HEALTHCHECK --interval=10s --timeout=2s --start-period=5s --retries=3 \
    CMD ["python", "-m", "worthless.sidecar.health"]

# WOR-310: no static USER directive — container starts as root so deploy/start.py
# can spawn the sidecar as worthless-crypto (uid 10002) and drop self to
# worthless-proxy (uid 10001) before exec uvicorn. A pre-dropped uid cannot
# call setresuid() to a different uid; the runtime priv-drop dance requires
# the entrypoint to begin as root.

# Self-documenting security contract: docker inspect surfaces these so
# operators see what flags the security claim depends on.
#
# Capability note: ``--cap-drop=ALL`` is INCOMPATIBLE with the WOR-310
# runtime priv-drop dance — six caps are needed *briefly* during
# entrypoint bootstrap + the priv-drop dance, all cleared by the
# preexec_fn before exec so the post-drop process has zero caps:
#   * SETUID / SETGID — setresuid/setresgid/setgroups
#   * SETPCAP        — prctl(PR_CAPBSET_DROP)
#   * DAC_OVERRIDE   — entrypoint bootstrap writes into /data, which
#                      is owned by worthless-proxy (uid 10001);
#                      without DAC_OVERRIDE root is treated as "other"
#                      and mkdir /data/shard_a hits EACCES.
#   * CHOWN          — chown bootstrap output to worthless-proxy
#                      after first boot.
#   * FOWNER         — chmod fernet.key to 0400 (non-root-owned file).
# Phase C's priv-drop achieves the SAME end-state as ``--cap-drop=ALL``
# because the preexec_fn calls ``prctl(PR_CAPBSET_DROP, cap)`` for
# cap 0..63 immediately before setresuid — by the time uvicorn execs,
# the bounding set is empty.
LABEL org.worthless.required-run-flags="--security-opt=no-new-privileges"
LABEL org.worthless.recommended-run-flags="--read-only --tmpfs /tmp --tmpfs /run/worthless:uid=0,gid=10001,mode=0770 --cap-drop=ALL --cap-add=SETUID --cap-add=SETGID --cap-add=SETPCAP --cap-add=DAC_OVERRIDE --cap-add=CHOWN --cap-add=FOWNER"

# Bind/host live in entrypoint.sh — don't re-add `--host` here, it bypasses deploy_mode.
ENTRYPOINT ["tini", "--", "/entrypoint.sh"]
# No CMD: deploy/start.py runs the full lifecycle (split + spawn sidecar +
# exec uvicorn) — overriding the command would skip sidecar spawn and break
# the proxy's IPC contract.
