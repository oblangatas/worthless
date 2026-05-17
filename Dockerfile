# NOTE: pin patch versions; update quarterly or on CVE.
FROM python:3.13-slim-bookworm@sha256:f13a6b7565175da40695e8109f64cbc4d2e65f4c9ef2e3b321c3a44fa3c06fe7 AS builder

WORKDIR /build
COPY pyproject.toml ./
COPY src/ src/

RUN pip install --no-cache-dir .

# -----------------------------------------------------------
FROM python:3.13-slim-bookworm@sha256:f13a6b7565175da40695e8109f64cbc4d2e65f4c9ef2e3b321c3a44fa3c06fe7

RUN apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r worthless && useradd -r -g worthless -m worthless \
    && mkdir -p /data /secrets \
    && chown worthless:worthless /data /secrets \
    && mkdir -p /data/.openclaw \
    && chown worthless:worthless /data/.openclaw \
    && chmod 777 /data/.openclaw

COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin/worthless /usr/local/bin/worthless
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY deploy/entrypoint.sh /entrypoint.sh

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
    PORT=8787

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT}/healthz')"

USER worthless

# Bind/host live in entrypoint.sh — don't re-add `--host` here, it bypasses deploy_mode.
ENTRYPOINT ["tini", "--", "/entrypoint.sh"]
