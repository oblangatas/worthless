# WOR-307 sidecar prototype — single-container topology.
#
# Layout:
#   tini (PID 1, from apt) -> supervise.sh ->
#     + sidecar process (uid worthless-crypto=1002)  binds /var/run/worthless/sidecar.sock
#     + client process  (uid worthless-proxy=1001)   connects and exercises seal/open
#
# The two uids share group `worthless-crypto`, which the socket is
# group-owned by (mode 0660, set by start_sidecar). That lets the
# proxy connect without granting world access.
#
# This image is the v1.1 prototype demonstrating the pattern for
# WOR-309's production proxy deployment and the v2.0 Rust/MPC rewrite.
# It is NOT a shipping artifact; the test harness in
# tests/docker/test_container_smoke.py builds it and runs a roundtrip.
#
# Pin patch versions; update quarterly or on CVE.

# -----------------------------------------------------------
FROM python:3.13-slim-bookworm AS builder

WORKDIR /build
COPY pyproject.toml ./
COPY src/ src/

RUN pip install --no-cache-dir .

# -----------------------------------------------------------
FROM python:3.13-slim-bookworm

# tini     — PID 1 signal handler + reaper
# gosu     — drop-privileges shim used by supervise.sh (safer than su)
# procps   — for `ps`/`kill` inside supervise loop; ~400 KB
RUN apt-get update \
    && apt-get install -y --no-install-recommends tini gosu procps \
    && rm -rf /var/lib/apt/lists/*

# Two uids + shared group so proxy can connect to a 0660 socket owned
# by crypto. useradd -M skips the home dir — neither account needs one.
RUN groupadd -r -g 1002 worthless-crypto \
    && useradd -r -M -u 1002 -g worthless-crypto worthless-crypto \
    && groupadd -r -g 1001 worthless-proxy \
    && useradd -r -M -u 1001 -g worthless-proxy -G worthless-crypto worthless-proxy \
    && mkdir -p /var/run/worthless /secrets \
    && chown worthless-crypto:worthless-crypto /var/run/worthless /secrets \
    && chmod 0750 /var/run/worthless \
    && chmod 0700 /secrets

COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY docker/sidecar/supervise.sh /usr/local/bin/supervise
COPY docker/sidecar/smoke_client.py /usr/local/bin/smoke_client.py
COPY docker/sidecar/gen_shares.py /usr/local/bin/gen_shares.py
RUN chmod 0755 /usr/local/bin/supervise /usr/local/bin/smoke_client.py /usr/local/bin/gen_shares.py

ENV WORTHLESS_SIDECAR_SOCKET=/var/run/worthless/sidecar.sock \
    WORTHLESS_SIDECAR_SHARE_A=/secrets/share_a.bin \
    WORTHLESS_SIDECAR_SHARE_B=/secrets/share_b.bin \
    WORTHLESS_SIDECAR_ALLOWED_UID=1001 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# tini reaps zombies + forwards signals; supervise.sh wires sidecar + client.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/supervise"]
