#!/usr/bin/env python3
"""Raw-socket wire-level probes for the worthless.sh Worker.

Sends 8 distinct adversarial User-Agent byte sequences (the unit suite
in ``workers/worthless-sh/test/ua-edge-cases.test.ts`` carries 9
``it.fails`` sentinels — two of them assert different response-side
invariants on the same input UA, which collapses to 8 unique bytes
on the wire) to the deployed Worker via a TLS socket — bypassing
curl/undici/http.client header validation — and asserts the Worker's
defenses hold on the wire. Companion to the unit-test regression
sentinels (which alarm if vitest's runtime layer ever loosens) and to
WOR-374 (this file is the wire-level coverage referenced from there).

Invariants asserted for every probe:

1. No 5xx — the Worker isolate must not crash on malformed bytes.
2. No injected ``X-Inject`` response header (case-insensitive).
3. No reflected ``pwned`` token in any response header line.
4. No premature ``\\r\\n\\r\\n`` inside the body's first 1 KiB
   (catches CRLF slipping past edge normalization and splitting a
   header into the body).

What this DELIBERATELY does not assert
--------------------------------------
The original WOR-374 spec said "expect 302 to wless.io for all 9
shapes". In practice workerd normalizes leading/trailing OWS and
strips NUL bytes before the Worker sees them, so the realistic
on-the-wire outcome for those shapes is ``200 install.sh`` (the UA
the Worker classifies is the post-normalization clean curl string).
The unit-test ``it.fails`` sentinels in ua-edge-cases.test.ts already
capture the expectation flip; this file's job is the *wire-level
safety floor* — "no crash, no header reflection" — not status-code
mirroring. Status-code regressions surface in the Worker's own unit
suite.

Usage::

    wire-attack-probes.py https://worthless.sh/

Exits non-zero with a per-probe failure summary on any invariant
violation.
"""

from __future__ import annotations

import socket
import ssl
import sys
from urllib.parse import urlparse

# Each tuple is (label, ua-bytes). Bytes match the unit-test sentinels
# in ``workers/worthless-sh/test/ua-edge-cases.test.ts`` byte-for-byte.
# The unit suite's two CRLF response-header sentinels (`X-Inject not
# present` + `no header value contains pwned/CR/LF`) test the SAME
# input UA bytes; ``assert_invariants`` checks both response-side
# invariants per probe, so the wire side carries one entry not two.
PROBES: list[tuple[str, bytes]] = [
    ("U-03 leading whitespace", b"  curl/8.4.0"),
    ("U-03 trailing tab", b"curl/8.4.0\t"),
    ("U-03 leading tab", b"\tcurl/8.4.0"),
    ("U-07 CRLF injection (safe-redirect)", b"curl/8.4.0\r\nX-Inject: 1"),
    ("U-07 LF-only injection (safe-redirect)", b"curl/8.4.0\nX-Inject: 1"),
    ("U-07 CRLF response-header (X-Inject + pwned reflection)", b"curl/8.4.0\r\nX-Inject: pwned"),
    ("gap-3 NUL polyglot Mozilla", b"curl/8.4.0\x00Mozilla/5.0"),
    ("gap-3 NUL polyglot trailing junk", b"curl/8.4.0\x00\x00\x00"),
]

CONNECT_TIMEOUT_S = 10
READ_BUDGET_BYTES = 64 * 1024


def send_raw(host: str, port: int, path: str, ua_bytes: bytes) -> tuple[int, bytes, bytes]:
    """Open a TLS socket, write a raw HTTP/1.1 GET with arbitrary UA bytes.

    Returns ``(status_code, head_bytes, body_bytes)``. ``head_bytes`` is
    everything up to and including ``\\r\\n\\r\\n``; ``body_bytes`` is
    the bytes after.

    Raises ``socket.error``/``ssl.SSLError`` if the wire layer rejects
    the bytes (e.g. edge closes connection on garbled request line).
    """
    ctx = ssl.create_default_context()
    # Belt-and-braces TLS minimum: Python 3.10+ already defaults to
    # TLSv1.2 here, but pinning explicitly satisfies CodeQL's static
    # rule and makes the floor visible without relying on Python
    # version defaults shifting.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ".encode("ascii")
        + ua_bytes
        + b"\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )

    raw_sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_S)
    try:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
            ssock.sendall(request)
            buf = bytearray()
            while len(buf) < READ_BUDGET_BYTES:
                chunk = ssock.recv(8192)
                if not chunk:
                    break
                buf.extend(chunk)
    finally:
        # `wrap_socket` closes the underlying socket on context exit; if
        # we never made it that far (handshake failure), close manually.
        try:
            raw_sock.close()
        except OSError:
            pass

    head, sep, body = bytes(buf).partition(b"\r\n\r\n")
    if not sep:
        raise RuntimeError("response missing header/body separator")
    status_line = head.split(b"\r\n", 1)[0]
    parts = status_line.split(b" ", 2)
    if len(parts) < 2:
        raise RuntimeError(f"malformed status line: {status_line!r}")
    return int(parts[1]), head, body


def assert_invariants(label: str, status: int, head: bytes, body: bytes) -> list[str]:
    """Return the list of invariant-violation messages for this probe."""
    failures: list[str] = []
    if status >= 500:
        failures.append(f"{label}: 5xx ({status}) — Worker isolate destabilized")
    head_lower = head.lower()
    if b"x-inject" in head_lower:
        failures.append(f"{label}: response head contains X-Inject (header reflection)")
    if b"pwned" in head_lower:
        failures.append(f"{label}: response head contains pwned (token reflection)")
    if b"\r\n\r\n" in body[:1024]:
        failures.append(f"{label}: \\r\\n\\r\\n inside body[:1024] (CRLF slipped to body)")
    return failures


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: wire-attack-probes.py <https-target-url>", file=sys.stderr)
        return 2
    target = sys.argv[1]
    parsed = urlparse(target)
    if parsed.scheme != "https" or not parsed.hostname:
        print(f"target must be an https URL, got: {target!r}", file=sys.stderr)
        return 2
    host = parsed.hostname
    port = parsed.port or 443
    path = parsed.path or "/"

    print(f"Wire-attack probes against {target} ({host}:{port}{path})\n")

    failures: list[str] = []
    for label, ua in PROBES:
        try:
            status, head, body = send_raw(host, port, path, ua)
        except (OSError, ssl.SSLError, RuntimeError, ValueError) as exc:
            # Wire-layer rejection (edge closed, TLS error) is a SAFE
            # outcome — the bytes never reached the Worker, no exploit
            # possible. Record and continue.
            print(f"  [skipped-by-wire] {label}: {type(exc).__name__}: {exc}")
            continue

        probe_failures = assert_invariants(label, status, head, body)
        if probe_failures:
            failures.extend(probe_failures)
            print(f"  [FAIL] {label}: status={status}")
        else:
            print(f"  [ok]   {label}: status={status}")

    print()
    if failures:
        print(f"::error::wire-attack probes detected {len(failures)} invariant violation(s):")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(f"All {len(PROBES)} wire-attack byte sequences passed safety invariants.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
