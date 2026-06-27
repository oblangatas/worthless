#!/usr/bin/env python3
"""Container smoke client — exercises the sidecar over the shared socket.

Runs as uid ``worthless-proxy`` (1001) inside the container. Connects
to the sidecar's AF_UNIX socket, does a handshake + seal + open +
attest roundtrip, and exits 0 on success.

Prints one JSON line per step so the test harness can assert on
concrete values rather than greppy substrings.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from worthless.ipc.client import IPCClient


async def _run() -> int:
    socket_path = os.environ.get("WORTHLESS_SIDECAR_SOCKET", "/var/run/worthless/sidecar.sock")
    plaintext = b"hello from worthless-proxy"
    nonce = b"\x00" * 16

    async with IPCClient(socket_path, timeout=5.0) as client:
        print(
            json.dumps({"step": "handshake", "ok": True, "caps": list(client.backend_caps)}),
            flush=True,
        )

        ciphertext = await client.seal(plaintext)
        print(
            json.dumps({"step": "seal", "ok": True, "ct_len": len(ciphertext)}),
            flush=True,
        )

        recovered = await client.open(ciphertext)
        ok = recovered == plaintext
        print(
            json.dumps({"step": "open", "ok": ok, "pt_len": len(recovered)}),
            flush=True,
        )
        if not ok:
            return 1

        evidence = await client.attest(nonce, purpose="smoke")
        print(
            json.dumps({"step": "attest", "ok": True, "evidence_len": len(evidence)}),
            flush=True,
        )

    print(json.dumps({"step": "done", "ok": True}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_run()))
