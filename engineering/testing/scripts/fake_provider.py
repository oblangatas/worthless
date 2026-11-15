"""A stand-in OpenAI-style provider for the restart-survival scripts (WOR-861).

Answers 200 ONLY when the request carries the exact original key, so a 200
through the proxy proves the proxy rebuilt the real key — not just that a
process is listening. Anything else gets a 401. The key is never printed.

    EXPECTED_KEY=sk-... python3 fake_provider.py PORT
"""

from __future__ import annotations

import hmac
import http.server
import json
import os
import sys

EXPECTED = ("Bearer " + os.environ["EXPECTED_KEY"]).encode()


class Provider(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        length = int(self.headers.get("content-length") or 0)
        if length:
            self.rfile.read(length)
        got = (self.headers.get("authorization") or "").encode()
        ok = hmac.compare_digest(got, EXPECTED)
        print(f"fake provider: {self.path} key_matches={ok}", flush=True)
        body = (
            {
                "id": "chatcmpl-restart-proof",
                "object": "chat.completion",
                "model": "gpt-4o-mini",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
            }
            if ok
            else {"error": {"message": "invalid key"}}
        )
        payload = json.dumps(body).encode()
        self.send_response(200 if ok else 401)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:  # noqa: A003 — keep output to our one line
        return


if __name__ == "__main__":
    http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Provider).serve_forever()
