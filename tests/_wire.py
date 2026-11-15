"""Raw HTTP/1.1 bytes the WOR-1071 tests' fake servers and proxies read and send."""

from __future__ import annotations

import json


def content_length(head: bytes) -> int:
    """The Content-Length of a request or response head, 0 if it has none."""
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            return int(value.strip())
    return 0


def chat_completion(content: str, model: str = "gpt-4o") -> bytes:
    """An OpenAI chat-completion JSON body whose reply is *content*."""
    return json.dumps(
        {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "created": 0,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
    ).encode()


def http_200_json(body: bytes) -> bytes:
    """A complete ``200 OK`` response carrying *body* as JSON, closing the connection."""
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body
    )
