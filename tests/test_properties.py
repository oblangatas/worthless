"""Property-based tests for adapter invariants and crypto roundtrips."""

from __future__ import annotations

import string

import httpx
import pytest
from hypothesis import HealthCheck, given, settings as hsettings
from hypothesis import strategies as st

from tests.helpers import make_streaming_response
from worthless.adapters.anthropic import DEFAULT_ANTHROPIC_VERSION, AnthropicAdapter
from worthless.adapters.openai import OpenAIAdapter
from worthless.adapters.types import AdapterRequest, relay_response, strip_internal_headers
from worthless.crypto.splitter import reconstruct_key, split_key

_HOP_BY_HOP_HEADERS = (
    "connection",
    "transfer-encoding",
    "te",
    "upgrade",
    "proxy-authorization",
    "host",
    "keep-alive",
    "trailer",
    "proxy-connection",
)

_SAFE_HEADER_KEYS = st.from_regex(r"[a-z][a-z0-9-]{0,20}", fullmatch=True).filter(
    lambda key: (
        not key.startswith("x-worthless-")
        and key not in _HOP_BY_HOP_HEADERS
        and key != "anthropic-version"
    )
)
_HEADER_VALUES = st.text(
    alphabet=string.ascii_letters + string.digits + "-_/;= .",
    min_size=0,
    max_size=32,
)
_SAFE_HEADERS = st.dictionaries(
    keys=_SAFE_HEADER_KEYS,
    values=_HEADER_VALUES,
    max_size=6,
)
_API_KEY_STRINGS = st.text(
    alphabet=string.ascii_letters + string.digits + "-_",
    min_size=8,
    max_size=48,
).filter(lambda key: key != "REDACTED")
# bytearray strategy for adapter api_key tests (SR-01: no immutable types for secrets)
_API_KEYS = _API_KEY_STRINGS.map(lambda s: bytearray(s.encode()))


def _apply_case_mask(text: str, mask: list[bool]) -> str:
    """Apply a boolean mask to a string, uppercasing selected characters."""
    chars: list[str] = []
    for idx, char in enumerate(text):
        should_upper = mask[idx] if idx < len(mask) else False
        chars.append(char.upper() if should_upper else char.lower())
    return "".join(chars)


async def _collect_streaming_chunks(response: httpx.Response) -> list[bytes]:
    relayed = await relay_response(response)
    assert relayed.is_streaming is True
    assert relayed.stream is not None
    return [chunk async for chunk in relayed.stream]


def _mask_header_map(headers: dict[str, str], mask: list[bool]) -> dict[str, str]:
    """Apply casing changes across a header map while preserving values."""
    masked_headers: dict[str, str] = {}
    offset = 0
    for key, value in headers.items():
        masked_headers[_apply_case_mask(key, mask[offset : offset + len(key)])] = value
        offset += len(key)
    return masked_headers


class TestHypothesisConfiguration:
    def test_event_stream_property_disables_deadline(self) -> None:
        fn = TestRelayResponseProperties.test_event_stream_responses_yield_original_chunks

        assert fn._hypothesis_internal_use_settings.deadline is None


class TestStripInternalHeadersProperties:
    @given(
        suffix=st.text(
            alphabet=string.ascii_letters + string.digits + "-",
            min_size=1,
            max_size=16,
        ),
        safe_headers=_SAFE_HEADERS,
    )
    def test_internal_prefix_is_always_stripped(
        self, suffix: str, safe_headers: dict[str, str]
    ) -> None:
        raw_headers = dict(safe_headers)
        raw_headers[f"X-WorThLeSs-{suffix}"] = "secret"

        stripped = strip_internal_headers(raw_headers)
        expected_headers = {key.lower(): value for key, value in safe_headers.items()}

        assert stripped == expected_headers

    @given(
        hop_header=st.sampled_from(_HOP_BY_HOP_HEADERS),
        mask=st.lists(st.booleans(), min_size=1, max_size=1_024),
        safe_headers=_SAFE_HEADERS,
    )
    def test_hop_by_hop_headers_are_case_insensitively_stripped(
        self, hop_header: str, mask: list[bool], safe_headers: dict[str, str]
    ) -> None:
        header_name = _apply_case_mask(hop_header, mask[: len(hop_header)])
        raw_headers = dict(safe_headers)
        raw_headers[header_name] = "blocked"

        stripped = strip_internal_headers(raw_headers)
        expected_headers = {key.lower(): value for key, value in safe_headers.items()}

        assert stripped == expected_headers

    @given(
        headers=_SAFE_HEADERS,
        mask=st.lists(st.booleans(), min_size=1, max_size=1_024),
    )
    def test_safe_headers_are_preserved_and_lowercased(
        self, headers: dict[str, str], mask: list[bool]
    ) -> None:
        mixed_case_headers = _mask_header_map(headers, mask)
        stripped = strip_internal_headers(mixed_case_headers)
        assert stripped == {key.lower(): value for key, value in headers.items()}


class TestPrepareRequestProperties:
    # WOR-658 follow-up: input generation under xdist parallel load (10
    # workers) hits Hypothesis's too_slow HealthCheck on some runs. The
    # strategies themselves aren't slow — CPU contention from sibling tests
    # is. Suppress the health check here; the property assertions are still
    # exercised on every generated example.
    @hsettings(suppress_health_check=[HealthCheck.too_slow])
    @given(body=st.binary(max_size=4096), headers=_SAFE_HEADERS, api_key=_API_KEYS)
    def test_openai_prepare_request_preserves_body_and_sets_auth(
        self, body: bytes, headers: dict[str, str], api_key: bytearray
    ) -> None:
        req = OpenAIAdapter().prepare_request(
            body=body, headers=headers, api_key=api_key, base_url="https://api.openai.com/v1"
        )

        assert req.body == body
        assert req.headers["authorization"] == f"Bearer {api_key.decode()}"
        assert req.url.endswith("/v1/chat/completions")

    @given(body=st.binary(max_size=4096), headers=_SAFE_HEADERS, api_key=_API_KEYS)
    def test_anthropic_prepare_request_adds_default_version_when_missing(
        self, body: bytes, headers: dict[str, str], api_key: bytearray
    ) -> None:
        req = AnthropicAdapter().prepare_request(
            body=body, headers=headers, api_key=api_key, base_url="https://api.anthropic.com/v1"
        )

        assert req.body == body
        assert req.headers["x-api-key"] == api_key.decode()
        assert req.headers["anthropic-version"] == DEFAULT_ANTHROPIC_VERSION
        assert req.url.endswith("/v1/messages")

    @given(
        body=st.binary(max_size=4096),
        headers=_SAFE_HEADERS,
        api_key=_API_KEYS,
        version=_HEADER_VALUES.filter(bool),
    )
    def test_anthropic_prepare_request_preserves_explicit_version(
        self, body: bytes, headers: dict[str, str], api_key: bytearray, version: str
    ) -> None:
        raw_headers = dict(headers)
        raw_headers["anthropic-version"] = version

        req = AnthropicAdapter().prepare_request(
            body=body,
            headers=raw_headers,
            api_key=api_key,
            base_url="https://api.anthropic.com/v1",
        )

        assert req.headers["anthropic-version"] == version

    @given(
        body=st.binary(max_size=4096),
        headers=_SAFE_HEADERS,
        api_key=_API_KEYS,
        version=_HEADER_VALUES.filter(bool),
        mask=st.lists(st.booleans(), min_size=1, max_size=1_024),
    )
    def test_anthropic_prepare_request_preserves_explicit_version_case_insensitively(
        self,
        body: bytes,
        headers: dict[str, str],
        api_key: bytearray,
        version: str,
        mask: list[bool],
    ) -> None:
        raw_headers = dict(headers)
        header_name = _apply_case_mask(
            "anthropic-version",
            mask[: len("anthropic-version")],
        )
        raw_headers[header_name] = version

        req = AnthropicAdapter().prepare_request(
            body=body,
            headers=raw_headers,
            api_key=api_key,
            base_url="https://api.anthropic.com/v1",
        )

        assert req.headers["anthropic-version"] == version


class TestAdapterRequestProperties:
    @given(
        authorization=_API_KEY_STRINGS,
        anthropic_key=_API_KEY_STRINGS,
        data=st.data(),
    )
    def test_repr_redacts_sensitive_headers(
        self,
        authorization: str,
        anthropic_key: str,
        data: st.DataObject,
    ) -> None:
        other_headers = data.draw(
            st.dictionaries(
                keys=_SAFE_HEADER_KEYS,
                values=_HEADER_VALUES.filter(
                    lambda value: value not in {"REDACTED", authorization, anthropic_key}
                ),
                max_size=6,
            )
        )
        headers = dict(other_headers)
        headers["authorization"] = authorization
        headers["x-api-key"] = anthropic_key
        req = AdapterRequest(url="https://example.test", headers=headers, body=b"payload")

        text = repr(req)

        assert f"'authorization': '{authorization}'" not in text
        assert f"'x-api-key': '{anthropic_key}'" not in text
        assert "authorization" in text
        assert "x-api-key" in text


class TestRelayResponseProperties:
    @given(
        body=st.binary(max_size=4096),
        content_type=st.sampled_from(
            ["application/json", "text/plain", "application/octet-stream", ""]
        ),
    )
    async def test_non_streaming_responses_preserve_body(
        self, body: bytes, content_type: str
    ) -> None:
        headers = {"content-type": content_type} if content_type else {}
        upstream = httpx.Response(status_code=200, content=body, headers=headers)

        relayed = await relay_response(upstream)

        assert relayed.is_streaming is False
        assert relayed.body == body
        assert relayed.stream is None

    @hsettings(deadline=None)
    @given(
        chunks=st.lists(st.binary(min_size=1, max_size=64), min_size=1, max_size=8),
        extra_param=_HEADER_VALUES,
    )
    async def test_event_stream_responses_yield_original_chunks(
        self, chunks: list[bytes], extra_param: str
    ) -> None:
        content_type = "text/event-stream"
        if extra_param:
            content_type = f"text/event-stream; {extra_param}"

        upstream = make_streaming_response(
            chunks,
            headers={"content-type": content_type},
        )

        collected = await _collect_streaming_chunks(upstream)

        assert collected == chunks


# ------------------------------------------------------------------
# WOR-76: Split/reconstruct roundtrip property tests
# ------------------------------------------------------------------


class TestSplitReconstructProperties:
    """WOR-76: Hypothesis roundtrip property tests for split/reconstruct."""

    @given(key=st.binary(min_size=16, max_size=128))
    @hsettings(max_examples=200)
    def test_split_reconstruct_roundtrip_property(self, key: bytes) -> None:
        """For arbitrary key bytes (16-128 len), split then reconstruct equals original."""
        sr = split_key(key)
        try:
            shard_a_copy = bytearray(sr.shard_a)
            result = reconstruct_key(shard_a_copy, sr.shard_b, sr.commitment, sr.nonce)
            assert bytes(result) == key, (
                f"Roundtrip failed: reconstructed {result!r} != original {key!r}"
            )
        finally:
            sr.zero()

    def test_split_reconstruct_empty_key_rejected(self) -> None:
        """Zero-length key raises ValueError."""
        with pytest.raises(ValueError, match="empty"):
            split_key(b"")

    @given(key=st.binary(min_size=1, max_size=15))
    @hsettings(max_examples=50)
    def test_split_reconstruct_short_keys(self, key: bytes) -> None:
        """Short keys (1-15 bytes) also roundtrip correctly."""
        sr = split_key(key)
        try:
            shard_a_copy = bytearray(sr.shard_a)
            result = reconstruct_key(shard_a_copy, sr.shard_b, sr.commitment, sr.nonce)
            assert bytes(result) == key
        finally:
            sr.zero()
