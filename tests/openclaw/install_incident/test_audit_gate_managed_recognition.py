"""WOR-777 Layer 1 — audit gate recognizes worthless's own managed provider.

After F1/WOR-647 worthless writes its inert shard-A into the user's REAL
provider entry (e.g. ``providers.openai``), not a ``worthless-*`` decoy.  The
plaintext-audit gate's name allowlist (``WORTHLESS_OWN_PROVIDERS``) no longer
matches, so on RE-LOCK the gate flags worthless's own shard-A as a leak and
aborts with exit 73 — rotation is impossible (bead worthless-b8me).

The fix recognizes a managed entry the same way WOR-650 does: parse the proxy
alias out of the provider's ``baseUrl`` and check it against this machine's
``shards`` DB (``managed_aliases``).  Recognized entry -> advisory, not
blocking.  These tests are RED until ``recognize_managed_providers`` and the
``recognized_managed`` parameter on ``classify_findings`` exist.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from worthless.openclaw.audit import (
    AuditFinding,
    AuditResult,
    classify_findings,
    recognize_managed_providers,
)

PROXY = "http://127.0.0.1:8787"


def _write_models_json(path: Path, *, provider: str, alias: str, api_key: str) -> None:
    """Write a models.json projection in OpenClaw's runtime shape (no ``models.`` wrapper)."""
    path.write_text(
        json.dumps(
            {
                "providers": {
                    provider: {
                        "api": "openai-completions",
                        "apiKey": api_key,
                        "baseUrl": f"http://127.0.0.1:8787/{alias}/v1",
                        "models": [],
                    }
                }
            }
        ),
        encoding="utf-8",
    )


def _plaintext_finding(file: str, provider: str = "openai") -> AuditFinding:
    return AuditFinding(
        code="PLAINTEXT_FOUND",
        severity="warn",
        file=file,
        json_path=f"providers.{provider}.apiKey",
        message=f"providers.{provider}.apiKey is stored as plaintext.",
        provider=provider,
    )


def _result(finding: AuditFinding) -> AuditResult:
    return AuditResult(
        version=1,
        status="findings",
        files_scanned=(finding.file,),
        plaintext_count=1,
        findings=(finding,),
    )


class TestRecognizeManagedProviders:
    def test_alias_in_db_is_recognized(self, tmp_path: Path) -> None:
        mj = tmp_path / "models.json"
        _write_models_json(mj, provider="openai", alias="openai-32c28ff4", api_key="sk-proj-AAAA")
        recognized = recognize_managed_providers([str(mj)], {"openai-32c28ff4"}, PROXY)
        assert recognized == {(str(mj), "openai")}

    def test_alias_not_in_db_is_not_recognized(self, tmp_path: Path) -> None:
        mj = tmp_path / "models.json"
        _write_models_json(mj, provider="openai", alias="openai-deadbeef", api_key="sk-proj-AAAA")
        assert recognize_managed_providers([str(mj)], {"openai-32c28ff4"}, PROXY) == set()

    def test_none_managed_aliases_recognizes_nothing(self, tmp_path: Path) -> None:
        """DB snapshot failed -> fail-safe: recognize nothing, never silently trust."""
        mj = tmp_path / "models.json"
        _write_models_json(mj, provider="openai", alias="openai-32c28ff4", api_key="sk-proj-AAAA")
        assert recognize_managed_providers([str(mj)], None, PROXY) == set()

    def test_openclaw_json_wrapper_shape_also_recognized(self, tmp_path: Path) -> None:
        """openclaw.json nests providers under ``models.`` — recognition handles both shapes."""
        cj = tmp_path / "openclaw.json"
        cj.write_text(
            json.dumps(
                {
                    "models": {
                        "providers": {
                            "openai": {
                                "apiKey": "sk-proj-AAAA",
                                "baseUrl": "http://127.0.0.1:8787/openai-32c28ff4/v1",
                            }
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        assert recognize_managed_providers([str(cj)], {"openai-32c28ff4"}, PROXY) == {
            (str(cj), "openai")
        }

    def test_foreign_baseurl_alias_not_recognized(self, tmp_path: Path) -> None:
        """A real key pasted under providers.openai with a non-proxy baseUrl must NOT be
        recognized — recognition keys on the worthless proxy alias, not the provider name."""
        mj = tmp_path / "models.json"
        mj.write_text(
            json.dumps(
                {
                    "providers": {
                        "openai": {
                            "apiKey": "sk-proj-REALLEAK",
                            "baseUrl": "https://api.openai.com/v1",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        assert recognize_managed_providers([str(mj)], {"openai-32c28ff4"}, PROXY) == set()

    def test_attacker_host_carrying_managed_alias_not_recognized(self, tmp_path: Path) -> None:
        """SECURITY (brutus): an attacker host that embeds a managed alias in its path
        must NOT be recognized — else a real key in that entry would be demoted past the
        audit gate. The alias is ``provider-sha256(key)[:8]``, computable by anyone."""
        mj = tmp_path / "models.json"
        mj.write_text(
            json.dumps(
                {
                    "providers": {
                        "openai": {
                            "apiKey": "sk-proj-REALLEAK",
                            "baseUrl": "https://evil.example/openai-32c28ff4/v1",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        assert recognize_managed_providers([str(mj)], {"openai-32c28ff4"}, PROXY) == set()

    def test_attacker_same_port_foreign_host_not_recognized(self, tmp_path: Path) -> None:
        """SECURITY (brutus): the worthless port but a foreign host is NOT our proxy."""
        mj = tmp_path / "models.json"
        mj.write_text(
            json.dumps(
                {
                    "providers": {
                        "openai": {
                            "apiKey": "sk-proj-REALLEAK",
                            "baseUrl": "http://evil.example:8787/openai-32c28ff4/v1",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        assert recognize_managed_providers([str(mj)], {"openai-32c28ff4"}, PROXY) == set()

    def test_scheme_mismatch_same_host_port_not_recognized(self, tmp_path: Path) -> None:
        """CodeRabbit (PR #387): the fallback host/port match must also require the
        SAME scheme as the proxy. worthless's proxy is http-only (_DEFAULT_PROXY_BASE_URL);
        an ``https://`` entry on the same host:port cannot be a real worthless-written
        entry — recognizing it anyway would demote a real key past the audit gate."""
        mj = tmp_path / "models.json"
        mj.write_text(
            json.dumps(
                {
                    "providers": {
                        "openai": {
                            "apiKey": "sk-proj-REALLEAK",
                            "baseUrl": "https://127.0.0.1:8787/openai-32c28ff4/v1",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        assert recognize_managed_providers([str(mj)], {"openai-32c28ff4"}, PROXY) == set()

    def test_docker_bridge_host_is_recognized(self, tmp_path: Path) -> None:
        """Cross-environment: worthless wrote a docker-bridge host on the proxy port —
        still ours. The host-pin allows loopback + the Docker bridge, not arbitrary hosts."""
        mj = tmp_path / "models.json"
        mj.write_text(
            json.dumps(
                {
                    "providers": {
                        "openai": {
                            "apiKey": "sk-proj-AAAA",
                            "baseUrl": "http://172.17.0.1:8787/openai-32c28ff4/v1",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        assert recognize_managed_providers([str(mj)], {"openai-32c28ff4"}, PROXY) == {
            (str(mj), "openai")
        }

    def test_malformed_port_baseurl_is_rejected_not_crashing(self, tmp_path: Path) -> None:
        """SECURITY (brutus): a baseUrl whose port can't be parsed (host like
        '127.0.0.1:8787.evil.com') must be rejected, not raise ValueError and crash
        the audit gate."""
        mj = tmp_path / "models.json"
        mj.write_text(
            json.dumps(
                {
                    "providers": {
                        "openai": {
                            "apiKey": "sk-proj-REALLEAK",
                            "baseUrl": "http://127.0.0.1:8787.evil.com/openai-32c28ff4/v1",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        assert recognize_managed_providers([str(mj)], {"openai-32c28ff4"}, PROXY) == set()

    def test_bracketed_non_ipv6_host_is_rejected_not_crashing(self, tmp_path: Path) -> None:
        """SECURITY (brutus): a bracketed non-IPv6 host makes urlsplit raise on
        Python 3.12+ (the proxy runs 3.12; CI runs 3.13) — recognition must reject
        it (return set()), never let ValueError escape and crash the gate."""
        mj = tmp_path / "models.json"
        mj.write_text(
            json.dumps(
                {
                    "providers": {
                        "openai": {
                            "apiKey": "sk-proj-REALLEAK",
                            "baseUrl": "http://[evil.com]:8787/openai-32c28ff4/v1",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        assert recognize_managed_providers([str(mj)], {"openai-32c28ff4"}, PROXY) == set()

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are POSIX-only")
    @pytest.mark.timeout(10)
    def test_named_pipe_is_skipped_not_hung(self, tmp_path: Path) -> None:
        """SECURITY (brutus): a FIFO planted at a scanned path must never be
        read — with no writer, read_text() blocks forever, hanging worthless
        lock's pre-flight audit gate indefinitely. Mirrors the existing
        snapshot_hashes guard."""
        fifo = tmp_path / "models.json"
        os.mkfifo(fifo)
        assert recognize_managed_providers([str(fifo)], {"openai-32c28ff4"}, PROXY) == set()

    def test_missing_file_is_skipped(self, tmp_path: Path) -> None:
        """A path in filesScanned that does not exist is skipped, not an error."""
        assert (
            recognize_managed_providers([str(tmp_path / "nope.json")], {"openai-32c28ff4"}, PROXY)
            == set()
        )


class TestClassifyWithRecognition:
    def test_recognized_managed_provider_is_not_blocking(self) -> None:
        """THE Layer-1 fix: worthless's own shard-A entry -> advisory, re-lock proceeds."""
        finding = _plaintext_finding("/home/node/.openclaw/agents/main/agent/models.json")
        classification = classify_findings(
            _result(finding),
            recognized_managed={(finding.file, "openai")},
        )
        assert classification.blocking == ()
        assert classification.advisory_count == 1

    def test_unrecognized_provider_still_blocks(self) -> None:
        """Regression: a genuinely leaked key (not worthless-managed) still blocks."""
        finding = _plaintext_finding("/home/node/.openclaw/agents/main/agent/models.json")
        classification = classify_findings(_result(finding), recognized_managed=set())
        assert len(classification.blocking) == 1

    def test_recognition_defaults_to_blocking_when_omitted(self) -> None:
        """Back-compat: callers that don't pass recognized_managed get today's behavior."""
        finding = _plaintext_finding("/home/node/.openclaw/openclaw.json")
        classification = classify_findings(_result(finding))
        assert len(classification.blocking) == 1
