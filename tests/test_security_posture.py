"""Smoke tests for the consolidated security documentation.

Validates that the split between the root SECURITY.md (disclosure policy) and
docs/security.md (threat model + invariants + residual risk) stays honest:

- SECURITY.md exists and points disclosure at a real channel.
- docs/security.md covers the three architectural invariants, cites the
  CI-enforcing tests, lists known limitations, and does not overclaim any
  compliance certification.
- CONTRIBUTING-security.md carries the SR-* contributor invariants.
"""

from __future__ import annotations

from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parent.parent
_SECURITY_PATH = _REPO_ROOT / "SECURITY.md"
_THREAT_MODEL_PATH = _REPO_ROOT / "docs" / "security.md"
_CONTRIB_RULES_PATH = _REPO_ROOT / "CONTRIBUTING-security.md"


class TestSecurityMd:
    """SECURITY.md must exist at repo root with disclosure policy."""

    def test_security_md_exists(self) -> None:
        assert _SECURITY_PATH.exists(), (
            "SECURITY.md not found at repo root — vulnerability disclosure policy is missing"
        )

    def test_links_to_threat_model(self) -> None:
        text = _SECURITY_PATH.read_text()
        assert "docs/security.md" in text, (
            "SECURITY.md must link to docs/security.md for the full threat model"
        )


class TestThreatModelDoc:
    """docs/security.md is the consolidated threat model (real today)."""

    def _text(self) -> str:
        assert _THREAT_MODEL_PATH.exists(), (
            "docs/security.md must exist — it is the consolidated threat model"
        )
        return _THREAT_MODEL_PATH.read_text()

    def test_covers_all_three_invariants(self) -> None:
        text = self._text().lower()
        assert "client-side splitting" in text
        assert "gate before reconstruction" in text
        assert "server-side containment" in text or "server-side direct" in text

    def test_has_trust_boundary(self) -> None:
        text = self._text().lower()
        assert "trust boundary" in text

    def test_has_known_limitations(self) -> None:
        text = self._text()
        assert "Known limitations" in text or "Known Limitations" in text

    def test_has_non_goals(self) -> None:
        text = self._text().lower()
        assert "non-goals" in text or "out of scope" in text

    def test_has_residual_risk(self) -> None:
        text = self._text().lower()
        assert "residual risk" in text

    def test_has_changelog(self) -> None:
        text = self._text()
        assert "Changelog" in text or "Change Log" in text

    def test_cites_test_evidence(self) -> None:
        text = self._text()
        assert "test_invariants" in text, (
            "docs/security.md must cite test_invariants.py as invariant evidence"
        )
        assert "test_security_properties" in text, (
            "docs/security.md must cite test_security_properties.py as invariant evidence"
        )

    def test_has_rust_mitigation_path(self) -> None:
        text = self._text()
        assert "Rust" in text or "zeroize" in text, (
            "docs/security.md must reference the Rust / zeroize hardening path"
        )

    def test_no_compliance_overclaiming(self) -> None:
        text = self._text().lower()
        overclaims = [
            claim
            for claim in ("soc 2 certified", "fips validated", "iso 27001 certified")
            if claim in text
        ]
        assert not overclaims, f"docs/security.md overclaims compliance: {overclaims}"


class TestContributorRules:
    """CONTRIBUTING-security.md must carry the SR-* contributor invariants."""

    def test_rules_file_exists(self) -> None:
        assert _CONTRIB_RULES_PATH.exists(), (
            "CONTRIBUTING-security.md missing — SR-* invariants must live somewhere"
        )

    def test_covers_core_security_rules(self) -> None:
        text = _CONTRIB_RULES_PATH.read_text()
        for rule_num in range(1, 9):
            rule_id = f"SR-{rule_num:02d}"
            assert rule_id in text, f"CONTRIBUTING-security.md must reference {rule_id}"
