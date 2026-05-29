from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = REPO_ROOT / "docs"
RED = DOCS / "red"

TRUST_PAGES = {
    "red/index.html": RED / "index.html",
    "red/claims.html": RED / "claims.html",
    "red/incidents.html": RED / "incidents.html",
    "red/security-model.html": RED / "security-model.html",
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _hrefs(html: str) -> list[str]:
    return re.findall(r'href="([^"]+)"', html)


def test_wor398_stable_trust_urls_exist_and_are_cross_linked() -> None:
    for page in TRUST_PAGES.values():
        assert page.exists(), f"{page.relative_to(REPO_ROOT)} should exist"

    red_index = _read(RED / "index.html")

    assert "incidents.html" in _hrefs(red_index)
    assert "claims.html" in _hrefs(red_index)
    assert "security-model.html" in _hrefs(red_index)
    assert "Read the claim ledger" not in red_index
    assert "Review threat reports" in red_index


def test_claim_ledger_states_claims_proof_and_limitations() -> None:
    html = _read(RED / "claims.html").lower()

    for required in (
        "what we claim",
        "what we do not claim",
        "copied key alone cannot call the provider",
        "format-preserving .env shard",
        "local proxy",
        "scan --install-hook",
        "provider registry",
        "not a general vault",
        "not a scanner replacement",
        "not native windows support",
        "not all-secret protection",
        "not protection against full same-user host compromise",
    ):
        assert required in html


def test_security_model_summary_uses_public_scope_boundaries() -> None:
    html = _read(RED / "security-model.html").lower()

    for required in (
        "supported ai keys",
        "macos",
        "linux",
        "wsl",
        "no cloud account required",
        "token-budget guardrail",
        "not a hard spend cap",
        "not a general vault",
        "not a replacement for gitleaks or trufflehog",
        "full same-user host compromise",
    ):
        assert required in html


def test_incident_index_is_sourced_and_scoped() -> None:
    html = _read(RED / "incidents.html").lower()

    assert "incident ledger" in html
    assert "source" in html
    assert "what worthless would change" in html
    assert "what worthless would not change" in html
    assert "https://news.ycombinator.com/item?id=47791871" in html
    assert "https://news.ycombinator.com/item?id=47231469" in html
    assert "https://dev.to/ayame0328/" in html


def test_trust_pages_avoid_disallowed_public_claims() -> None:
    banned_phrases = (
        "enforces a hard spend cap",
        "guarantees a hard spend cap",
        "native windows is supported",
        "native windows support is available",
        "aws key",
        "stripe key",
        "github token",
        "protects all secrets",
        "protects any secret",
        "nothing happens if",
        "can't do anything",
    )

    offenders: dict[str, list[str]] = {}
    for label, path in TRUST_PAGES.items():
        html = _read(path).lower()
        found = [phrase for phrase in banned_phrases if phrase in html]
        if found:
            offenders[label] = found

    assert offenders == {}


def test_touched_public_pages_do_not_reference_worthless_cloud() -> None:
    pages = dict(TRUST_PAGES)
    pages["docs/index.html"] = DOCS / "index.html"

    offenders = [label for label, path in pages.items() if "worthless.cloud" in _read(path)]

    assert offenders == []


def test_homepage_keeps_proof_trust_links_minimal() -> None:
    html = _read(DOCS / "index.html")
    hrefs = _hrefs(html)

    assert "red/index.html" in hrefs
    assert "red/claims.html" not in hrefs
    assert "red/security-model.html" not in hrefs
    assert "red/incidents.html" not in hrefs


def test_red_blog_posts_are_hidden_until_publication_flag_changes() -> None:
    posts_js = _read(RED / "red-posts.js")
    red_index = _read(RED / "index.html")

    assert "const SHOW_DRAFT_POSTS = false;" in posts_js
    assert "published: false" in posts_js
    assert 'id="red-post-list"' in red_index
    assert "Coming soon" not in red_index
