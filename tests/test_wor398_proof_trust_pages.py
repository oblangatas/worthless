from __future__ import annotations

from html.parser import HTMLParser
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

RED_POSTS = {
    "red/posts/package-before-build.html": RED / "posts" / "package-before-build.html",
    "red/posts/bitwarden-cli-npm.html": RED / "posts" / "bitwarden-cli-npm.html",
    "red/posts/axios-rat.html": RED / "posts" / "axios-rat.html",
    "red/posts/trapdoor.html": RED / "posts" / "trapdoor.html",
    "red/posts/shai-hulud.html": RED / "posts" / "shai-hulud.html",
    "red/posts/github-action-secrets.html": RED / "posts" / "github-action-secrets.html",
}

AI_SLOP_PHRASES = (
    "in today's rapidly evolving threat landscape",
    "it is important to understand",
    "comprehensive security posture",
    "robust protection",
    "seamlessly empowers",
    "this article explores",
    "public evidence layer",
    "changes what leaks",
)

DRAFT_POST_TITLES = (
    "How leaked AI keys get reused",
    "Provider budgets are not blast-radius controls",
)


class _HeadParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_head = False
        self.links: list[dict[str, str | None]] = []
        self.metas: list[dict[str, str | None]] = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "head":
            self.in_head = True
        elif self.in_head and tag == "title":
            self._in_title = True
        elif self.in_head and tag == "link":
            self.links.append(attrs_dict)
        elif self.in_head and tag == "meta":
            self.metas.append(attrs_dict)

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "head":
            self.in_head = False


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _hrefs(html: str) -> list[str]:
    return re.findall(r'href="([^"]+)"', html)


def _head(path: Path) -> _HeadParser:
    parser = _HeadParser()
    parser.feed(_read(path))
    return parser


def _meta_content(parser: _HeadParser, **attrs: str) -> list[str]:
    matches = []
    for meta in parser.metas:
        if all(meta.get(name) == value for name, value in attrs.items()):
            content = meta.get("content")
            if content:
                matches.append(content)
    return matches


def _canonical(parser: _HeadParser) -> list[str | None]:
    return [link.get("href") for link in parser.links if link.get("rel") == "canonical"]


def _assert_public_social_head(parser: _HeadParser, canonical: str, og_type: str) -> None:
    assert parser.title.strip()
    assert _meta_content(parser, name="description")
    assert _canonical(parser) == [canonical]
    assert _meta_content(parser, property="og:url") == [canonical]
    assert _meta_content(parser, property="og:type") == [og_type]
    assert _meta_content(parser, property="og:site_name") == ["Worthless"]
    assert _meta_content(parser, property="og:image") == ["https://wless.io/og-image.png"]
    assert _meta_content(parser, name="twitter:card") == ["summary_large_image"]
    assert _meta_content(parser, name="twitter:image") == ["https://wless.io/og-image.png"]


def test_wor398_stable_trust_urls_exist_without_owning_red_blog_structure() -> None:
    for page in TRUST_PAGES.values():
        assert page.exists(), f"{page.relative_to(REPO_ROOT)} should exist"

    red_index = _read(RED / "index.html")

    assert "incidents.html" not in _hrefs(red_index)
    assert "claims.html" not in _hrefs(red_index)
    assert "security-model.html" not in _hrefs(red_index)
    assert "Read the claim ledger" not in red_index


def test_red_index_is_attack_blog_not_trust_dashboard() -> None:
    html = _read(RED / "index.html")
    lower = html.lower()

    assert "Red Blog" in html
    assert "Proof surfaces" not in html
    assert "Audit with AI" not in html
    assert "terminal" not in lower
    assert "Review threat reports" not in html
    assert "Read the claim ledger" not in html
    assert "Proof & limits" not in html
    assert "Incident notes" not in html
    assert "Security model" not in html
    assert "Posts stay hidden until they are ready." not in html
    assert lower.count("<section") <= 4


def test_red_index_uses_real_attack_headlines() -> None:
    html = _read(RED / "index.html")

    for required in (
        "How keys get stolen.",
        "The package ran before your build did.",
        "Bitwarden CLI was real. The package went bad.",
        "Axios shipped a RAT for three hours.",
        "TrapDoor hid in npm, PyPI, and crates.",
        "Shai-Hulud put the secrets in public repos.",
        "A GitHub Action printed the secrets.",
    ):
        assert required in html


def test_red_index_links_to_local_writeups_not_external_sources() -> None:
    html = _read(RED / "index.html")
    hrefs = _hrefs(html)

    for label in RED_POSTS:
        assert label.removeprefix("red/") in hrefs

    assert "microsoft.com" not in html
    assert "paloaltonetworks.com" not in html
    assert "stepsecurity.io" not in html
    assert "thehackernews.com" not in html
    assert "wiz.io" not in html


def test_red_writeups_keep_sources_and_worthless_boundaries() -> None:
    expected_sources = (
        "microsoft.com",
        "paloaltonetworks.com",
        "stepsecurity.io",
        "thehackernews.com",
        "wiz.io",
    )

    for path in RED_POSTS.values():
        html = _read(path).lower()
        assert "source:" in html
        assert "worthless" in html
        assert any(source in html for source in expected_sources)
        assert "would have prevented" not in html
        assert "leaks are harmless" not in html
        assert "hard spend cap" not in html


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

    assert "incident notes" in html
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
        *AI_SLOP_PHRASES,
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
    for title in DRAFT_POST_TITLES:
        assert title in posts_js
        assert title not in red_index


def test_red_index_and_writeups_are_indexable_with_social_metadata() -> None:
    red_index = _head(RED / "index.html")

    _assert_public_social_head(red_index, "https://wless.io/red/", "website")
    assert _meta_content(red_index, name="robots") == []

    for label, path in RED_POSTS.items():
        parser = _head(path)
        _assert_public_social_head(parser, f"https://wless.io/{label}", "article")
        assert _meta_content(parser, name="robots") == []


def test_reference_trust_pages_are_stable_but_noindexed() -> None:
    for label, path in TRUST_PAGES.items():
        if label == "red/index.html":
            continue

        parser = _head(path)
        _assert_public_social_head(parser, f"https://wless.io/{label}", "website")
        assert _meta_content(parser, name="robots") == ["noindex, follow"]
