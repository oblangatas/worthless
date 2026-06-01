from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import re

from defusedxml import ElementTree


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = REPO_ROOT / "docs"

PUBLIC_HTML = {
    "docs/index.html": "https://wless.io/",
    "docs/features.html": "https://wless.io/features.html",
    "docs/how-it-works.html": "https://wless.io/how-it-works.html",
    "docs/blog/index.html": "https://wless.io/blog/",
    "docs/red/index.html": "https://wless.io/red/",
    "docs/memes.html": "https://wless.io/memes.html",
    "docs/coming-soon.html": "https://wless.io/",
}

SEO_DISCOVERY_FILES = [
    "docs/robots.txt",
    "docs/sitemap.xml",
    "docs/llms.txt",
    *PUBLIC_HTML.keys(),
]

NON_RED_SEO_COPY_FILES = [
    "docs/index.html",
    "docs/features.html",
    "docs/how-it-works.html",
    "docs/blog/index.html",
    "docs/coming-soon.html",
    "docs/llms.txt",
]


class _HeadParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_head = False
        self.links: list[dict[str, str | None]] = []
        self.metas: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "head":
            self.in_head = True
        elif self.in_head and tag == "link":
            self.links.append(attrs_dict)
        elif self.in_head and tag == "meta":
            self.metas.append(attrs_dict)

    def handle_endtag(self, tag: str) -> None:
        if tag == "head":
            self.in_head = False


def _head(path: str) -> _HeadParser:
    parser = _HeadParser()
    parser.feed((REPO_ROOT / path).read_text(encoding="utf-8"))
    return parser


def _meta_content(parser: _HeadParser, **attrs: str) -> list[str]:
    matches = []
    for meta in parser.metas:
        if all(meta.get(name) == value for name, value in attrs.items()):
            content = meta.get("content")
            if content:
                matches.append(content)
    return matches


def test_public_seo_surfaces_do_not_reference_worthless_cloud() -> None:
    offenders = [
        path
        for path in SEO_DISCOVERY_FILES
        if "worthless.cloud" in (REPO_ROOT / path).read_text(encoding="utf-8")
    ]

    assert offenders == []


def test_public_pages_use_wless_canonicals_and_social_urls() -> None:
    for path, canonical in PUBLIC_HTML.items():
        parser = _head(path)
        canonicals = [link.get("href") for link in parser.links if link.get("rel") == "canonical"]

        assert canonicals == [canonical]

        og_urls = _meta_content(parser, property="og:url")
        if og_urls:
            assert og_urls == [canonical]

        og_images = _meta_content(parser, property="og:image")
        twitter_images = _meta_content(parser, name="twitter:image")
        for image_url in [*og_images, *twitter_images]:
            assert image_url.startswith("https://wless.io/")


def test_robots_points_to_wless_sitemap() -> None:
    robots = (DOCS / "robots.txt").read_text(encoding="utf-8")

    assert "User-agent: *" in robots
    assert "Allow: /" in robots
    assert "Sitemap: https://wless.io/sitemap.xml" in robots


def test_sitemap_uses_existing_wless_public_pages() -> None:
    doc = ElementTree.parse(DOCS / "sitemap.xml")
    locs = [loc.text for loc in doc.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")]

    assert locs == [
        "https://wless.io/",
        "https://wless.io/features.html",
        "https://wless.io/how-it-works.html",
        "https://wless.io/blog/",
        "https://wless.io/red/",
        "https://wless.io/memes.html",
    ]
    assert "https://wless.io/coming-soon.html" not in locs


def test_coming_soon_is_noindexed_duplicate_homepage() -> None:
    parser = _head("docs/coming-soon.html")

    assert _meta_content(parser, name="robots") == ["noindex, follow"]


def test_llms_txt_uses_approved_story_and_docs_links() -> None:
    llms = (DOCS / "llms.txt").read_text(encoding="utf-8")

    assert "copied `.env` value alone cannot call the provider" in llms
    assert "curl -sSL https://worthless.sh | sh" in llms
    assert "https://docs.wless.io/" in llms
    assert "https://wless.io/" in llms


def test_non_red_seo_copy_avoids_disallowed_claim_boundaries() -> None:
    banned_phrases = [
        "$0 damage",
        "$10k",
        "all secrets",
        "any key",
        "aws keys",
        "can't do anything",
        "doesn't matter",
        "gemini changed the rules",
        "github token",
        "hard spending cap",
        "hard spend cap",
        "hard stop",
        "millions of secrets",
        "native Windows",
        "openai bill",
        "Gemini (planned)",
        "pip install worthless",
        "reset-budget",
        "stripe keys",
        "tens of thousands",
        "OpenClaw leaks",
    ]
    offenders: list[tuple[str, str]] = []

    for path in NON_RED_SEO_COPY_FILES:
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        lowered = text.lower()
        for phrase in banned_phrases:
            pattern = re.compile(rf"(?<![a-z0-9]){re.escape(phrase.lower())}(?![a-z0-9])")
            if pattern.search(lowered):
                offenders.append((path, phrase))

    assert offenders == []


def test_non_red_pages_do_not_use_restricted_faq_schema() -> None:
    restricted_schema = ['"@type": "FAQPage"', '"@type":"FAQPage"']
    offenders = [
        path
        for path in NON_RED_SEO_COPY_FILES
        if any(
            schema in (REPO_ROOT / path).read_text(encoding="utf-8")
            for schema in restricted_schema
        )
    ]

    assert offenders == []
