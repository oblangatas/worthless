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

TEXT_SUFFIXES = {".css", ".html", ".js", ".json", ".md", ".txt", ".xml", ""}
LEGAL_RISK_PATTERN = re.compile(
    r"(we will|we commit|we aim|we strive|hall of fame|^Acknowledgments$|"
    r"dollar liability cap|successor-entity|EU rep)",
    re.IGNORECASE | re.MULTILINE,
)


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


def _public_text_files() -> list[Path]:
    files = []
    for path in DOCS.rglob("*"):
        if path.is_file() and path.suffix in TEXT_SUFFIXES:
            path.read_text(encoding="utf-8")
            files.append(path)
    return sorted(files)


def test_public_seo_surfaces_do_not_reference_worthless_cloud() -> None:
    offenders = [
        path
        for path in SEO_DISCOVERY_FILES
        if "worthless.cloud" in (REPO_ROOT / path).read_text(encoding="utf-8")
    ]

    assert offenders == []


def test_publishable_docs_do_not_include_internal_planning_sources() -> None:
    internal_paths = [
        DOCS / "DOMAIN_PLAN.md",
        DOCS / "adversarial",
        DOCS / "research",
        DOCS / "superpowers",
    ]

    offenders = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in internal_paths
        if path.is_file() or (path.is_dir() and any(path.rglob("*")))
    ]

    assert offenders == []


def test_publishable_docs_do_not_reference_stale_worthless_domains() -> None:
    offenders = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in _public_text_files()
        if re.search(r"worthless\.cloud|worthless-cloud", path.read_text(encoding="utf-8"))
    ]

    assert offenders == []


def test_publishable_docs_do_not_advertise_unreleased_pip_install() -> None:
    offenders = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in _public_text_files()
        if "pip install worthless" in path.read_text(encoding="utf-8")
    ]

    assert offenders == []


def test_publishable_docs_do_not_use_em_dashes() -> None:
    offenders = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in _public_text_files()
        if "—" in path.read_text(encoding="utf-8")
    ]

    assert offenders == []


def test_publishable_docs_do_not_regress_legal_language() -> None:
    offenders = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in _public_text_files()
        if LEGAL_RISK_PATTERN.search(path.read_text(encoding="utf-8"))
    ]

    assert offenders == []


def test_security_txt_uses_advisory_contact_and_policy() -> None:
    security_txt = (DOCS / ".well-known" / "security.txt").read_text(encoding="utf-8")

    assert "Contact: https://github.com/shacharm2/worthless/security/advisories/new" in security_txt
    assert "Contact: mailto:security@wless.io" in security_txt
    assert "Canonical: https://wless.io/.well-known/security.txt" in security_txt
    assert "Policy: https://github.com/shacharm2/worthless/blob/main/SECURITY.md" in security_txt


def test_mobile_nav_wraps_on_launch_pages() -> None:
    for path in ("docs/features.html", "docs/how-it-works.html", "docs/blog/index.html"):
        html = (REPO_ROOT / path).read_text(encoding="utf-8")

        assert "@media (max-width: 720px)" in html
        assert "flex-wrap:wrap" in html or "flex-wrap: wrap" in html
        assert "overflow-x:auto" in html or "overflow-x: auto" in html


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
        "https://wless.io/red/posts/package-before-build.html",
        "https://wless.io/red/posts/bitwarden-cli-npm.html",
        "https://wless.io/red/posts/axios-rat.html",
        "https://wless.io/red/posts/trapdoor.html",
        "https://wless.io/red/posts/shai-hulud.html",
        "https://wless.io/red/posts/github-action-secrets.html",
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
        text = text.replace(
            "Your API key gets leaked. Or stolen. Doesn't matter. It won't work.",
            "",
        )
        lowered = text.lower()
        for phrase in banned_phrases:
            pattern = re.compile(rf"(?<![a-z0-9]){re.escape(phrase.lower())}(?![a-z0-9])")
            if pattern.search(lowered):
                offenders.append((path, phrase))

    assert offenders == []


def test_homepage_uses_approved_original_hero_tagline() -> None:
    index = (DOCS / "index.html").read_text(encoding="utf-8")
    coming_soon = (DOCS / "coming-soon.html").read_text(encoding="utf-8")

    assert (
        "Your API key gets leaked. Or stolen. Doesn't matter. It won't work."
        in index
    )
    assert (
        "Your API key gets leaked. Or stolen. Doesn't matter. It won't work. "
        "It's Worthless."
        in coming_soon
    )


def test_launch_pages_are_compatible_with_live_content_security_policy() -> None:
    index = (DOCS / "index.html").read_text(encoding="utf-8")
    blog = (DOCS / "blog" / "index.html").read_text(encoding="utf-8")

    assert '<script src="homepage.js" defer></script>' in index
    assert '<script src="blog.js" defer></script>' in blog
    inline_script = re.compile(
        r'<script(?![^>]*\bsrc=)(?![^>]*type="application/ld\+json")[^>]*>',
        re.IGNORECASE,
    )
    assert not inline_script.search(index)
    assert not inline_script.search(blog)
    assert not re.search(r"\son[a-z]+=", index)
    assert not re.search(r"\son[a-z]+=", blog)
    assert "https://cdn.simpleicons.org/" not in index


def test_blog_controls_are_accessible_and_hash_routes_are_valid() -> None:
    blog = (DOCS / "blog" / "index.html").read_text(encoding="utf-8")
    blog_js = (DOCS / "blog" / "blog.js").read_text(encoding="utf-8")

    for post_id in ("p0", "p4", "p1", "p2"):
        assert f'aria-controls="{post_id}"' in blog
        assert 'aria-expanded="false"' in blog

    assert "Read article" in blog
    assert "real-leaks" not in blog_js
    assert "if (!full || !btn) return;" in blog_js


def test_publishable_site_does_not_ship_stale_duplicate_security_docs() -> None:
    assert not (DOCS / "ARCHITECTURE.md").exists()
    assert not (DOCS / "security-model.md").exists()


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
