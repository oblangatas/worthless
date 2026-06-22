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
    # Public legal pages (WOR-663).
    "docs/privacy.html": "https://wless.io/privacy.html",
    "docs/terms.html": "https://wless.io/terms.html",
    "docs/security.html": "https://wless.io/security.html",
    "docs/license.html": "https://wless.io/license.html",
}

# Footer legal cluster (WOR-663): every public launch page and every legal page
# links to all six legal documents, with the relative prefix for its directory.
LEGAL_PAGES = [
    "privacy.html",
    "terms.html",
    "security.html",
    "license.html",
]

FOOTER_LEGAL_SURFACES = {
    "docs/index.html": "",
    "docs/features.html": "",
    "docs/how-it-works.html": "",
    "docs/memes.html": "",
    "docs/coming-soon.html": "",
    "docs/blog/index.html": "../",
    "docs/red/index.html": "../",
    "docs/privacy.html": "",
    "docs/terms.html": "",
    "docs/security.html": "",
    "docs/license.html": "",
}

LEGAL_DOC_PAGES = [
    "docs/privacy.html",
    "docs/terms.html",
    "docs/security.html",
    "docs/license.html",
]

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


def _relative_luminance(hex_color: str) -> float:
    channels = [int(hex_color[index : index + 2], 16) / 255 for index in range(1, 7, 2)]
    linear = [
        channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast_ratio(foreground: str, background: str) -> float:
    lighter, darker = sorted(
        (_relative_luminance(foreground), _relative_luminance(background)),
        reverse=True,
    )
    return (lighter + 0.05) / (darker + 0.05)


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


def test_static_publish_tree_does_not_ship_markdown_docs() -> None:
    markdown_files = sorted(path.relative_to(REPO_ROOT).as_posix() for path in DOCS.rglob("*.md"))

    assert markdown_files == []


def test_publishable_docs_do_not_reference_stale_worthless_domains() -> None:
    # The [.-] character class matches both the dot and hyphen variants of the
    # stale domain while keeping the contiguous banned literal out of source, so
    # the repo's no-cloud-references pre-commit hook does not flag this guard.
    stale_domain = re.compile(r"worthless[.-]cloud")
    offenders = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in _public_text_files()
        if stale_domain.search(path.read_text(encoding="utf-8"))
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
    assert "Policy: https://wless.io/security.html" in security_txt


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
        "https://wless.io/privacy.html",
        "https://wless.io/terms.html",
        "https://wless.io/security.html",
        "https://wless.io/license.html",
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
            "Your API key just got leaked. Or stolen. Doesn't matter.",
            "",
        )
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


def test_homepage_uses_approved_hero_tagline() -> None:
    index = (DOCS / "index.html").read_text(encoding="utf-8")
    coming_soon = (DOCS / "coming-soon.html").read_text(encoding="utf-8")

    assert "Your API key just got leaked. Or stolen." in index
    assert (
        '<summary role="button" aria-expanded="false">'
        "Worthless makes leaked keys worthless. How?</summary>" in index
    )
    assert (
        "Your API key ends up in a leaked .env. The half sitting there "
        "can't call the provider on its own." in coming_soon
    )


def test_homepage_scroll_hint_invites_the_leak_story_accessibly() -> None:
    index = (DOCS / "index.html").read_text(encoding="utf-8")

    assert 'href="#leak-story" aria-label="Scroll to the leak story"' in index
    assert '<span class="scroll-hint__text">Follow the leak</span>' in index
    assert '<span class="scroll-hint__wick" aria-hidden="true"></span>' in index
    assert '<section class="cinema" id="leak-story" aria-label="Leak story">' in index
    assert ".scroll-hint:focus-visible" in index
    assert "@keyframes leak-drop" in index
    assert "prefers-reduced-motion: reduce" in index
    assert ".scroll-hint__wick::after" in index
    assert "animation: none;" in index
    assert "Scroll the leak" not in index


def test_homepage_explains_the_product_without_hiding_the_install_path() -> None:
    index = (DOCS / "index.html").read_text(encoding="utf-8")
    script = (DOCS / "homepage.js").read_text(encoding="utf-8")

    assert (
        "Worthless replaces each protected API key in your <code>.env</code> "
        "with a share that cannot call the provider alone." in index
    )
    assert ".promise-explainer:not([open]) > :not(summary)" in index
    assert 'href="how-it-works.html">See how it works</a>' in index
    assert '<p class="install-eyebrow">Protect your keys</p>' in index
    assert "curl -sSL https://worthless.sh | sh" in index
    assert '<span class="copy-success" aria-hidden="true">Copied</span>' in index
    assert 'class="copy-check"' in index
    assert 'id="copy-install-help"' in index
    assert "Copy unavailable. Use the install guide below." in script
    assert "Select the install command text." not in script
    assert ".install:hover" in index
    assert ".install:focus-visible" in index
    assert "Protected first. Your LLMs still work." not in index


def test_homepage_uses_visible_unboxed_audit_icons() -> None:
    index = (DOCS / "index.html").read_text(encoding="utf-8")
    script = (DOCS / "homepage.js").read_text(encoding="utf-8")

    assert '<svg hidden aria-hidden="true" style="display: none">' in index
    assert index.count("Don’t trust us. Audit with AI.") == 2
    assert index.count('class="audit-icon"') == 8
    assert index.count('href="#audit-claude"') == 2
    assert index.count('href="#audit-chatgpt"') == 2
    assert index.count('href="#audit-gemini"') == 2
    assert index.count('href="#audit-grok"') == 2
    assert "audit-letter" not in index
    assert "beat-trust" not in index
    assert "beatTrust" not in script
    assert ".audit-icon {" in index
    audit_rule = index.split(".audit-icon {", 1)[1].split("}", 1)[0]
    assert "border: 0;" in audit_rule
    assert "background: transparent;" in audit_rule
    assert "flex-direction: column;" in index
    assert 'href="#" data-audit=' not in index
    assert index.count('href="https://claude.ai/new" data-audit="claude"') == 2
    assert index.count('href="https://chatgpt.com/" data-audit="chatgpt"') == 2
    assert index.count('href="https://gemini.google.com/app" data-audit="gemini"') == 2
    assert index.count('href="https://grok.com/" data-audit="grok"') == 2


def test_launch_page_utility_text_meets_wcag_aa_contrast() -> None:
    index = (DOCS / "index.html").read_text(encoding="utf-8")
    how_it_works = (DOCS / "how-it-works.html").read_text(encoding="utf-8")

    assert "--ink-faint: oklch(54% 0.035 226);" in index
    assert "--text2: #586b82;" in how_it_works


def test_homepage_primary_navigation_preserves_front_facing_brand_routes() -> None:
    index = (DOCS / "index.html").read_text(encoding="utf-8")
    features = (DOCS / "features.html").read_text(encoding="utf-8")
    how_it_works = (DOCS / "how-it-works.html").read_text(encoding="utf-8")

    homepage_nav = index.split('<nav class="nav" aria-label="Primary">', 1)[1].split("</nav>", 1)[0]
    for page in (features, how_it_works):
        primary_nav = page.split("<nav>", 1)[1].split("</nav>", 1)[0]
        assert "memes.html" not in primary_nav
        assert "ko-fi.com" not in primary_nav

    assert 'href="memes.html"' in homepage_nav
    assert 'href="https://ko-fi.com/shacharme"' in homepage_nav
    assert 'href="#early-access"' in homepage_nav
    assert 'aria-label="Buy me a coffee on Ko-fi"' in homepage_nav
    mobile_rules = index.split("@media (max-width: 820px)", 1)[1].split(
        "@media (max-width: 520px)", 1
    )[0]
    compact_rules = index.split("@media (max-width: 520px)", 1)[1].split(
        "@media (max-width: 370px)", 1
    )[0]
    assert ".nav-actions .ghost {\n        display: none;" in mobile_rules
    assert ".nav-actions .kofi {" in mobile_rules
    assert "width: 2.15rem;" in mobile_rules
    assert "height: 2.15rem;" in mobile_rules
    assert ".nav-links .nav-early {" in compact_rules
    assert "width: 2.15rem;" in compact_rules
    assert ".nav-early-label {\n        display: none;" in compact_rules


def test_homepage_describes_hosted_early_access_as_a_separate_future_product() -> None:
    index = (DOCS / "index.html").read_text(encoding="utf-8")

    assert 'id="early-access"' in index
    assert "Hosted Worthless" in index
    assert "A separate managed product we're exploring for later" in index
    assert "not the open-source tool on this page" in index
    assert (
        "does not imply current hosted service, team support, or protection for every secret type"
        in index
    )
    assert "Join early access" in index
    assert "https://tally.so/r/WOpNVL" in index

    for unsupported_copy in (
        "More secrets next.",
        "all secret types",
        "hosted today",
    ):
        assert unsupported_copy not in index


def test_launch_copy_uses_bounded_supported_key_claims() -> None:
    index = (DOCS / "index.html").read_text(encoding="utf-8")
    features = (DOCS / "features.html").read_text(encoding="utf-8")
    how_it_works = (DOCS / "how-it-works.html").read_text(encoding="utf-8")

    assert "cannot call the provider on its own" in features
    assert "cannot call the provider on its own" in how_it_works
    assert "supported AI-provider key patterns" in features
    assert "Docker, CI, and unusual SDK flows" in features
    assert "Docker, CI, or unusual SDK flows" in how_it_works

    for stale_copy in (
        "Leaked half is useless.",
        "They get random bytes. Useless",
        "The leaked half is useless on its own.",
        "That's the only change.",
    ):
        assert stale_copy not in features
        assert stale_copy not in how_it_works

    assert "Make copied .env AI keys useless" not in index


def test_blog_uses_bounded_supported_key_claims() -> None:
    blog = (DOCS / "blog" / "index.html").read_text(encoding="utf-8")
    approved_description = (
        "Plain-English explainers on AI agent key leaks, scanners, vaults, "
        "and how Worthless changes what a copied protected .env value can do."
    )
    expected_copy = (
        "Why I built Worthless: change what a copied protected .env value can do",
        "Different tools cover different leak stages",
        "Introducing Worthless: scoped protection for copied .env AI-key values",
        "Worthless changes what a copied protected .env value can do. "
        "It does not protect a compromised host or attacker-controlled local code.",
    )

    assert f'<meta name="description" content="{approved_description}" />' in blog
    assert "the copied .env value alone cannot call the provider" in blog.lower()
    for approved_copy in expected_copy:
        assert approved_copy in blog

    for stale_copy in (
        "change what a copied API key can do",
        "None protect you after it leaks",
        "post-leak API key protection",
        "post-leak protection",
        "Worthless protects you after it leaks",
        "Useless on its own.",
        "They can't brute-force it.",
        "They can't derive anything from it.",
        "It's just random bytes.",
        "Why splitting a key makes it useless",
        'When we say "a leaked share is worthless,"',
        "it's useless without the other half",
        "Why is A useless alone?",
    ):
        assert stale_copy not in blog


def test_homepage_moves_the_hero_up_on_tall_viewports() -> None:
    index = (DOCS / "index.html").read_text(encoding="utf-8")

    assert "@media (max-aspect-ratio: 4 / 5)" in index
    portrait_rule = index.split("@media (max-aspect-ratio: 4 / 5)", 1)[1]
    portrait_rule = portrait_rule.split("@media", 1)[0]
    assert "align-items: start;" in portrait_rule
    assert "padding-top: max(7rem, 12svh);" in portrait_rule


def test_how_it_works_has_an_obvious_quiet_return_home_link() -> None:
    page = (DOCS / "how-it-works.html").read_text(encoding="utf-8")

    assert 'href="index.html" class="nav-logo" aria-label="Back to Worthless home"' in page
    assert '<span aria-hidden="true">&larr;</span> Worthless' in page


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


def test_homepage_javascript_honors_reduced_motion() -> None:
    homepage_js = (DOCS / "homepage.js").read_text(encoding="utf-8")

    assert "prefers-reduced-motion: reduce" in homepage_js
    assert "if (!reduceMotion)" in homepage_js


def test_red_faint_text_meets_wcag_aa_contrast() -> None:
    surfaces = {
        DOCS / "red" / "index.html": "#090b10",
        DOCS / "red" / "posts" / "post.css": "#0b0c10",
    }

    for path, background in surfaces.items():
        text = path.read_text(encoding="utf-8")
        match = re.search(r"--faint:\s*(#[0-9a-fA-F]{6})", text)
        assert match is not None
        assert _contrast_ratio(match.group(1), background) >= 4.5


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
            schema in (REPO_ROOT / path).read_text(encoding="utf-8") for schema in restricted_schema
        )
    ]

    assert offenders == []


def test_public_launch_pages_link_to_full_footer_legal_cluster() -> None:
    missing: list[tuple[str, str]] = []

    for path, prefix in FOOTER_LEGAL_SURFACES.items():
        html = (REPO_ROOT / path).read_text(encoding="utf-8")
        for page in LEGAL_PAGES:
            if f'href="{prefix}{page}"' not in html:
                missing.append((path, f"{prefix}{page}"))

    assert missing == []


def test_legal_pages_are_indexable_csp_safe_documents() -> None:
    for path in LEGAL_DOC_PAGES:
        html = (REPO_ROOT / path).read_text(encoding="utf-8")
        parser = _head(path)

        assert _meta_content(parser, name="robots") == ["index, follow"]
        assert 'rel="stylesheet" href="legal.css"' in html
        # Same content-security posture as the launch pages: no inline scripts,
        # no inline event handlers.
        assert "<script" not in html
        assert not re.search(r"\son[a-z]+=", html)


def test_legal_pages_anchor_license_to_agpl() -> None:
    license_page = (DOCS / "license.html").read_text(encoding="utf-8")

    assert "AGPL-3.0-only" in license_page
    assert "GNU Affero General Public License" in license_page
    assert "https://www.gnu.org/licenses/agpl-3.0.txt" in license_page


def test_privacy_page_omits_clauses_conflicting_with_wor663_guardrails() -> None:
    privacy = (DOCS / "privacy.html").read_text(encoding="utf-8").lower()

    # WOR-663 bans successor-entity assignment clauses on the public surface;
    # the approved WOR-575 draft still carried one, so it is held out here.
    assert "successor" not in privacy
    # Launch decision is DCO-only, no CLA (WOR-575 / WOR-532); no CLA reference.
    assert "contributor license agreement" not in privacy
    assert "cla.md" not in privacy


def test_security_page_makes_no_response_time_commitment() -> None:
    security = (DOCS / "security.html").read_text(encoding="utf-8")

    assert "security@wless.io" in security
    assert "https://github.com/shacharm2/worthless/security/advisories/new" in security
    assert "best effort only" in security
    assert "no SLA" in security
    # No response-time promise should appear in the public security copy.
    assert not re.search(r"within\s+\d+\s+(hours|days|weeks)", security, re.IGNORECASE)
