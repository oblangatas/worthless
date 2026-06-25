"""Regression guards for main:website/ publish safety (WOR-737).

Production GitHub Pages deploys from ``website/`` on ``main``. Internal
research, planning, prompts, and adversarial review material must never
ship in that tree.
"""

from __future__ import annotations

from pathlib import Path
import re

REPO_ROOT = Path(__file__).resolve().parent.parent
WEBSITE = REPO_ROOT / "website"

# Explicit publish allowlist — new public assets must be added here deliberately.
ALLOWED_RELATIVE_PATHS = frozenset(
    {
        ".well-known/security.txt",
        "CNAME",
        "android-chrome-192x192.png",
        "android-chrome-512x512.png",
        "apple-touch-icon.png",
        "blog/blog.js",
        "blog/index.html",
        "coming-soon.html",
        "favicon-16x16.png",
        "favicon-32x32.png",
        "favicon.ico",
        "favicon.png",
        "features.html",
        "hero.png",
        "homepage.js",
        "how-it-works.html",
        "index.html",
        "legal.css",
        "license.html",
        "llms.txt",
        "logo-transparent.png",
        "meme-jenga.png",
        "meme-llm-tower.png",
        "memes.html",
        "news-feed.js",
        "news-feed.json",
        "og-image.png",
        "privacy.html",
        "red/claims.html",
        "red/incidents.html",
        "red/index.html",
        "red/posts/axios-rat.html",
        "red/posts/bitwarden-cli-npm.html",
        "red/posts/github-action-secrets.html",
        "red/posts/package-before-build.html",
        "red/posts/post.css",
        "red/posts/shai-hulud.html",
        "red/posts/trapdoor.html",
        "red/red-posts.js",
        "red/security-model.html",
        "robots.txt",
        "security.html",
        "site.webmanifest",
        "sitemap.xml",
        "terms.html",
    }
)

PROHIBITED_PATHS = [
    WEBSITE / "research",
    WEBSITE / "adversarial",
    WEBSITE / "ARCHITECTURE.md",
    WEBSITE / "security-model.md",
    WEBSITE / "risk-key-material-in-python-memory.md",
    WEBSITE / "DOMAIN_PLAN.md",
    WEBSITE / "PROTOCOL.md",
    WEBSITE / "install-openclaw.md",
    WEBSITE / "news-feed.md",
    WEBSITE / "superpowers",
    WEBSITE / "planning",
    WEBSITE / ".planning",
]

TEXT_SUFFIXES = {".css", ".html", ".js", ".json", ".md", ".txt", ".xml", ""}

DISCOVERY_SURFACE_PATHS = (
    WEBSITE / "sitemap.xml",
    WEBSITE / "llms.txt",
    WEBSITE / "robots.txt",
)

EXTRA_REFERENCE_NEEDLES = (
    ".planning/",
    "ROADMAP.md",
    "worthless" + "-" + "cloud",
    "PROTOCOL.md",
    "install-openclaw.md",
    "news-feed.md",
)

REQUIRED_LAUNCH_URLS = {
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
    "https://wless.io/privacy.html",
    "https://wless.io/terms.html",
    "https://wless.io/security.html",
    "https://wless.io/license.html",
    "https://wless.io/memes.html",
}

LEGAL_LINK_TARGETS = (
    "privacy.html",
    "terms.html",
    "security.html",
    "license.html",
)


def _pyproject_version() -> str:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE)
    assert match, "pyproject.toml must declare project.version"
    assert '"Development Status :: 4 - Beta"' in pyproject
    return match.group(1)


def _prohibited_reference_needles() -> tuple[str, ...]:
    needles: list[str] = []
    for path in PROHIBITED_PATHS:
        if not path.suffix:
            segment = path.name
            needles.extend(
                (
                    f"website/{segment}/",
                    f"website/{segment}",
                    f"/{segment}/",
                    f"/{segment}",
                    f"wless.io/{segment}/",
                    f"wless.io/{segment}",
                    f'href="/{segment}',
                    f"href='/{segment}",
                )
            )
            continue

        rel = path.relative_to(WEBSITE).as_posix()
        needles.extend(
            (
                rel,
                f"website/{rel}",
                f"/{rel}",
                f"wless.io/{rel}",
                f'href="/{rel}',
                f"href='/{rel}",
            )
        )

    return tuple(dict.fromkeys(needles))


def _internal_url_fragments() -> tuple[str, ...]:
    fragments: list[str] = []
    for path in PROHIBITED_PATHS:
        if not path.suffix:
            fragments.append(f"/{path.name}/")
            fragments.append(f"/{path.name}")
            continue
        rel = path.relative_to(WEBSITE).as_posix()
        fragments.append(rel)
        fragments.append(f"/{rel}")
    return tuple(dict.fromkeys(fragments))


def _public_text_files() -> list[Path]:
    files: list[Path] = []
    for path in WEBSITE.rglob("*"):
        if path.is_file() and path.suffix in TEXT_SUFFIXES:
            path.read_text(encoding="utf-8")
            files.append(path)
    return sorted(files)


def test_website_tree_matches_publish_allowlist() -> None:
    actual = {path.relative_to(WEBSITE).as_posix() for path in WEBSITE.rglob("*") if path.is_file()}
    unexpected = sorted(actual - ALLOWED_RELATIVE_PATHS)
    missing = sorted(ALLOWED_RELATIVE_PATHS - actual)

    assert unexpected == [], f"Unexpected publish files: {unexpected}"
    assert missing == [], f"Allowlist entries missing from tree: {missing}"


def test_website_tree_contains_no_public_markdown() -> None:
    markdown_files = sorted(
        path.relative_to(REPO_ROOT).as_posix() for path in WEBSITE.rglob("*.md") if path.is_file()
    )

    assert markdown_files == []


def test_website_tree_excludes_internal_planning_sources() -> None:
    offenders = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in PROHIBITED_PATHS
        if path.is_file() or (path.is_dir() and any(path.rglob("*")))
    ]

    assert offenders == []


def test_website_discovery_surfaces_match_launch_policy() -> None:
    sitemap = (WEBSITE / "sitemap.xml").read_text(encoding="utf-8")
    robots = (WEBSITE / "robots.txt").read_text(encoding="utf-8")
    llms = (WEBSITE / "llms.txt").read_text(encoding="utf-8")

    assert "User-agent: *" in robots
    assert "Allow: /" in robots
    assert "Sitemap: https://wless.io/sitemap.xml" in robots

    for url in REQUIRED_LAUNCH_URLS:
        assert url in sitemap

    assert "https://wless.io/red/claims.html" not in sitemap
    assert "https://wless.io/red/incidents.html" not in sitemap
    assert "https://wless.io/red/security-model.html" not in sitemap

    discovery_text = "\n".join((sitemap, robots, llms))
    for stale_path in ("PROTOCOL.md", "install-openclaw.md", "news-feed.md"):
        assert stale_path not in discovery_text


def test_website_security_txt_is_rfc9116_public_surface() -> None:
    security_txt = (WEBSITE / ".well-known" / "security.txt").read_text(encoding="utf-8")

    assert "Contact: mailto:security@wless.io" in security_txt
    assert "Contact: https://github.com/shacharm2/worthless/security/advisories/new" in security_txt
    assert "Expires:" in security_txt
    assert "Canonical: https://wless.io/.well-known/security.txt" in security_txt
    assert "Policy: https://wless.io/security.html" in security_txt


def test_website_homepage_launch_affordances_survive_promotion() -> None:
    index = (WEBSITE / "index.html").read_text(encoding="utf-8")

    assert "curl -sSL https://worthless.sh | sh" in index
    assert 'href="memes.html"' in index
    assert 'href="https://ko-fi.com/shacharme"' in index
    assert 'href="#early-access"' in index
    assert '<span class="scroll-hint__text">Follow the leak</span>' in index
    assert "Hosted Worthless" in index
    assert "A separate managed product we're exploring for later" in index
    assert "not the open-source tool on this page" in index
    assert 'href="red/index.html"' in index


def test_website_homepage_beta_label_matches_pyproject_version() -> None:
    version = _pyproject_version()
    index = (WEBSITE / "index.html").read_text(encoding="utf-8")

    assert f"Beta CLI · v{version} · runs locally" in index
    assert f"Beta CLI, version {version}, runs locally." in index
    assert f"Worthless CLI beta · v{version}" in index


def test_website_waitlist_processing_is_disclosed_and_scoped() -> None:
    index = (WEBSITE / "index.html").read_text(encoding="utf-8")
    coming_soon = (WEBSITE / "coming-soon.html").read_text(encoding="utf-8")
    privacy = (WEBSITE / "privacy.html").read_text(encoding="utf-8")

    assert "https://tally.so/r/WOpNVL" in index
    assert "https://tally.so/r/WOpNVL" in coming_soon
    assert "Hosted Worthless is a separate managed product being explored for later" in coming_soon
    assert (
        "does not imply current hosted service, team support, or protection for every secret type"
        in coming_soon
    )
    assert "Tally" in privacy
    assert "https://tally.so/help/privacy-policy" in privacy
    assert "separate future Hosted Worthless managed product" in privacy


def test_every_public_html_page_links_legal_footer_cluster() -> None:
    offenders: list[str] = []
    for path in sorted(WEBSITE.rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        missing = [target for target in LEGAL_LINK_TARGETS if target not in text]
        if missing:
            offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}: {missing}")

    assert offenders == []


def test_website_text_files_do_not_reference_internal_paths() -> None:
    needles = _prohibited_reference_needles() + EXTRA_REFERENCE_NEEDLES
    offenders: list[str] = []
    for path in _public_text_files():
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle in text:
                offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}: {needle}")
                break

    assert offenders == []


def test_website_discovery_surfaces_exclude_internal_urls() -> None:
    fragments = _internal_url_fragments()
    offenders: list[str] = []
    for path in DISCOVERY_SURFACE_PATHS:
        text = path.read_text(encoding="utf-8")
        for fragment in fragments:
            if fragment in text:
                offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}: {fragment}")
                break

    assert offenders == []
