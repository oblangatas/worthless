"""Regression guards for main:website/ publish safety (WOR-737).

Production GitHub Pages deploys from ``website/`` on ``main``. Internal
research, planning, prompts, and adversarial review material must never
ship in that tree.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WEBSITE = REPO_ROOT / "website"

# Explicit publish allowlist — new public assets must be added here deliberately.
ALLOWED_RELATIVE_PATHS = frozenset(
    {
        ".well-known/security.txt",
        "CNAME",
        "PROTOCOL.md",
        "android-chrome-192x192.png",
        "android-chrome-512x512.png",
        "apple-touch-icon.png",
        "blog/index.html",
        "coming-soon.html",
        "favicon-16x16.png",
        "favicon-32x32.png",
        "favicon.ico",
        "favicon.png",
        "features.html",
        "hero.png",
        "how-it-works.html",
        "index.html",
        "install-github-actions.md",
        "install-mcp.md",
        "install-openclaw.md",
        "install-self-hosted.md",
        "install-solo.md",
        "install-teams.md",
        "llms.txt",
        "logo-transparent.png",
        "meme-jenga.png",
        "meme-llm-tower.png",
        "memes.html",
        "news-feed.js",
        "news-feed.json",
        "news-feed.md",
        "og-image.png",
        "robots.txt",
        "site.webmanifest",
        "sitemap.xml",
    }
)

PROHIBITED_PATHS = [
    WEBSITE / "research",
    WEBSITE / "adversarial",
    WEBSITE / "ARCHITECTURE.md",
    WEBSITE / "security-model.md",
    WEBSITE / "risk-key-material-in-python-memory.md",
    WEBSITE / "DOMAIN_PLAN.md",
    WEBSITE / "superpowers",
    WEBSITE / "planning",
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
)


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


def test_website_tree_excludes_internal_planning_sources() -> None:
    offenders = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in PROHIBITED_PATHS
        if path.is_file() or (path.is_dir() and any(path.rglob("*")))
    ]

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
