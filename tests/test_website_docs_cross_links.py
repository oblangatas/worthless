from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
WEBSITE_HOME = REPO_ROOT / "docs" / "index.html"
DOCS_INSTALL = REPO_ROOT / "docs" / "install-solo.md"
GITHUB_ACTIONS_INSTALL = REPO_ROOT / "docs" / "install-github-actions.md"
README = REPO_ROOT / "README.md"


def _hrefs(html: str) -> list[str]:
    return re.findall(r'href="([^"]+)"', html)


def test_homepage_routes_install_cta_to_docs_install() -> None:
    html = WEBSITE_HOME.read_text(encoding="utf-8")

    assert "https://docs.wless.io/install/" in _hrefs(html)
    assert "https://docs.wless.io/install-solo/" not in _hrefs(html)


def test_homepage_uses_worthless_sh_as_standard_install() -> None:
    html = WEBSITE_HOME.read_text(encoding="utf-8")

    assert "curl -sSL https://worthless.sh | sh" in html
    assert "pip install worthless" not in html


def test_homepage_docs_links_target_existing_docs_routes() -> None:
    html = WEBSITE_HOME.read_text(encoding="utf-8")
    docs_links = sorted(
        {href for href in _hrefs(html) if href.startswith("https://docs.wless.io/")}
    )

    assert docs_links == [
        "https://docs.wless.io/",
        "https://docs.wless.io/install/",
        "https://docs.wless.io/protocol/",
        "https://docs.wless.io/recovery/",
        "https://docs.wless.io/security/",
    ]


def test_docs_install_page_links_back_to_website() -> None:
    assert "https://wless.io/" in DOCS_INSTALL.read_text(encoding="utf-8")


def test_docs_install_page_uses_worthless_sh_as_standard_install() -> None:
    text = DOCS_INSTALL.read_text(encoding="utf-8")

    assert "curl -sSL https://worthless.sh | sh" in text
    assert "Target-state install (coming soon)" not in text
    assert "pip install worthless" not in text


def test_readme_routes_architecture_to_canonical_docs() -> None:
    text = README.read_text(encoding="utf-8")

    assert "https://docs.wless.io/protocol/" in text
    assert "docs/ARCHITECTURE.md" not in text


def test_github_actions_guide_does_not_link_mismatched_example() -> None:
    text = GITHUB_ACTIONS_INSTALL.read_text(encoding="utf-8")

    assert "curl -sSL https://worthless.sh | sh" in text
    assert "examples/ci/worthless-ci.yml" not in text


def test_cross_link_surfaces_do_not_reference_worthless_cloud() -> None:
    surfaces = {
        "docs/index.html": WEBSITE_HOME.read_text(encoding="utf-8"),
        "docs/install-solo.md": DOCS_INSTALL.read_text(encoding="utf-8"),
    }

    offenders = [path for path, content in surfaces.items() if "worthless.cloud" in content]

    assert offenders == []
