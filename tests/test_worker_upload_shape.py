"""What `wrangler deploy` sends to Cloudflare for the install-page worker.

Cloudflare's WAF on api.cloudflare.com inspects every multipart upload part and
403s a release when bytes look like shell injection (wrangler.toml comment,
ADR-001). So the upload is kept to the bundled worker JS.

Wrangler 4.150 started uploading source maps by default, and a map carries the
original source text as an extra upload part. `upload_source_maps = false`
keeps the upload to the bundle alone (measured 2026-11-18 with wrangler 4.160:
121 KB `index.js.map` without the line, none with it).

Edit that turns this red: delete `upload_source_maps = false`, or move it under
a `[section]` where it no longer applies to every environment.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WRANGLER_TOML = REPO_ROOT / "workers" / "worthless-sh" / "wrangler.toml"


def _top_level(text: str) -> str:
    """The keys before the first table header; they apply to every env."""
    return re.split(r"^\s*\[", text, maxsplit=1, flags=re.MULTILINE)[0]


def test_the_worker_deploy_uploads_no_source_maps() -> None:
    top = _top_level(WRANGLER_TOML.read_text(encoding="utf-8"))
    assert re.search(r"^upload_source_maps\s*=\s*false\s*(#.*)?$", top, re.MULTILINE), (
        "wrangler.toml must set top-level `upload_source_maps = false`: since wrangler "
        "4.150 a deploy uploads source maps by default, an extra part the WAF inspects"
    )
