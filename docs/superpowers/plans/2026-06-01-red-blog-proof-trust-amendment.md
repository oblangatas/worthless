# Red Blog Proof/Trust Amendment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Amend PR #243 so `/red/` ships as a minimal, human-written attack blog surface with stable proof/trust URLs, hidden drafts, and explicit limitation language.

**Architecture:** Keep the existing static HTML structure under `docs/red/`, but demote proof/trust pages to secondary references and make `docs/red/index.html` the sparse blog front door. Preserve the draft registry in `docs/red/red-posts.js`; tests in `tests/test_wor398_proof_trust_pages.py` become the guardrails for hidden drafts, overclaim bans, stable URLs, and non-slop copy.

**Tech Stack:** Static HTML/CSS/JS in `docs/red/`; Python `pytest` static-content tests; existing website link/deploy tests.

---

## Path Ownership Plan

Expected touched files:

- Modify: `docs/red/index.html`
- Modify: `docs/red/red-posts.js`
- Modify: `docs/red/claims.html`
- Modify: `docs/red/incidents.html`
- Modify: `docs/red/security-model.html`
- Modify: `tests/test_wor398_proof_trust_pages.py`
- Create or modify: `docs/superpowers/plans/2026-06-01-red-blog-proof-trust-amendment.md`

Expected not touched:

- `docs/sitemap.xml`
- `docs/robots.txt`
- `docs/llms.txt`
- broad SEO/AEO metadata files
- Cloudflare, Workers, Wrangler, DNS, HSTS, Transform Rules
- `marketing/`
- `main` branch

Likely WOR-397 overlap:

- Low if this plan only changes page body copy and stable page links.
- Possible overlap if `docs/red/*.html` metadata, canonical tags, sitemap inclusion, robots, `llms.txt`, or discovery text are edited. Do not expand those. Leave URL discovery ownership to WOR-397.
- Output for WOR-397: stable URLs to include are `/red/`, `/red/incidents.html`, `/red/claims.html`, and `/red/security-model.html`.

## Design Inputs

Use these before editing:

- Spec: `docs/superpowers/specs/2026-06-01-red-blog-editorial-design.md`
- Temporary Impeccable shape: `/private/tmp/wor398-red-blog-impeccable-context/SHAPE.md`

Core design rules:

- `/red/` is a blog index, not a trust dashboard.
- First viewport: small Red Blog label, one hard headline, one short premise.
- Voice: snappy, concrete, skeptical, human, no vendor sludge.
- No fake terminal chrome.
- No card grid as the primary surface.
- Draft post titles are hidden unless local preview is explicit.
- Supporting proof/security URLs stay stable but secondary.

## Task 1: Tighten Failing Static Tests First

**Files:**

- Modify: `tests/test_wor398_proof_trust_pages.py`

- [ ] **Step 1: Add a test that rejects the current overloaded `/red/` front door**

Add assertions to `test_wor398_stable_trust_urls_exist_and_are_cross_linked` or create a new focused test:

```python
def test_red_index_is_attack_blog_not_trust_dashboard() -> None:
    html = _read(RED / "index.html")
    lower = html.lower()

    assert "Red Blog" in html
    assert "Proof surfaces" not in html
    assert "Audit with AI" not in html
    assert "terminal" not in lower
    assert "Review threat reports" not in html
    assert "Read the claim ledger" not in html
    assert "Posts stay hidden until they are ready." not in html
    assert lower.count("<section") <= 4
```

- [ ] **Step 2: Add AI-slop phrase bans for Red Blog pages**

Add a helper-level banned phrase list and check all trust pages:

```python
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
```

Expected: the existing implementation may fail on `"public evidence layer"` if that phrase appears in shipped copy, and should fail on current overloaded index assertions.

- [ ] **Step 3: Add draft metadata guardrails**

Extend `test_red_blog_posts_are_hidden_until_publication_flag_changes`:

```python
assert "showDraftPosts" in posts_js or "SHOW_DRAFT_POSTS" in posts_js
assert "How leaked AI keys get reused" in posts_js
assert "How leaked AI keys get reused" not in red_index
assert "Provider budgets are not blast-radius controls" not in red_index
```

- [ ] **Step 4: Run focused test and verify it fails**

Run:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run pytest tests/test_wor398_proof_trust_pages.py -q
```

Expected: at least `test_red_index_is_attack_blog_not_trust_dashboard` fails against the current index.

## Task 2: Rebuild `/red/` As A Sparse Attack Blog Index

**Files:**

- Modify: `docs/red/index.html`
- Test: `tests/test_wor398_proof_trust_pages.py`

- [ ] **Step 1: Replace the current dashboard-style index structure**

Keep basic static page shell, favicon, canonical URL, and `red-posts.js`.

Remove:

- fake terminal summary
- three-card proof grid as first major content
- `Audit with AI` installer prompt block
- overloaded CTA buttons
- "Posts stay hidden until they are ready." as a visible product explanation

- [ ] **Step 2: Use the approved first viewport**

Use copy in this shape:

```html
<section class="hero" aria-labelledby="red-title">
  <p class="eyebrow">Red Blog</p>
  <h1 id="red-title">The leak is the start.</h1>
  <p class="lead">Someone copies a key-looking value. What happens next is the whole story.</p>
</section>
```

Acceptable alternate headline if it reads better in layout:

```html
<h1 id="red-title">How leaked keys get used.</h1>
```

- [ ] **Step 3: Add the post list as the main body**

Make the visible post area the primary section:

```html
<section class="posts" aria-labelledby="posts-title">
  <div class="section-label">Published notes</div>
  <h2 id="posts-title">Attack notes</h2>
  <div class="post-list" id="red-post-list" aria-live="polite">
    <article class="empty">
      <strong>No reviewed posts yet.</strong>
      <p>The drafts stay hidden until they are sourced, scoped, and worth reading.</p>
    </article>
  </div>
</section>
```

- [ ] **Step 4: Move supporting pages below the blog list**

Use a quiet reference strip, not cards:

```html
<section class="references" aria-label="Proof references">
  <a href="claims.html"><span>Proof & limits</span><small>What Worthless claims and what it does not.</small></a>
  <a href="incidents.html"><span>Incident notes</span><small>Sourced examples, scoped carefully.</small></a>
  <a href="security-model.html"><span>Security model</span><small>The boundary, in plain English.</small></a>
</section>
```

- [ ] **Step 5: Simplify CSS**

CSS goals:

- dark near-black background
- one restrained red accent
- max width around `920px`
- no grid of cards above the post list
- no fake terminal styles
- mobile single-column navigation
- no negative letter spacing stronger than the existing site can tolerate on mobile

- [ ] **Step 6: Run focused test**

Run:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run pytest tests/test_wor398_proof_trust_pages.py -q
```

Expected: red-index test passes or reveals copy/style remnants to remove.

## Task 3: Make Draft Registry Match Blog Row Shape

**Files:**

- Modify: `docs/red/red-posts.js`
- Test: `tests/test_wor398_proof_trust_pages.py`

- [ ] **Step 1: Keep drafts hidden by default**

Keep:

```javascript
const SHOW_DRAFT_POSTS = false;
```

- [ ] **Step 2: Use post metadata that can render a real blog row later**

Use fields:

```javascript
{
  title: "How leaked AI keys get reused",
  label: "Walkthrough",
  href: "#",
  published: false,
  summary: "A copied provider key gets tested fast. Worthless only changes the path if the leaked value was locked first.",
  verdict: "Copied locked value alone is not enough."
}
```

The second draft can stay, but must be hidden:

```javascript
{
  title: "Provider budgets are not blast-radius controls",
  label: "Boundary",
  href: "#",
  published: false,
  summary: "Budget alerts help after usage starts. They are not the same thing as making copied material fail.",
  verdict: "A guardrail is not a hard spend cap."
}
```

- [ ] **Step 3: Render safely with DOM APIs**

Avoid injecting unsanitized strings through `innerHTML`. Use `document.createElement`, `textContent`, and `setAttribute`.

Post row shape:

```html
<article class="post">
  <div class="post-label">Walkthrough</div>
  <a href="#">How leaked AI keys get reused</a>
  <p>...</p>
  <small>Copied locked value alone is not enough.</small>
</article>
```

- [ ] **Step 4: Run focused tests**

Run:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run pytest tests/test_wor398_proof_trust_pages.py -q
```

Expected: draft hiding tests pass.

## Task 4: De-Emphasize Supporting Proof Pages Without Breaking Stable URLs

**Files:**

- Modify: `docs/red/claims.html`
- Modify: `docs/red/incidents.html`
- Modify: `docs/red/security-model.html`
- Test: `tests/test_wor398_proof_trust_pages.py`

- [ ] **Step 1: Rename public navigation labels away from "claim ledger"**

Use:

- `Proof & limits`
- `Incident notes`
- `Security model`
- `Red Blog`

Avoid visible `Claim ledger` as a primary label. If the phrase remains for test compatibility, keep it in a sentence like "This is the engineer-facing proof table" rather than as the Red Blog identity.

- [ ] **Step 2: Shorten top copy on `claims.html`**

Target tone:

```html
<h1>Proof & limits.</h1>
<p class="lead">The short claim is strong and narrow: copied locked AI-key material alone is not enough to call the provider. Everything below is the boundary.</p>
```

Keep required claims and limitations from current tests.

- [ ] **Step 3: Rename `incidents.html` away from "Incident ledger"**

Target tone:

```html
<h1>Incident notes.</h1>
<p class="lead">Real leak stories, read through one question: would a copied locked AI key have changed the path?</p>
```

Keep sourced links already present. Do not add new incidents unless sources are available and link-checked.

- [ ] **Step 4: Shorten `security-model.html`**

Keep required sections:

- supported AI keys
- macOS, Linux, WSL
- no cloud account required
- token-budget guardrail, not hard spend cap
- not general vault
- not scanner replacement
- full same-user host compromise

Tone target:

```html
<h1>Security model.</h1>
<p class="lead">Worthless changes what copied locked AI-key material can do. It does not make the leak fine.</p>
```

- [ ] **Step 5: Run focused tests**

Run:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run pytest tests/test_wor398_proof_trust_pages.py -q
```

Expected: tests pass.

## Task 5: Visual And Link Verification

**Files:**

- Inspect only unless a visual bug is found.
- Potential modify: `docs/red/index.html`, `docs/red/*.html`, `docs/red/red-posts.js`

- [ ] **Step 1: Run local static server**

Run from repo root:

```bash
python3 -m http.server 4173 --directory docs
```

Expected: server listens at `http://127.0.0.1:4173/`.

- [ ] **Step 2: Open browser targets**

Check:

- `http://127.0.0.1:4173/red/`
- `http://127.0.0.1:4173/red/claims.html`
- `http://127.0.0.1:4173/red/incidents.html`
- `http://127.0.0.1:4173/red/security-model.html`

Desktop and mobile acceptance:

- no horizontal overflow
- nav does not crowd or clip
- first viewport has one clear idea
- Red Blog looks like blog/index, not dashboard
- proof/security pages feel secondary
- no fake terminal visual

- [ ] **Step 3: Check internal links**

Run:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run pytest tests/test_website_docs_cross_links.py tests/test_wor398_proof_trust_pages.py -q
```

Expected: all pass.

- [ ] **Step 4: Check external incident links if feasible**

Run existing feasible HEAD checks for non-HN links:

```bash
curl -I https://dev.to/ayame0328/60k-billed-in-13-hours-why-leaked-firebase-keys-keep-killing-ai-built-apps-6l6
```

Expected: HTTP 200/3xx. Hacker News may return non-HEAD behavior; use browser or GET if needed, but do not block on HEAD 405.

## Task 6: Broader PR Checks And Commit

**Files:**

- Commit all modified implementation and test files.

- [ ] **Step 1: Run deploy static tests**

Run:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run pytest tests/test_deploy_static.py -q
```

Expected: pass.

- [ ] **Step 2: Run ruff on changed test**

Run:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run --extra dev ruff check tests/test_wor398_proof_trust_pages.py
```

Expected: pass.

- [ ] **Step 3: Check git diff for forbidden scope**

Run:

```bash
git diff --stat
git diff -- docs/sitemap.xml docs/robots.txt docs/llms.txt
```

Expected: no sitemap/robots/llms changes.

- [ ] **Step 4: Commit**

Run:

```bash
git add docs/red/index.html docs/red/red-posts.js docs/red/claims.html docs/red/incidents.html docs/red/security-model.html tests/test_wor398_proof_trust_pages.py
git commit -m "feat(wor-398): reshape red blog as attack notes"
```

Expected: one implementation commit after the existing spec commits.

- [ ] **Step 5: Push and inspect PR**

Run:

```bash
git push origin feature/wor-398-proof-trust-red-blog
gh pr view 243 --json url,baseRefName,headRefName,state
gh pr checks 243
```

Expected:

- base is `website-dev`
- head is `feature/wor-398-proof-trust-red-blog`
- PR checks pass or failures are investigated before final report.

## Final Report Checklist

Report back with:

- PR URL
- changed paths
- proof/trust claims kept or added
- explicit limitations kept or added
- stable URLs for WOR-397
- dependencies on WOR-397
- blockers
- verification commands and results
