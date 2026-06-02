# Red Blog Editorial Design Spec

## Goal

Red Blog is a human-edited attack notebook about how leaked AI keys get abused and where Worthless breaks the copied-key path.

It should not feel like a claim ledger, trust dashboard, SEO page, or AI-generated content framework. It should feel like a small, sharp publication written by someone who understands both the attack and the product boundary.

## Core Reader

The primary reader is a technical builder who has seen API key leaks happen in repos, chat, logs, screenshots, generated code, or support threads. They are skeptical of marketing language and want to know:

- how the leak gets exploited;
- what the attacker tries first;
- whether Worthless would change that path;
- where Worthless would not help.

Secondary readers include security-minded buyers, incident responders, and SEO/AEO visitors who land on a specific leak or attack question.

## Editorial Position

Red Blog is not the main Worthless marketing blog. It is the adversarial track.

Every Red Blog page should answer one concrete attack question. The writing should be spare, direct, and opinionated. If a paragraph sounds like a product manager explaining a content strategy, cut it. If the UI looks like a dashboard for claims, remove it.

Good Red Blog writing sounds like:

> The attacker does not need your whole repo. They need one working provider key and enough time before you notice.

Bad Red Blog writing sounds like:

> This public evidence layer demonstrates Worthless's proof and trust posture through scoped claim surfaces and limitation-aware incident analysis.

## Writing Style

Red Blog should read like a sharp technical post someone would actually pass around on Reddit, Hacker News, or security Twitter.

The voice is:

- snappy;
- concrete;
- skeptical;
- mildly opinionated;
- allergic to filler.

Use short paragraphs. Prefer one hard sentence over four careful ones. Open with the attack, not the background. Say what happened, why it matters, where the attacker wins, and where Worthless changes the path.

Good rhythm:

> Someone leaked a working AI key. The attacker does not need the whole repo. They paste the key, test it, and start burning tokens before anyone notices.

Also good:

> Worthless does not make the leak fine. It makes the copied value less useful.

Avoid AI-slop patterns:

- `In today's rapidly evolving threat landscape`;
- `it is important to understand`;
- `comprehensive security posture`;
- `robust protection`;
- `seamlessly empowers`;
- `this article explores`;
- long intro paragraphs before the attack appears;
- ten-word labels for simple ideas;
- balanced-but-empty corporate caveats.

If a sentence could appear in a vendor whitepaper, rewrite it. If it sounds like a LinkedIn announcement, delete it. If it hides the point, cut the setup and say the thing.

## Article Shapes

### Attack Walkthrough

Purpose: explain how an attacker turns a leaked value into usage.

Required shape:

- sharp title;
- one-sentence premise;
- attacker path in plain language;
- what the attacker needs;
- where Worthless breaks the path;
- where Worthless does not help;
- sources or explicit hypothetical label.

Example title:

- `How leaked AI keys get reused`

### Incident Note

Purpose: analyze a sourced external incident without overclaiming.

Required shape:

- source and date;
- what leaked;
- what the attacker could do;
- what Worthless would change if the leaked value were a locked supported AI key;
- what Worthless would not change;
- incident-response note, including rotation or revocation when relevant.

Example title:

- `An AI-built app pushed .env to GitHub`

### Boundary Note

Purpose: write the uncomfortable page that keeps the product claim honest.

Required shape:

- narrow boundary statement;
- concrete scenario;
- why Worthless does not solve it;
- what the user should do instead.

Example title:

- `If local malware can use your proxy, this is still an incident`

## Visible Index

The `/red/` index should behave like a blog index, not a trust portal.

It should show:

- a minimal hero;
- the attack premise;
- published posts only;
- short post summaries;
- restrained labels such as `Walkthrough`, `Incident`, and `Boundary`;
- a short verdict line when useful.

It should not show:

- claim tables as the primary CTA;
- long explanations of what Red Blog is;
- proof grids;
- nested cards;
- fake terminal output;
- draft post titles unless explicitly enabled for local preview.

## Draft Policy

Drafts may exist in source-controlled metadata, but they must stay hidden from public pages until reviewed.

Use a simple publication gate:

- `published: false` hides drafts;
- `published: true` shows reviewed posts;
- local preview flags may reveal drafts only for development.

Draft copy must not be written as if it is public proof.

## Worthless Applicability Rule

Every attack or incident page that mentions Worthless must use this framing:

- `Worthless would change:` the copied-key reuse path for a locked supported AI key.
- `Worthless would not change:` unsupported credentials, full same-user host compromise, provider billing disputes, broad cloud account exposure, or any path where attacker-controlled code can use the trusted local route.

Avoid:

- `Worthless would have prevented this incident`
- `leaks are harmless`
- `nothing happens if your key leaks`
- `hard spend cap`
- broad all-secret or any-secret claims.

Use:

- `copied locked value alone is not enough`;
- `would change copied-key reuse`;
- `would partially reduce blast radius`;
- `would not materially change this incident`.

## Visual Direction

The visual style should be minimal, dark, and attack-oriented, but not theatrical hacker cosplay.

References:

- research credibility from Google Project Zero;
- practitioner field notes from red-team blogs;
- case-study discipline from NCC Group and Trail of Bits;
- practical exploit indexing from PortSwigger;
- a small amount of underground notebook energy, but not Matrix green, skulls, neon, or fake shell prompts.

The design should use:

- one strong headline;
- a small number of post rows;
- generous negative space;
- source and verdict details only when they clarify;
- mono only for real artifacts, commands, labels, or copied values;
- short labels;
- no decorative terminal chrome unless the content is an actual artifact.

## Relationship To Proof And Trust Pages

Proof and limitation URLs may exist for WOR-397 to reference, but they should not dominate Red Blog.

Stable supporting URLs:

- `/red/`
- `/red/incidents.html`
- `/red/claims.html`
- `/red/security-model.html`

`/red/claims.html` should be treated as supporting `Proof & limits`, not as the main Red Blog experience.

`/red/security-model.html` should be treated as a boundary reference, not a blog post.

## PR #243 Amendment Scope

The current PR should be amended to align with this spec:

- keep the hidden draft mechanism;
- keep stable proof/trust URLs;
- make `/red/` a minimal attack notebook index;
- de-emphasize `claims.html` and `security-model.html`;
- avoid shipping a fake finished Red Blog with no reviewed posts;
- keep sourced incident/proof material only if it is short, scoped, and clearly not overclaiming.

The amendment should not:

- redesign the homepage;
- expand sitemap, robots, `llms.txt`, or SEO/AEO metadata;
- create broad SEO pages;
- publish unsourced Red Blog articles;
- claim unsupported provider, platform, or secret coverage.

## Acceptance Criteria

- `/red/` reads like a human-written attack blog index, not a product trust dashboard.
- The first viewport contains fewer than three conceptual claims.
- Copy uses short, concrete sentences.
- Draft posts are hidden by default.
- Supporting proof/security URLs remain stable but secondary.
- Tests guard against overclaims and accidental draft publication.
- Desktop and mobile render without clipped text, horizontal overflow, or crowded navigation.
