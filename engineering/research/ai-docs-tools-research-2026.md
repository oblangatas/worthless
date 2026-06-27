# AI-First Engineering Documentation Tools — 2026 Landscape

*Research date: 2026-04-17. All "alive" claims verified against live homepage/docs/GitHub within the last ~6 months.*

## 1. Market summary

The category consolidated hard in 2024–2025. Mutable.ai — the original "Wikipedia for your code" — was acquired by Google in Nov 2024 and shut down ([HN discussion](https://news.ycombinator.com/item?id=42542512); [Tech Startups recap](https://techstartups.com/2025/12/09/top-ai-startups-that-shut-down-in-2025-what-founders-can-learn/)). Its vision was picked up by three credible successors: **Cognition's DeepWiki** (free for public, Devin-gated for private, launched Apr 2025) ([Cognition blog](https://cognition.ai/blog/deepwiki)), **Google's Code Wiki** (public preview Nov 2025, private-repo CLI on waitlist) ([Google Developers Blog](https://developers.googleblog.com/en/introducing-code-wiki-accelerating-your-code-understanding/)), and **Mintlify's Agent/Autopilot** (self-updating docs from code, Dec 2025) ([Mintlify blog](https://www.mintlify.com/blog/autopilot)). Meanwhile the incumbent **Swimm** added AI-Assisted Doc Creation on top of its patented auto-sync ([Swimm pricing](https://swimm.io/pricing)), and two serious open-source contenders emerged: **deepwiki-open** (~15.7k stars, MIT, web-UI-first) ([repo](https://github.com/AsyncFuncAI/deepwiki-open)) and **CodeWiki/FSoft-AI4Code** (877 stars, CLI-first with incremental `--update` mode and MCP server — the rare OSS tool built for generated-first docs committed in-repo, last commit 2026-04-04) ([repo](https://github.com/FSoft-AI4Code/CodeWiki)). Deterministic code-graph tools (GitNexus, SCIP, tree-sitter, ast-grep) remain essential verification/grounding layers — LLM-only docs drift; graph-grounded docs don't.

## 2. Table 1 — Best current AI-first tools for engineering docs

| Tool | Alive in 2026? | Free tier? | SaaS / Local | Private repo | Best for | Weakness |
|---|---|---|---|---|---|---|
| **DeepWiki (Cognition)** | Yes — actively maintained; MCP server added 2025 ([blog](https://cognition.ai/blog/deepwiki-mcp-server)) | Free for public repos | SaaS (hosted) | Requires paid Devin account ($20+/mo) ([Devin pricing](https://devin.ai/pricing/)) | Zero-effort wiki + MCP-accessible Q&A over your code | Your code leaves your infra; not source-controlled |
| **Google Code Wiki** | Yes — public preview launched Nov 13 2025 ([codewiki.google](https://codewiki.google/)) | Free for public | SaaS; CLI (Gemini extension) for private — **waitlist only** ([Google blog](https://developers.googleblog.com/en/introducing-code-wiki-accelerating-your-code-understanding/)) | Public now; private via CLI when off waitlist | Highest-quality generated wikis; diagrams + chat | Private path not GA in April 2026 |
| **Mintlify Agent (Autopilot)** | Yes — launched Dec 8 2025 ([blog](https://www.mintlify.com/blog/autopilot)) | Free tier for public/small; paid for agent workflows (~$300/mo review, [Ferndesk](https://ferndesk.com/blog/mintlify-review)) | SaaS; docs-as-code in your repo | Yes, via GitHub/GitLab app | Docs-as-code shops who want PRs opened against them when code ships | Heavy toward marketing/API ref aesthetic; pricey for solo devs |
| **Swimm** | Yes — active, 2026 updates ([pricing](https://swimm.io/pricing)) | Free plan (≤5 users, repo limits) ([research.com](https://research.com/software/reviews/swimm)) | SaaS + on-prem + air-gapped | Yes (enterprise incl. self-hosted LLMs) | IDE-embedded tutorials/walkthroughs with patented auto-sync on PR | Doc-authoring-centric, not fully generated-first |
| **deepwiki-open (AsyncFuncAI)** | Yes — 214 commits, active, MIT ([repo](https://github.com/AsyncFuncAI/deepwiki-open)) | Free, OSS | Local / self-hosted | Yes, via PAT for GitHub/GitLab/Bitbucket | Self-hosted DeepWiki clone; bring your own LLM (Gemini/OpenAI/Ollama) | No auto-update loop out of the box; manual re-run |
| **CodeWiki (FSoft-AI4Code)** | Yes — last commit 2026-04-04, 877 stars ([repo](https://github.com/FSoft-AI4Code/CodeWiki)) | Free, OSS | Local CLI + Docker + MCP server | Yes — local only; no telemetry; BYO-key LLM | **Generated-first docs committed in-repo with `codewiki generate --update` incremental mode** — CI-friendly. 8 languages (Py/Java/JS/TS/C/C++/C#/Kotlin). OpenAI / Anthropic / Bedrock / Azure; Ollama works via `--base-url http://localhost:11434/v1` (implicit, not documented). Mermaid diagrams | **No LICENSE file in repo** despite MIT claim in README ([file list](https://github.com/FSoft-AI4Code/CodeWiki)); "ACL 2026" claim cites an arXiv 2025 preprint ([arXiv:2510.24428](https://arxiv.org/abs/2510.24428)) — acceptance not yet demonstrable. Research-grade UX |
| **Qodo (Gen/Merge)** | Yes — Qodo 2.0 released Feb 2026 ([Wikipedia](https://en.wikipedia.org/wiki/Qodo)) | Free tier | SaaS + IDE/CLI/Git plugin | Yes | `/add_docs` and `/describe` agents on PRs; changelog maintenance | PR-side doc updates, not whole-repo wiki generation |
| **GitHub Copilot Spaces** | Yes — launched May 2025, in Copilot Free ([changelog](https://github.blog/changelog/2025-05-29-introducing-copilot-spaces-a-new-way-to-work-with-code-and-context/)) | Yes (included in Copilot Free) | SaaS (github.com/copilot/spaces) | Yes, any repo you can access | Curated context bundles + Q&A; sharable within org | Not generated docs — a context curation layer |
| **Unblocked** | Yes — $20M raised May 2025 ([TechCrunch](https://techcrunch.com/2025/05/06/unblocked-raises-20-million-for-its-ai-assistant-to-help-devs-understand-legacy-codebases/)); commits April 2026 | 21-day trial, no free tier | SaaS + on-prem (enterprise) | Yes; incl. GitHub Enterprise, GitLab self-managed ([pricing](https://getunblocked.com/pricing)) | Q&A grounded in code + Slack/Jira/Notion — strong for legacy codebases | Context engine, not a docs-tree generator |
| **Continue.dev (CLI doc agent)** | Yes — active ([docs](https://docs.continue.dev/guides/doc-writing-agent-cli)) | OSS + free CLI | Local CLI + GitHub Actions | Yes (runs in your repo) | Wiring up doc-update agents in CI from `git diff` | DIY: you write the agent rules; no out-of-box wiki |
| **Sourcegraph Amp (née Cody)** | Yes — Amp replaces Cody self-serve (shut down July 23 2025) ([blog](https://sourcegraph.com/blog/changes-to-cody-free-pro-and-enterprise-starter-plans)) | No free tier; contact sales | SaaS + enterprise self-host | Yes (enterprise) | Codebase Q&A + agent loops across monorepos | Enterprise-only now; wrong altitude for solo devs |
| **Cursor codebase docs** | Yes — active product ([docs](https://docs.cursor.com/context/codebase-indexing)) | Free tier; Pro $20/mo | SaaS indexing; source stays local | Yes — only embeddings leave your machine ([Cursor blog](https://cursor.com/blog/secure-codebase-indexing)) | @Docs + codebase chat while coding; not generated docs | No wiki output — interactive only |
| **Mutable.ai** | **NO — shut down / acquired by Google Nov 2024** ([HN](https://news.ycombinator.com/item?id=42542512)) | — | — | — | — | Dead — do not pursue |
| **Watermelon** | Yes but wrong category — PR code-review context ([repo](https://github.com/watermelontools/watermelon)) | Free tier | SaaS | Yes | Pre-PR context from Slack/Jira/Notion | Not a docs-generator |
| **Pieces for Developers** | Yes but wrong category — snippet/context manager ([aichief review](https://aichief.com/ai-productivity-tools/pieces-for-developers/)) | Free tier | Local-first desktop | N/A | Personal snippet memory across tools | Not a repo docs generator |
| **Sourcery** | Yes but wrong category — AI PR review ([pricing](https://docs.sourcery.ai/Plans-and-Pricing/)) | Free for OSS; $12/user/mo private | SaaS | Yes | PR review comments, IDE scans | Not a docs-generator |

## 3. Table 2 — Helper tools for understanding codebases and verifying generated docs

These deterministically extract structure from code (no LLM guessing). Use them to **ground** generated docs and to **detect drift**.

| Tool | Type | What it helps with | Why it matters |
|---|---|---|---|
| **GitNexus** | Code knowledge graph + MCP + wiki CLI ([repo](https://github.com/abhigyanpatwari/GitNexus), v1.6.1 Apr 13 2026) | `gitnexus analyze` builds a tree-sitter graph of symbols/flows; `gitnexus wiki` generates per-module docs grounded in that graph; MCP for Claude Code hooks | Already installed in Worthless (see `CLAUDE.md`). Graph-grounded facts stop LLM hallucinations and let you ask "what breaks if I change X?" before editing |
| **tree-sitter** | Incremental AST parser | Language-agnostic structural parsing (used by Cursor, aider, GitNexus, ast-grep) | The de facto substrate for every modern code-aware tool; free and fast |
| **ast-grep** | CLI structural search/lint/rewrite on tree-sitter ([repo](https://github.com/ast-grep/ast-grep)) | Find + rewrite patterns by AST, not regex; custom rules per codebase | Deterministic codemods and doc-anchor checks (e.g. "every public function must have a docstring") |
| **Sourcegraph SCIP** | Code-intel protocol + indexers ([blog](https://sourcegraph.com/blog/announcing-scip)) | Precise go-to-def / find-refs across TypeScript, Java, Scala, Kotlin, Python, Go, Rust | 8x smaller / 3x faster than LSIF; the canonical way to produce verified xrefs |
| **aider repo-map** | tree-sitter + PageRank symbol ranker ([docs](https://aider.chat/docs/repomap.html)) | Exports a compact "what exists and is important" map of a repo | Excellent ground-truth context for any LLM doc step; `aider --show-repo-map > map.md` |
| **Sphinx autodoc / AutoAPI** | Docstring-driven reference docs ([autoapi](https://autoapi.readthedocs.io/)) | Canonical Python API reference from the source | Zero-hallucination layer for API reference; pair with LLM layer for narrative |
| **Doxygen + Breathe** | Multi-language API reference ([Breathe](https://breathe.readthedocs.io/)) | Same for C/C++/Java etc. | Ground truth for non-Python surfaces |
| **Diátaxis framework** | Information architecture (tutorials / how-to / reference / explanation) ([diataxis.fr](https://diataxis.fr/)) | Structures your `engineering/` tree so each generated doc has a correct shape | Fits generated-first workflows — different quadrants, different generators |
| **Semgrep / ast-grep rules** | Policy-as-code over AST | Enforce "every new public function in `src/worthless/crypto/` has a docstring + linked doc page" | Catches doc drift deterministically at CI time |

## 4. Table 3 — Recommendation for the Worthless use case

**User's use case:** generated-first `engineering/` docs tree for a Python-first split-key proxy codebase (already indexed by GitNexus). Docs auto-update with code. Interactive help while coding. Canonical docs live in-repo.

| Rank | Tool / stack | Verdict | Why |
|---|---|---|---|
| **1** | **GitNexus `wiki` + Claude Code (existing stack) + Mintlify Agent on top** | **Adopt** | GitNexus already running (`CLAUDE.md`), already MCP-integrated with Claude Code, already generates per-module docs grounded in a real graph — zero hallucination risk. Add Mintlify Agent to open PRs against the `engineering/` tree when code ships (keeps docs source-controlled). Mintlify is the only tool that does generated-first PRs *into your repo* ([autopilot](https://www.mintlify.com/blog/autopilot)). This beats giving up control to DeepWiki's hosted wiki. |
| **2** | **CodeWiki (FSoft-AI4Code)** for the in-repo `engineering/` tree + CI auto-update | **Pilot → likely Adopt** | Best single-tool fit for "generated-first docs committed in-repo, re-run on each commit." CLI writes files directly; `codewiki generate --update` does incremental regeneration of changed modules — drop it into a GitHub Action on push. Private-safe (local, no telemetry), BYO-key (Anthropic works natively; Ollama via `--base-url`). Caveats: missing LICENSE file despite MIT README claim — flag to legal if that matters; ACL 2026 label unverified. Pairs cleanly with GitNexus as ground truth. |
| **3** | **deepwiki-open (self-hosted)** as a secondary browsable surface | **Pilot** | MIT (real LICENSE file), 15.7k stars, explicit Ollama support ([repo](https://github.com/AsyncFuncAI/deepwiki-open)). Web-UI-first — not the right primary tool when docs must live in-repo, but an excellent *second* surface for new-hire browsing alongside the CodeWiki-generated tree. |
| **4** | **Cursor @Docs + Copilot Spaces** for "interactive help while vibe coding" | **Adopt** | Both free (or included), both private-repo-safe, both complementary to the generated tree. Spaces lets you bundle PRD + GitNexus output + code for ad-hoc Q&A across the org. |
| 5 | **Swimm** | **Reject for this use case** | Authoring-centric (patented auto-sync is great for *hand-written* docs pinned to snippets) but generation story is weaker than Mintlify/CodeWiki. Heavier overhead than value for a solo/small team. |
| 6 | **Google Code Wiki (private CLI)** | **Revisit Q3 2026** | Likely best-in-class once the Gemini CLI ships for private repos ([Google blog](https://developers.googleblog.com/en/introducing-code-wiki-accelerating-your-code-understanding/)), but waitlist-only today — do not depend on. |
| 7 | **DeepWiki hosted (private, via Devin)** | **Reject** | Sends code to Cognition; no source control of docs; $20+/mo minimum. For a security product (Worthless), hosted private-repo indexing is the wrong tradeoff. |
| 8 | **Sourcegraph Amp** | **Reject** | Enterprise-only since July 2025 — wrong altitude and price for Worthless. |
| 9 | **Qodo `/add_docs`** | **Optional add-on** | Useful as a PR-side automation (auto-updates docstrings/changelog on merge). Complementary, not primary. |

**Verification layer (mandatory, already in place):** GitNexus graph + ast-grep rules + Sphinx autodoc for the Python API surface. Any LLM-generated narrative doc that contradicts the graph must fail CI. This is the "don't hallucinate the architecture" guarantee.

## 5. Tools investigated but excluded

| Tool | Reason excluded |
|---|---|
| **Mutable.ai** | Dead. Acquired by Google Nov 2024; site dark ([HN](https://news.ycombinator.com/item?id=42542512)) |
| **GitHub Copilot Workspace** | Task-execution environment, not a docs-tree generator ([githubnext](https://githubnext.com/projects/copilot-workspace/)) |
| **Supermaven** | Autocomplete product; no docs-generation surface |
| **Codeium / Windsurf** | IDE assistant + autocomplete; no whole-repo wiki output |
| **Glean** | Enterprise knowledge search — great at code search ([blog](https://www.glean.com/blog/code-search-code-writer-jan-drop-2026)) but not a code-to-docs generator and enterprise-priced |
| **Watermelon** | PR-context tool, not docs-generator ([repo](https://github.com/watermelontools/watermelon)) |
| **Pieces for Developers** | Personal snippet/context manager, wrong category |
| **Sourcery** | AI PR reviewer, not docs generator ([site](https://www.sourcery.ai/)) |
| **Daytona** | Sandbox infra for running agent code ([site](https://www.daytona.io/)); not a docs tool |
| **Devin (standalone)** | Coding agent; docs-generation goes through DeepWiki, already covered |
| **Backstage / BookStack / Outline / Notion / Confluence / GitBook / Docmost** | Generic wikis, not code-aware; explicitly excluded |
| **OpenDeepWiki (AIDotNet)** | Alive but less mature than deepwiki-open; redundant alternative |
| **Microsoft auto-github-docs-generator** | README-level generator, last meaningful activity old — unable to verify as actively maintained for 2026 |
| **open-repo-wiki (daeisbae)** | Small OSS project; unable to verify active maintenance vs deepwiki-open; skipped as redundant |

---

*Sources are linked inline at each verified claim. Every "alive in 2026" row was cross-checked against the tool's own site, GitHub activity, or a dated 2026 blog/changelog.*
