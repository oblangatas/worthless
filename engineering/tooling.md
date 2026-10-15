# Tooling and Verification

## Goal

`engineering/` is intended to be generated-first, but not hallucination-first.

The working model is:

- AI-first generation for breadth and speed
- deterministic structure extraction for verification
- direct source review for important claims

## Current tool choices

### Primary pilot: `CodeWiki`

`CodeWiki` is the first pilot candidate for generated-first engineering docs because it is the best current fit for writing repo-owned docs files instead of only hosting a web UI.

Planned role:

- generate first-pass module and system docs
- support incremental updates as the repo changes
- write candidate content that can be reviewed and promoted into `engineering/`

Local workflow:

- `scripts/codewiki.sh`: bootstrap and run `CodeWiki` in an isolated tool env
- `scripts/codewiki.sh generate --output engineering/generated/codewiki-pilot`: generate draft docs there
- `.venvs/codewiki`: dedicated `CodeWiki` virtualenv, separate from the repo `.venv`
- `.codewiki-home/`: repo-local `CodeWiki` state/config directory

### Deterministic verification: `pyreverse`

`pyreverse` is the structural verification floor.

Planned role:

- generate package/class relationship artifacts for the Python codebase
- provide a deterministic check on AI-generated module structure claims
- help detect drift between the actual package layout and generated docs

Status right now:

- current outputs live under `engineering/generated/pyreverse/`
- rendered SVG diagrams can be produced from those DOT files via `graphviz`
- regenerating the `pyreverse` artifacts requires a local `pyreverse`/`pylint` install outside the project dependency set, because the repo license gate rejects committing `pylint` as a project dependency
- `engineering/generated/module-tree.md` remains as a simple supplemental baseline generated directly from the repo tree
- `CodeWiki` is isolated from repo dependencies via `scripts/codewiki.sh` and `.venvs/codewiki`

### Interactive helper: code graph tooling

Code-graph tooling is useful for maintainers while exploring the repo, but it is not the source of truth.

Use it for:

- tracing symbols and callers
- understanding impact before edits
- validating whether generated docs describe the real execution paths

Do not use it as a substitute for canonical repo docs.

## Test lanes

The `test-*` commands were removed in worthless-nd65 (they installed onto every user's PATH).
These are their exact equivalents. The `-o addopts=...` part matters: it drops the default
`-n auto --reruns 1` and the 30 s timeout, so the slow lanes run one at a time with their own
timeout, and the paid live lane never runs in parallel or retries.

| Lane | Command |
|---|---|
| unit | `uv run pytest -x -q` |
| docker | `uv run pytest -x -v -m docker -o "addopts=--strict-markers --timeout=300"` |
| live (real APIs, costs money) | `uv run pytest -x -v -s -m live -o "addopts=--strict-markers --timeout=120"` |
| openclaw | `uv run pytest -x -v -m openclaw -o "addopts=--strict-markers --timeout=300"` |
| everything | `uv run pytest -v -o "addopts=--strict-markers --timeout=300"` |

## Verification workflow

1. generate candidate docs
2. compare major structure claims against deterministic outputs
3. spot-check important modules and runtime flows in source
4. promote reviewed content into canonical `engineering/`

## Failure rule

If generated docs and the repo disagree:

- source wins
- deterministic structure outputs win over LLM guesses about layout
- canonical docs are corrected in repo
- the generator is adjusted or replaced; the docs taxonomy stays
