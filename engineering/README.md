# Engineering Docs

`engineering/` is the developer-facing documentation tree for the current `worthless` codebase.
It is the canonical place to answer:

- what exists in the repo right now
- how the major runtime flows work
- which modules own which responsibilities
- how to maintain and extend the current Python implementation

## Boundary

- `engineering/` documents the current codebase as it exists now.
- `security-audit/` documents security-specific analysis, findings, and enforcement gaps.
- `docs/` is the public website/docs tree and should not be used for internal engineering material.

## Structure

- [architecture.md](architecture.md): current system shape and runtime boundaries
- [modules.md](modules.md): module ownership, security invariants, and edit rules per module — read before touching a module
- [flows.md](flows.md): the main end-to-end flows through the system
- [operations.md](operations.md): operator and maintainer runtime notes
- [release-gates.md](release-gates.md): hard go/no-go criteria for Starter and OpenClaw releases
- [tooling.md](tooling.md): generated-docs workflow, verification, and helper tooling
- [research/README.md](research/README.md): internal research inputs and retained working analysis
- [research/ai-docs-tools-research-2026.md](research/ai-docs-tools-research-2026.md): preserved market research for AI-first docs tooling
- `generated/pyreverse/`: deterministic structure artifacts generated from the repo

## Working rules

- Generated docs are inputs, not truth.
- Canonical truth stays in repo files.
- Structural claims should be checked against source and deterministic outputs.
- Historical planning docs under `.planning/` are context only; `engineering/` describes the live repo.
