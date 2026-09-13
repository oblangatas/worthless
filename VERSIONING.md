# Versioning

## Rule

Worthless follows [SemVer](https://semver.org/) for PyPI releases:

```
MAJOR.MINOR.PATCH
```

- **PATCH** — backwards-compatible bug fixes, doc updates
- **MINOR** — backwards-compatible new features
- **MAJOR** — breaking changes to CLI, config, or proxy protocol

Git tags `vMAJOR.MINOR.PATCH` trigger the four publishers — PyPI (`.github/workflows/publish.yml`, via [trusted publishing](https://docs.pypi.org/trusted-publishers/)), npm, the GHCR image and the worthless.sh Worker — and then the GitHub Release. How to cut one: [RELEASING.md](RELEASING.md).

## Current Version

**v0.3.0** — first PyPI release (2026-04-18).

## Release History

| Version | Date       | Highlights                                                                 |
|---------|------------|----------------------------------------------------------------------------|
| `v0.3.0`| 2026-04-18 | First PyPI publish. Magic default command, format-preserving key split (WOR-207 P1–P2), Anthropic auth, CodeQL hardening. |

## Historical (pre-PyPI) tags

Tags `v0.1.0`, `v0.2.0`, `v0.3.0` (legacy), `v0.3.1`, `v1.0` were created during PoC development as phase/milestone markers and **were never published to PyPI**. They remain in the repo as historical anchors only. The first tag pushed to the `publish.yml` pipeline is `v0.3.0` (this release).

## Milestones

| Milestone | Goal                                                |
|-----------|-----------------------------------------------------|
| PoC       | Python + SQLite, prove the architecture — complete  |
| v1.x      | CLI + proxy maturity, PyPI-published — current      |
| Harden    | Rust reconstruction service, production hardening   |
| Attack    | Pen-testing, red team, security audit               |

## For Agents

- **Check `Current Version` above** to know what ships on PyPI.
- **Do not tag releases without confirmation.** Tagging `vX.Y.Z` on `main` fires all four publishers and burns that version on PyPI and npm forever (neither accepts a re-upload of the same version).
- **Pre-release dry runs**: push `vX.Y.Zrc1` to test the publish pipeline without burning the final version number. It still runs all four publishers and asks for the same approvals — including deploying the Worker to production.
- **Update this file** and `pyproject.toml` in the same commit as any version bump — a CI drift test compares them.
