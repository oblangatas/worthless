# Install -- Teams

> [!NOTE]
> **Planned** -- Team deployment with per-member spend caps and a shared dashboard
> is not yet available. The documentation below describes the target-state design.
> See the [GitHub repository](https://github.com/shacharm2/worthless) for current install options.

## Target-state features

- One-click deploy to Railway or your own infrastructure
- Team dashboard with per-member spend caps
- Contractor management and budget isolation
- Proxy listens on port 8787
- Audit log for all API calls

## Current option

Each team member runs the proxy locally:

```bash
git clone https://github.com/shacharm2/worthless && cd worthless
uv pip install -e .
worthless lock
worthless wrap python your_app.py
```

See the [GitHub repository](https://github.com/shacharm2/worthless) for the full quickstart.
