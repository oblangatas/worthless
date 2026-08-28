# macOS Background Items — Phase C verification (2026-06-15)

Manual checklist from OS-state cleanup research. Records CLI-verifiable behavior after
`worthless service install` / `uninstall`. **Settings UI must be checked by a human** — no
public API exposes Background Items list state.

## Environment

- macOS, user `shachar`, `gui/502`
- Branch: `main` (editable install from checkout)
- Label: `dev.worthless.proxy`
- Plist: `~/Library/LaunchAgents/dev.worthless.proxy.plist`

## Results

| Step | Plist on disk | `launchctl print gui/$UID/dev.worthless.proxy` |
|------|---------------|--------------------------------------------------|
| Before (clean) | absent | `Could not find service` |
| After `worthless service install --yes` | present (`-rw-------`, 904 bytes) | `active count = 1`, path matches plist |
| After `worthless service uninstall --yes` | **absent** | `Could not find service` |

## Conclusions

1. **`worthless service uninstall` fully removes the LaunchAgent** at the launchd layer (plist deleted, job not loaded).
2. **Background Items notification** appears on install (macOS Ventura+); Worthless does not call a separate unregister API.
3. **Settings → Login Items & Extensions → Background Items** may still list `worthless` after uninstall — treat as **cosmetic stale UI** when plist is absent and `launchctl print` fails.
4. **Repeated install/uninstall cycles** (live packs) can produce **duplicate notifications**; not a sign of multiple running agents.

## Human follow-up (optional)

After reading this doc, open **System Settings → General → Login Items & Extensions → Background Items** and note whether `worthless` appears post-uninstall. If listed but plist is gone, toggle off manually.

## Reproduce

```bash
PLIST="$HOME/Library/LaunchAgents/dev.worthless.proxy.plist"
ls -la "$PLIST" 2>&1 || true
launchctl print "gui/$(id -u)/dev.worthless.proxy" 2>&1 | head -3

worthless service install --yes
ls -la "$PLIST"
launchctl print "gui/$(id -u)/dev.worthless.proxy" 2>&1 | head -3

worthless service uninstall --yes
test ! -f "$PLIST"
launchctl print "gui/$(id -u)/dev.worthless.proxy" 2>&1 | head -3  # expect not found
```
