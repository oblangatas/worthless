# PROTOTYPE — throwaway, never merge

Disposable code for worthless-oi9b. It answers one question for each remaining
untested install.sh branch: can the branch be reached for real, and what is the
cheapest faithful way to observe it?

## Answers

| Branch | Reachable | Cheapest faithful way |
|---|---|---|
| unknown OS | yes, rc=20 | stub uname |
| sw_vers missing | yes (warns, then continues) | a PATH without /usr/bin, because macOS has a real sw_vers there |
| unparseable macOS version | yes, rc=20 | stub sw_vers |
| no trusted hasher | yes, rc=40 | only with the escape hatch, by hiding the hashers from PATH |
| Astral installer fails | yes, rc=10 | only with a stub hasher that returns the pinned sha |
| uv missing after bootstrap | yes, rc=40 | installer stub exits 0 and places nothing |
| colour arm | yes | PTY with NO_COLOR unset; NO_COLOR=1 suppresses it |
| real trusted loops, no escape hatch | **found two security bugs** | see below |

## Security findings

- **worthless-52lm (P0).** When the pinned uv lives outside ~/.local/bin
  (for example ~/.cargo/bin or /opt/homebrew/bin), ensure_uv returns early and
  skips its PATH prepend. The attacker's uv then runs `tool install`. Repro:
  `premortem-uvprobe/`.
- **worthless-2qfm (P1).** Astral's installer is a child process that inherits
  PATH. The PATH lockdown omits /sbin, where macOS keeps sha256sum, so a planted
  sha256sum runs. We spied on all 297 sbin-only tools during a real install, and
  sha256sum is the only one executed.
