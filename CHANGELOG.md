# Changelog

All notable changes to Worthless are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Security
- **A process allowed to talk to the sidecar can no longer pin its memory by sending half a message and going quiet** (WOR-1076).
  Before: the sidecar, the process that holds your encryption key and does all decrypting, waited forever for a message to finish arriving and kept any number of connections open. A process running as an allowed user could open many connections, start a 1 MiB message on each, stop one byte short, and hold about 1 MiB of sidecar memory per connection until the sidecar ran out of file handles or was killed for using too much memory. Without the sidecar nothing decrypts. In the Docker image the proxy runs as a user that can't otherwise stop the sidecar (WOR-306), so a compromised proxy gained a way to take it down.
  Now: once a message has started, the rest must arrive within 10 s, and the first message (the hello) within 10 s of connecting. Otherwise the sidecar closes that connection. It holds at most 32 connections at once and closes any extra one as soon as it accepts it, before reading anything from it. A connection stalled mid-message holds at most 1 MiB, so 32 hold at most 32 MiB, and only for 10 s before they must be sent again. Worthless's own clients (the proxy, the CLI and the health check) send each message in one piece as soon as they connect or have a request, so neither limit affects them. A connection that is idle between messages stays open, because the proxy keeps one open for as long as it runs.

  **Limits.**
  - An allowed process can still fill all 32 connections and leave them idle, so new connections are refused: a health check, a CLI command, or the proxy reconnecting. Only a process running as an allowed user (in Docker, the proxy's) can do this, and a compromised proxy could already refuse to serve. Before, the same lockout took using up the sidecar's file handles; now it takes 32 connections.
  - A process that sends requests and never reads the replies isn't covered. Its connection stays open with about 2 MiB of unread requests queued until it closes. The cap still limits this to 32 connections, about 75 MiB (WOR-1079).
  - Neither limit can be changed by config.
- **Lock no longer says "You're protected" while a copy of your key is still in the `.env` as plain text** (WOR-1048, [#740](https://github.com/oblangatas/worthless/pull/740)).
  Before: if the `.env` held a second copy of a key on a line lock doesn't replace, such as a quoted name (`'OPENROUTER_API_KEY'=sk-or-…`), a commented-out line with the same key, or the key inside another variable's value, lock replaced the key's own line, said "You're protected", and left the real key readable in the file. python-dotenv reads the last line, so an app reading a quoted copy, or anyone with a copy of the file, still got the real key. If that file also had a `*_BASE_URL` line with no value, or a quoted one, lock used to stop with WRTLS-199 instead; the WOR-1041 fix below makes such a file lock, so both changes ship together.
  Now: before it stores anything or touches the `.env`, lock checks that no copy of a key it is replacing would stay in the file. If one would, it stops with WRTLS-112 and names the variable, never the value. Your `.env` is unchanged, nothing new is stored, and a key this `.env` had already locked stays locked. Delete the copy and run `worthless lock` again.

  **Limits.**
  - Lock looks for the key's exact text. A copy that was changed, for example split across lines, escaped, encoded or assembled from `${...}` parts, isn't found.
  - Lock checks only the keys it is replacing now. A different key on a line it won't replace, such as a commented-out older key, stays readable, and lock still says you're protected.
- **Unlocking a key that v0.3.16 or earlier locked puts back its vendor's address where that is safe, and tells you when it can't** (WOR-981, [#737](https://github.com/oblangatas/worthless/pull/737); WOR-1013, [#738](https://github.com/oblangatas/worthless/pull/738)).
  If your `.env` had a `*_BASE_URL` line before a normal lock with v0.3.16 or earlier, for example `OPENROUTER_BASE_URL=https://openrouter.ai/api/v1`, lock replaced it with the proxy URL and kept no copy of your value. Unlock and uninstall now put back that vendor's address when your key names the vendor (an `sk-or-` key gets OpenRouter's), and say so. Removing the line instead would let an app that reads `OPENROUTER_BASE_URL` with no default send your OpenRouter key to OpenAI. Before this release, unlock left the dead proxy line, so calls failed on your machine (an `OPENAI_BASE_URL` or `ANTHROPIC_BASE_URL` line was removed instead).

  **Limits.**
  - If lock had added the line, unlock leaves it in place with the vendor's address. Delete it if you don't want it.
  - Unlock removes the line instead, and tells you to set it again, when it can't be sure the address is right for every app that reads the line:
    - The key is an OpenAI-style `sk-` key. That prefix also starts DeepSeek and other keys, and OpenAI's address is the SDK default anyway.
    - Another key in the same `.env`, locked or not, reads that line too, for example an OpenAI key next to an OpenRouter key's `OPENAI_BASE_URL`.
    - The address speaks Anthropic's protocol (Anthropic's own, or a gateway you registered with `--protocol anthropic`), or the line is `ANTHROPIC_BASE_URL`. The Anthropic SDK adds its own `/v1`.
    - The stored address isn't in the provider list, isn't a public https address (a local Ollama, for example), or contains a `$`.

    A gateway you registered yourself with `--protocol openai` still goes back under the same line rules, because it came from your own line. An app that reads a removed line with no default uses its SDK's default address. Unlock only sees keys in this `.env`. It does not see another `.env` your app also loads (such as `.env.local`) or keys your shell exports, so an OpenAI key kept there can still end up reading an OpenRouter address (WOR-1034).
  - The stored address isn't sealed: someone who can write the Worthless database can change it. Unlock writes back only an address that passes the rules above, and the proxy already sends your key to the stored address while the key is locked (worthless-rzi1).
  - For a key locked with this version, a saved value changed in the Worthless database is never replaced by the stored address: unlock removes the line and tells you.
  - The written value is the one lock resolved, so a `${...}` reference you had comes back expanded.
  - If the same key was also locked from another `.env`, the stored address is the last one lock saw for that key, which may be the other file's (WOR-1029).
- **Malformed messages no longer leak the sidecar's memory** (CVE-2026-114613, [#745](https://github.com/oblangatas/worthless/pull/745)).
  Before: Worthless accepted any msgpack from 1.0 on. msgpack 1.2.2 and earlier leak the rest of every message the sidecar rejects for having a non-string key. A process the sidecar accepts could grow it by about 1 MiB per message, without limit. Measured on the real sidecar, 200 such messages added 199 MiB. The proxy reads the sidecar's replies with the same decoder, so a fake sidecar could do the same to the proxy (WOR-1078).
  Before, too: one 5 KB message that declares huge lists made the sidecar briefly allocate about 513 MiB (GHSA-j8c6-9vc5-hj6x).
  Now: this release requires msgpack 1.2.4 or newer. It fixes the leak: the same 200 messages add 1 to 4 MiB, and 2,000 add no more. It also caps how much a list header can reserve, so the 5 KB message peaks at about 80 MiB instead of 513 MiB. Installing or upgrading to this release upgrades msgpack with it.

  **Limits.**
  - Only a process that passes the sidecar's peer-uid check can send these messages to the sidecar. The proxy doesn't yet check who is on the other end of its socket (WOR-1078).
  - An existing install keeps the msgpack it has until you upgrade Worthless.
  - Decoding still costs far more memory than the message size: one 5 KB malformed message peaks at about 80 MiB, and a valid 1 MB message of empty lists costs about 68 MiB on any msgpack version. Tighter decoder limits are tracked in WOR-1075.
  - A process the sidecar accepts can still hold its memory by opening many connections and stalling half-sent 1 MiB frames (WOR-1076).

### Fixed
- **`worthless lock` accepts a `*_BASE_URL` line with no value** (WOR-1041, [#740](https://github.com/oblangatas/worthless/pull/740)).
  Before: a `.env` with a name and no `=`, such as `OPENROUTER_BASE_URL` or `export OPENROUTER_BASE_URL`, on the line lock writes for a key made lock stop with WRTLS-199, an internal error. A name in quotes, such as `'OPENROUTER_BASE_URL'=https://openrouter.ai/api/v1`, did the same. Nothing changed: your `.env` kept its key, and lock left nothing in the Worthless database.
  Now: lock leaves that line as it is, adds its proxy line after it, and says the line "had no value", or that it "can't edit the line you have for it". python-dotenv, Node's `--env-file` and docker compose read the last line for a name, which is now the proxy line. Unlock removes only the line lock added, so lock then unlock gives back the `.env` you started with. Lock also prints that it added a line only after the `.env` is written, so a refused write no longer reports a line it never added.
  New: after writing, lock reads the `.env` the way python-dotenv does, and if a `*_BASE_URL` it wrote doesn't come back as its proxy address, it warns you, even with `--quiet`, that the app's calls won't reach the proxy and will fail.

  **Limits.**
  - If the same name also has a value on an earlier line, lock rewrites that line as before, and a later bare line (or a later quoted `'NAME'=...` line) still decides what python-dotenv reads, so your app doesn't reach the proxy and its calls fail. Lock exits 0 and warns you. Delete the later line (WOR-1045).
  - Changed in this release: if the line lock rewrites sits inside another variable's multi-line quoted value, lock writes its proxy address into that value until unlock, and your app doesn't reach the proxy. Lock exits 0 and warns you. Before, lock routed the key, but unlock deleted that line from the value for good (WOR-1045).
  - If you give the bare line a value while the key is locked, unlock removes it along with lock's line, as it does for any name on two lines (WOR-1014).
  - A `.env` whose last line has no newline gets one, as with every lock that adds a line (see the WOR-981 entry below).
- **`worthless unlock` puts back a `*_BASE_URL` line you had before lock** (WOR-1013, [#738](https://github.com/oblangatas/worthless/pull/738)).
  Before: if your `.env` already had the line lock writes for a key, for example `OPENROUTER_BASE_URL=https://openrouter.ai/api/v1` next to `OPENROUTER_API_KEY`, or your own gateway in `OPENAI_BASE_URL`, lock replaced its value with the proxy URL and did not keep yours. Unlock then removed the line. An app that reads `OPENROUTER_BASE_URL` with no default then used OpenAI's address and sent your OpenRouter key to OpenAI.
  Now: lock saves, for each key, which line it writes and the value it replaces. Unlock writes that value back as you wrote it, with its quotes, comment and any `${...}` reference, and removes the line only if lock added it. Lock then unlock gives back the `.env` you started with. `worthless uninstall` does the same.

  **Limits.**
  - A key locked with an older version has nothing saved, so unlock puts back the vendor's address where that is safe, or removes the line, and says which. See Security above. Keys you lock with this version get back exactly what you wrote.
  - Unlock writes your value back only while the line still points at that key on the proxy. If you changed or deleted the line after lock, unlock keeps your change and tells you, without putting your earlier value back (WOR-1024).
  - The saved value is tied to your Worthless encryption key and to its own row. If someone without that key changes it in the Worthless database, unlock does not write it: it removes the line and tells you. Someone who can write that database can still delete the saved value, or swap in one saved by an earlier lock of the same key (WOR-1023). With the saved value deleted, unlock treats the key as one an older version locked (see Security above).
  - A value that can't be written back unchanged (one with a quote, a space before `#`, or whitespace at one end) is not saved. Lock warns you, and unlock removes the line and tells you to set it again (WOR-1027, WOR-1042).
  - A value that spells out one of your keys is not saved either, so the record never holds a key. A `${OPENAI_API_KEY}` reference is saved as written and comes back. Lock warns you, and unlock removes the line and tells you to set it again (WOR-1035, WOR-1042).
  - An unquoted value loses whitespace at its end.
  - A value that refers to another line lock rewrites, such as `OPENROUTER_BASE_URL=${OPENAI_BASE_URL}`, directly or through another variable, comes back as the value it had at lock, not as the reference. Restored as written, it would point at the other key's proxy line while that key is still locked. Lock says so (WOR-1026).
  - If the `.env` sets the same `*_BASE_URL` on two lines, both get the last line's value back.
  - Older versions don't read the saved value, so going back to one before you unlock loses your value: its unlock removes `OPENAI_BASE_URL` or `ANTHROPIC_BASE_URL`, and leaves any other proxy line, such as `OPENROUTER_BASE_URL`, pointing at the proxy. Unlock with this version first.
  - When two keys share one line, for example `OPENAI_API_KEY` and `MY_OPENAI_KEY` both use `OPENAI_BASE_URL`, unlocking only `OPENAI_API_KEY` puts your value back while `MY_OPENAI_KEY` stays locked, so `MY_OPENAI_KEY`'s calls go to your URL with a locked value and fail. Unlock both together.
  - If you replaced a key and kept the old one in the same `.env` under another name, lock now stops with the `.env` unchanged. Before, it left the old key's copy impossible to unlock (WOR-1017).
- **`--quiet` no longer hides what unlock did to your `*_BASE_URL` line, and unlock says when lock couldn't save your value** (WOR-1042, [#739](https://github.com/oblangatas/worthless/pull/739)).
  The notes `worthless unlock` and `worthless uninstall` print when they write back or remove a `*_BASE_URL` line (see the entries above) are printed even with `--quiet`, because they report a change to your `.env`, not progress. So are lock's warnings that it won't save a line's value as written. Agents often pass `--quiet`. When lock couldn't save the value you had on the line, unlock removes the line and says so, for example "lock couldn't save the value you had in OPENAI_BASE_URL", rather than removing it like a line lock added. The notes name the line, never its value.

  **Limits.**
  - If you changed or deleted the line after lock, unlock leaves it as it is and says nothing about the value lock couldn't save.
  - A value that refers to another line lock rewrites comes back as the value it had at lock, and unlock doesn't say so again; lock does (WOR-1026).
  - If the line appears more than once in the `.env`, unlock writes back or removes every copy, including one you added after lock, and says nothing about the extra copies (WOR-1014).
  - The notes are plain text on stderr. `--json` output doesn't include them.
- **`--quiet` no longer hides which keys `worthless uninstall` couldn't restore, or what it did to your files** (WOR-1043, [#741](https://github.com/oblangatas/worthless/pull/741)).
  Before: `--quiet` hid every warning uninstall printed. `worthless --quiet uninstall --yes --force` could delete Worthless's half of a key it couldn't put back in its `.env` and print nothing, so nothing told you which file it was or to rotate that key. It was just as silent about an enroll-only key it removed, the record of a project whose `.env` is gone, a broken install `--force` wiped, and a `~/.worthless` it couldn't fully remove. It also gave no sign that it had set a `.env` other users could read to owner-only (0o600), or kept that mode because you said so at the prompt, that it couldn't tighten a file's mode, that `openclaw.json` may still point at the proxy, what `--remove-mcp` removed from an editor config or couldn't edit, or that one still names the Worthless MCP server. Without `--force`, the refusal said "fix the above" with nothing above it.
  Now: those notes print even with `--quiet`, like unlock's `*_BASE_URL` notes (WOR-1042). `--quiet` still hides progress, such as "restored", "Worthless uninstalled" and OpenClaw's "[OK] restored". The OpenClaw `[FAIL]` block that unlock and uninstall print shows in full under `--quiet`, not only its first line, so it still says that `openclaw.json` may not be restored and to run `worthless doctor`. So do the notes that an OpenClaw entry stays on the proxy, because its saved record is damaged or because the restored `.env` couldn't be read back. The note about a project whose `.env` is gone now says to rotate its key if you moved the project rather than deleting it.
  - If uninstall can't write a note while it restores keys (for example, stderr refuses the write), it stops with WRTLS-103 and Worthless not removed, rather than reading the error as a broken install. Before, `--force` then wiped the keys it hadn't restored yet, and without `--force` it told you to re-run with `--force`. The keys it already restored stay restored, and the message says `openclaw.json` may still point at the proxy for them. Re-run `worthless uninstall` to restore the rest.
  - A project folder uninstall can't open is named like a `.env` it couldn't restore, so the refusal says which file, and `--force` can still finish. Before, on Python 3.13 and earlier it read as a broken install: without `--force` you were told to wipe, and `--force` wiped silently. On Python 3.14 it read as a deleted project, and uninstall dropped that key even without `--force`.
  - A `.env` that is a symlink loop is named the same way. Before, it read as a deleted project and its key was dropped.
  - Uninstall prints `.env`, editor-config and `~/.worthless` paths without control characters, so a folder name can't send escape codes to your terminal. Before, it did in a normal run. The `chmod` command it suggests quotes the path for the shell, so one with a space doesn't become two files. The `[FAIL]` block's details are printed the same way.

  **Limits.**
  - A `.env` on a drive or network share that isn't connected reads as a deleted project, the same as before: uninstall drops its key without `--force`. Connect the drive before you uninstall (WOR-1068).
  - `--quiet` still hides that uninstall couldn't remove the service unit or the keychain entry, or couldn't stop the proxy (WOR-1055).
  - If uninstall stops partway, or refuses because a `.env` can't be restored, `openclaw.json` may still point at the proxy for the keys it restored first. A second run doesn't fix that (WOR-1053).
  - When uninstall refuses to read your encryption key (its mode, owner or a symlink), that message prints the key file's path as it is (WOR-1054).
  - A suggested `chmod` command can still name another file when the path holds an emoji code such as `:fire:`, or wraps across lines when stderr is a pipe (WOR-1056).
  - Under `--yes`, if setting a `.env` to 0o600 then fails, uninstall first says it set 0o600, then that it couldn't (WOR-1057).
  - Lock's OpenClaw `[FAIL]` block still shows only its first line under `--quiet` (WOR-1052).
  - The notes are plain text on stderr. `--json` output doesn't include them.
- **`worthless uninstall --force` gives OpenClaw back the real key of each `.env` it restores** (WOR-1051, [#742](https://github.com/oblangatas/worthless/pull/742)).
  Before: when one `.env` couldn't be restored, `uninstall --force` wrote NUL bytes in place of each restored key that OpenClaw uses, in `openclaw.json` and in the agent caches (`models.json`, `auth-profiles.json`). It pointed those providers back at the vendor, printed `[OK] OpenClaw: restored`, and exited 0. The keys were back in their `.env`, but OpenClaw couldn't use them, and the record that could fix `openclaw.json` was deleted with `~/.worthless`. If this happened to you, copy each key from its `.env` over the NUL bytes (`\u0000`) in OpenClaw's `openclaw.json` (usually `~/.openclaw/openclaw.json`) and in its agent caches (usually under `~/.openclaw/agents/`).
  Now: OpenClaw gets each restored key back, the same as when every `.env` is restored. Uninstall still wipes from memory the keys it holds for OpenClaw before it exits, now also when it stops after restoring them, for example on a line it can't write. The limits below list the exceptions.

  **Limits.**
  - An `openclaw.json` entry that lock added still points at the removed proxy after uninstall. So does the entry for a key whose `.env` couldn't be restored, whether lock added it or replaced it. Uninstall still says `[OK]` (WOR-1062).
  - If two projects set the same variable, such as `OPENAI_API_KEY`, to different keys, `openclaw.json` and the agent caches can get the other project's key instead of the one OpenClaw had before lock. This also happens when every `.env` is restored (WOR-1061, WOR-1067).
  - Text copies of a key that Python makes while writing `openclaw.json` can't be wiped. Keys are also left in memory if closing the database fails, or a Ctrl-C lands, just after the restores (WOR-1064). Uninstall doesn't turn off core dumps, as lock and unlock do (WOR-1060).
- **`worthless unlock` removes the proxy line that lock added for an OpenRouter key** (WOR-981, [#737](https://github.com/oblangatas/worthless/pull/737)).
  Before: lock names the proxy line after the key's variable, so `OPENROUTER_API_KEY` gets `OPENROUTER_BASE_URL`. Unlock looked for `OPENAI_BASE_URL` instead. After unlock, `OPENROUTER_BASE_URL` still sent your app to the local proxy, for a key the proxy no longer had, and the `.env` did not match the original. The same happened for any other `<NAME>_API_KEY` variable, such as `GROQ_API_KEY`. If you had your own `OPENAI_BASE_URL` in that file, unlock deleted it, after a normal lock or a `--keys-only` one. If the `.env` also had a locked `OPENAI_API_KEY`, unlocking only the OpenRouter key deleted `OPENAI_BASE_URL`. The OpenAI key stayed locked, so its scrambled value then went straight to OpenAI and failed.
  Now: unlock removes the line that lock wrote for each key it unlocks, and only while that line still sends that key's alias to the proxy (whatever the host or port). Other `*_BASE_URL` lines are kept, including your own after a `--keys-only` lock. If lock added the line, lock then unlock gives back the `.env` you started with. `worthless uninstall` restores the same way.

  **Limits.**
  - A `.env` you already unlocked with an older version keeps its leftover line. Run `worthless doctor` in that project's folder: it checks the file named `.env` there and reports the line as a BASE_URL alias missing from the DB. Delete that line by hand.
  - If one `*_BASE_URL` name appears twice in the file, unlock decides on the last one, then keeps or removes every line with that name (WOR-1014).
  - When two keys share one line (for example `OPENAI_API_KEY` and `MY_OPENAI_KEY` both use `OPENAI_BASE_URL`, which points at `OPENAI_API_KEY`), unlock both together. Unlocking only `OPENAI_API_KEY` removes the line if lock added it (if it was yours, see the WOR-1013 entry above) while `MY_OPENAI_KEY` stays locked. Unlocking only `MY_OPENAI_KEY` keeps the line, so an app that reads it sends `MY_OPENAI_KEY`'s real key to the local proxy, which refuses it (401) and never forwards it, and `lock` refuses that file until the other key is unlocked too.
  - A `.env` whose last line has no newline gets one. This happened before too, for every key.
- **A provider reply whose `usage` isn't an object no longer locks a key out of its token budget** (WOR-980, [#727](https://github.com/oblangatas/worthless/pull/727)).
  Before: a reply such as `{"usage": "x"}` or `{"usage": null}` crashed the step that records spend after the response is sent. That step never released the request's token-budget hold. A key with a daily budget then got `429 token_budget_exceeded` with no tokens spent, and a spend-capped key's hold waited for the sweeper.
  Now: such a reply counts as "usage unknown". The proxy logs a warning and releases the hold. A spend-capped key is billed right away at the larger of its admission estimate and the 128,000-token ceiling, the same amount the sweeper charged before.

  **Limits.**
  - A token count inside `usage` that is `null` or not a number still crashes the same step and can lock the key out the same way (WOR-1002, [#730](https://github.com/oblangatas/worthless/pull/730)).
  - A reply nested thousands of levels deep still crashes the same step, with the same lockout (WOR-1030).
  - On a key with a token budget but no spend cap, a reply whose usage can't be read is not counted against the budget (WOR-1031).

## [0.3.16] — 2026-10-22

### Security
- **A key that the doctor bug unlinked keeps both of its halves until it can be re-linked** (WOR-959, [#709](https://github.com/oblangatas/worthless/pull/709)).

  Before: on an old-format key, a second `worthless doctor --fix` deleted the key's first half from `~/.worthless/shard_a/`. After that, the key could not be recovered. `worthless unlock` told you to remove the locked values "if they are junk".

  Now: `doctor --fix` keeps that file when the key's other half is still stored, and reports the key as probably recoverable. If doctor cannot read the stored halves, it deletes nothing. When the `.env` names a key that lost its link, `unlock` tells you to keep the locked lines, and not to re-lock or uninstall. If the file can't say which key it holds (a `--keys-only` lock) and this machine has such a key, it tells you not to re-lock yet. Otherwise, for raw keys, it tells you to lock them.

  **Limits.**
  - This release does not re-link the key. WOR-937 does that.
  - A file whose key has no stored half left is still removed. Nothing can use that file.
  - `worthless uninstall` still removes a key that lost its link, without a warning. If the doctor bug hit this machine, do not run `uninstall` until the re-link release (WOR-937) ships.

### Fixed
- **A busy-lock error no longer tells you to delete the lock file** (WOR-965).
  Before: when another worthless command held the lock, the error said "Remove ~/.worthless/.lock-in-progress if stale." If that command was still running, deleting the file let two commands write to your keys at once.
  Now: the error says "Another worthless command is running. Wait for it to finish, then try again." When worthless can't prove the lock is dead (a lock from another host, a file system without file locks, an empty lock file from an older version), the error says the lock clears by itself, and in how many seconds. A lock left by a crashed command clears itself (see the entry below), so you never need to delete it by hand.

  **Limits.**
  - `worthless doctor --fix` has its own lock and still uses its own wording (WOR-1003).
  - If the lock file's time is in the future (clock skew between hosts), the countdown is long. It is accurate: the lock really clears only then.
  - If something other than a file sits at the lock path (a symlink or a folder), the message does not say so.

- **After a crash, the next worthless command runs at once** (WOR-962, [#714](https://github.com/oblangatas/worthless/pull/714)).
  Before: if a worthless command was killed (`kill -9`, out of memory, power loss), every write command failed for 5 minutes with "WRTLS-105: Lock file is 1s old (< 300s). Another operation may be running." This included the `worthless lock` that `status` tells you to run after a cut-off lock. Also, a command that ran longer than 5 minutes could have its lock taken by a second command.
  Now: the lock is held with the operating system's file lock, which is released when the process stops. The next command sees that the old holder is gone and runs at once. A command that is still running keeps its lock, however long it runs.

  **Limits.**
  - On native Windows, and on file systems that do not support file locks (some NFS, SMB and FUSE mounts), the old 5-minute rule still applies. These paths are tested with simulated failures, not on real NFS or SMB.
  - A lock written on a different host or container, for example through a shared mount, also keeps the 5-minute rule.
  - Two machines with the same hostname that share one `~/.worthless` on a mount whose file locks are local to each machine (for example NFSv3 with `local_lock`) are not protected: each can take over the other's live lock. Do not share `~/.worthless` between machines.
  - A command killed in the first instant, before it takes the file lock, leaves an empty lock file. That file also keeps the 5-minute rule.
  - `worthless doctor --fix` has its own lock, with a similar race. It is not changed here (WOR-963).

- **A stale key can't make the background service look healthy any more** ([#729](https://github.com/oblangatas/worthless/pull/729)).

  Before: if `~/.worthless/fernet.key` held a key that can't unlock your locked keys (for example, restored from an old backup), the background service still started. `/healthz` returned 200, and every request failed with 401. `worthless doctor` said "No issues found." `worthless lock` with a different `WORTHLESS_FERNET_KEY` in the shell printed `[OK]` and sealed the new project with a key the service does not have.

  Now: the service prints WRTLS-121 once, serves nothing, and waits. When you fix `fernet.key`, it exits so launchd or systemd restart it. `worthless up` that you run yourself stops with the cause and the fix. `lock` refuses a shell `WORTHLESS_FERNET_KEY` that differs from the stored key, and changes nothing. `worthless doctor` names the projects the service's key can't unlock.

  **Limits.**
  - Worthless never repairs the key. `doctor` tells you which key source unlocks your keys; you choose.
  - A key that unlocks only some projects still serves them. `status` stays green; only `doctor` and the service log name the broken ones.
  - A stale key that is only in the keychain does not heal on its own. Run `worthless service restart` after you fix it.
  - `worthless down` does not see a service that is waiting. Use `worthless service stop`, or fix the key.
  - The restart after the exit is done by launchd or systemd. The tests prove the exit, not a real service manager's restart.

## [0.3.15] — 2026-10-18

### Changed
- **`worthless status` and `verify` say whether your protection lasts past a restart** (WOR-860, [#708](https://github.com/oblangatas/worthless/pull/708)).
  Before: `status` said "🟢 You're protected" and `verify` said GREEN for a proxy started with `worthless up` or plain `worthless`. That proxy stops at the next restart, and neither command said so. The AI editor status tool gave the same answer.
  Now: without the background service, they say "You're protected now" and "GREEN now". They add one shared sentence: "Not after a restart", plus the fix, `worthless service install`. On WSL the sentence also says protection ends once your last WSL window closes. With the service running, they say when it starts on your platform. `status --json`, `verify --json` and the MCP status tool add `survives_restart`. It is true only when the background service is running on its own port and the proxy is proven to be Worthless.

  **Limits.**
  - `survives_restart` describes the service now. It does not prove that a restart brings it back.
  - The WSL wording was checked in CI on real WSL, not by a person in an interactive WSL terminal.
  - `status` now runs one `launchctl` or `systemctl` call when the proxy is up. This adds tens of milliseconds.

### Removed
- **Installing Worthless adds only the `worthless` command** (`worthless-nd65`, [#692](https://github.com/oblangatas/worthless/pull/692)).
  Before: an install also added six internal commands. They were `test-unit`, `test-docker`, `test-live`, `test-openclaw`, `test-all` and `docs-generate`. They did not work outside the source repository. Their names could conflict with other tools.
  Now: an install adds only `worthless`. If you run the installer again on an older version, it removes the six commands. A test stops a new non-Worthless command from being added.

  **Limits.**
  - We did not test an upgrade with `pipx`.
  - Worthless does not remove copies that a different installer made, for example an old `pip install --user`.

### Fixed
- **Bare `worthless` reports a failed or stopped lock with its real exit code** (`worthless-nhc0`).
  Before: when the lock step of bare `worthless` failed or was stopped, the command exited 0. A script or an agent read success after LOCK FAILED, Ctrl-C or `docker stop`.
  Now: the exit code is the same as `worthless lock` gives: 73 or 87 for a failed OpenClaw step, 130 for Ctrl-C, 143 for SIGTERM, 129 when the terminal closes. The proxy does not start. If you say no at a prompt, the exit code is still 0.

- **Stopping `worthless lock` puts OpenClaw's provider entries back, and never erases your OpenClaw config** (`worthless-2nta`, `worthless-1jfr`, [#698](https://github.com/oblangatas/worthless/pull/698)).
  Before: a Ctrl-C between two OpenClaw provider writes left one provider on the Worthless proxy and the next one not. If `openclaw.json` could not be read before the lock and a later write failed, Worthless wrote `{}` over the whole file, and every provider was lost. A Ctrl-C during a skill reinstall deleted the OpenClaw skill.
  Now: a Ctrl-C puts back the provider entries this lock wrote, or removes them if `openclaw.json` did not exist. It changes only entries that still point at this lock's proxy, so a change made by someone else stays. A re-lock keeps its new key. An unreadable `openclaw.json` stays as it is. The old skill stays until the new skill is in place.

  **Limits.**
  - A Ctrl-C does not undo the clean-up of an old `worthless-<provider>` entry.
  - `kill -9` or a power cut during a write is not undone.
  - OpenClaw writes its config without a lock. A write by OpenClaw at the same moment can still conflict with a Worthless write.
  - If another Worthless process holds the `openclaw.json` lock for more than 2 seconds after a Ctrl-C, the undo stops. `worthless doctor` repairs the remaining entries.

- **The all-container OpenClaw setup can lock and run again** (WOR-510, [#700](https://github.com/oblangatas/worthless/pull/700), [#695](https://github.com/oblangatas/worthless/pull/695)).
  Before: running `deploy/docker-compose.yml` as the install page says failed at three points. `worthless lock` refused to set up OpenClaw, because it read `WORTHLESS_OPENCLAW_CONFIG_SHARED` as a reason to stop. On a working setup, lock exited 91 with "do NOT trust this lock", because its check called the `proxy` hostname and the check answers only on loopback. The OpenClaw container restarted again and again with `EACCES`, because it was not in the shared volume's group and could not write its config.
  Now: lock sets up OpenClaw in the shared volume. An owner mismatch that compose did not declare still stops the lock, and an unreadable config is still never overwritten. Lock checks the proxy on `127.0.0.1`, as `worthless verify` already does. Compose adds the OpenClaw container to group `10001`, and lock and unlock keep the shared files group-writable, even when they fail. Lock does not follow symlinks in the shared volume, and it refuses to install or remove the skill through a link that points outside it. The install page now matches what lock does.

  **Limits.**
  - Unlock does not work in the all-container setup yet (WOR-953).
  - We tested on Docker Desktop on macOS, not on native Linux.
  - Lock still runs as root in the container (WOR-955).
  - If you already run this setup: download `docker-compose.yml` again for the new `group_add`, pull the new image, then run lock again.

- **`worthless doctor --json` finishes on a Mac instead of crashing** (`worthless-7xsa`, [#701](https://github.com/oblangatas/worthless/pull/701)).
  Before: on macOS, `doctor --json` crashed with exit 134 when the keychain held a Worthless entry. It printed no JSON. Its lock file stayed behind and blocked every `doctor` for 5 minutes.
  Now: `doctor --json` reports every check. Findings that the crash hid now show up.

  **Limits.**
  - A keychain account name longer than 1023 bytes reads as empty. Worthless writes only short names.

- **Every command Worthless tells you, or your agent, to run now exists** (`worthless-qvvs`, [#680](https://github.com/oblangatas/worthless/pull/680)).
  Before: two `worthless lock` failure messages said to run `worthless unlock --all`, which fails with `No such option: --all`. A proxy log line said to run `worthless relock`, which does not exist. SKILL.md told agents to run `worthless service status --json`, and `service status` has no `--json`.
  Now: the lock error names the exact `worthless unlock --alias <alias> --env <path>` and `worthless lock --env <path>` to run. After a failed rollback, lock tells you to run `worthless lock --env <path>` again, which finishes the job. The proxy log names the alias to unlock and lock again. SKILL.md says `worthless service status`. A test checks every printed command and every SKILL.md command against the real CLI.

  **Limits.**
  - The test does not check commands printed without backticks, or commands built while the program runs.

### Security
- **Worthless's own repair command stops destroying healthy keys, and keys whose project moved** (WOR-935, [#676](https://github.com/oblangatas/worthless/pull/676)). Since v0.3.7, doctor's `broken_status` check called every current-format key broken: it looked for Shard A in `~/.worthless/shard_a/`, where only old-format keys keep it. So `worthless doctor --fix --json` — the command agents are told to run — deleted the enrollment of every healthy key, and `unlock` then failed with WRTLS-102 even though both shards survived. The check now judges old-format keys only, and deletes nothing if it can't read the shard rows. Separately, `doctor --fix` (text and JSON) treated a missing `.env` file like a deleted line and purged keys whose project had merely moved. A missing file is now always kept, because doctor can't tell a moved project from a deleted one. Every orphan finding carries `reason` (`env_line_missing` / `env_file_missing`). A key whose `.env` is missing gets honest advice: put a moved project back and run `worthless unlock`, or remove a deleted one with `worthless revoke --alias <alias>`, which doctor offers only when no other project has the same key locked (revoke removes a key everywhere). `--fix --json` reports only the records it actually deleted.

  **If you were hit** (`unlock` fails with WRTLS-102 after running `doctor --fix`): do not run `worthless uninstall` or delete `~/.worthless`. Both halves of your key still exist, and getting them back is WOR-937.

  **What this does NOT fix.** Keys already unlinked by v0.3.7–v0.3.14 stay unlinked until WOR-937. A deleted project's key — `git worktree remove` deletes the `.env` — is unrecoverable; doctor now keeps its record instead of purging it; remove it with `revoke --alias` only if no other project has the same key locked. Deleting still needs no extra consent and can't be undone (WOR-938). "Line missing" is still a guess: a renamed variable, a commented-out line, a branch whose `.env` lacks the line, or a re-cloned project with a fresh `.env` at the same path all look like a dead key and still get purged, though the key may be recoverable (WOR-938). An old-format key whose line was deleted is purged even though its Shard A file could rebuild it (WOR-940).

- **After a crash in the middle of `worthless lock`, Worthless stops calling your plaintext key safe** (WOR-958, [#707](https://github.com/oblangatas/worthless/pull/707)).
  Before: lock saves to its database, then rewrites `.env`. A `kill -9`, an out-of-memory kill or a power cut between the two left the real key in `.env`. `scan` still said "All 1 keys are protected" and passed the pre-commit hook. `status` said `PROTECTED`. `doctor` said "No issues found." Bare `worthless` said nothing.
  Now: `scan` shows the key as `UNPROTECTED` and exits 1. `status` and the MCP status tool show the key as `EXPOSED`, a red "At risk" verdict, and exit 73. `doctor` and `doctor --json` name the key and the fix, `worthless lock --env <path>`. Bare `worthless` warns, then starts the proxy. Healthy locked keys read as before.

  **Limits.**
  - A crash in that moment still leaves the key in plain text. Worthless now tells you. You still need to run `worthless lock` again.
  - `doctor --fix` does not repair this state.

- **`worthless doctor` finds key shares that a stopped proxy left on disk, and `--fix` deletes them** (`worthless-7qb6`, [#699](https://github.com/oblangatas/worthless/pull/699)).
  Before: `worthless up` and `wrap` write both key shares to `~/.worthless/run/<pid>/`. A crash or a kill skipped the clean-up, and the folder stayed forever. Together, the two shares rebuild your key. `doctor` said "No issues found."
  Now: `doctor` names each folder and tells you to run `worthless doctor --fix`. `--fix` asks first (`--yes` skips the question). It deletes a folder only when its process is gone, its sidecar does not answer, and no proxy is recorded as running. `doctor --json` adds a `dead_proxy_run_dirs` check.

  **Limits.**
  - Worthless deletes the files. It does not securely erase them.
  - Nothing cleans up by itself. You run `doctor --fix`.
  - After `kill -9` on `worthless up` and then `worthless down`, the sidecar keeps answering. `doctor` treats the folder as in use and does not report it.
  - A container and the host that share one Worthless home see different process IDs. `doctor` can miss a folder in that case.
  - The check does not run on Windows.

## [0.3.14] — 2026-10-13

### Fixed
- **Worthless does not overwrite a key file that it cannot read safely** (`worthless-6hu7`, [#669](https://github.com/oblangatas/worthless/pull/669)).
  Before: Worthless treated a `fernet.key` as missing if it had the wrong permissions, had a different owner, or was a symlink. A fresh install then made a new key. Without a keychain, the new key overwrote the file. With a keychain, Worthless deleted the file as "stale". With a symlink, the write followed the link to a file outside your home folder. As root in the container, that file could be at any path.
  Four more paths had the same mistake. The keychain migration read the file without checks and could put the wrong key in your keychain. A locked keychain, or a cancelled keychain prompt, made a key that was there look missing. `uninstall` called a key with the wrong permissions "unrecoverable" and offered `--force`.
  Now: all of these stop with `WRTLS-121` and do not change the key. The error shows the repair: `chmod 0600 …`, or move a symlink to a different location. If a working keychain key exists, Worthless ignores a leftover key file with the wrong permissions, so it does not lock you out. Key writes do not follow symlinks. Each key file gets mode 0600.

  **Limits.**
  - A symlink to a missing file, for example on an unmounted volume, still counts as "no key" (`worthless-0atz`). The empty-database guard stops this from costing locked keys. A fresh install can still make a new key.
  - Worthless does not repair the file for you. There is no `doctor --fix` for this. The error and `doctor --explain fernet_key_refused` show the command to run.
  - This release cannot recover a key that an older version already replaced.
  - A full disk during a write can still leave an empty key file. This was also true before this release.

- **`worthless lock` stops safely on Ctrl-C, on `docker stop`, and when you close the terminal** (`worthless-595v`, `worthless-f1xx`, `worthless-y4fn`, `worthless-dnp9`, `worthless-v9gg`, `worthless-3em7`, [#691](https://github.com/oblangatas/worthless/pull/691)).
  Before: #668 made Ctrl-C work after lock saved the keys. Other parts of lock still had gaps. On Python 3.11 and later, lock ignored Ctrl-C for seconds during the OpenClaw safety check, then ran the check again. Lock ignored a press at the end of the database writes or during the `.env` rewrite, and continued. `docker stop` (SIGTERM) exited with code 130, or killed lock before it was ready. Closing the terminal (SIGHUP) killed lock with no rollback and no record. A press during a rollback that an error started could cancel the rollback and leave old records.
  Now: lock stops at once. If lock did not rewrite `.env` yet, it rolls back all changes. If lock already rewrote `.env`, your keys stay locked, and `worthless status` shows that OpenClaw setup is not complete. The exit code shows the signal: 130 for Ctrl-C, 143 for SIGTERM, 129 for a closed terminal. Worthless records the interrupt, also when the terminal is gone. On a machine without OpenClaw, the message does not mention OpenClaw.

  **Limits.**
  - `kill -9` (SIGKILL) cannot be caught. It can leave records behind (WOR-646 Part 2).
  - The MCP `worthless_lock` tool runs off the main thread, where no signal arrives (`worthless-dqzj`).
  - A signal in the first moments of lock, before the safety check, ends lock the normal way. Lock has not written anything at that time.
  - Bare `worthless` still changes the exit code of an interrupted lock to 0 (`worthless-nhc0`).
  - A press during a rollback that an error started exits with the error's code, not 128 plus the signal number. The rollback still finishes.
  - An interrupted OpenClaw provider write can leave `openclaw.json` partly changed (`worthless-2nta`).

- **A failed OpenClaw check after lock does not destroy your key** (`worthless-im3x`, [#688](https://github.com/oblangatas/worthless/pull/688)).
  Before: after lock rewrote `.env`, it checked OpenClaw's files again if they changed. If that check refused (it found new plaintext), failed or timed out, lock deleted its stored half of the key. Your `.env` then held only the other half. For a newly locked key, you could not recover the key on this machine: `worthless unlock` found nothing, and `worthless lock` refused to run again.
  Now: your keys stay locked and you can recover them. Lock does not change OpenClaw. Lock shows LOCK FAILED and exits with code 87. `worthless status` shows that OpenClaw setup is not complete. To recover, remove the plaintext key from OpenClaw. Then run `worthless unlock`, then `worthless lock`. If you only run `worthless lock` again, it exits with code 73 and does not say "still protected". This also applies after a lock that was interrupted during OpenClaw setup.

  **Limits.**
  - `worthless unlock` restores each OpenClaw provider entry to its value before lock. It does this also if you edited the entry during the failed lock (`worthless-kzpw`).
  - Worthless records "not complete" for the Worthless home, not for each `.env`. After a failed lock in one project, a lock of a different, fully locked project also exits with code 73. A later successful lock in a different project hides the record (`worthless-seho`).
  - To clear exit code 73, you must run unlock and then lock. This puts the real key back in `.env` for a short time. The MCP lock tool shows this case as a raw error (`worthless-098h`).

### Changed
- **Worthless asks you before it installs a background service** ([#673](https://github.com/oblangatas/worthless/pull/673)).
  Worthless can install a background service that starts automatically: at login on macOS, and at boot on Linux through lingering. Before it installs the service, it now tells you what it adds and when it starts. It also tells you that the master key moves into a file, that Linux turns on lingering, and how to remove all of it. Enter means no. Worthless installs the service only after someone types `y`. `--yes` never installs it. Plain `worthless` now asks the same question. In a container, you get one line that tells you to run the proxy as the main process instead.

  **Limits.**
  - Worthless finds an AI coding agent only through the `CLAUDECODE` and `AI_AGENT` environment variables. It does not ask the question in that case. An agent that removes these variables gets the question like a person. A person whose terminal inherited them gets a hint, not the question.
  - The "not protected after a reboot" line in `status` and `doctor` is not in this release (WOR-860).
  - We did not test that the service starts again after a reboot (WOR-725).

## [0.3.13] — 2026-10-12

### Added
- **`scan` warns when an older commit still holds the `.env` behind a passing login token** (`worthless-87rb`). A Claude Code login token in a local `.env` passes `scan` (`worthless-p55g`), but "local now" can still mean "committed once": you ran `git rm --cached .env` and committed that, or it sits on another branch you may have pushed. Scan now asks git for the newest commit that added or changed that `.env` on any branch or tag in this clone (including a branch merged and then deleted, a merge commit itself, and the first commit), and adds "Older commits hold a copy of `.env` (newest change: commit abc1234, on some branch or tag). Revoke any login token that was ever in it: those commits keep it. To check, run `git -C . log --all --full-history -m -p -- .env`." The scan still passes: history keeps the old `.env` forever, so failing on it would stay red even after you revoke and rotate. Text, `--json` (new `committed_before` field; `schema_version` stays 2), SARIF (still `note`), the MCP `worthless_scan` tool and bare `worthless` carry the same line. The lookup runs with the same guards as the login-token git checks from `worthless-p55g` (`GIT_*` stripped, `core.fsmonitor` off, no fetch), plus `--no-show-signature`, so a scanned folder's own config can't make it run its gpg program. User config that would change the answer (`log.showRoot`, `log.follow`, `log.diffMerges`, `i18n.logOutputEncoding`) is pinned. File names in the commands scan prints — this one and the `git rm --cached` / `git ls-files` advice from `worthless-p55g` — are now shell-quoted, so a folder named like `$(...)` or `a;b` can't run anything when the line is pasted, and a folder with a space still works.

  **What this does NOT do.**
  - It doesn't know which token was in that copy, so it says "any login token that was ever in it". It never reads old file contents.
  - It checks the history of this `.env` path only: the same token committed under another file name isn't found.
  - It sees only the history in this clone: commits that exist only on a remote, or that were rewritten away (only the reflog still has them), aren't checked. A local stash isn't counted either: it is never pushed. A shallow (`--depth`) or treeless (`--filter=tree:0`) clone holds too little history to answer, so it gets no warning even when the remote's history has the token.
  - If git can't answer (no git, a timeout, a repo it can't read), there is simply no warning.
  - When the `.env` was never committed, git walks the whole history: about a second at 72k commits. On a very large repo it can hit the 10 s git timeout, and then there is no warning.
  - It only adds a warning. A token in git's index or latest commit still fails, as before.

- **A release whose GitHub Release never appears now opens an issue instead of staying silent** (WOR-922, [#616](https://github.com/oblangatas/worthless/pull/616)). The Release creates itself only when all four publishers pass and a maintainer approves, and nothing noticed when that never happened. `release-watchdog.yml` checks every tag from the last 14 days every 6 hours and files one assigned issue saying why: the approval has waited 3+ days (or is for a commit a re-tag replaced), a publisher failed or never finished, or the automation never created it. It stays quiet during the normal approval pause, decides from signed tags and Actions run data only — never a GitHub Release object — and counts only runs started by the default branch's workflow and only issues it filed itself.

  **What this does NOT catch.** A watchdog that never runs: GitHub can start cron jobs about a day late and disables them after 60 days without repo activity, and nothing alarms on that. A tag's age comes from its signing date, so a tag pushed more than 14 days after it was signed is never watched. Removing the `release-watchdog` label from an open alarm makes the next check file a duplicate. It reports a missing Release; it does not verify that an existing Release is correct, or notice one deleted after it was created.

- **Every PR now gets a CVE verdict on its locked dependency tree** (`worthless-jymn`, [#531](https://github.com/oblangatas/worthless/pull/531)). `uv-audit` was `stages: [pre-push]`, so it never ran for a Dependabot PR, a GitHub web edit, `git push --no-verify`, or a clone that never ran `pre-commit install` — a vulnerable locked dependency could reach `main` through any of those and surface only at release time. `dependency-audit.yml` runs the hook's entry byte-identically on every pull request, pinned by a test so the two cannot drift apart, with `shell: bash` for pipefail (the run is a pipeline, and GitHub's default `bash -e` would let a partial `uv export` audit a fragment and exit 0) and a `uv lock --check` step, since `--frozen` otherwise audits a lock that may no longer match `pyproject.toml`.
- **The Worker's dependencies are audited and updated like everything else** (`worthless-yhcc`, [#532](https://github.com/oblangatas/worthless/pull/532)). `workers/worthless-sh` has its own `package-lock.json` that nothing in CI audited, and `.github/dependabot.yml` declared only `uv` and `github-actions` — so GitHub raised advisories for the Worker that no automation could clear, and `main` accumulated 5. Dependabot now covers it, and the dependency gate gained an `npm audit` job alongside the Python one.

- **Lock offers to keep protection running, and WSL users learn when it stops** ([#606](https://github.com/oblangatas/worthless/pull/606)).
- **The MCP server tells your editor to start the proxy instead of failing silently (WOR-829)** ([#458](https://github.com/oblangatas/worthless/pull/458)).

### Changed
- **The MCP server runs on the mcp 2.x SDK** (WOR-929, [#631](https://github.com/oblangatas/worthless/pull/631)). The `mcp` extra moves from `mcp>=1.0,<2` to `mcp>=2.1,<3`, and the server imports `MCPServer` from `mcp.server.mcpserver` (2.x renamed `FastMCP` and removed the old module). mcp 2.x hides the text of any tool exception that is not its own `ToolError`. On a plain port, "Worthless is not initialized. Run `worthless lock` first." would reach the agent as a bare "Error executing tool worthless_spend". `WorthlessError` messages, which are written for users, are passed through as `ToolError` by one `MCPServer.call_tool` override, so every tool gets it. The text of every other exception is now hidden from the client; 1.x relayed it. A stdio test proves the passthrough through a real MCP client (tool schemas, a success result, and an error result carrying the message); in-memory client tests pin both the message and the hidden crash. The dependency guard rejects any range that admits 1.x (no `mcp.server.mcpserver`) or 3.x. Upgrading with plain `pip install -U worthless` keeps an old mcp 1.x, where `worthless mcp` died with an opaque `WRTLS-199`. It now says `` WRTLS-100: `worthless mcp` could not load the MCP SDK (found mcp 1.29.0). Reinstall with the extra, which pins a compatible mcp: pip install -U 'worthless[mcp]' ``. The server reports worthless's own version in the MCP handshake; 2.x sends an empty string unless told.

  **What this does NOT do.**
  - No 1.x fallback. An environment that keeps `mcp<2` next to this release cannot start the server; it gets the reinstall message above. `npx worthless-mcp` is unaffected, because `uvx` resolves the extra fresh in its own environment.
  - In a shared pip environment where another package needs `mcp<2`, `pip install -U 'worthless[mcp]'` can silently resolve an older worthless that still accepts 1.x, missing later fixes. Install worthless in its own environment (`uv tool` / `pipx` / `npx worthless-mcp`).
  - Other failures, such as a permission error while scanning or a locked database, now reach the agent with no reason (WOR-932).
  - The passthrough trusts `WorthlessError` text, and some of it is not safe to relay. Two `lock` errors echo a base URL verbatim, so a credential embedded in that URL reaches the agent, and some messages carry absolute paths. Main already leaked these, since 1.x relayed every exception; tracked as WOR-931.
  - Crash text is hidden from the client only. The server still logs tracebacks to stderr. If the host process has an OpenTelemetry SDK with an exporter configured, mcp 2.x records tool exceptions on its spans.
  - Only mcp 2.2.0 is tested. The 2.1 floor, real hosts such as Claude Desktop, and MCP over stdio on Windows are not.

### Removed
- **The Snyk CI check stops reporting green on a scan that never ran** (`worthless-tidv`, [#529](https://github.com/oblangatas/worthless/pull/529)). `snyk-security.yml` exported `requirements.txt` but never installed it, and Snyk's pip plugin resolves from installed package metadata — so the step failed with `SNYK-CLI-0000 / Missing required packages` on every run in the retained history (100 runs, oldest 2026-08-15). `continue-on-error: true` rewrote each failure as a job success, so completely that even `gh run view --json jobs` reported the step as `success` alongside exit code 2. The workflow is deleted rather than repaired: it ran `snyk monitor`, which is upload-only and cannot fail a build, and its assumed consumers do not read it — the README badge uses Snyk's server-side on-demand endpoint, and app.snyk.io's GitHub integration monitors the repo independently. `requirements.txt` and its pre-commit exporter are kept. (Correction, WOR-904: the stated reason was wrong — Snyk's badge endpoint returns byte-identical output for this path, for a path that does not exist, and for an organisation that does not exist, so `?targetFile=` does not drive it. The file's real reader is the monitored Snyk PROJECT, imported at the repo root and scanned independently of the badge.)

### Fixed
- **`scan` stops failing the build over a login token `lock` can't protect** (`worthless-p55g`). A `.env` holding a Claude Code login token (`sk-ant-oat01-`) made `scan` exit 1, call it `UNPROTECTED` and say "Run `worthless lock`". `lock` skips that token on purpose, so the build stayed red and there was no way out. Scan now reports it as `CAN'T PROTECT`, names the one fix that exists (swap it for a static `sk-ant-api03-` key, or delete the line), and no longer fails on it. Text, `--json` (`is_unshardable`, `exposure`, `remediation`; `schema_version` stays 2), SARIF (its own rule, `worthless/unshardable-oauth-token`, at level `note`), the MCP `worthless_scan` tool and bare `worthless` all say the same thing. `--quiet` still prints it when nothing else fails the scan. A file that also holds a real exposed key still fails, counting only that key. A token pasted over a variable that was locked earlier is no longer reported as protected.

  **Behaviour change.** An OAuth-only `.env` that git does not track now exits 0 where it exited 1, with its SARIF result as a `note` under the new rule. In CI that mostly means a job that writes `.env` from a secret: a fresh checkout holds only tracked files, and those still fail. If the `.env` is in git's index or its latest commit (including one you just ran `git rm --cached` on), is a symlink, or isn't a `.env` file, it still fails, and scan now states the exact reason with its fix — e.g. "This .env file is committed to git ... revoke it", or "staged in git but not committed yet. Unstage it" — instead of "run `worthless lock`". A token in the environment under `--deep` still fails too, but is told to scope the CI secret, not to revoke a working token. To decide, a plain scan now runs read-only git in the token's folder, with `core.fsmonitor` and lazy fetch switched off, so that folder's own `.git/config` can't make scan run its fsmonitor command or fetch from a remote.

  **What this does NOT do.**
  - The pass covers a `.env`-family file that is in neither git's index nor its latest commit. If git can't answer (not installed, timed out, "dubious ownership", or a repo it can't open, such as a moved worktree or a lost `HEAD`), scan assumes it is in git and the token fails. A repo git can open but whose objects are damaged (say, `HEAD`'s tree deleted) can still read as not committed.
  - Only the innermost repo is asked. If an enclosing repo committed the file before someone ran `git init` inside its folder, the token passes.
  - `scan --code` and the `--pre-commit` path still run git without switching `core.fsmonitor` off; that predates this change (worthless-jj5u).
  - Only the current branch's latest commit can fail the scan. Older commits and other branches, even pushed ones, only add a warning (`worthless-87rb`, above): once you commit the untracking, scan passes though history still holds the token. A green scan doesn't mean you revoked it.
  - A `.env` tracked only through an exported `GIT_DIR`/`GIT_WORK_TREE` (the bare-repo dotfiles pattern) reads as untracked, because scan ignores `GIT_*` variables. A `.env` hardlinked to a committed file isn't detected either, nor, on a case-insensitive disk (the macOS default), one committed as `.ENV` but scanned as `.env`: git matches names exactly.
  - It does not check `.gitignore`. An untracked `.env` that isn't ignored still passes, and one `git add .` stages it. The `--pre-commit` hook blocks it from there, if the hook is installed.
  - A CI job that keeps the token as a secret and runs `scan --deep` still fails, as it does today for any provider key held as a CI secret.
  - The token is still a live secret in plain text. A plain scan now passes with it present. It is named every time, but nothing stops it.
  - The `--pre-commit` hook still blocks a staged token, because a commit writes it into history for good. In that mode `--format sarif` and `--json` still mark the token as a `note` while the hook exits 1.
  - Only Claude Code tokens in the files scan reads. OpenClaw's other unshardable credential stores are `worthless doctor`'s job, not scan's.

- **Ctrl-C stops `worthless lock`'s OpenClaw setup at once, and never costs you your keys** (found while chasing `worthless-3clz`, [#668](https://github.com/oblangatas/worthless/pull/668)). Once the keys were committed, the rest of the lock was synchronous OpenClaw work, so Ctrl-C was dropped: for 15s during the reload wait, and forever while another worthless process held its lock on OpenClaw's config file (OpenClaw itself never takes that lock). Now Ctrl-C stops there in under a second and keeps the keys locked. It warns that OpenClaw may still be using the real key, `worthless status` flags OpenClaw as broken, and the CLI exits 130, even with `--quiet`. Ctrl-D at the "Route them through Worthless?" prompt no longer rolls back the database under a rewritten `.env`, as it did on earlier releases, and Ctrl-C there is now answered. A second Ctrl-C during a rollback now says why it is not stopping.

  **What this does NOT fix.**
  - The CI sighting that opened worthless-3clz came from a chaos trial with no OpenClaw, and its cause is still unknown. The chaos hang guard now records the stuck stack.
  - Ctrl-C before the keys are committed is unchanged. On Python 3.11+, a press during the pre-flight audit can wait out one audit retry (worthless-595v).
  - A real post-flight failure (exit 87) still runs its documented rollback after the `.env` rewrite (worthless-im3x).
  - A Ctrl-C during OpenClaw setup can leave it partly done, for example `openclaw.json` updated for one provider but not the next. It is reported, not undone (worthless-2nta).
  - Bare `worthless` (no subcommand) still exits 0 after an interrupted lock (worthless-nhc0).
  - `kill -9` mid-lock (WOR-646 Part 2) is unchanged.

- **A rotating Claude Code login token no longer gets frozen into a dead key** (WOR-837, [#456](https://github.com/oblangatas/worthless/pull/456) + [#567](https://github.com/oblangatas/worthless/pull/567)). Claude Code's OAuth login issues `sk-ant-oat01-` (access) and `sk-ant-ort01-` (refresh) tokens, both of which collide with the static `sk-ant-` prefix `scan_env_keys` classifies on — so `lock` treated them as ordinary API keys and sharded them. Sharding rewrites the `sk-ant-oat` marker Claude Code is recognised by, and the proxy cannot reconstruct the OAuth request shape that loss costs, so a locked token silently broke the user's login instead of protecting it. `lock` now recognises them via `is_oauth_token` and skips them before they can become lock candidates, with a warning naming the variable (sanitised — dotenv keys are permissive enough to smuggle terminal-injection sequences into the message). Anthropic-only by construction: OpenAI and Google OAuth tokens are JWTs, xAI has no dev OAuth, and OpenRouter's OAuth yields a genuine static key. Two honesty fixes ride along: the summary no longer prints the product's headline verdict ("You're protected", ".env no longer contains a usable secret") over a credential it just decided to leave in plaintext, and `.env` permission hardening is no longer gated on `fresh_count`, so an OAuth-only file is still tightened to `0600` on a run where nothing was locked (it previously stayed `0644` holding a live token).

  **What this does NOT fix.** The skipped token is still sitting in `.env` in plaintext, and `lock` says so rather than implying otherwise — Worthless does not protect it, and `0600` only stops other local users, not the stolen-`.env` threat model (malware, a malicious postinstall, an agent, a stray `git push`), all of which run as the user and read `0600` fine. `scan` reported the token as unprotected and pointed at `lock` until `worthless-p55g`, in this same release.

- **Azure / enterprise / self-hosted gateways get the right upstream** (WOR-834, [#460](https://github.com/oblangatas/worthless/pull/460)). `lock` read the gateway URL out of `openclaw.json` and threw it away, resolving the upstream from `.env` or a registry lookup by provider name instead. Registry providers landed correctly by luck; a gateway that exists only in `openclaw.json` — exactly the Azure/enterprise case — fell through to the `api.openai.com` default, so the proxy forwarded the reconstructed key to OpenAI and every request 401'd. The gateway's `baseUrl` is now the upstream, and it survives re-locks (after the first lock the live entry is proxy-shaped, so re-resolving silently reverted the alias to the registry default on the second lock). Because `openclaw.json` is locally writable, a non-registry URL must clear a fail-closed guard first: https-only, no userinfo, and no loopback / link-local (incl. metadata `169.254.169.254`) / private / CGNAT / unspecified / reserved / multicast host — after normalizing encoded-IP forms (decimal, hex, octal, short, trailing-dot) and folding IPv4-mapped `::ffff:0:0/96` and NAT64 `64:ff9b::/96` to the embedded IPv4. Without that fold, mapped CGNAT reached through on Python 3.13 only, because `IPv6Address.is_private` delegates to the embedded address from 3.10.15/3.11.10 on and CGNAT is not `is_private`. Proven against a real OpenClaw install in CI, not only against mocks.

  **Does NOT defend against:** a plausible *public* attacker URL — a lock-time static check cannot tell `azure.com` from `evil.com`. The host checks apply to IP **literals**; a DNS *name* that resolves to a blocked address (`https://127.0.0.1.nip.io/v1`, or any name with an `A` record pointing at loopback or metadata) still passes, because the guard deliberately never resolves DNS — a lock-time lookup is meaningless against a host that re-resolves at request time. So this raises attacker cost (a domain, a valid certificate, attributable hosting) rather than making redirection impossible. Also undefended: post-lock tampering of the stored upstream by anything that can write the database, and the `.env` + `providers.toml` path, which reaches the upstream through registry membership without passing this guard at all. Closing these needs request-time re-resolution and re-validation in the proxy, tracked separately.

  **Private-address gateways are refused.** A gateway written as a bare RFC1918 literal (`https://10.0.0.5/v1`, `192.168.x`, `172.16-31.x`) is rejected along with loopback, link-local, CGNAT, and cleartext. A self-hosted gateway reached by **hostname** (`https://gateway.corp.internal/v1`) is accepted — DNS names are never resolved, so they are not classified as private. If your gateway currently lives at a bare private IP, give it a DNS name or register it as a provider and set the matching `*_BASE_URL`.
- **The pre-push audit stops passing over a broken scan** (`worthless-mh0r`, [#541](https://github.com/oblangatas/worthless/pull/541)). The `uv-audit` hook piped `uv export` into `pip-audit` under a shell without `pipefail`, so only `pip-audit`'s exit code counted — an export that died partway handed over a truncated-but-valid stream, which audited the packages that arrived and passed. It now runs under `bash -c 'set -o pipefail; …'`; bash explicitly, because `pipefail` is not POSIX and `/bin/sh` is dash on many systems. CI already had this via `shell: bash`.
- **A live advisory against the pinned `pip` is cleared** ([#541](https://github.com/oblangatas/worthless/pull/541)). `PYSEC-2026-3721` (`CVE-2026-13346`) was published 2026-07-29, but its OSV record was amended on 2026-08-21 to cover the pinned `pip 26.1.2` — so it began failing the new dependency gate hours after that gate merged. The first thing the gate caught, and exactly the behaviour its own entry predicted. Bumped to 26.2.1, lockfile only.

- **Uninstall stops deleting the only tool that can restore your keys, and only tells you what it knows about them (WOR-939). It restores your keys with the copy uv or pipx installed, never a stale copy on PATH; a refusal deletes nothing; and it says your keys are back, that they are lost and you must rotate, or that it can't tell** ([#645](https://github.com/oblangatas/worthless/pull/645)).
- **The installer won't report success for the wrong worthless version** ([#674](https://github.com/oblangatas/worthless/pull/674)).
- **The installer stops claiming success when another copy answers instead (WOR-597)** ([#585](https://github.com/oblangatas/worthless/pull/585)).
- **A downloaded uv always does the install, even with XDG folders set** ([#643](https://github.com/oblangatas/worthless/pull/643)).
- **An interrupted install can fix itself by being run again** ([#586](https://github.com/oblangatas/worthless/pull/586)).
- **Ctrl+C stops the installer instead of blaming your network** ([#582](https://github.com/oblangatas/worthless/pull/582)).
- **A slow-starting service is no longer reported as a failed install (worthless-rnl8)** ([#570](https://github.com/oblangatas/worthless/pull/570)).
- **WSL users without systemd get fix steps that work and don't kill Docker** ([#599](https://github.com/oblangatas/worthless/pull/599)).
- **Following worthless's own repair advice no longer locks the sidecar out of the key** ([#656](https://github.com/oblangatas/worthless/pull/656)).
- **The scan verdict names the file it scanned, and only points at lock when lock can act** ([#581](https://github.com/oblangatas/worthless/pull/581)).
- **Doctor stops recommending a file that may hold your old key (WOR-599)** ([#524](https://github.com/oblangatas/worthless/pull/524)).
- **`verify` on a machine with no Worthless home no longer crashes** ([#568](https://github.com/oblangatas/worthless/pull/568)).
- **The compose file you download can actually start (WOR-553)** ([#543](https://github.com/oblangatas/worthless/pull/543)).
- **Docs can no longer tell you to run a worthless command that doesn't exist** ([#666](https://github.com/oblangatas/worthless/pull/666)).

### Security

- **The container stops shipping on an operating system that no longer gets security fixes** (`worthless-tw1g`, [#604](https://github.com/oblangatas/worthless/pull/604)). Both images pinned `python:3.13-slim-bookworm`, and grype reported Debian 12 as end-of-life on every scan — *"105 packages from EOL distro debian 12 — vulnerability data may be incomplete or outdated."* Behind the failing check sat 35 High/Critical findings marked `fix=not-fixed`, including a Critical in openssl, invisible because an earlier step short-circuited the job before the gate that reports them ever ran. `Dockerfile` and `docker/sidecar/Dockerfile` now build on digest-pinned `python:3.13-slim-trixie` (Debian 13).

- **The Worker's test toolchain stops shipping an image library with a known memory-corruption hole** (`worthless-kzfq`, [#604](https://github.com/oblangatas/worthless/pull/604)). GHSA-rgj7-g3m4-5g8c (libheif heap overflow, CWE-122) covers sharp `<0.35.4`, which reached the Worker as `sharp <- miniflare <- wrangler / @cloudflare/vitest-pool-workers`. `npm audit` re-resolves advisories from the registry at run time, so the advisory's publication turned an unchanged lockfile red and blocked every open PR in the repo. This branch first suppressed it with a dated allowlist arguing *"no forward fix exists at any version"* — **that was measured wrong**. sharp 0.35.4 is published; npm offered only the breaking `@cloudflare/vitest-pool-workers` 0.22.0 → 0.8.30 downgrade because miniflare pins `"sharp": "0.35.2"` exactly, so its resolver could only walk backwards. `overrides` is a different search space and reaches the patch: `npm audit` goes 4 HIGH → 0 with wrangler, miniflare, vitest-pool-workers and vitest all unchanged, and the Worker suite byte-identical either way (244 passed, 9 expected-fail on both 0.35.2 and 0.35.4). The allowlist, its `check_npm_audit.py` enforcer, and a gate test that could no longer fail are deleted; `run: npm audit` is bare and unsuppressible again.

  **What this does NOT fix.** Bare `npm audit` has no valve: the next Worker advisory with no forward fix will redden `main` the same way, and the deliberate choice is to argue it then rather than keep a suppression file warm. Two CPython advisories (`CVE-2026-17084`, `CVE-2026-15806`, both Medium) are **suppressed, not fixed** — they remain in the shipped image. Grype's only fixed version for both is 3.15.0rc2, a release candidate; measured 2026-09-10, `python:3.13-slim-trixie` (3.13.15) and `python:3.14-slim-trixie` (3.14.7) are both still affected, so there is nowhere stable to upgrade to. They carry their own `2026-12-08` expiry in `.grype.yaml` — deliberately not the bulk `2027-01-31` date 21 other entries share — and the build fails when it lapses.

- **CI stops turning red overnight because three copies of zizmor disagreed** (`worthless-tw1g`, [#604](https://github.com/oblangatas/worthless/pull/604), absorbing [#600](https://github.com/oblangatas/worthless/pull/600)). The repo carried zizmor at three different versions with nothing holding them in lockstep, so a new upstream rule could fail every open PR without anyone changing a line — which is exactly what happened, 26 findings of a single new `self-repository` rule across 20 workflows. `sast.yml` and `.pre-commit-config.yaml` now pin the same `1.30.0`, with a comment saying they must move together.

- **A crash in a key-holding CLI command no longer hands your key to a Linux core handler** (`worthless-dupf.10`, [#465](https://github.com/oblangatas/worthless/pull/465)). `lock`, `unlock`, `up` and `wrap` each reconstruct the real API key in memory, and their only protection was `RLIMIT_CORE=(0, 0)` — which Linux **ignores** when `core_pattern` pipes to a handler such as `systemd-coredump` or `apport`, the default on most Docker hosts and not namespaced. The kernel treats a piped handler as unlimited size, so the `RLIMIT_CORE == 0` early-abort governs only the core *file* path and the key still reached host core storage. `disable_core_dumps()` now also sets `PR_SET_DUMPABLE=0`, which is evaluated *before* `core_pattern` and so aborts the dump before the pipe helper is ever spawned, and confirms it with a `PR_GET_DUMPABLE` read-back rather than trusting the call. Measured on a Docker linuxkit host with a real piped `core_pattern` installed through `nsenter -t 1`: unprotected wrote a core with a recoverable key, `RLIMIT_CORE=(0, 0)` alone **still** wrote that core, and dumpable=0 produced no core at all. On the real CLI under `SIGABRT`, `origin/main` wrote a 65,085,440-byte core and this build wrote none. The call sits above `get_home()` in every command, since `get_home()` is what materializes `home.fernet_key`. Where the protection cannot be confirmed the key-holding commands now **stop** with `WRTLS-120` instead of running unprotected; `scan`, `down`, and the seven `service` subcommands harden themselves the same way but only warn, because they never reconstruct a key and a read-only command should not be blocked by a kernel quirk. Programs launched through `wrap` stay attachable by `gdb`/`lldb`/`py-spy`, because `execve` resets the dumpable bit; their core *files* were already suppressed by the inherited `RLIMIT_CORE`, which predates this change. `doctor` also stops guessing "home mismatch" from an unreadable `/proc/<pid>` environment, which a self-hardened foreground `up` now produces.

- **A planted uv or system tool can no longer steer `curl worthless.sh | sh`** ([#641](https://github.com/oblangatas/worthless/pull/641)).
- **The installer no longer runs a worthless it merely found on your PATH** ([#671](https://github.com/oblangatas/worthless/pull/671)).
- **The installer stops trusting binaries it found on the caller's PATH (worthless-rlio, worthless-v0tl)** ([#580](https://github.com/oblangatas/worthless/pull/580)).
- **Real integrity checks replace a size limit that couldn't catch tampering** ([#677](https://github.com/oblangatas/worthless/pull/677)).
- **A repo you clone cannot use a filename to scramble what your terminal shows you** ([#588](https://github.com/oblangatas/worthless/pull/588)).
- **Service install can't quietly stop wiping the master key from memory (worthless-pyx7)** ([#642](https://github.com/oblangatas/worthless/pull/642)).
- **Two of the master key's copies stop outliving the command (worthless-m7n0, worthless-g648)** ([#554](https://github.com/oblangatas/worthless/pull/554)).
- **FastAPI's built-in telemetry stays off in the proxy, whatever's installed** ([#670](https://github.com/oblangatas/worthless/pull/670)).
- **The container image can't publish without the same signed-tag proof as everything else (WOR-881)** ([#523](https://github.com/oblangatas/worthless/pull/523)).
- **Verifying a Worthless image signature works again (worthless-c478)** ([#546](https://github.com/oblangatas/worthless/pull/546)).

### Internal
- 84 more pull requests changed tests, CI, release automation, repository references and dependency versions. They are listed on the [compare page](https://github.com/oblangatas/worthless/compare/v0.3.12...v0.3.13).

### What this does NOT fix
- **The proxy daemon — the longest-lived key holder — is still unhardened** (`worthless-dupf.16`). `git grep -icE "dumpable|RLIMIT_CORE" -- src/worthless/proxy/` matches nothing, `up` spawns it through `subprocess.Popen` with no `preexec_fn`, and `execve` resets the dumpable bit, so it runs at `dumpable=1` while reconstructing keys per request. Its core-*file* path is closed (`RLIMIT_CORE` **is** inherited across exec); its piped path is not. The `[Unreleased]` protection covers the CLI commands, **not** the proxy.
- **Windows gets nothing, and says nothing.** There is no `resource` module and no dumpable bit, so `disable_core_dumps()` returns success having applied nothing at all. `up` and `wrap` are gated by `fail_if_windows()`, but `lock` and `unlock` are not — they run natively, and Windows Error Reporting can write a full `.dmp` containing the reconstructed key. Failing closed there would hard-fail those commands on every run, so the trade is deliberate; the gap is real (`worthless-8s78`).
- **`doctor`, `revoke` and `uninstall` touch key material and are unhardened** (`worthless-dupf.17`).
- **macOS beyond the core file.** No dumpable bit exists, so `RLIMIT_CORE` is the only lever; `.ips` crash reports still capture register state (not memory pages) and `sysdiagnose` aggregates them.
- **Swap and hibernation.** Nothing is `mlock`ed (`worthless-dupf.11`). And root or `CAP_SYS_PTRACE` reads `/proc/<pid>/mem` regardless — inherent.
- **The live kernel proof is not a committed test** (`worthless-dupf.18`). The A/B/C above was run on an ad-hoc harness that is not in the repository and does not run in CI, so nothing currently prevents this from regressing silently. `tests/test_cli_dumpable.py` covers the readback, the strict/warn split and the ordering guard, but not the piped-`core_pattern` bypass itself.
- **A newly-blind `doctor` check.** Suppressing the mismatch warning on an unreadable environment means a stale pidfile or a foreign-user proxy now reports no-mismatch instead of warning.
- **The new dependency gate reports, but does not yet block.** `uv-audit (locked runtime tree)` is not among ruleset `15499127`'s required contexts, so a red result is visible on the PR without preventing a merge until that context is added.
- **The `mcp` extra is audited by nothing.** `uv export` omits extras, so it is absent from what the gate and the pre-push hook scan; the container scan cannot see it either, because the image installs without extras.
- **It covers the linux/CPython 3.13 resolution of the lock, not the whole lock.** pip-audit skips requirements whose environment markers do not match the runner, and 16 of 116 pins are marker-gated — `numpy==2.2.6`, `scipy==1.15.3`, `pywin32-ctypes` and the `backports-*` set among them (`worthless-mh0r`). Grype in `docker-security.yml` does block medium-and-above on pull requests, but only for CVEs with a fix available, and only for what lands in the built image — `Dockerfile` installs without extras, so the `mcp` extra is invisible to it.
- **The Worker's dev tooling is deliberately not gated.** The npm job audits `--omit=dev` — what the Worker actually ships. Its `package.json` declares `"dependencies": {}`, so production is empty and the job passes. The 5 advisories on `main` all arrive through `wrangler` and `@cloudflare/vitest-pool-workers` -> `miniflare` -> `undici`, every one a devDependency that never enters the bundle. Gating the full tree would have shipped a job red on arrival; Dependabot upgrades those instead.
- **Neither audit job blocks yet.** `npm audit (worker production deps)` is not a required context either, so like its Python sibling it reports without preventing a merge.
- **This corrects an earlier claim in this file.** The 0.3.7 entry below states "Snyk reports the dependency tree we actually ship". That was not true when written and never became true; the scan never completed successfully.
- **Whether the Snyk dashboard reflects the right project is still unverified** (`worthless-7fey`). The repo was re-imported as `oblangatas/worthless` on 2026-08-19 while the org slug stayed `shacharm2`, and a stale duplicate project would now go uncontradicted.
- **The `SNYK_TOKEN` repo secret is not revoked by this change** (`worthless-s78g`). It is unused after this release but still present.

## [0.3.12] — 2026-08-11

`worthless mcp` starts again on a fresh install. An unbounded dependency let a new major of the MCP SDK reach every new installation and kill the server at startup.

### Fixed
- **`worthless mcp` works again on a fresh install** (WOR-864, [#473](https://github.com/oblangatas/worthless/pull/473)). The `mcp` extra was declared as `mcp>=1.0` with no upper bound. When the MCP SDK published 2.0.0 on 2026-07-28 it removed `mcp.server.fastmcp` — the module the server imports — so every fresh `pip install "worthless[mcp]"` or `npx worthless-mcp` resolved 2.x and died at import with an opaque `WRTLS-199`. The extra is now capped at `mcp>=1.0,<2`. The floor stays at 1.0 so anyone already resolved on an older 1.x is untouched.
- **A dependency change now runs the check that resolves like a real user does** (WOR-864, [#496](https://github.com/oblangatas/worthless/pull/496)). CI installs from `uv.lock`; a user resolves fresh against the index. The one job that resolves live wasn't watching `pyproject.toml` or `uv.lock`, so a dependency-only edit triggered nothing — which is how the broken bound shipped past a fully green pipeline. Both files are now on its triggers.
- **A future cleanup can't silently re-break it** (WOR-868, [#474](https://github.com/oblangatas/worthless/pull/474)). A guard asserts the declared bound actually excludes 2.x, reading it as a version rather than checking that some `<` is present — `mcp>=1.0,<99` has an upper bound and still resolves straight to the broken release.

### What this does NOT fix
- **Versions 0.3.0 through 0.3.11 stay broken for the MCP server, permanently.** Package metadata is immutable once published, so those releases will always declare the unbounded `mcp>=1.0`. Yanking does not help either: a yanked version still installs when pinned exactly, which is what the npm wrapper does. **The only fix is upgrading to 0.3.12.**
- If you already have mcp 2.x installed, `pip install -U worthless` **without** the `[mcp]` extra will not re-evaluate it. Upgrade with the extra: `pip install -U "worthless[mcp]"`.
- Only the `[mcp]` extra was affected. `enroll`, `wrap`, `scan`, `status` and the proxy were never impacted — the MCP server is imported lazily, so the rest of the CLI kept working throughout.

## [0.3.11] — 2026-07-24

Closes the last gap from the OpenClaw install incident: you can now ask Worthless, on demand, whether your gateway is actually protecting you *right now* — and get an answer that can't be faked by a stale counter.

### Added
- **`worthless verify` — confirm the gateway is protecting you right now** (WOR-517, [#457](https://github.com/oblangatas/worthless/pull/457)). The incident that started this ended with a user killing the Worthless gateway and watching his agent keep working — with no way to tell his key was now exposed. `worthless verify` answers that question directly: it fires a live loopback bind-probe and reports **GREEN only when that probe routes through the proxy this instant**, never from the cumulative `requests_proxied` count (which stays frozen at its last value when the gateway dies, and would have printed green over the exact bypass it exists to catch). A down gateway reports **RED with exit code 73**, worded as an active exposure — "any agent still holding a cached token may be sending your key in the clear right now" — not as a tool that merely isn't configured. A healthy-but-unidentified responder on the port reports RED rather than claiming an attacker, since the identity marker is public. `--json` for scripting.

### Security
- **The rollback record can't carry an unprefixed secret** (WOR-827, [#452](https://github.com/oblangatas/worthless/pull/452)). Secrets without a recognized provider prefix are redacted from the OpenClaw rollback record instead of being written through.

### What this does NOT defend against
- **`worthless verify` proves the proxy is live and routing a request now — not that your agent's last request went through it.** The probe is a separate synthetic request; a proxy that is up and an agent that bypasses it on a cached token can coexist. The command says so in its own GREEN output rather than implying full coverage. Confirming that a *specific* application's traffic is routed remains the job of `worthless status` and the load-bearing proxy work (WOR-621).
- The hosted `curl worthless.sh | sh` install path is proven by a manual release smoke, not automation — the installer only ever fetches the published pin, so unreleased code cannot be exercised through it.

## [0.3.10] — 2026-07-21

Credential-leak hardening across the OpenClaw path and the "am I protected?" verdict, plus honest reporting when Worthless can't protect or can't look. Also lands background service management and a rebuilt install experience.

### Security
- **`lock` scrubs the real API key OpenClaw caches in its config** (WOR-796, [#424](https://github.com/oblangatas/worthless/pull/424)). `lock` scrubs the cached real key from OpenClaw's per-agent `auth-profiles.json` / `models.json` to an uppercase `${VAR}` SecretRef → shard-A, and warns when a non-uppercase key var blocks the scrub. Static `api_key` credentials only — see *What this does NOT defend against*.
- **`lock` tells you the truth about logins it can't shard** (WOR-797, [#425](https://github.com/oblangatas/worthless/pull/425)). OAuth tokens, keychain creds, and Vertex ADC are enumerated and honestly flagged as unprotectable — never implied as sharded — with `gcloud auth application-default login` guidance for Vertex.
- **`lock` confirms OpenClaw applied the new proxy URL before printing `[OK]` — when it can observe the reload** (WOR-756, [#431](https://github.com/oblangatas/worthless/pull/431)). No more false green while the live gateway still routes the real key; an observed rejected reload exits 92.
- **"Am I protected?" no longer reads green just because *something* answers on the proxy port** (WOR-822, [#451](https://github.com/oblangatas/worthless/pull/451)). `worthless status` and the editor's `worthless_status` tool used to report 🟢 "you're protected" whenever any service returned 200 on the proxy port — a leftover dev server that happened to bind it earned the same green light while the app's traffic went elsewhere. The verdict now gates green on the `bind_probe_count` identity marker (WOR-658) a real worthless proxy stamps on `/healthz`; a healthy-but-unidentified responder gets a new 🟡 `proxy_unrecognised` verdict instead. The gate lives in the one shared verdict function, so the CLI and editor answer identically.
- **Old OpenClaw installs auto-heal their leftover decoy on the next lock** (WOR-656, [#437](https://github.com/oblangatas/worthless/pull/437)).
- **A scan that couldn't look no longer reports "clean"** (WOR-823, [#449](https://github.com/oblangatas/worthless/pull/449)). The credential scan stops crashing on unreadable files and names the surface it couldn't check instead of falsely reporting nothing found.
- **The editor stops telling you your keys are exposed when they're actually safe** (WOR-820, [#447](https://github.com/oblangatas/worthless/pull/447)). Same five-state verdict as the CLI, including an honest `protected_at_rest` when the proxy is down.
- **Worthless's own commands can't print a live key** (WOR-655, [#442](https://github.com/oblangatas/worthless/pull/442)). A build tripwire fails if any command leaks a provider-shaped key or post-lock shard-A, and `scan --show-suffix` prints a stable non-secret identifier, not real bytes.
- **The sidecar can't leak a key through its own logs or a crash dump** (WOR-826/WOR-831, [#455](https://github.com/oblangatas/worthless/pull/455)). The process that holds raw shares redacts its own log lines and uncaught tracebacks before they reach stderr (a self-protecting `sys.excepthook`), and `RLIMIT_CORE=0` blocks a core-dump *file* of share bytes — with residual crash-dump paths noted below.
- **Worthless closes the named plaintext-recovery points for a leaked key** (WOR-277, [#426](https://github.com/oblangatas/worthless/pull/426)) — `enroll` shell history, proxy access-log query strings, the bare-`worthless` traceback, `scan --deep` temp files, and core-dump suppression across lock/enroll/unlock/scan.
- **A crash mid-unlock no longer leaves a reconstructed key lingering in memory** (SR-02, [#443](https://github.com/oblangatas/worthless/pull/443)).
- **Uninstall never force-wipes a recoverable key; install never mints over an orphaned one** (WOR-716, [#432](https://github.com/oblangatas/worthless/pull/432)).

### Added
- **Service management: a background proxy that tells you when it's silently broken** (WOR-193, [#430](https://github.com/oblangatas/worthless/pull/430)).
- **Install page leads with a one-click, per-tool picker** (WOR-790, [#441](https://github.com/oblangatas/worthless/pull/441)).
- **CI proves the real `npx worthless-mcp` mounts its 4 tools** (WOR-809, [#438](https://github.com/oblangatas/worthless/pull/438)).
- **`worthless uninstall --remove-mcp` cleans up only Worthless's own MCP entry** ([#448](https://github.com/oblangatas/worthless/pull/448)) — surgical removal that leaves other MCP servers in your config untouched.

### Fixed
- **Uninstall points you at the leftover MCP config instead of staying silent** ([#439](https://github.com/oblangatas/worthless/pull/439)).
- **Every push stops dying on a click CVE we never trigger** ([#435](https://github.com/oblangatas/worthless/pull/435)).

### Docs
- **Install docs claim only what we can back** (WOR-810, [#433](https://github.com/oblangatas/worthless/pull/433)) — dropped "90 seconds", qualified MCP verification.
- **`curl` leads the install hero; editor paths state they don't route keys** (WOR-819, [#445](https://github.com/oblangatas/worthless/pull/445)).

### What this does NOT defend against
- **OAuth / keychain / Vertex logins stay unprotectable** (WOR-797). `lock` shards a static `api_key`; it cannot shard a refresh token. It *discloses* and can *clear* these — you re-authenticate — but never *protects* them. WOR-796's scrub covers the api_key path only.
- **A cached key in an agent file the scrub can't safely rewrite** (WOR-796). The scrub is best-effort: a symlinked, foreign-owned, or otherwise unwritable `auth-profiles.json` / `models.json` is skipped and its cached real key survives. A non-uppercase key var is warned about loudly, but a silent write failure is not.
- **A motivated same-host process that forges the proxy marker** (WOR-822). `bind_probe_count` is a public, presence-only field; a process that reads the open-source `/healthz` handler can echo it and still read green. Scope is honest-payload loopback trust, and the marker proves responder *identity*, not that traffic is actually *routed* (that's `bind_confirmation`'s job). `proxy_unrecognised` keeps exit code 0 — machines gating on protection must read the `verdict` enum, not `$?`.
- **An unconfirmed OpenClaw reload** (WOR-756). When the reload can't be observed (openclaw binary not co-located, no event in the window), `lock` prints `[OK]` + an advisory at exit 0 — indistinguishable from a proven pass. Only an *observed* rejection blocks with exit 92.
- **The macOS keychain scan blind spot** (WOR-823, deferred to WOR-824). A keychain probe that times out or can't find the `security` binary can still fail without naming the surface.
- **Full plaintext-recovery closure** (WOR-277). WOR-826/831 now redact the sidecar's own logs and uncaught tracebacks and block its core-dump *file*, but the redaction matches provider-key *text* — not raw share bytes or the Fernet key (an AST guard, not redaction, keeps sinks from interpolating shares). Residual crash paths: on a **piped-`core_pattern` Linux host** `RLIMIT_CORE=0` is bypassed, and — *as of 0.3.10* — the `lock`/`unlock`/`up`/`wrap`/`scan` CLIs did not set `PR_SET_DUMPABLE=0`, so a CLI crash there could still write the Fernet key to host core storage (**WOR-839**; **closed in [Unreleased] by `worthless-dupf.10`** — that entry's own caveats replace this clause for the CLI, and the proxy daemon remains unhardened); macOS `DiagnosticReports` capture register state (dev-only); unprefixed admin tokens aren't redaction-matched.

## [0.3.9] — 2026-07-08

### Security
- **Rotating an API key now rotates the key OpenClaw actually uses** (WOR-777, [#387](https://github.com/oblangatas/worthless/pull/387)).
- **Look-alike filenames that impersonate a real path are flagged in scan output** (WOR-800, [#419](https://github.com/oblangatas/worthless/pull/419)).
- **`worthless doctor --json` zeroes the Fernet master key from memory after the run** (WOR-799, [#421](https://github.com/oblangatas/worthless/pull/421)).
- **OpenClaw config provably carries the per-alias shard-A** (WOR-652, [#423](https://github.com/oblangatas/worthless/pull/423)) — regression test pinning the invariant.
- **Spend cap stops the no-`max_tokens` money leak** (WOR-696, [#285](https://github.com/oblangatas/worthless/pull/285)). A request without `max_tokens` that disconnected mid-stream wrote a near-zero `spend_log` row — cap counter never moved, runaway loop could burn unbounded provider spend. `settle_at_estimate` now floors at a global 128K-token ceiling (`GLOBAL_CEILING_TOKENS`), so every fallback event bills honestly. Direction of error is conservative: gpt-4o-mini disconnect over-bills ~$0.017 vs the old ~$0.002 leak, but Opus 4.5 / gpt-5 disconnects bill exactly.
- **Streams can't outlast the cap** (WOR-696). Two new operator-tunable kill paths close slow-drip variants where no client disconnect ever fires:
  - `WORTHLESS_MAX_STREAM_DURATION_SECONDS` (default `900` = 15min) — hard wall-clock cap per stream.
  - `WORTHLESS_MAX_IDLE_BETWEEN_CHUNKS_SECONDS` (default `90`) — kills a stream that drips one chunk every N minutes.
  Either kill triggers the same settle path, which floors at the global ceiling.
- **Silent provider re-routes are observable** (WOR-696). When a provider responds with a different `model` than the request asked for (e.g. `gpt-4o-mini` → `gpt-5`), `app.state.response_model_mismatch_counter[(request_model, response_model)]` increments. Observation only — no enforcement, no header munging, passthrough preserved. **Counter semantics: once per stream**, not once per chunk-with-mismatch. The response model can't change mid-stream, so per-chunk counting was operator-noise (10k-chunk stream produced a count of 10k for the same logical event). Per-stream counting gives operators the right cardinality.
- **Worthless accepts ANY model string** (WOR-696). No registry, no admission-time model check. Works on OpenRouter, Azure custom deployments, Enterprise gateways, and any future model launch without operator intervention. Cap stays honest via the global-ceiling fallback regardless of model name.
- **Crash-orphan sweeper backstop bills the ceiling** (WOR-696, `worthless-osgt`). Brutus + chaos-engineer found that if the proxy was SIGKILL'd between stream-start and the BackgroundTask settle, the orphan `pending_charges` row would be swept later but billed at the stored estimate (zero for no-`max_tokens` requests). The sweeper now applies `max(estimate, GLOBAL_CEILING_TOKENS)` — same floor every other terminal path uses. Closes the gap at sweeper TTL (default ~60s).
- **`worthless lock` won't print [OK] until the proxy proves it received a test request** (WOR-658, [#340](https://github.com/oblangatas/worthless/pull/340)). After lock rewrites the OpenClaw provider entry, it now fires a HEAD against the proxy's new `/_bind_probe/{alias}` endpoint and reads a dedicated `bind_probe_count` field on `/healthz` before and after. Counter ticks → sentinel records `bind_confirmation: {status: pass, delta, reached, aliases}`. Counter doesn't tick → lock exits **91** (new code, distinct from 73/87) with `[FAIL] Bind-confirmation: test request did not reach the proxy`. The bind_probe counter is intentionally separated from `requests_proxied` (spend_log) so probe traffic never pollutes the real-traffic meter and a real-traffic burst can never fake a probe pass. Probe endpoint is loopback-only (`127.0.0.1` / `::1` — non-loopback origins get 404 without ticking the counter). When a recognised proxy isn't found at `/healthz` (missing `bind_probe_count` field), lock classifies the verdict as `skipped, reason=proxy_unrecognised` rather than `fail` — refuses to manufacture a failure against an unrecognised peer.
- **`worthless status` and `worthless doctor` surface the bind-confirmation verdict** (WOR-658). Status reports the specific reason (`Proof-of-routing FAILED — the test request didn't reach the proxy`, or `The service answering /healthz isn't a worthless proxy`) instead of generic DEGRADED. Doctor's new `bind_confirmation` check turns the same signal into a remediation hint (`restart OpenClaw's daemon` or `re-run worthless lock`). The DEGRADED exit-code from status remains 73 for backwards-compat; lock-side bind-fail is exit 91. **`worthless wrap` warns before spawning a child** when the last lock left a DEGRADED sentinel — the magic-moment command is no longer blind to bind-fail state.
- **Recovery path from bind-fail is tested** (WOR-658). The `[FAIL]` message now lists both repair routes: restart OpenClaw + re-run `worthless lock`, OR `worthless unlock` to roll back. `tests/openclaw/test_unlock_after_bind_fail.py` pins that unlock from the bind-fail state restores the `.env` byte-for-byte and clears the DEGRADED sentinel.

### Fixed
- **`worthless uninstall` survives a broken or half-deleted install** (WOR-713, [#360](https://github.com/oblangatas/worthless/pull/360)). A missing `fernet.key` or corrupted `worthless.db` used to crash uninstall (WRTLS-102/103); a deleted project (its locked `.env` gone) used to block uninstall forever via the key-shredder guard. Now a broken install refuses cleanly and points at `--force`; a missing `.env` is skipped with a warning and never blocks; and `worthless doctor` (both text and `--json`) diagnoses both states instead of crashing, each pointing at `worthless uninstall --force`. The restore-then-wipe guard is unchanged: it still aborts before deleting anything if a *recoverable* key can't first be restored, and `--force` only widens the wipe decision — it never skips a restore on a healthy install.

### What this does NOT defend against
- Future models with >128K max-output (Anthropic's next reasoning tier, a 256K-output OpenAI release, etc.) — these will under-bill by their excess until `GLOBAL_CEILING_TOKENS` is raised.
- **A stale OpenClaw daemon ignoring the rewritten `baseUrl`** (WOR-658 known gap, [WOR-756](https://linear.app/plumbusai/issue/WOR-756) closes it). Bind-confirmation proves the *proxy* received a test request — it does NOT prove OpenClaw's running daemon will use the new URL on the next chat. OpenClaw caches provider config; until WOR-756 ships an automatic daemon-reload trigger, the user must restart OpenClaw after `worthless lock` to guarantee end-to-end routing. Lock's `[OK]` is honest about the proxy side; OpenClaw's `[OK]` is on the user.
- **A co-resident malicious process impersonating the worthless proxy on the configured port** (WOR-658 known gap, [WOR-768](https://linear.app/plumbusai/issue/WOR-768) closes it). Squatter-resistance today is "does `/healthz` include `bind_probe_count`?" — a local service that mimics the protocol passes that check. The loopback-only gate closes the realistic remote attacker; the co-resident-with-protocol-knowledge case awaits a cryptographic identity check.
- A 14m59s drip stream still completes inside the duration window — the kill bounds wall-time, not provider cost within that window.
- A compromised proxy can disable any check that lives inside the proxy, including this ceiling. T7 defends against honest bugs, runaway agents, and zombie streams; the compromised-proxy threat model is WOR-269 territory.
- Response-model mismatch counter is observation-only — a silent re-route to a more expensive model is NOT blocked. The cap still moves only by token count, not by dollar-equivalent at the actual upstream model.
- Cap is per-key per-DB. Deleted DB row or filesystem-level tampering = no cap.
- Per-alias concurrency is unbounded in this PR. 200 parallel just-under-threshold streams could burn 25.6M tokens before admission denies request #201. Tracked as a follow-up.
- **`worthless uninstall --force` on a broken install does NOT recover your keys** (WOR-713). When the `fernet.key` or `worthless.db` is gone, the locked secrets can't be reconstructed — `--force` wipes the unrecoverable remains so the machine is left clean, but those API keys are lost. Rotate them at the provider.

### Changed
- **Bare `worthless` now starts the sidecar-supervised proxy path** (WOR-717). The default command spawns detached `worthless up` instead of the legacy sidecar-less `start_daemon` helper. The latter remains for internal compatibility but is deprecated for v1.2 removal. Service unit detection compares `WORTHLESS_HOME` by realpath so symlinked install paths (e.g. `/tmp` vs `/private/tmp`) match. **Does not yet** include foreign-unit guards on service mutators or default-command exit **2** when a platform service is stopped/failed — both land in wave 3b (#292).

## [0.3.8] — 2026-06-13

The "agents and exits" release. Two headline additions: a zero-Python npm wrapper lets editors (Claude Code, Cursor, Windsurf) install the MCP server in under 30 seconds, and `worthless uninstall` gives every locked `.env` its original key back before removing itself — no stranded files, clean exit. Alongside that: a proxy kill switch stops OpenClaw agents dead when the proxy goes down, the spend cap is now exact per process, and the install pipeline closes three supply-chain attack surfaces that were confirmed reachable.

### Added
- **One-line MCP setup for editors** (WOR-229, #be567bc). `worthless-mcp` npm package: drop one JSON block into `.mcp.json` and Claude Code / Cursor / Windsurf discover and launch the MCP server automatically. No Python or uv needed on the editor side; the wrapper bootstraps uv and pins the Python package to the matching npm version.
- **`worthless uninstall`** (WOR-435, #301). Reads every enrolled `.env` the tool ever locked, writes the original API key back, then removes itself. Leaves no stranded locked files and no user having to remember what the plaintext key was.
- **Proxy kill switch for agents** (WOR-621 Phase 3, #276). Stopping the Worthless proxy now halts any OpenClaw agent that is mid-flight on a locked provider. Agents can't leak around a downed proxy.

### Security
- **Spend cap is exact per process** (WOR-662, #273). The proxy refuses to start with `WEB_CONCURRENCY > 1`. Two workers could each independently run up to the full cap; now the cap means what it says.
- **Compromised proxy can no longer act as a key oracle** (#269). The locked vault stopped signing arbitrary upstream requests when the proxy process is breached — closes the master-key extraction path identified in the security audit.
- **Install is resistant to supply-chain poisoning** (WOR-709 + WOR-673 + WOR-679, #284 + #281 + #280). Three surfaces closed: (1) `install.sh` skips a pipx path-confusion check that was an empirically-confirmed RCE vector when pipx lives in an untrusted directory; (2) poisoned `UV_*` / `PIP_*` env vars can't redirect the install to a malicious host; (3) CDN integrity verification now has its own exit code — retry loops can't silently swallow a poisoned artifact.
- **Every commit to main is signed and author-verified** (WOR-589 + WOR-590, #305 + #308). A push-time hook and a pre-commit check enforce GPG-verified commits from the canonical author. A stolen GitHub token can't push unverifiable commits.

### Fixed
- **Error messages now show their reason** (worthless-k82c, #268). A parser bug was silently stripping the explanatory clause from error text — errors now say "because X", not just the error code.
- **Post-lock scan can't freeze the terminal** (worthless-8vvg, #264). The prompt scan that runs after a successful `worthless lock` now exits on large repos instead of hanging indefinitely.
- **14 dead documentation links repaired** (#303). Broken internal links that sent users to 404s are fixed; a CI guard blocks new dead links from shipping.

### Changed
- **CLI discloses "AS IS, no warranty" on first run** (WOR-488, #302). Shown once at first invocation. Honest, not noisy.
- **SECURITY.md is honest about response scope** (#306). Best-effort response commitment, no overstatements about SLAs we can't guarantee.
- **Dependabot tuned to batch non-major updates** (#326). Actions updates are grouped; semver-major bumps are held for manual review.

### Docs & Infrastructure
- **Install docs live in one place** (#309). The stale website copies are removed; `docs/install-*.md` is the single source and the website pulls from there.
- **OpenClaw routing contract test** (WOR-621, #266). Tag-pinned integration test catches routing drift before it reaches production.

## [0.3.7] — 2026-05-30

The "harden the whole front door" release. Everything merged since v0.3.6 ships at once: your API key now survives a proxy compromise (a crypto sidecar holds the key, not the proxy), OpenClaw runs fully containerised and `worthless lock` refuses to proceed when plaintext keys are present, and the entire install path — `worthless.sh`, the `?explain=1` audit, the PyPI publish, and the Worker deploy — is version-pinned and signed-tag-verified end to end. Plus a wave of `lock`/`doctor` fixes that tell you the truth instead of failing silently.

### Security
- **Your API key survives a proxy compromise** (WOR-306, #134). On the Docker topology a crypto sidecar holds the Fernet key under a separate uid; a breached proxy process can no longer read it.
- **`worthless lock` blocks on plaintext keys** (#210). The OpenClaw secrets-audit gate refuses to lock when an unprotected API key is present instead of silently locking around it.
- **A stolen shard-A is inert** (#208). Tightened the upsert API + doctor consistency so a leaked key-half can't be replayed.
- **The install front door is honest and signed end to end.** The `?explain=1` audit page no longer claims a version pin / line numbers that don't exist, and a CI check fails if a version literal drifts back in (WOR-558, #213). The default `curl | sh` pins a known-good PyPI release instead of running latest (WOR-559, #217). Every Worker deploy (WOR-391, #205) **and now every PyPI publish** verifies the maintainer's GPG-signed tag. The release-sync monitor anchors to signed git tags, not a forgeable GitHub Release object (#224). Production edge wire-defenses are probed daily, not only at deploy (#216).
- **Stolen creds can't deadlock cron jobs** (worthless-16x2, #198) — a stable auth token for the OpenClaw→proxy hop.
- **`lock` flags hardcoded provider URLs** that would route around the proxy (#174, #182).

### Added
- **OpenClaw runs fully containerised** — no host process required (#192); agents work through the proxy with the 400s and Docker connectivity fixed (#188).
- **`worthless doctor` heals itself** — `check-registry`, `--json` for agents, and 4 new checks (WOR-464, #190); it catches wrong-database confusion before you waste hours on phantom 401s (#195).
- **Verified end-to-end install journeys** for solo, Claude Code, and Docker users (WOR-502, #197), with proof traces (WOR-441, #194) and a user-journey → proof matrix (WOR-544, #206).
- Website: homepage incident ticker (#199, #204) and wless.io source migrated into the main repo (WOR-455, #179).

### Fixed
- **Re-lock tells you it worked**, not nothing (WOR-504, #207); **`lock` catches a broken app before you walk away** (WOR-493, #180).
- **Silent 401 fixed** — the canonical key now wins the `BASE_URL` slot (WOR-496, #176).
- **LAN mode actually binds the network** (worthless-rczo, #186).
- **`LOCK FAILED` summary** ends the mixed `[FAIL]`+`[OK]` ambiguity (#222).
- The last revoke wipes the orphan Fernet key from the keychain (#175).
- `worthless_status` (MCP) returns keys correctly from an async context (#196); ticker script loads under CSP (#200).

### Changed
- Version labels aligned to PyPI `v0.x` (WOR-489, #183).
- Internal security docs privatised (WOR-593, #236); Snyk reports the dependency tree we actually ship (#235, #237).

### Tests & Infrastructure
- New user-flow test foundation plus native and adversarial stress journeys (WOR-439/447/567/442, #177/#187/#215/#212); install-failure and repo-health monitoring with flaky-test quarantine (WOR-578, #226); Windows test collection no longer crashes on a POSIX-only `os.getuid()` (#211); xdist flake suppression (WOR-571, #218; #238); PR auto-labelling by branch prefix and security paths (#219).

## [0.3.6] — 2026-05-12

The "OpenClaw integration actually works for Docker users" release. v0.3.5 shipped the WOR-431 OpenClaw magic-integration (Phase 2), but Brutus review caught 3 release blockers and CodeRabbit caught 2 more before the developer-facing flow was sound. Headline: `worthless lock` on a host with a Dockerised OpenClaw now writes a `baseUrl` that OpenClaw can actually reach (loopback → docker0 bridge / `host.docker.internal`), SKILL.md ships the YAML frontmatter ClawHub needs for auto-install discovery, and cross-environment re-locks on non-default ports correctly refresh the apiKey instead of misclassifying our own entries as third-party conflicts.

### Fixed
- **`worthless lock` now writes a Docker-reachable proxy URL** (PR #168). `apply_lock` resolves the proxy host at lock-time via `_resolve_proxy_base_url()` — bare-metal returns `127.0.0.1:8787`, Docker Desktop returns `host.docker.internal:8787`, Docker on Linux reads the `docker0` bridge gateway (default `172.17.0.1`). Pre-fix every OpenClaw-in-Docker user hit a silent connection-refused; `127.0.0.1` from inside the container points back at the container, not the host. The probe uses `shutil.which("docker")` + a 3 s `docker info` timeout, so when Docker is absent there's zero startup latency cost.
- **`_is_proxy_url` cross-host fallback handles non-default ports** (PR #168, CodeRabbit catch). The original fallback hardcoded `:8787`. A user on `--port 9090` who locked without Docker then re-locked with Docker on would have the existing entry's `apiKey` silently skip refresh — primary prefix check fails on host mismatch, fallback regex fails on port mismatch, entry misclassified as third-party conflict. Now the fallback derives the port from `proxy_base_url` via `urlsplit()`, so `WORTHLESS_PORT`/`--port` deployments work end-to-end. Regression test pins port 9090 with host mismatch.
- **`health_check()` uses the same resolved host as `apply_lock`** (PR #168, CodeRabbit catch). Pre-fix, doctor compared the `openclaw.json` entry against a hardcoded `http://127.0.0.1:<port>/<alias>/v1`. On Docker hosts every healthy config got reported as drifted. Optional `proxy_base_url` parameter defaults to `_resolve_proxy_base_url()`; `proxy_port` is preserved so non-default deployments don't false-flag.
- **urllib3 bumped to 2.7.0** (PR #168). Closes GHSA-qccp and GHSA-mf9v via lockfile bump (no direct dependency added).

### Added
- **SKILL.md `metadata.openclaw` frontmatter** (PR #168). `requires.bins: [worthless]` enforces the worthless CLI is installed before the skill activates; `install` array gives ClawHub two recipes (`uv tool install` + `pip install`) for one-click bootstrap. Pre-fix ClawHub had no way to auto-install; the developer had to know they needed worthless on the host before the skill made sense.
- **WOR-432 e2e Docker test runs in CI** (PR #168). `tests/test_openclaw_skill_e2e.py` was already implemented but had been gated on a Docker daemon — confirmed it runs locally end-to-end (mock upstream receives the reconstructed key, shard-A absent from outbound traffic).
- **+8 unit tests covering all `_resolve_proxy_base_url()` branches** (PR #168). Linux/macOS/Windows + Docker present/absent + bridge inspection failure.

### Changed
- **`_is_proxy_url` rewrite** (PR #168). Architecturally the cleanest fix is an explicit `managedBy` marker on each entry; v0.3.6 ships the heuristic and tracks the proper fix as [WOR-487](https://linear.app/plumbusai/issue/WOR-487). Outstanding research: does OpenClaw's daemon preserve unknown fields on rewrite?

### Notes
- The end-to-end developer flow (clean machine → OpenClaw + worthless → first protected request) still leans on the developer reading docs to install worthless first. Real ClawHub publish (WOR-94 + WOR-478) is a separate ticket.

## [0.3.5] — 2026-05-08

The "WOR-431 Phase 2 lands + install front-door drift fixed" release. Ships the OpenClaw magic-integration that `worthless lock` had been promising — automatic detection + `openclaw.json` rewrite + SKILL.md install — plus a daily CI check that every install front door (`worthless.sh`, `docs.wless.io/install/`, `install.sh` digests) stays in sync.

### Added
- **`worthless lock` detects OpenClaw and rewires its config automatically** (WOR-431 Phase 2, #152). On any host where `~/.openclaw/` exists, `lock` injects `worthless-<provider>` entries into `openclaw.json` and installs the worthless SKILL.md into the skill workspace. Best-effort + idempotent — failures here surface as structured events in `--json` and never roll back the `.env`/DB writes. Symmetric undo on `unlock`. New `worthless doctor` rows surface drift between the proxy and `openclaw.json`.
- **Install front-door daily-drift CI** (WOR-452, #149). Cron check pulls `worthless.sh`, `docs.wless.io/install/`, and the `install.sh` digest from each surface — flags divergence as a Linear issue automatically.
- **`scripts/bump-version.sh`** (#145). Atomic version bumper that writes to `pyproject.toml`, `SKILL.md`, and the lockfile in one shot — prevents SKILL.md drift that previously slipped through.

### Fixed
- **`install.sh` surfaces uv's actual stderr instead of a generic banner** (#148). Previously a uv install failure showed only "installation failed" with no clue why; now the user sees uv's real error message.
- **xdist-isolated default-command tests don't collide with a real port-8787 daemon** (#147).
- **Worker-concurrency tests stop flaking the merge gate** (WOR-448, #142).
- **`DOCS_URL` points at live `docs.wless.io`** instead of stale staging (worthless-1lfi, #144).

### Removed
- **Dead `_build_child_env` helper in `wrap.py`** (#146).

## [0.3.4] — 2026-05-06

The "make `worthless wrap` actually work end-to-end" hotfix. v0.3.3's HF10 fresh-install verification surfaced that `worthless wrap python main.py` on a clean machine left the child unable to reach the proxy: `lock` writes port 8787 to `.env` but `wrap` was binding a random port the child had no way to discover. The earlier "wrap works" verdict was contaminated by a stale `worthless up` daemon hogging 8787 across sessions. Fix: `wrap` now binds the same port `lock` wrote.

### Fixed
- **`worthless wrap` proxy now binds the port `lock` wrote to `.env`** (worthless-djoe, closes worthless-hyb1). Pre-fix `wrap` called `spawn_proxy(port=0)` (OS-random), which gave the proxy a port the child couldn't discover — post-8rqs `wrap` had stopped injecting `*_BASE_URL` vars into child env, so the only port the child saw was `.env`'s. With lock writing 8787 and wrap binding random, the child hit 8787 and got connection-refused. Now `wrap` calls `_resolve_port(None)` (same priority chain `lock` and `up` use: arg → `WORTHLESS_PORT` env → `8787` default), so child + proxy agree. Regression introduced in v0.3.3 / PR #127 (worthless-8rqs).
- **`worthless wrap` gives a clean error when its port is already in use.** If `worthless up` is already running on the same port, wrap names it: *"port 8787 is already serving a worthless proxy (`worthless up` is running). Either run your command directly (the daemon proxies it already), or stop the daemon and re-run wrap."* If a non-worthless process holds the port, wrap names that case too. `up` and `wrap` are alternatives, not combinable on the same port.

## [0.3.3] — 2026-05-05

The "make `curl install.sh | sh` actually work" release. v0.3.2 dogfood surfaced 9 hotfixes (HF1-9) covering keychain UX, scan/status correctness, unlock messaging, and orphan recovery. Plus install-matrix supply-chain hardening (WOR-317-320) so the release pipeline can't be tampered with via floating-tag base images.

### Added
- **`WORTHLESS_DEPLOY_MODE` trust-boundary contract** (WOR-345). Three modes — `loopback` / `lan` / `public` — pin host bind, X-Forwarded-Proto trust source, and whether `WORTHLESS_ALLOW_INSECURE` is even legal. `public` mode requires `WORTHLESS_TRUSTED_PROXIES` (validated as CIDR; placeholders are rejected at startup). PaaS auto-detection (RENDER / FLY_APP_NAME / KUBERNETES_SERVICE_HOST) refuses silent loopback default.
- **`worthless doctor --fix`** (HF7, worthless-3907, PR #128). Recovers stuck states from the v0.3.2 dogfood scenario where `unlock` reported "no keys" but `status` reported "PROTECTED". Surgical delete by `(alias, env_path)` tuple. Shared `cli/orphans.py` module owns the `is_orphan` predicate plus canonical user-facing phrases — no drift between scan/status/doctor wording.
- **`worthless lock` supports multiple providers side-by-side** (PR #127). One `.env` can have OpenAI + Anthropic + Google + xAI keys; each enrolls with its own per-provider upstream URL.
- **Per-key unlock messaging** (HF4, worthless-5u6y, PR #123). `worthless unlock` now prints `Restored {var} ({provider}, alias {alias_id}) → {env_path}` per key, plus skip lines for missing shard-A vars. Final summary `Restored N, skipped K`. No more silent batch-fatal exceptions.
- **Scanner scope docs** (HF6, worthless-8axm, PR #123). README + SKILL.md + threat model document the LLM-provider-keys-only scope; recommend gitleaks/trufflehog as companions for general secret detection.
- **Cross-command state-machine integration tests** (HF8, worthless-5koc, PR #120). Tests covering commitment-mismatch, partial-unlock, scan-orphan, status-orphan, unlock-db-wipe, unlock-no-db-row contracts.
- **Install matrix supply-chain hardening** (WOR-317-320, PR #132). Pinned base-image digests (`@sha256:...`) on every fixture, Astral installer SHA verification in `Dockerfile.ubuntu-with-uv`, BuildKit cache mount on uv-running RUN steps, non-root user fixture (`ubuntu-nonroot`), idempotency check fixture (`ubuntu-idempotency`) that runs `install.sh` twice and diffs snapshots. `install.sh` gains a fast-path: `WORTHLESS_VERSION` set + matches installed → return early before `uv tool install/upgrade` writes metadata.

### Changed
- **BREAKING — Docker default bind is now loopback** (`127.0.0.1`), not `0.0.0.0`. The Dockerfile no longer hard-codes `--host 0.0.0.0`; bind is composed by `entrypoint.sh` from `WORTHLESS_DEPLOY_MODE`. `docker run -p 8787:8787 worthless` without setting the env var binds only inside the container — set `-e WORTHLESS_DEPLOY_MODE=lan` to restore network reachability behind a private network, or `=public` (with `WORTHLESS_TRUSTED_PROXIES`) for edge deployments. `deploy/docker-compose.env.example` and `deploy/render.yaml` updated accordingly.
- **`worthless scan` JSON shape** (HF5, worthless-gmky, PR #131): bare-array → `{schema_version: 2, findings, orphans}`. Schema version is pinned exactly in a contract test. Consumers must update.

### Fixed
- **OpenRouter API keys classified as `openrouter`** (HF1, worthless-lj0z, PR #124, advances WOR-381). `sk-or-v1-...` and `sk-or-...` keys were previously mislabeled `openai` because the generic `sk-` prefix won the longest-first match; the new `openrouter` prefixes now beat it. **Behaviour change:** SARIF/scan consumers filtering on `provider == "openai"` for OpenRouter keys will see relabels to `provider == "openrouter"` — update filter logic accordingly. Detection only; per-enrollment proxy routing for `provider == "openrouter"` is tracked separately under `worthless-8rqs` and remains future work.
- **macOS Keychain prompts collapse to one per CLI invocation** (HF2, worthless-mnlp, PR #125). `WorthlessHome.fernet_key` is now memoized per-instance via a private `_cached_fernet_key` field, so a single `worthless lock` triggers exactly one keychain ACL probe instead of 3+. Cache populate uses a per-instance `threading.Lock` with double-checked init so concurrent first-readers collapse to a single `read_fernet_key` call. Cache is process-scoped — new CLI invocations still re-prompt once until "Always Allow" is granted.
- **`worthless scan` and `worthless status` no longer prompt for keychain on read-only paths** (HF3, worthless-cmpf, PR #126). New `_fernet_key_present(home)` gate at the scan path; placeholder `bytearray(b"")` for the unused parameter on missing-key paths. Scans + status checks now produce zero popups even on a brand-new machine.
- **`worthless status` and `worthless scan` flag broken DB rows as `BROKEN`** (HF5, worthless-gmky, PR #131) instead of lying that they're `PROTECTED`. Plain-English wording: `PROBLEM_PHRASE = "can't restore"`, `FIX_PHRASE = "worthless doctor --fix"`. Per-alias aggregation: `BROKEN` iff all enrollments are orphan; `PROTECTED` if any enrollment is healthy.
- **`worthless unlock` default `--env` no longer surfaces HF4's hard error on implicit defaults** (pnn2, PR #129). Implicit `--env=.env` doesn't trigger the per-key skip messaging path that was meant only for explicit user-named paths.

### Security
- **Pinned base-image digests across the install test matrix** (WOR-319). Every `FROM` line uses `@sha256:<digest>` instead of floating tags, so a compromised upstream tag cannot ship malware via our matrix.
- **Astral uv installer SHA verification** in `Dockerfile.ubuntu-with-uv` (WOR-319). The fixture awks `ASTRAL_INSTALLER_SHA256` out of `install.sh` at build time so the SHA stays in lockstep with `UV_VERSION`.

### Verified manually
- **HF9 (worthless-xw2m) keychain popup contract on dev machine, 2026-05-05**. Wiped keychain (drained 6 entries to 0) + `~/.worthless/`, fresh `uv tool install` from main, ran `worthless lock` + status / scan / unlock / lock / up / down. **0 popups across all commands.** HF2 unit + user-flow tests prove the 1-popup contract on truly clean machines via real-keyring spy. Phase-2 second-machine run is best-practice but not blocker.

### Known limitations
- **Manual `worthless up` after every reboot** until WOR-174 (macOS launchd) and WOR-175 (Linux systemd) ship in v0.4.
- **Docker app + host worthless** requires manually editing `.env` to use `host.docker.internal:8787` instead of `127.0.0.1:8787` — `worthless lock` writes `127.0.0.1` blindly today (filed as v1.2 work).
- **Two `worthless up` proxy bugs** discovered during HF9 manual QA: stale orphan proxy on port 8787 (`worthless-6gkb`) and `worthless up &` exits prematurely (`worthless-n8tj`). Both filed as v0.3.4 / v1.2 work; do not affect lock/scan/status/unlock paths.

## [0.3.0] — 2026-04-18

First release published to PyPI. `pip install worthless` now works.

### Added
- **Magic default command** (`worthless` with no arguments). Detects API keys in `.env`/`.env.local`, prompts to lock, starts the proxy daemon, reports healthy — zero-config first-time setup. `--yes` for non-interactive, `--json` for read-only state.
- **Format-preserving key split** (WOR-207 Phase 1). Shard A now preserves the original key's prefix, charset, and length, so scanners and SDK validators see a key-shaped token. Database migration included for existing installs.
- **Anthropic key authentication** (WOR-207 Phase 2). `x-api-key` support alongside OpenAI-style `Authorization: Bearer`.
- **SR-09 shard separation enforcement**. Pre-commit hook blocks commits that would co-locate Shard A and Shard B in any code path.
- **Pre-commit stack**: gitleaks, semgrep, bandit, pip-audit, ruff, codespell, actionlint, zizmor, SR-rule custom checks.
- **Docker e2e test suite**. Single-container and compose-stack fixtures; read-only container + tmpfs for `/tmp`.
- **OpenClaw integration harness** (WOR-213). Live attack suite validates 9 attack vectors against real OpenAI + Anthropic.
- Security FAQ and threat-model docs (WOR-196).

### Changed
- `DEVELOPMENT.md` and `SECURITY.md` rewritten for doc accuracy — commands and paths now match the shipping CLI.
- Test suite no longer hardcodes version literals; assertions read from `importlib.metadata` / `pyproject.toml` to prevent drift.

### Fixed
- CodeQL alerts resolved: SR-01 bytearray usage, B603 subprocess hardening, tamper-detection test correctness, schema SQL formatting.
- CodeRabbit review comments across docs and CLI (WOR-196 #55, #58).

### Security
- All crypto operations use `bytearray` + explicit zeroing (SR-01).
- Constant-time comparisons on all digest/HMAC paths (SR-07).
- Gate evaluation strictly precedes shard reconstruction (SR-03).
- Published artifacts built via PyPI trusted publishing (OIDC, no long-lived tokens).

[0.3.16]: https://github.com/oblangatas/worthless/releases/tag/v0.3.16
[0.3.15]: https://github.com/oblangatas/worthless/releases/tag/v0.3.15
[0.3.14]: https://github.com/oblangatas/worthless/releases/tag/v0.3.14
[0.3.13]: https://github.com/oblangatas/worthless/releases/tag/v0.3.13
[0.3.12]: https://github.com/oblangatas/worthless/releases/tag/v0.3.12
[0.3.11]: https://github.com/oblangatas/worthless/releases/tag/v0.3.11
[0.3.10]: https://github.com/oblangatas/worthless/releases/tag/v0.3.10
[0.3.9]: https://github.com/oblangatas/worthless/releases/tag/v0.3.9
[0.3.8]: https://github.com/oblangatas/worthless/releases/tag/v0.3.8.0
[0.3.7]: https://github.com/oblangatas/worthless/releases/tag/v0.3.7
[0.3.6]: https://github.com/oblangatas/worthless/releases/tag/v0.3.6
[0.3.5]: https://github.com/oblangatas/worthless/releases/tag/v0.3.5
[0.3.4]: https://github.com/oblangatas/worthless/releases/tag/v0.3.4
[0.3.3]: https://github.com/oblangatas/worthless/releases/tag/v0.3.3
[0.3.0]: https://github.com/oblangatas/worthless/releases/tag/v0.3.0
