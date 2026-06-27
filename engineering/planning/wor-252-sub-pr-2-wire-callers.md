# WOR-252 Sub-PR 2 — Wire `dotenv_rewriter` through `safe_rewrite`

**Ticket:** [WOR-252](https://linear.app/uglabs/issue/WOR-252) (Urgent)
**Stack:** branches off `feat/wor-252-sub-pr-1-safe-rewrite` (the safety gate)
**Branch:** `feat/wor-252-sub-pr-2-wire-callers` → targets sub-PR 1 in GitHub
**Revision:** v1 — TDD-first, post-planner-agent.

---

## Goal

Route every destructive `.env` write through the `safe_rewrite()` gate landed in sub-PR 1. After this PR, no code path in the project can write to a `.env` file without passing the 10 invariants. The unsafe `python-dotenv` `set_key`/`unset_key` calls disappear from the destructive write path.

The three functions that change:

- `add_or_rewrite_env_key(env_path, var_name, value)` — adds new OR replaces existing.
- `remove_env_key(env_path, var_name)` — removes if present, no-op if absent.
- `rewrite_env_key(env_path, var_name, new_value)` — replaces existing; `KeyError` if absent.

Public signatures unchanged. Happy-path bytes unchanged. Comments, blank lines, ordering, export prefixes, and quoted/multiline values preserved exactly as today.

## Non-goals

- **No** changes to `safe_rewrite()` itself. (Bug fixes go on sub-PR 1.)
- **No** backups. Sub-PR 3.
- **No** restore command. Sub-PR 4.
- **No** RECOVERY.md. Sub-PR 5.
- **No** leak closures. Sub-PR 6.
- **No** caller-site changes in `commands/lock.py` / `commands/unlock.py` / `mcp/server.py` beyond import swaps if needed.
- **No** new public API. New helpers stay private (underscore-prefixed).

---

## Why a hand-rolled serializer

`dotenv_values` parses `.env` into a dict, but discards comments, blank lines, ordering, and export prefixes. `safe_rewrite()` accepts the **full new file content** as bytes — it does not do partial-key edits.

Round-tripping through `dotenv_values` would silently rewrite the user's file and lose all formatting. That regresses today's behavior (current `python-dotenv.set_key` modifies one line in place). We need a line-preserving rewriter.

## Module surface

`src/worthless/cli/dotenv_rewriter.py` keeps its three public functions. New private helpers:

```python
@dataclass(frozen=True)
class _LogicalLine:
    raw: bytes              # exact original bytes, including EOL
    key: str | None         # parsed key name, or None if blank/comment/non-assignment
    has_export: bool        # leading `export ` prefix


def _detect_eol(buf: bytes) -> bytes: ...       # b"\r\n" | b"\n"
def _strip_bom(buf: bytes) -> tuple[bytes, bool]: ...   # returns (stripped, had_bom)
def _restore_bom(buf: bytes, had_bom: bool) -> bytes: ...
def _split_logical_lines(buf: bytes) -> list[_LogicalLine]: ...
def _serialize_lines(lines: list[_LogicalLine]) -> bytes: ...
def _rebuild_assignment_preserving_format(key: str, value: str, *, has_export: bool, eol: bytes) -> bytes: ...
def _validate_value(value: str) -> None: ...    # rejects newlines, NUL, control chars
def _read_file_bytes_or_empty(path: Path) -> bytes: ...
```

Each public function becomes:

```python
def add_or_rewrite_env_key(env_path: Path, var_name: str, value: str) -> None:
    _validate_value(value)
    existing = _read_file_bytes_or_empty(env_path)
    stripped, had_bom = _strip_bom(existing)
    eol = _detect_eol(stripped) or b"\n"
    lines = _split_logical_lines(stripped)
    new_line = _LogicalLine(
        raw=_rebuild_assignment_preserving_format(var_name, value, has_export=False, eol=eol),
        key=var_name,
        has_export=False,
    )
    matched = False
    for i, line in enumerate(lines):
        if line.key == var_name:
            lines[i] = _LogicalLine(
                raw=_rebuild_assignment_preserving_format(var_name, value, has_export=line.has_export, eol=eol),
                key=var_name,
                has_export=line.has_export,
            )
            matched = True
            break
    if not matched:
        # Ensure the previous line ends with a newline before appending.
        if lines and not lines[-1].raw.endswith((b"\n", b"\r\n")):
            lines[-1] = _LogicalLine(
                raw=lines[-1].raw + eol,
                key=lines[-1].key,
                has_export=lines[-1].has_export,
            )
        lines.append(new_line)
    new_content = _restore_bom(_serialize_lines(lines), had_bom)
    safe_rewrite(
        env_path,
        new_content,
        original_user_arg=env_path,
        allow_outside_repo=True,   # caller has already chosen the path
    )
```

`rewrite_env_key` is the same minus the append branch (raises `KeyError` if no match). `remove_env_key` deletes the matching `_LogicalLine` and serializes.

### Worked example

Input file:
```
# Production keys
OPENAI_API_KEY=sk-real-1234

DATABASE_URL=postgres://localhost/db
export ANTHROPIC_API_KEY="sk-ant-real"
```

Call: `rewrite_env_key(env, "ANTHROPIC_API_KEY", "sk-ant-decoy-0001")`.

Output file (byte diff is a single line):
```
# Production keys
OPENAI_API_KEY=sk-real-1234

DATABASE_URL=postgres://localhost/db
export ANTHROPIC_API_KEY=sk-ant-decoy-0001
```

(Existing python-dotenv strips the quotes too — we match that behavior.)

---

## Test inventory

All new tests under `tests/dotenv_rewriter/` (new directory). Existing `tests/test_dotenv_rewriter.py` stays put and stays green.

### `tests/dotenv_rewriter/conftest.py`

- `safe_rewrite_spy` — wraps the real `safe_rewrite` and records `(target, new_content, original_user_arg)` per call. Asserts can verify it was called exactly once with expected bytes.
- `make_env_file(tmp_path, content, mode=0o600)` — copy from sub-PR 1's conftest, adjusted for bytes.
- `sha256_of(path)`.
- `assert_byte_identical(path, expected_sha256)`.

### `tests/dotenv_rewriter/test_safety_invariants.py` — 9 tests

The red-line tests prove the gate is wired through every entry point.

1. `test_add_to_symlink_pointing_at_zshrc_refused` — **first red test.** Creates `~/.zshrc` (in tmp), creates `.env` as symlink to it, calls `add_or_rewrite_env_key`. Asserts `UnsafeRewriteRefused`, zshrc sha256 unchanged.
2. `test_rewrite_to_symlink_pointing_at_zshrc_refused` — same for `rewrite_env_key`.
3. `test_remove_to_symlink_pointing_at_zshrc_refused` — same for `remove_env_key`.
4. `test_add_to_basename_dot_zshrc_refused` — direct `.zshrc` path (not symlink).
5. `test_rewrite_to_fifo_refused` — special-file guard.
6. `test_add_to_path_outside_repo_with_default_settings_refused` — containment.
7. `test_add_with_value_containing_newline_refused` — `_validate_value`.
8. `test_add_with_value_containing_nul_byte_refused` — `_validate_value`.
9. `test_add_to_one_mib_plus_one_file_refused` — size invariant via gate.

### `tests/dotenv_rewriter/test_safety_wired.py` — 5 tests

Prove `safe_rewrite` is actually being called.

1. `test_add_calls_safe_rewrite_exactly_once` — uses `safe_rewrite_spy`.
2. `test_rewrite_calls_safe_rewrite_exactly_once`.
3. `test_remove_calls_safe_rewrite_exactly_once`.
4. `test_remove_noop_does_not_call_safe_rewrite` — when key absent, no write happens.
5. `test_python_dotenv_set_key_is_not_imported` — module-source assertion: `"set_key" not in dotenv_rewriter source`, `"unset_key" not in dotenv_rewriter source`. Prevents accidental regression.

### `tests/dotenv_rewriter/test_preserves_formatting.py` — 11 tests

The hardest correctness property.

1. `test_preserves_leading_comments`.
2. `test_preserves_trailing_comments`.
3. `test_preserves_blank_lines`.
4. `test_preserves_inline_comments_on_other_lines`.
5. `test_preserves_key_ordering`.
6. `test_preserves_lf_eol`.
7. `test_preserves_crlf_eol`.
8. `test_preserves_no_trailing_newline_then_appends_one_with_new_key`.
9. `test_preserves_utf8_bom_at_file_start`.
10. `test_byte_diff_minimal_for_single_value_change` — diff `before` vs `after`; only the matched line changed.
11. `test_idempotent_rewrite_with_same_value` — calling `rewrite_env_key` with the existing value yields byte-identical output (idempotency under the gate's delta check is non-trivial).

### `tests/dotenv_rewriter/test_export_prefix.py` — 4 tests

1. `test_rewrite_preserves_export_prefix`.
2. `test_remove_drops_exported_line_and_nothing_else`.
3. `test_add_does_not_add_export_prefix_to_new_keys`.
4. `test_export_with_unusual_whitespace_preserved` (`export   FOO=bar`).

### `tests/dotenv_rewriter/test_multiline_values.py` — 5 tests

1. `test_rewrite_replaces_multiline_value_with_single_line` — original is `KEY="line1\nline2"`, new value is `decoy`.
2. `test_remove_drops_multiline_block_completely`.
3. `test_add_with_value_containing_literal_newline_refused` — `_validate_value` blocks injection.
4. `test_quoted_value_with_escaped_quote_preserved_on_unrelated_change`.
5. `test_dollar_sign_value_not_expanded` (preserve `$VAR` literal).

### `tests/dotenv_rewriter/test_substring_traps.py` — 4 tests

The line scanner must do exact key match, not substring.

1. `test_does_not_match_key_when_target_is_substring` — file has `MY_API_KEY` and `API_KEY`; rewriting `API_KEY` must not touch `MY_API_KEY`.
2. `test_does_not_match_key_inside_value` — file has `OTHER=API_KEY=hidden`; rewriting `API_KEY` must not touch `OTHER`.
3. `test_does_not_match_commented_out_assignment` — file has `# API_KEY=oldvalue`; rewriting `API_KEY` does not match the comment.
4. `test_does_not_match_assignment_to_indented_key` — file has `\tAPI_KEY=indented` (leading whitespace); should still match per dotenv semantics; assert deliberate.

### `tests/dotenv_rewriter/test_existing_behavior.py` — 1 test

1. `test_existing_dotenv_rewriter_test_module_still_passes` — meta-test runs the existing `tests/test_dotenv_rewriter.py` and asserts 0 failures. Belt-and-suspenders for behavior preservation.

**Total new: 39 tests.** Existing 24 tests in `tests/test_dotenv_rewriter.py` remain green.

---

## TDD order (red lines first)

1. `test_add_to_symlink_pointing_at_zshrc_refused` — the entire ticket's justification in one assertion.
2. `test_rewrite_to_symlink_pointing_at_zshrc_refused` and `test_remove_to_symlink_pointing_at_zshrc_refused` (red triplet).
3. `test_python_dotenv_set_key_is_not_imported` — drives the module-level import removal.
4. `test_add_calls_safe_rewrite_exactly_once` (and the two siblings).
5. `test_remove_noop_does_not_call_safe_rewrite`.
6. `test_byte_diff_minimal_for_single_value_change` — drives the line-preserving serializer.
7. Formatting suite (11 tests).
8. Export-prefix + multiline + substring traps.
9. Remaining safety invariants.
10. Existing-behavior parity meta-test.

After step 1 passes, every other test is refinement. Step 1 is the ticket's entire reason for existing — wired through every public entry point.

---

## Risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | CRLF `.env` files (Windows-edited) lose their EOL on rewrite | `_detect_eol` + per-line preservation; tested. |
| 2 | UTF-8 BOM at file start eats the first key on parse | `_strip_bom` before scan, `_restore_bom` after. |
| 3 | Substring match on `API_KEY` clobbers `MY_API_KEY` | Logical-line scanner does exact left-of-`=` match after stripping `export ` and leading whitespace; test covers. |
| 4 | Multi-line quoted values misparsed as multiple logical lines | `_split_logical_lines` tracks open quote state; tested. |
| 5 | `original_user_arg=env_path` may be a symlink the caller wants to follow | Sub-PR 2 always passes the unresolved path; gate refuses symlinks. Caller must resolve before calling if they intend that — but no current caller does. |
| 6 | `allow_outside_repo=True` weakens containment | Necessary because callers (lock/unlock) operate on user-chosen paths outside any repo. Containment was a defense for the gate's *internal* use; rewriter is invoked by user intent, not auto-discovery. |
| 7 | Concurrent writes to same `.env` via two `worthless lock` invocations | Sub-PR 1 `flock` already serializes them at gate level. |
| 8 | Line-preserving serializer drifts from `python-dotenv` semantics on edge cases | `test_existing_behavior.py` runs full existing test suite; any drift fails CI. |
| 9 | `_validate_value` breaks legitimate values containing `#` | `python-dotenv` quotes them; we'd need to mirror. Tested. |

---

## Success criteria

- [ ] 39 new tests RED before any line of `dotenv_rewriter.py` changes.
- [ ] First red test: `test_add_to_symlink_pointing_at_zshrc_refused`.
- [ ] All 24 existing tests in `tests/test_dotenv_rewriter.py` stay green throughout.
- [ ] `safe_rewrite_spy` confirms exactly one `safe_rewrite` call per write op (zero on no-op remove).
- [ ] `python-dotenv.set_key` and `python-dotenv.unset_key` are no longer imported by `dotenv_rewriter.py`.
- [ ] Byte-diff between before-and-after on a single value change touches only the changed line + EOL preservation.
- [ ] Comments, blank lines, ordering, export prefixes, quoted multiline values, BOM, CRLF all preserved.
- [ ] All pre-commit hooks pass (ruff, ruff-format, codespell, bandit, xenon, pyright, vulture, conventional-commit).
- [ ] No production caller of `add_or_rewrite_env_key` / `rewrite_env_key` / `remove_env_key` modified beyond import lines.
- [ ] Symlink-to-zshrc red-line test passes with byte-identical zshrc on every rejection.
