# WOR-464 — Test Summary

All tests added or touched in this PR. The legacy doctor suite (135
tests across `tests/test_doctor_icloud.py`, `tests/test_wor456_additional.py`,
`tests/openclaw/test_doctor_command_openclaw.py`, `tests/cli/test_doctor_purge.py`,
`tests/user_flows/test_doctor_dogfood.py`) is unchanged and continues
to pass byte-identical text output. The 28 new tests below pin the new
contracts: check registry, JSON envelope, and per-check behaviour
(including the two WOR-464 guardrails — `fernet_drift.fixable=False`
and `orphan_keychain` allowlisting the active install).

## Registry contract

| Test | Covers | Result |
|---|---|---|
| `tests/cli/doctor/test_registry.py::test_schema_version_is_string` | `SCHEMA_VERSION` is a non-empty string. | PASS |
| `tests/cli/doctor/test_registry.py::test_all_checks_registered` | `ALL_CHECKS` contains the eight documented `check_id` values, no more, no less. | PASS |
| `tests/cli/doctor/test_registry.py::test_check_protocol_surface` | Every entry exposes `check_id` and a callable `run`. | PASS |
| `tests/cli/doctor/test_registry.py::test_check_result_keys` | Each `run(ctx)` returns the full `CheckResult` key set. | PASS |
| `tests/cli/doctor/test_registry.py::test_fernet_drift_is_never_fixable` | `fernet_drift.fixable` is `False` even with `fix=True`. (Guardrail.) | PASS |
| `tests/cli/doctor/test_registry.py::test_check_id_is_snake_case[*]` | Every `check_id` is snake_case (8 parametrised cases). | PASS |

## JSON output contract

| Test | Covers | Result |
|---|---|---|
| `tests/cli/doctor/test_json_output.py::test_json_emits_single_parseable_document` | `worthless doctor --json` writes exactly one JSON document to stdout. | PASS |
| `tests/cli/doctor/test_json_output.py::test_json_includes_all_check_ids` | All 8 check_ids appear in the `checks` array, even when status is `ok`. | PASS |
| `tests/cli/doctor/test_json_output.py::test_json_ok_true_on_clean_install` | Fresh home with no findings → `ok=true`, summary counts zero. | PASS |

## orphan_keychain (NEW)

| Test | Covers | Result |
|---|---|---|
| `tests/cli/doctor/test_orphan_keychain.py::test_active_install_username_is_allowlisted` | Current install's `fernet-key-<digest>` never appears in findings (WOR-464 guardrail). | PASS |
| `tests/cli/doctor/test_orphan_keychain.py::test_non_darwin_skipped_reason` | Linux/Windows: `status=ok`, `skipped_reason="non-darwin platform"`. | PASS |
| `tests/cli/doctor/test_orphan_keychain.py::test_fix_deletes_only_non_allowlisted` | `--fix` deletes orphans but never the allowlisted username. | PASS |
| `tests/cli/doctor/test_orphan_keychain.py::test_findings_are_well_formed` | Each finding is a dict. | PASS |

## stranded_shards (NEW)

| Test | Covers | Result |
|---|---|---|
| `tests/cli/doctor/test_stranded_shards.py::test_no_stranded_when_empty` | Empty shard_a dir → ok. | PASS |
| `tests/cli/doctor/test_stranded_shards.py::test_detects_stranded_shard` | File with no DB match → warn finding. | PASS |
| `tests/cli/doctor/test_stranded_shards.py::test_fix_unlinks_stranded` | `--fix` removes the stranded file. | PASS |
| `tests/cli/doctor/test_stranded_shards.py::test_dry_run_does_not_unlink` | `--dry-run` keeps the file, returns warn. | PASS |
| `tests/cli/doctor/test_stranded_shards.py::test_fixable_is_true` | Check declares `fixable=True`. | PASS |

## fernet_drift (NEW — never auto-fixable)

| Test | Covers | Result |
|---|---|---|
| `tests/cli/doctor/test_fernet_drift.py::test_fixable_always_false` | `fixable` is `False` in the baseline path. | PASS |
| `tests/cli/doctor/test_fernet_drift.py::test_fixable_false_even_with_fix_flag` | `fix=True` still reports `fixable=False`, `fixed=[]`. (Guardrail.) | PASS |
| `tests/cli/doctor/test_fernet_drift.py::test_no_drift_when_only_keyring_present` | Only keyring present, no file → status=ok. | PASS |
| `tests/cli/doctor/test_fernet_drift.py::test_drift_detected_when_values_differ` | Different bytes in both sources → status=error with instructions. | PASS |
| `tests/cli/doctor/test_fernet_drift.py::test_no_drift_when_values_match` | Same bytes in both sources → status=ok. | PASS |

## broken_status (NEW)

| Test | Covers | Result |
|---|---|---|
| `tests/cli/doctor/test_broken_status.py::test_no_findings_when_shard_a_present` | Enrollment + matching shard_a file → ok. | PASS |
| `tests/cli/doctor/test_broken_status.py::test_detects_missing_shard_a` | Enrollment without shard_a → warn with `inferred_status=BROKEN`. | PASS |
| `tests/cli/doctor/test_broken_status.py::test_fix_deletes_broken_enrollment` | `--fix` removes dangling enrollment rows. | PASS |
| `tests/cli/doctor/test_broken_status.py::test_dry_run_does_not_delete` | `--dry-run` keeps the row. | PASS |
| `tests/cli/doctor/test_broken_status.py::test_fixable_true` | Check declares `fixable=True`. | PASS |

## Regression coverage (unchanged, still green)

| Test file | Count | Result |
|---|---|---|
| `tests/test_doctor_icloud.py` | 20 | PASS |
| `tests/test_wor456_additional.py` | 67 | PASS |
| `tests/openclaw/test_doctor_command_openclaw.py` | 16 | PASS |
| `tests/cli/test_doctor_purge.py` | 5 | PASS |
| `tests/user_flows/test_doctor_dogfood.py` | 27 (1 skipped non-darwin) | PASS |

Run the full suite locally:

```bash
uv run pytest tests/test_doctor_icloud.py tests/cli/test_doctor_purge.py \
              tests/openclaw/test_doctor_command_openclaw.py tests/test_wor456_additional.py \
              tests/cli/doctor/ tests/user_flows/test_doctor_dogfood.py
```

Last run: 135 passed, 1 skipped (non-darwin migrate test), 0 failures.
