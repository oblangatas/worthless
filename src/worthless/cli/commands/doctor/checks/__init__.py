"""WOR-464: doctor check modules.

Each module exposes ``check_id: str`` and ``run(ctx) -> CheckResult``.
The legacy checks (orphan_db, openclaw, icloud_keychain, recovery_import)
delegate to the helpers in the parent package's ``__init__.py`` so the
existing text output stays byte-identical. The new checks (orphan_keychain,
stranded_shards, fernet_drift, broken_status) implement their logic here.
"""
