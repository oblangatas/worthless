"""Worthless cryptographic primitives.

Reconstruction primitives (``reconstruct_key``, ``secure_key``) live in
:mod:`worthless.crypto.reconstruction` so the proxy can import them
without tripping the AST CI guard at
``tests/architecture/test_proxy_imports.py``. Enrollment-side
``split_key`` lives in :mod:`worthless.crypto.splitter` — import it
directly from there. We deliberately do NOT re-export ``split_key``
here: this package is on the proxy import path (via
:mod:`worthless.crypto.reconstruction`), and re-exporting the splitter
would cause every proxy boot to load the splitter into ``sys.modules``
even though the proxy never enrolls keys. See the runtime
import-snapshot test in ``tests/ipc/test_proxy_client_unit.py``.
"""

from worthless.crypto.reconstruction import reconstruct_key, secure_key
from worthless.crypto.types import SplitResult
from worthless.exceptions import ShardTamperedError

__all__ = [
    "ShardTamperedError",
    "SplitResult",
    "reconstruct_key",
    "secure_key",
]
