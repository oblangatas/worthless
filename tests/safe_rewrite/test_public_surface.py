"""Public-surface invariants for ``worthless.cli.safe_rewrite``.

The ``skip_delta`` flag is an *internal* knob on the private
``_safe_rewrite_core`` helper. It must never leak onto the public
``safe_rewrite`` or ``safe_restore`` signatures, and the private helper
must not be re-exported via ``__all__``. See
``engineering/planning/wor-276-recovery-final-plan.md`` §4.
"""

from __future__ import annotations

import inspect

import worthless.cli.safe_rewrite as safe_rewrite_module


def test_safe_rewrite_public_surface_has_no_skip_delta() -> None:
    """``skip_delta`` must stay private; ``_safe_rewrite_core`` must not be re-exported."""
    # Use ``hasattr`` for clear failure messages on the public API; we keep
    # a bare attribute access on ``_safe_rewrite_core`` below so the RED
    # phase fails loudly with AttributeError while the helper is missing.
    assert hasattr(safe_rewrite_module, "safe_rewrite"), "safe_rewrite() missing from public API"
    assert hasattr(safe_rewrite_module, "safe_restore"), "safe_restore() missing from public API"
    safe_rewrite = safe_rewrite_module.safe_rewrite
    safe_restore = safe_rewrite_module.safe_restore

    for fn, name in ((safe_rewrite, "safe_rewrite"), (safe_restore, "safe_restore")):
        params = inspect.signature(fn).parameters
        assert "skip_delta" not in params, f"skip_delta leaked onto {name}() signature"
        assert not any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()), (
            f"{name}() accepts **kwargs; skip_delta could be smuggled in"
        )

    # Positively assert the private helper exists with ``skip_delta`` on
    # its signature. This must come BEFORE the ``__all__`` check so the
    # helper's absence produces a clean AttributeError during RED.
    core = safe_rewrite_module._safe_rewrite_core
    assert "skip_delta" in inspect.signature(core).parameters, (
        "_safe_rewrite_core must expose skip_delta as its private knob"
    )

    exported = getattr(safe_rewrite_module, "__all__", None)
    if exported is not None:
        assert "skip_delta" not in exported
        assert "_safe_rewrite_core" not in exported, (
            "_safe_rewrite_core must remain a private helper"
        )
