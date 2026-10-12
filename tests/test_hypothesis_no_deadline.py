"""worthless-h4jf: timing is not a property under test.

Hypothesis fails any example that takes over 200 ms unless the deadline is
off. On a busy machine (parallel sessions, xdist) a crypto property that holds
then fails, everyone learns to re-run it, and a re-run that goes green looks
the same whether the property held or the machine was quiet. conftest.py
turns the deadline off for every profile, so no test can forget it.
"""

from __future__ import annotations

import time

from hypothesis import given, settings
from hypothesis import strategies as st


@given(st.just(0))
@settings(max_examples=2)
def test_a_slow_example_does_not_fail_a_property_that_holds(_: int) -> None:
    time.sleep(0.3)  # over Hypothesis's 200 ms default deadline
