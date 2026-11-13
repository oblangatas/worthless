"""Live test suite — real-provider round-trips (``@pytest.mark.live``).

These tests hit real OpenAI/Anthropic APIs through the worthless proxy and cost
real money, so they are excluded from the default run and skipped without keys.
Run them with the live lane in ``engineering/tooling.md`` (one at a time, no
retries); they require the relevant provider API key(s) in the environment.
"""
