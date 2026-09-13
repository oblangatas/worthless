"""Docker probes used in module-level ``skipif`` must never raise.

They run at import time, so an exception is a collection error that aborts
the whole run on any machine without a ``docker`` binary.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests._docker_helpers import docker_available, image_present


@pytest.fixture
def no_docker_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("PATH", str(tmp_path))
    docker_available.cache_clear()
    yield
    docker_available.cache_clear()


def test_image_present_is_false_without_docker_binary(no_docker_on_path: None) -> None:
    assert image_present("worthless-oc-test:local") is False
