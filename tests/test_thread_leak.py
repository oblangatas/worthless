"""Tests for thread leak detector and flaky test auto-quarantine."""

import subprocess
import sys
from pathlib import Path


def test_thread_leak_detection():
    """Test that a leaked background thread is caught by the detector."""
    # Write a test file that leaks a thread inside the tests directory so conftest.py is loaded
    test_file = Path(__file__).parent / "tmp_leak_test.py"
    test_file.write_text(
        """
import threading
import time

def test_leaky():
    def _run():
        time.sleep(1)
    t = threading.Thread(target=_run, name="LeakedTestThread")
    t.start()
    # Leaks the thread
""",
        encoding="utf-8",
    )

    try:
        # Run pytest on the temporary test file in a subprocess. ``timeout``
        # guards against a stuck child hanging the suite indefinitely.
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_file), "-vv", "-o", "addopts="],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),  # Run from project root so conftest.py is loaded
            timeout=30,
        )

        assert (
            "Thread leak detected: 1 thread(s) leaked during test" in result.stdout
            or "Thread leak detected" in result.stderr
        )
        assert "LeakedTestThread" in result.stdout or "LeakedTestThread" in result.stderr
        assert result.returncode != 0
    finally:
        if test_file.exists():
            test_file.unlink()


def test_quarantine_collection(tmp_path):
    """Verify that tests listed in quarantined_tests.txt are marked as quarantine."""
    # Create the tests directory inside tmp_path to mock the config rootdir structure
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    quarantine_file = tests_dir / "quarantined_tests.txt"
    quarantine_file.write_text("tests/test_dummy.py::dummy_quarantined_test\n", encoding="utf-8")

    # We can dynamically run pytest collection or verify using a mock config
    from tests.conftest import pytest_collection_modifyitems

    class MockConfig:
        def __init__(self, rootdir):
            self.rootdir = rootdir

    class MockItem:
        def __init__(self, nodeid, name):
            self.nodeid = nodeid
            self.name = name
            self.markers = []

        def add_marker(self, marker):
            self.markers.append(marker)

    config = MockConfig(tmp_path)
    # The collection logic matches by nodeid only, so we provide nodeid matching what we quarantined
    item1 = MockItem("tests/test_dummy.py::dummy_quarantined_test", "dummy_quarantined_test")
    item2 = MockItem("tests/test_dummy.py::healthy_test", "healthy_test")

    items = [item1, item2]
    pytest_collection_modifyitems(config, items)

    # Verify item1 got marked as quarantine
    assert len(item1.markers) > 0
    assert item1.markers[0].name == "quarantine"
    # Verify item2 did not
    assert len(item2.markers) == 0


def test_flaky_test_warning(caplog):
    """Verify that flaky tests (outcome passed, rerun > 0) log a warning message."""
    from tests.conftest import pytest_runtest_logreport
    import logging

    class MockReport:
        def __init__(self, when, outcome, rerun, nodeid):
            self.when = when
            self.outcome = outcome
            self.rerun = rerun
            self.nodeid = nodeid

    # Normal clean pass should not warn
    clean_report = MockReport("call", "passed", 0, "tests/test_foo.py::test_clean")
    with caplog.at_level(logging.WARNING):
        pytest_runtest_logreport(clean_report)
    assert not any("worthless-quarantine" in record.message for record in caplog.records)

    # Flaky pass (rerun > 0) should warn
    caplog.clear()
    flaky_report = MockReport("call", "passed", 1, "tests/test_foo.py::test_flaky")
    with caplog.at_level(logging.WARNING):
        pytest_runtest_logreport(flaky_report)

    warnings = [r.message for r in caplog.records if "worthless-quarantine" in r.message]
    assert len(warnings) == 1
    assert "Flaky test detected: tests/test_foo.py::test_flaky" in warnings[0]
