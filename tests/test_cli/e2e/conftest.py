"""Fixtures the console script's end-to-end tests share."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def wheel_cache(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Where this test run keeps its one wheel (``_build_wheel``).

    One directory for all of the run's xdist workers, under pytest's base
    temporary directory, so pytest removes it with the run's other files.
    """
    base = tmp_path_factory.getbasetemp()
    if os.environ.get("PYTEST_XDIST_WORKER"):
        base = base.parent
    return base / "opentide-wheel"
