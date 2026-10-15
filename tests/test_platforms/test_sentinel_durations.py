"""Sentinel rule durations: the ISO 8601 contract and the legacy shorthand."""

from __future__ import annotations

from datetime import timedelta

import pytest

from opentide.core.errors import Errors
from opentide.platforms.sentinel.client import iso_duration_timedelta


@pytest.mark.parametrize(
    ("duration", "expected"),
    [
        ("PT1H", timedelta(hours=1)),
        ("PT2H", timedelta(hours=2)),
        ("PT30M", timedelta(minutes=30)),
        ("P1D", timedelta(days=1)),
        ("P14D", timedelta(days=14)),
        ("P1DT2H", timedelta(days=1, hours=2)),
        ("PT1H30M", timedelta(hours=1, minutes=30)),
        ("P1W", timedelta(weeks=1)),
        ("pt15m", timedelta(minutes=15)),
        ("15m", timedelta(minutes=15)),
        ("1h", timedelta(hours=1)),
        ("14d", timedelta(days=14)),
    ],
)
def test_iso_duration_timedelta_parses_iso_and_shorthand(
    duration: str, expected: timedelta
) -> None:
    assert iso_duration_timedelta(duration) == expected


@pytest.mark.parametrize("duration", ["", "1", "1x", "P", "PT", "P1DT", "PT1.5H", "one hour"])
def test_iso_duration_timedelta_rejects_malformed_values(duration: str) -> None:
    with pytest.raises(Errors.TideMDRDataModelErrors, match="not an ISO 8601 duration"):
        iso_duration_timedelta(duration)


def test_client_module_imports_without_the_azure_sdk() -> None:
    """Parsing a duration must not need the ``sentinel`` extra."""
    import subprocess
    import sys

    script = """
import sys

class BlockAzure:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "azure" or fullname.startswith("azure."):
            raise ModuleNotFoundError(f"{fullname} blocked by regression test")
        return None

sys.meta_path.insert(0, BlockAzure())
from opentide.platforms.sentinel.client import iso_duration_timedelta
assert iso_duration_timedelta("PT1H").total_seconds() == 3600
assert "azure" not in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, check=False, text=True
    )
    assert result.returncode == 0, result.stderr
