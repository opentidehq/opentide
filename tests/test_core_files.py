"""Unit tests for opentide.core.files helpers."""

from __future__ import annotations

import pytest

from opentide.core.files import safe_file_name


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("hello/world", "helloworld"),
        ("safe-name", "safe-name"),
        ('bad<>:"|?*', "bad"),
    ],
)
def test_safe_file_name(raw: str, expected: str) -> None:
    assert safe_file_name(raw) == expected
