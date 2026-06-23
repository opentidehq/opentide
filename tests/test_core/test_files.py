"""Unit tests for opentide.core.files helpers."""

from __future__ import annotations

import pytest
import yaml

from opentide.core.files import IndentFullDumper, OrderedYAMLDumper, safe_file_name


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


def test_indent_full_dumper_preserves_nested_structure() -> None:
    payload = {"outer": {"inner": [1, 2]}}
    dumped = yaml.dump(payload, Dumper=IndentFullDumper, default_flow_style=False)
    loaded = yaml.safe_load(dumped)
    assert loaded == payload


def test_ordered_yaml_dumper_is_indent_full_subclass() -> None:
    assert issubclass(OrderedYAMLDumper, IndentFullDumper)
    payload = {"z": 1, "a": {"b": 2}}
    dumped = yaml.dump(payload, Dumper=OrderedYAMLDumper, default_flow_style=False)
    assert dumped.startswith("z:") or "z:" in dumped
