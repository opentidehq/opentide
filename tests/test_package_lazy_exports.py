"""Public package exports remain compatible without eager registry initialisation."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

_DOCUMENTATION_SCRIPT = """
from opentide.core.registry import OpenTide
import opentide.documentation as documentation

assert OpenTide.is_initialised is False
assert documentation.DocumentFlavor.github.value == "github"
assert callable(documentation.render_rule)
assert OpenTide.is_initialised is False
assert {"DocumentFlavor", "render_rule", "__name__"} <= set(dir(documentation))
"""

_GENERATION_SCRIPT = """
from opentide.core.registry import OpenTide
import opentide.generation as generation

assert OpenTide.is_initialised is False
assert callable(generation.generate_schemas)
assert callable(generation.generate_templates)
assert OpenTide.is_initialised is False
assert {"generate_schemas", "generate_templates", "__name__"} <= set(dir(generation))
"""


@pytest.mark.parametrize("script", [_DOCUMENTATION_SCRIPT, _GENERATION_SCRIPT])
def test_public_package_exports_are_lazy(script: str) -> None:
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        check=False,
        text=True,
        env={**os.environ},
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("package", ["opentide.documentation", "opentide.generation"])
def test_lazy_packages_reject_unknown_exports(package: str) -> None:
    script = f"""
import {package} as package

try:
    package.missing_export
except AttributeError as exc:
    assert "has no attribute" in str(exc)
else:
    raise AssertionError("unknown export did not raise AttributeError")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        check=False,
        text=True,
        env={**os.environ},
    )
    assert result.returncode == 0, result.stderr
