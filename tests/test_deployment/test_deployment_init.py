"""Tests for the deployment compatibility exports."""

from __future__ import annotations

import importlib
import inspect
import subprocess
import sys

import pytest

_LAZY_DECLARE_PACKAGES = (
    "opentide.platforms.sentinel",
    "opentide.platforms.crowdstrike",
    "opentide.platforms.defender_for_endpoint",
    "opentide.platforms.sentinel_one",
    "opentide.platforms.harfanglab",
)


def test_import_deployment_does_not_import_pandas_dependent_planning() -> None:
    script = """
import sys

class BlockPandas:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "pandas" or fullname.startswith("pandas."):
            raise ModuleNotFoundError("pandas blocked by regression test")
        return None

sys.meta_path.insert(0, BlockPandas())
import opentide.deployment

assert "opentide.deployment.planning" not in sys.modules
"""

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_import_planning_does_not_require_pandas() -> None:
    script = """
import sys

class BlockPandas:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "pandas" or fullname.startswith("pandas."):
            raise ModuleNotFoundError("pandas blocked by regression test")
        return None

sys.meta_path.insert(0, BlockPandas())
import opentide.deployment.planning as planning

assert hasattr(planning, "TideDeployment")
assert "pandas" not in sys.modules
"""

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("module_name", _LAZY_DECLARE_PACKAGES)
def test_platform_package_exports_defined_declare(module_name: str) -> None:
    module = importlib.import_module(module_name)
    exported = module.declare
    assert "declare" in module.__all__
    assert inspect.isfunction(exported)
    assert exported.__module__ == module_name


def test_sentinel_declare_does_not_require_azure_or_pandas() -> None:
    script = """
import sys

class BlockOptional:
    def find_spec(self, fullname, path=None, target=None):
        blocked = ("pandas", "azure")
        if fullname in blocked or fullname.startswith("pandas.") or fullname.startswith("azure."):
            raise ModuleNotFoundError(f"{fullname} blocked by regression test")
        return None

sys.meta_path.insert(0, BlockOptional())
from opentide.platforms.sentinel import declare

assert "opentide.platforms.sentinel.deployer" not in sys.modules
deployer = declare()
assert deployer is not None
assert "azure" not in sys.modules
"""

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_tide_deployment_compatibility_export_is_lazy() -> None:
    from opentide import deployment

    deployment.__dict__.pop("TideDeployment", None)

    from opentide.deployment.planning import TideDeployment

    assert deployment.TideDeployment is TideDeployment
    assert deployment.__dict__["TideDeployment"] is TideDeployment
