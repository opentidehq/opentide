"""Public package exports remain compatible without eager registry initialisation."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

_DOCUMENTATION_SCRIPT = """
from opentide.core.registry import Opentide
import opentide.documentation as documentation

assert Opentide.is_initialised is False
assert documentation.DocumentFlavor.github.value == "github"
assert callable(documentation.render_rule)
assert Opentide.is_initialised is False
assert {"DocumentFlavor", "render_rule", "__name__"} <= set(dir(documentation))
"""

_GENERATION_SCRIPT = """
from opentide.core.registry import Opentide
import opentide.generation as generation

assert Opentide.is_initialised is False
assert callable(generation.generate_schemas)
assert callable(generation.generate_templates)
assert Opentide.is_initialised is False
assert {"generate_schemas", "generate_templates", "__name__"} <= set(dir(generation))
"""

# #536: these modules used to evaluate `Opentide.Configurations.Systems.Index`
# at module level, so importing them built the whole registry index (~271 ms)
# and bound whichever opentide was live at the time -- which is how a test that
# imported one under patch() left a dead MagicMock behind for the process.
# Importing the deployment package must touch no registry state; only reading
# SYSTEMS_CONFIGS_INDEX may.
_DEPLOYMENT_SCRIPT = """
from opentide.core.index_manager import IndexManager
from opentide.core.registry import Opentide
import opentide.deployment as deployment

assert Opentide.is_initialised is False, "importing opentide.deployment initialised the registry"
assert IndexManager._cache is None, "importing opentide.deployment built the registry index"

# The re-export still resolves, and only now is the index built.
assert isinstance(deployment.SYSTEMS_CONFIGS_INDEX, dict)
assert IndexManager._cache is not None
assert {"SYSTEMS_CONFIGS_INDEX", "check_status", "__name__"} <= set(dir(deployment))
"""

_DEPLOYMENT_SUBMODULE_SCRIPT = """
from opentide.core.index_manager import IndexManager
from opentide.core.registry import Opentide

for name in ("utils", "ci", "git_repo", "planning"):
    __import__("opentide.deployment." + name)
    assert Opentide.is_initialised is False, name + " import initialised the registry"
    assert IndexManager._cache is None, name + " import built the registry index"

# Each module still serves the name it used to define at import time.
import opentide.deployment.ci as ci
import opentide.deployment.git_repo as git_repo
import opentide.deployment.planning as planning
import opentide.deployment.utils as utils

for module in (utils, ci, git_repo, planning):
    assert isinstance(module.SYSTEMS_CONFIGS_INDEX, dict), module.__name__
"""

# #539: #536 left reads in class bodies, which run at import just like module
# level ones. DebugEnvironment read the deployment config that way, and every
# platform client, deployer and validator imports it, so loading any engine
# built the index. Import every module in the package and check after each one.
# A module that needs a third-party package the environment lacks is skipped;
# a missing opentide module is still a failure.
_ALL_MODULES_SCRIPT = """
import importlib
import pkgutil

import opentide
from opentide.core.index_manager import IndexManager
from opentide.core.registry import Opentide

imported = 0
for info in pkgutil.walk_packages(opentide.__path__, "opentide."):
    if info.name.endswith(".__main__"):
        continue
    try:
        importlib.import_module(info.name)
    except ModuleNotFoundError as exc:
        if (exc.name or "").partition(".")[0] == "opentide":
            raise
        continue
    imported += 1
    assert Opentide.is_initialised is False, info.name + " import initialised the registry"
    assert IndexManager._cache is None, info.name + " import built the registry index"

assert imported > 200, imported

# The debug settings still resolve, and only now is the index built.
from opentide.core.debug import DebugEnvironment

assert isinstance(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, list)
assert isinstance(DebugEnvironment.SSL_ENABLED, bool)
assert IndexManager._cache is not None
"""


@pytest.mark.parametrize(
    "script",
    [
        _DOCUMENTATION_SCRIPT,
        _GENERATION_SCRIPT,
        _DEPLOYMENT_SCRIPT,
        _DEPLOYMENT_SUBMODULE_SCRIPT,
        _ALL_MODULES_SCRIPT,
    ],
)
def test_public_package_exports_are_lazy(script: str) -> None:
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        check=False,
        text=True,
        env={**os.environ},
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "package",
    [
        "opentide.documentation",
        "opentide.generation",
        "opentide.deployment",
        "opentide.deployment.utils",
        "opentide.deployment.ci",
        "opentide.deployment.git_repo",
        "opentide.deployment.planning",
    ],
)
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


@pytest.mark.parametrize(
    "module",
    ["opentide", "opentide.core", "opentide.core.registry"],
)
def test_the_pre_0_16_1_spelling_still_imports_with_a_warning(module: str) -> None:
    """``OpenTide`` was the class name through 0.16.0; it keeps working, deprecated."""
    import importlib

    mod = importlib.import_module(module)
    with pytest.warns(DeprecationWarning, match="OpenTide is now Opentide"):
        old = mod.OpenTide
    assert old is mod.Opentide


def test_the_old_registry_class_spelling_still_imports_with_a_warning() -> None:
    from opentide.core import registry

    with pytest.warns(DeprecationWarning, match="OpenTideRegistry is now OpentideRegistry"):
        old = registry.OpenTideRegistry
    assert old is registry.OpentideRegistry


@pytest.mark.parametrize(
    "module",
    ["opentide.core.files", "opentide.registry.builder", "opentide.mutation.promotion"],
)
def test_module_imports_first_in_a_fresh_interpreter(module: str) -> None:
    """``import opentide`` no longer loads the registry, so no import order is implied.

    ``opentide.core.files`` and ``opentide.registry`` import each other; a
    module that reaches ``core.files`` first must still import.
    """
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        capture_output=True,
        check=False,
        text=True,
        env={**os.environ},
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("package", "name", "loads"),
    [
        ("opentide", "Opentide", "opentide.core.registry"),
        ("opentide.core", "Opentide", "opentide.core.registry"),
        ("opentide.registry", "RegistryBuilder", "opentide.registry.builder"),
    ],
)
def test_lazy_names_are_listed_without_being_loaded(package: str, name: str, loads: str) -> None:
    """``dir()`` lists the lazy export for REPL and IDE completion, and loads nothing."""
    script = f"""
import sys
import {package} as package

assert {name!r} in dir(package), dir(package)
assert {loads!r} not in sys.modules, "dir() loaded {loads}"
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        check=False,
        text=True,
        env={**os.environ},
    )
    assert result.returncode == 0, result.stderr
