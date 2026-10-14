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

# #536: these modules used to evaluate `OpenTide.Configurations.Systems.Index`
# at module level, so importing them built the whole registry index (~271 ms)
# and bound whichever OpenTide was live at the time -- which is how a test that
# imported one under patch() left a dead MagicMock behind for the process.
# Importing the deployment package must touch no registry state; only reading
# SYSTEMS_CONFIGS_INDEX may.
_DEPLOYMENT_SCRIPT = """
from opentide.core.index_manager import IndexManager
from opentide.core.registry import OpenTide
import opentide.deployment as deployment

assert OpenTide.is_initialised is False, "importing opentide.deployment initialised the registry"
assert IndexManager._cache is None, "importing opentide.deployment built the registry index"

# The re-export still resolves, and only now is the index built.
assert isinstance(deployment.SYSTEMS_CONFIGS_INDEX, dict)
assert IndexManager._cache is not None
assert {"SYSTEMS_CONFIGS_INDEX", "check_status", "__name__"} <= set(dir(deployment))
"""

_DEPLOYMENT_SUBMODULE_SCRIPT = """
from opentide.core.index_manager import IndexManager
from opentide.core.registry import OpenTide

for name in ("utils", "ci", "git_repo", "planning"):
    __import__("opentide.deployment." + name)
    assert OpenTide.is_initialised is False, name + " import initialised the registry"
    assert IndexManager._cache is None, name + " import built the registry index"

# Each module still serves the name it used to define at import time.
import opentide.deployment.ci as ci
import opentide.deployment.git_repo as git_repo
import opentide.deployment.planning as planning
import opentide.deployment.utils as utils

for module in (utils, ci, git_repo, planning):
    assert isinstance(module.SYSTEMS_CONFIGS_INDEX, dict), module.__name__
"""


@pytest.mark.parametrize(
    "script",
    [_DOCUMENTATION_SCRIPT, _GENERATION_SCRIPT, _DEPLOYMENT_SCRIPT, _DEPLOYMENT_SUBMODULE_SCRIPT],
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
