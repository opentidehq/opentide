"""The package's public surface after UC-6.2 (#841): the SDK, the models, the
plugin API, the analysis door and the console script; nothing of the Python
implementation it replaced."""

from __future__ import annotations

import importlib
import sys
from importlib.metadata import entry_points
from importlib.resources import files
from pathlib import Path

import pytest

import opentide
import opentide.models

#: What ``opentide`` exports, from ``opentide.sdk``.
SDK = {
    "Canceller",
    "Capabilities",
    "Connection",
    "DeployOutcome",
    "DeployPlan",
    "LintReport",
    "LiveCheck",
    "OpentideError",
    "QueryResult",
    "TenantConfig",
    "Validation",
    "Workspace",
    "run_json",
}

#: Modules the Python implementation had; each is gone, with no shim.
REMOVED = (
    "opentide.cli",
    "opentide.cli.launch",
    "opentide.cli.services",
    "opentide.core",
    "opentide.core.registry",
    "opentide.validation",
    "opentide.loading",
    "opentide.registry",
    "opentide.indexing",
    "opentide.generation",
    "opentide.documentation",
    "opentide.export",
    "opentide.ci",
    "opentide.deployment",
    "opentide.platforms",
    "opentide.sharing",
    "opentide.query",
    "opentide.mcp_server",
    "opentide.vocabulary",
    "opentide._models",
    "opentide.models.delegation",
    "opentide.models.results",
    "opentide.schemas.store",
)


def test_the_sdk_is_the_package_api() -> None:
    assert set(opentide.__all__) == SDK | {"__version__"}
    assert opentide.__version__
    for name in SDK:
        assert getattr(opentide, name) is getattr(importlib.import_module("opentide.sdk"), name)


@pytest.mark.parametrize("name", ["Opentide", "OpenTide"])
def test_the_registry_is_gone(name: str) -> None:
    with pytest.raises(AttributeError):
        getattr(opentide, name)


@pytest.mark.parametrize("module", REMOVED)
def test_the_python_implementation_is_gone(module: str) -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module)


def test_the_models_are_the_rust_classes() -> None:
    from opentide.models import DetectionRule, DetectionRule_v1_1, ValidationError

    assert DetectionRule.__module__ == "opentide._native.models"
    assert DetectionRule_v1_1.__schema_identifier__ == "rule::1.1"
    assert issubclass(ValidationError, ValueError)
    for removed in ("TideModel", "TideRegistry", "ValidationResult", "RULE"):
        with pytest.raises(AttributeError):
            getattr(importlib.import_module("opentide.models"), removed)


def test_importing_the_package_loads_neither_the_engine_nor_pydantic() -> None:
    import subprocess

    code = (
        "import sys, opentide, opentide.models, opentide.plugins; "
        "print(sorted(m for m in ('opentide.sdk', 'pydantic') if m in sys.modules))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "[]"


def test_bundled_data_ships_with_the_package() -> None:
    data_path = Path(str(files("opentide.data")))
    assert data_path.is_dir()
    platforms = list((data_path / "configurations" / "platforms").glob("*.toml"))
    assert len(platforms) == 9
    assert (data_path / "diagnostics" / "engine_unavailable.md").is_file()


def test_no_builtin_platform_is_an_entry_point() -> None:
    """The built-in platforms are the Rust core's: the ``opentide.platforms``
    group holds plugins only."""
    from opentide.plugins import BUILTIN_PLATFORMS

    names = {point.name for point in entry_points(group="opentide.platforms")}
    assert not names & BUILTIN_PLATFORMS


def test_the_console_script_is_the_launcher() -> None:
    (script,) = [
        point for point in entry_points(group="console_scripts") if point.name == "opentide"
    ]
    assert script.value == "opentide._cli:main"


@pytest.mark.parametrize(
    "module",
    [
        "metadata",
        "objective",
        "platform",
        "platform_configs",
        "response",
        "rule",
        "threat",
    ],
)
def test_each_model_module_holds_the_rust_classes(module: str) -> None:
    """``opentide.models.<module>`` names the Rust classes of that module, and only them."""
    imported = importlib.import_module(f"opentide.models.{module}")
    assert imported.__all__
    for name in imported.__all__:
        value = getattr(imported, name)
        assert value.__module__ == "opentide._native.models", (module, name)
        assert getattr(opentide.models, name) is value
    with pytest.raises(AttributeError):
        imported.TideModel  # noqa: B018 -- the Pydantic machinery is gone
