"""opentide imports only the private Typer modules its ``typer`` pin guarantees.

Typer vendors Click under ``typer._click`` and keeps completion and Rich help
in private modules. opentide's CLI is built on them, and Typer changes them
without notice: 0.29.0 removed ``typer._types`` and ``click_type`` and rewrote
the vendored Click, so ``pip install opentide`` resolved a Typer that crashed
``opentide setup``. These tests fail when ``src/opentide`` starts importing a
private Typer path that the verified versions do not have, or when the pin in
``pyproject.toml`` lets pip install an unverified Typer.
"""

from __future__ import annotations

import ast
import importlib
import importlib.metadata
import importlib.util
import sys
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "opentide"

#: Private Typer paths opentide uses, each verified on every Typer the pin allows
#: (0.27.0 through 0.28.x). ``None`` means the whole module; a name is one
#: private attribute imported from a public module.
VERIFIED_PRIVATE: frozenset[tuple[str, str | None]] = frozenset(
    {
        ("typer._click", None),
        ("typer._click.core", None),
        ("typer._click.globals", None),
        ("typer._click.shell_completion", None),
        ("typer._completion_classes", None),
        ("typer._completion_shared", None),
        ("typer.rich_utils", "_get_rich_console"),
    }
)

#: The first Typer release that breaks the private paths above.
FIRST_BROKEN_TYPER = Version("0.29.0")


def _is_private(dotted: str) -> bool:
    return any(part.startswith("_") for part in dotted.split("."))


def _private_typer_imports(source: str) -> set[tuple[str, str | None]]:
    found: set[tuple[str, str | None]] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "typer" and _is_private(alias.name):
                    found.add((alias.name, None))
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            module = node.module
            if module.split(".")[0] != "typer":
                continue
            for alias in node.names:
                if _is_private(module):
                    found.add((module, None))
                elif alias.name.startswith("_"):
                    # ``from typer import _click`` imports a private module;
                    # ``from typer.rich_utils import _x`` a private attribute.
                    submodule = f"{module}.{alias.name}"
                    if importlib.util.find_spec(module) is not None and _is_module(submodule):
                        found.add((submodule, None))
                    else:
                        found.add((module, alias.name))
    return found


def _is_module(dotted: str) -> bool:
    try:
        return importlib.util.find_spec(dotted) is not None
    except ModuleNotFoundError:
        return False


def _package_private_imports() -> dict[tuple[str, str | None], list[str]]:
    uses: dict[tuple[str, str | None], list[str]] = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        for found in _private_typer_imports(path.read_text(encoding="utf-8")):
            uses.setdefault(found, []).append(str(path.relative_to(ROOT)))
    return uses


def _typer_requirement() -> Requirement:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    for entry in data["project"]["dependencies"]:
        requirement = Requirement(entry)
        if requirement.name == "typer":
            return requirement
    raise AssertionError("pyproject.toml declares no typer dependency")


def test_detector_sees_a_removed_private_module() -> None:
    """The scan catches the import that broke on Typer 0.29.0."""
    found = _private_typer_imports("from typer._types import TyperChoice\n")
    assert ("typer._types", None) in found


def test_detector_sees_private_modules_and_attributes() -> None:
    source = (
        "import typer\n"
        "from typer import _click\n"
        "from typer.core import TyperGroup\n"
        "from typer.rich_utils import _get_rich_console\n"
        "import typer._completion_shared\n"
    )
    assert _private_typer_imports(source) == {
        ("typer._click", None),
        ("typer.rich_utils", "_get_rich_console"),
        ("typer._completion_shared", None),
    }


def test_src_imports_only_verified_private_typer_paths() -> None:
    unverified = {
        found: files
        for found, files in _package_private_imports().items()
        if found not in VERIFIED_PRIVATE
    }
    assert not unverified, (
        "src/opentide imports private Typer paths no verified Typer guarantees; "
        f"use Typer's public API instead: {unverified}"
    )


@pytest.mark.parametrize(("module", "name"), sorted(VERIFIED_PRIVATE, key=str))
def test_verified_private_typer_paths_resolve(module: str, name: str | None) -> None:
    """Each private path exists in the installed Typer, which the pin allows."""
    imported = importlib.import_module(module)
    if name is not None:
        assert hasattr(imported, name), f"{module} has no {name}"


def test_typer_pin_excludes_the_first_broken_release() -> None:
    specifier = _typer_requirement().specifier
    assert not specifier.contains(FIRST_BROKEN_TYPER, prereleases=True), (
        f"typer {specifier} lets pip install {FIRST_BROKEN_TYPER}, which removed "
        "private paths opentide imports"
    )
    assert any(spec.operator in {"<", "<="} for spec in specifier), (
        "typer needs an upper bound while opentide imports private Typer paths"
    )


def test_installed_typer_satisfies_the_pin() -> None:
    installed = importlib.metadata.version("typer")
    assert _typer_requirement().specifier.contains(installed, prereleases=True)
