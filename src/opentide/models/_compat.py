"""What keeps the names ``opentide.models`` had before the Rust classes (ADR 0011).

Two mechanisms, both cheap until used (``import opentide.models`` loads neither
Pydantic nor the Pydantic package):

- :func:`deprecated_attribute`: a model module's name that is the Pydantic
  package's (``opentide.models.rule.TideRegistry``) resolves to it with a
  ``DeprecationWarning``, for one minor release.
- :class:`PydanticPackageAlias`: a submodule ``opentide.models`` no longer
  defines (``results``, ``configuration``, ``deployment_enums``,
  ``object_types``, ``schema_registry``, …, none of them Tide models) is the
  Pydantic package's module of that name: the same module object, so its
  classes are the ones the CLI uses, and ``isinstance`` checks agree.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
import warnings
from importlib.machinery import ModuleSpec
from types import ModuleType

#: The public package, and the Pydantic package it keeps names from.
PUBLIC = "opentide.models"
PYDANTIC = "opentide._models"

#: The submodules the public package defines itself: the Rust classes, by the
#: Pydantic module that held them, and the private ones.
OWN_SUBMODULES = frozenset(
    {
        "rule",
        "objective",
        "threat",
        "metadata",
        "platform",
        "platform_configs",
        "response",
        "delegation",
        "_compat",
    }
)


def deprecated_attribute(module: str, pydantic_module: str, name: str) -> object:
    """*name* of *pydantic_module*, with a ``DeprecationWarning``; *module* is
    the public module it was read from. An ``AttributeError`` when the
    Pydantic module has no such name either."""
    if name.startswith("__"):
        raise AttributeError(f"module {module!r} has no attribute {name!r}")
    source = importlib.import_module(pydantic_module)
    try:
        value = getattr(source, name)
    except AttributeError:
        raise AttributeError(f"module {module!r} has no attribute {name!r}") from None
    warnings.warn(
        f"{module}.{name} is part of the Pydantic models, which opentide.models no "
        "longer exports: the Tide models are Rust classes (ADR 0011). It will be "
        "removed in a later minor release.",
        DeprecationWarning,
        stacklevel=3,
    )
    return value


class _ExistingModule:
    """Loader that hands the import system a module already imported."""

    def __init__(self, target: str) -> None:
        self.target = target

    def create_module(self, spec: ModuleSpec) -> ModuleType:
        return importlib.import_module(self.target)

    def exec_module(self, module: ModuleType) -> None:
        return None


class PydanticPackageAlias:
    """Meta-path finder: ``opentide.models.<name>[.<sub>…]``, for a ``<name>``
    not in :data:`OWN_SUBMODULES`, is ``opentide._models.<name>[.<sub>…]``."""

    @classmethod
    def find_spec(
        cls, fullname: str, path: object = None, target: object = None
    ) -> ModuleSpec | None:
        if not fullname.startswith(PUBLIC + "."):
            return None
        rest = fullname[len(PUBLIC) + 1 :]
        if rest.partition(".")[0] in OWN_SUBMODULES:
            return None
        aliased = f"{PYDANTIC}.{rest}"
        if importlib.util.find_spec(aliased) is None:
            return None
        loader = _ExistingModule(aliased)
        # importlib.abc.Loader would be the declared type; importing importlib.abc costs
        # ~18 ms (it loads importlib.resources), more than half the import budget.
        return ModuleSpec(fullname, loader)  # ty: ignore[invalid-argument-type]  # duck-typed Loader


def install() -> None:
    """Puts :class:`PydanticPackageAlias` first on ``sys.meta_path``, once."""
    if PydanticPackageAlias not in sys.meta_path:
        sys.meta_path.insert(0, PydanticPackageAlias)
