"""PyPI distribution and migration tests."""

from __future__ import annotations

import importlib
import warnings

from opentide import __version__


def test_package_version_is_string() -> None:
    assert isinstance(__version__, str)
    assert __version__


def test_legacy_tide_shim_emits_deprecation_warning() -> None:
    import sys

    sys.modules.pop("Engines.modules.tide", None)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        mod = importlib.import_module("Engines.modules.tide")
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)
    assert mod.DataTide is not None
