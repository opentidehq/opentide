"""Tests for platform plugins deprecation."""

from __future__ import annotations

import contextlib
import warnings
from unittest.mock import patch

import pytest

# Imported here, at collection time, on purpose (#530).
#
# The test below nulls the accessor's caches to force `_ensure_loaded`, which
# does `from opentide.deployment import enabled_systems` *inside* the method --
# so that import runs while `opentide.core.registry.OpenTide` is patched with a
# MagicMock. `opentide.deployment.utils` binds `OpenTide` at module level and
# evaluates `SYSTEMS_CONFIGS_INDEX` at import time, so whichever test imports it
# first under that patch leaves the module holding a dead mock for the rest of
# the process. Every later deployment test then reads statuses off the mock,
# which iterates empty: "Status 'STAGING' is not defined ... Available: ."
#
# Importing it now means it is already in sys.modules, so the lazy import is a
# cache hit that cannot rebind. Do not move this inside the test.
import opentide.deployment  # noqa: F401
from opentide.platforms import plugins


def test_platforms_accessor_emits_deprecation_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    accessor = plugins.Platforms
    # monkeypatch, not bare assignment: these are the accessor's process-wide
    # caches. Assigning them left the mocked loader's empty dicts behind, and
    # because the guard is `is None` they never reloaded.
    monkeypatch.setattr(accessor, "_deployers", None, raising=False)
    monkeypatch.setattr(accessor, "_validators", None, raising=False)
    monkeypatch.setattr(accessor, "_instances", None, raising=False)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with (
            patch("opentide.platforms.plugins.PlatformLoader") as mock_loader,
            patch("opentide.core.registry.OpenTide") as mock_tide,
            patch("opentide.deployment.enabled_systems", return_value=[]),
        ):
            mock_loader.return_value.rule_deployers.return_value = {}
            mock_loader.return_value.query_validators.return_value = {}
            mock_tide.Configuration.Systems.Index = {}
            with contextlib.suppress(KeyError):
                _ = accessor["sentinel"]
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)

    # Regression guard for #530, asserted here rather than in a separate test
    # because a separate one is not guaranteed to run after this in the same
    # worker: xdist distributes individual tests, so it could land elsewhere and
    # never see the leak.
    #
    # Since #536 utils resolves `registry.OpenTide` at call time instead of
    # binding its own name, so a patch can no longer be captured by an import.
    # This asserts the property that actually matters -- what the code under
    # test will read -- and so keeps holding whichever way the seam is spelled.
    import opentide.deployment.utils as deployment_utils
    from opentide.core.registry import OpenTideRegistry

    assert isinstance(deployment_utils.registry.OpenTide, OpenTideRegistry), (
        "a mocked registry is still visible to opentide.deployment.utils after the "
        "patch exited; it must resolve registry.OpenTide at call time (#530, #536)"
    )
