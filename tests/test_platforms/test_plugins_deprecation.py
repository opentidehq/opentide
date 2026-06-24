"""Tests for platform plugins deprecation."""

from __future__ import annotations

import contextlib
import warnings
from unittest.mock import patch

from opentide.platforms import plugins


def test_platforms_accessor_emits_deprecation_warning() -> None:
    accessor = plugins.Platforms
    accessor._deployers = None
    accessor._validators = None
    accessor._instances = None
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
