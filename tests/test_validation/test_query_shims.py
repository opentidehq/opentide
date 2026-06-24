"""Validation shim module registration."""

from __future__ import annotations

import importlib


def test_splunk_query_shim_declares_validator() -> None:
    module = importlib.import_module("opentide.validation.splunk_query")
    validator = module.declare()
    assert validator.DEPLOYER_IDENTIFIER == "splunk"


def test_carbon_black_cloud_query_shim_declares_validator() -> None:
    module = importlib.import_module("opentide.validation.carbon_black_cloud_query")
    validator = module.declare()
    assert validator.DEPLOYER_IDENTIFIER == "carbon_black_cloud"
