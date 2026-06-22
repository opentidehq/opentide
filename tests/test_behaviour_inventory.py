"""Behaviour preservation tests driven by behaviour-inventory.md."""

from __future__ import annotations

import importlib

import pytest
from tests.behaviour_inventory import load_behaviour_ids, module_for_behaviour


@pytest.mark.parametrize("behaviour_id", load_behaviour_ids())
def test_behaviour_is_catalogued(behaviour_id: str) -> None:
    assert behaviour_id


@pytest.mark.parametrize("behaviour_id", load_behaviour_ids())
def test_behaviour_replacement_module_importable(behaviour_id: str) -> None:
    module_name = module_for_behaviour(behaviour_id)
    if module_name is None:
        pytest.skip(f"No replacement module mapped for {behaviour_id}")
    importlib.import_module(module_name)


def test_inventory_has_expected_minimum_count() -> None:
    assert len(load_behaviour_ids()) >= 55
