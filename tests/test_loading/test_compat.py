"""Legacy loader compatibility shims."""

from __future__ import annotations

from opentide.loading.compat import ObjectLoader, TideLoader
from opentide.loading.objective_loader import load_objective_from_dict, load_signal_from_dict


def test_object_loader_compat_shim_delegates() -> None:
    assert ObjectLoader.load_signal is load_signal_from_dict
    assert ObjectLoader.load_objective is load_objective_from_dict
    assert TideLoader.load_dom is load_objective_from_dict
