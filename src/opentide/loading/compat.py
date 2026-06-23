"""Backward-compatible loader aliases — delegates to opentide Pydantic loaders."""

from __future__ import annotations
from opentide.loading.objective_loader import load_objective_from_dict, load_signal_from_dict
from opentide.loading.rule_loader import load_rule_from_dict


class ObjectLoader:
    """Legacy ObjectLoader/TideLoader shim over Pydantic loaders."""

    load_signal = staticmethod(load_signal_from_dict)
    load_objective = staticmethod(load_objective_from_dict)
    load_rule = staticmethod(load_rule_from_dict)
    load_mdr = staticmethod(load_rule_from_dict)
    load_dom = staticmethod(load_objective_from_dict)


TideLoader = ObjectLoader
__all__ = ["ObjectLoader", "TideLoader"]
