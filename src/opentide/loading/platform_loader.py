"""Platform block loading for deploy, docs and the query checks: the models ``validate`` runs."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import Any, cast

from opentide.models.platform import (
    CarbonBlackConfig,
    CrowdstrikeConfig,
    DefenderConfig,
    ElasticConfig,
    HarfangLabConfig,
    PlatformConfigBase,
    SentinelConfig,
    SentinelOneConfig,
    SplunkConfig,
    SysdigConfig,
)
from opentide.states.deployment import is_legacy_external_id_key


def _without_external_ids(mdr_config: dict[str, Any]) -> dict[str, Any]:
    """Drop ``rule_id``, ``rule_id_bundle`` and ``rule_id::<tenant>`` from a block.

    Vendor ids live in ``.opentide/states/deployment/`` (RFC 0010). The keys are
    not read here: ``opentide validate`` reports them as ``external_id_in_rule``
    and deploy refuses the rule from its authored document, before any HTTP
    call. Dropping them lets the rest of the catalogue load while a rule waits
    for ``opentide deploy migrate-state``.
    """
    return {key: value for key, value in mdr_config.items() if not is_legacy_external_id_key(key)}


def _loader(model: type[PlatformConfigBase]) -> Callable[[dict[str, Any]], PlatformConfigBase]:
    """A block loader that is the model ``validate`` runs, and nothing else.

    The loaders used to rebuild each block field by field. Whatever they did not
    pick up was dropped: a key ``validate`` refused deployed silently, a block
    ``validate`` refused for a missing ``scheduling`` loaded with an empty one,
    and legacy spellings loaded on one path only. Validating the block with its
    model keeps deploy, docs and the query checks on exactly the rules
    ``validate`` accepts.
    """

    def load(mdr_config: dict[str, Any]) -> PlatformConfigBase:
        return model.model_validate(_without_external_ids(deepcopy(mdr_config)))

    load.__name__ = f"load_{model.__name__}"
    return load


load_sentinel_config = _loader(SentinelConfig)
load_defender_config = _loader(DefenderConfig)
load_splunk_config = _loader(SplunkConfig)
load_sentinel_one_config = _loader(SentinelOneConfig)
load_crowdstrike_config = _loader(CrowdstrikeConfig)
load_harfanglab_config = _loader(HarfangLabConfig)
load_carbon_black_config = _loader(CarbonBlackConfig)
load_elastic_config = _loader(ElasticConfig)
load_sysdig_config = _loader(SysdigConfig)


_PLATFORM_LOADERS = {
    "sentinel": load_sentinel_config,
    "defender_for_endpoint": load_defender_config,
    "splunk": load_splunk_config,
    "sentinel_one": load_sentinel_one_config,
    "crowdstrike": load_crowdstrike_config,
    "harfanglab": load_harfanglab_config,
    "carbon_black_cloud": load_carbon_black_config,
    "elastic": load_elastic_config,
    "sysdig": load_sysdig_config,
}


def load_platform_config(platform: str, payload: dict[str, Any]) -> PlatformConfigBase:
    """Parse a raw platform configuration dict into a typed model."""
    loader = _PLATFORM_LOADERS.get(platform)
    if loader is None:
        raise ValueError(f"Unknown platform {platform!r}")
    return cast(PlatformConfigBase, loader(payload))
