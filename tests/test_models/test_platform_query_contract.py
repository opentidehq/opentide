"""`query` must mean the same thing on every platform configuration (#233).

The drift was three-way: `SplunkConfig.query` and `CarbonBlackConfig.query`
were `str | None`, the JSON Schema extras listed `query` as required, and the
deployers treated a missing query as "skip this rule". Authors opening the
Splunk or Carbon Black template saw `#query: |` commented out while the other
five platforms showed it live, and a splunk::2.x rule deployed with no search
string at all because nothing mapped its legacy `search` field.
"""

from __future__ import annotations

import pytest

from opentide.generation.pydantic_skeleton import render_model_template
from opentide.loading.platform_loader import load_splunk_config
from opentide.models.platform import (
    PLATFORM_CONFIG_MODELS,
    CarbonBlackConfig,
    SplunkConfig,
)
from opentide.models.platform_schema import platform_root_extras

#: Platforms whose configuration carries a query string at all. SentinelOne
#: expresses detection through `condition`, HarfangLab through sigma/yara.
QUERY_PLATFORMS = [
    key for key, model in PLATFORM_CONFIG_MODELS.items() if "query" in model.model_fields
]


def test_the_query_platform_list_is_not_empty() -> None:
    assert len(QUERY_PLATFORMS) == 5


@pytest.mark.parametrize("key", QUERY_PLATFORMS)
def test_query_is_required_on_every_platform_that_has_one(key: str) -> None:
    field = PLATFORM_CONFIG_MODELS[key].model_fields["query"]
    assert field.is_required(), f"{key} declares query optional"


@pytest.mark.parametrize("key", QUERY_PLATFORMS)
def test_field_requiredness_agrees_with_the_schema_extras(key: str) -> None:
    """Extras drive the published JSON Schema; the model drives loading."""
    model = PLATFORM_CONFIG_MODELS[key]
    required = platform_root_extras(model).get("required", [])
    assert ("query" in required) == model.model_fields["query"].is_required()


@pytest.mark.parametrize("key", QUERY_PLATFORMS)
def test_templates_offer_query_uncommented(key: str) -> None:
    """The renderer follows FieldInfo, so authors see a live `query:` key."""
    rendered = render_model_template(PLATFORM_CONFIG_MODELS[key], indent=2)
    assert "\n  query: |" in rendered, f"{key} template comments out query"
    assert "#query:" not in rendered


@pytest.mark.parametrize("model", [SplunkConfig, CarbonBlackConfig])
def test_a_configuration_without_a_query_is_rejected(model: type) -> None:
    with pytest.raises(ValueError, match="query"):
        model(schema=f"{model.__name__}::3.0", status="STAGING")


#: Fields the JSON Schema extras call required while the model leaves them
#: optional. Left alone here on purpose, each for its own reason:
#:
#: * ``status`` is optional on the shared base for all seven platforms
#:   including Sentinel, so requiring it is a decision about every existing
#:   object rather than about Splunk;
#: * a Splunk correlation search has nothing to schedule;
#: * Sentinel entity mappings and alert grouping are genuinely optional on an
#:   analytics rule.
#:
#: Recorded so that *new* drift fails while the accepted set stays visible.
KNOWN_EXTRAS_ONLY_REQUIRED = frozenset({"status", "scheduling", "entities", "grouping"})


@pytest.mark.parametrize("key", sorted(PLATFORM_CONFIG_MODELS))
def test_no_new_drift_between_schema_extras_and_models(key: str) -> None:
    model = PLATFORM_CONFIG_MODELS[key]
    required = set(platform_root_extras(model).get("required", []))
    optional_in_model = {
        name
        for name in required
        if name in model.model_fields and not model.model_fields[name].is_required()
    }
    unexpected = optional_in_model - KNOWN_EXTRAS_ONLY_REQUIRED
    assert not unexpected, f"{key}: schema extras require {sorted(unexpected)}, model does not"


# --------------------------------------------------------------------------
# splunk::2.x compatibility
# --------------------------------------------------------------------------


LEGACY_SPLUNK = {
    "schema": "splunk::2.0",
    "enabled": True,
    "name": "Splunk SPL Rule",
    "status": "STAGING",
    "search": "index=main | head 1",
    "cron_schedule": "0 * * * *",
}


def test_legacy_search_becomes_the_query() -> None:
    config = load_splunk_config(dict(LEGACY_SPLUNK))
    assert config.query == "index=main | head 1"
    # Kept so the object round-trips unchanged.
    assert config.search == "index=main | head 1"


def test_legacy_cron_schedule_becomes_the_schedule() -> None:
    config = load_splunk_config(dict(LEGACY_SPLUNK))
    assert config.scheduling is not None
    assert config.scheduling.schedule is not None
    assert config.scheduling.schedule.cron == "0 * * * *"
    assert config.cron_schedule == "0 * * * *"


def test_a_modern_query_wins_over_the_legacy_spelling() -> None:
    config = load_splunk_config({**LEGACY_SPLUNK, "query": "index=modern"})
    assert config.query == "index=modern"


def test_a_modern_scheduling_block_wins_over_cron_schedule() -> None:
    config = load_splunk_config(
        {**LEGACY_SPLUNK, "scheduling": {"schedule": {"cron": "*/5 * * * *"}}}
    )
    assert config.scheduling is not None
    assert config.scheduling.schedule is not None
    assert config.scheduling.schedule.cron == "*/5 * * * *"


def test_schema_validation_maps_legacy_fields_too() -> None:
    """Validation calls `model_validate` on raw YAML, never the loader."""
    config = SplunkConfig.model_validate(LEGACY_SPLUNK)
    assert config.query == "index=main | head 1"
    assert config.scheduling is not None
